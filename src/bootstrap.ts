/**
 * Plugin bootstrap step 2 — component assembly + side-effect installs.
 *
 * Builds every long-lived collector/engine and wires them together, then
 * installs the process-level side effects (RuntimeHook seam, network
 * capture, signal handlers). The function is idempotent in shape but not
 * re-entrant — calling it twice will overwrite the first set of components.
 *
 * Lifecycle guarantees:
 *   - Returns disposers for every ctx.effect-bound cleanup. `apply()`
 *     composes them into its own ctx.effect shutdown block.
 *   - `runtimeHookInstalled` reflects whether the pre-spawn seam actually
 *     wrapped `ctx.subprocess.spawn` (false on headless boot — the
 *     deferred setTimeout fallback handles the common case).
 *   - onTamper callback reaches `applicationCollector` via late binding
 *     (lazy reference) so it carries the correct session identity for
 *     the post-construction emit.
 */
import type { Context, SubprocessRuntimeLike } from './types/external.js'
import { DEFAULT_PLATFORM_ID } from './types/index.js'
import type { Config as ConfigShape } from './config.js'
import { buildHostMeta, LocalNdjsonSink } from './collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from './collectors/ApplicationCollector.js'
import { NetworkHttpCollector } from './collectors/NetworkHttpCollector.js'
import { InterventionEngine } from './intervention/InterventionEngine.js'
import { RuntimeHook } from './intervention/RuntimeHook.js'
import { SensitivePathWatcher } from './intervention/SensitivePathWatcher.js'
import {
  createSelfProtectionGuard,
  installSelfProtectionGuard,
} from './intervention/SelfProtectionGuard.js'
import { installPluginUnloadSentinel } from './intervention/PluginUnloadSentinel.js'
import { DebugLog } from './utils/debugLog.js'
import { generateEventId } from './utils/eventId.js'
import { installSignalHandlers } from './utils/signalHandlers.js'
import { registerSecurityCommand } from './commands/security.js'
import { registerSecurityMonitorRemote } from './typert/host.js'
import { OverviewCache } from './status/overviewCache.js'
import { LivePatchManager } from './config/livePatch.js'
import { resolveStdioMirrorWrapperPath } from './runtime/stdioMirrorEntry.js'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

export interface AssembledComponents {
  eventCollector: LocalNdjsonSink
  interventionEngine: InterventionEngine
  applicationCollector: ApplicationCollector
  networkHttpCollector: NetworkHttpCollector
  runtimeHook: RuntimeHook
  disposeSecurityCommand: () => void
  disposeSecurityMonitorRemote: () => void
}

export function assembleComponents(
  ctx: Context,
  config: ConfigShape,
  debugLog: DebugLog,
  options?: {
    /**
     * Default-mode-from-policy seam.
     * True iff the operator explicitly set `intervention.mode` or
     * top-level `mode` in the config. When false, the engine is
     * allowed to consult the loaded policy files' `mode:` field
     * as the runtime default. See `InterventionEngine` constructor
     * option `defaultModeFromPolicy` for the resolution chain.
     */
    modeIsExplicit?: boolean
  },
): AssembledComponents {
  // Marketplace plugin — local NDJSON is the sole persistence sink. No HTTP
  // upload, no AuthProvider, no outbox, no NodeActivityClient, no
  // SystemCollector (process_monitor.py), no AssetCollector. The 3-phase
  // marketplace surface is: ApplicationCollector (tool-stack) +
  // NetworkHttpCollector (http.request capture) + RuntimeHook (subprocess
  // seam). Everything else was a platform-deployment backstop.
  //
  // Shared OverviewCache instance. Constructed here (before the sink) so
  // the same instance is wired to the sink's `onRotate` callback (for
  // invalidation on size-cap / low-disk rotation) AND passed to
  // `registerSecurityMonitorRemote` for use in the `overview` handler. One
  // cache per plugin lifetime.
  const overviewCache = new OverviewCache()
  // Pass the shared `DebugLog` so the sink's phase lines (`initialize` /
  // `flush_empty` / `local_direct` / ...) land in the same file the
  // apply() error sites write to. The `onRotate` callback invalidates
  // the cache so a size-cap rotation does not surface stale block
  // counts for up to TTL_MS.
  const eventCollector = new LocalNdjsonSink(config, {
    debugLog,
    onRotate: () => overviewCache.invalidate(),
  })

  // Policy file hash pinning — when a reload detects that the file's hash
  // diverged from the baseline (i.e. an external write between reloads),
  // the reload is rejected and we emit a `policy_tamper` event so the
  // platform can alert and operators can investigate. The old rules stay
  // in effect — a hostile policy write does NOT disable SPL.
  //
  // `onTamper` is declared as a function (not a closure) so it can read
  // `applicationCollector` after it is constructed, letting the emitted
  // security_audit event carry the active session's agent_id.
  //
  // Pass `builtinRulePaths` so the bundled
  // `policies/default-policy.spl.yaml` is appended after the operator's
  // `policyPaths[]` by default. Without this, a marketplace install whose
  // operator did not ship a `~/.dsh/security-policy.spl.yaml` loads 0
  // rules. Operators who explicitly want zero builtin rules can still
  // pass `[]` via custom embedding, or set `intervention.policyPaths: []`
  // plus `builtinRulePaths: []` — both reach the same "no builtins"
  // branch. Resolved via `import.meta.url`
  // so the bundled baseline works regardless of CWD (npm pack strips
  // symlinks and the marketplace install path is opaque to the plugin).
  const bundledBuiltinRulePath = fileURLToPath(
    // bootstrap is compiled to `<pkg>/lib/bootstrap.js`
    // while the bundled policy lives at `<pkg>/policies/default-policy.spl.yaml`
    // (sibling of `lib/`, listed in package.json `files:`). Resolving
    // `./policies/...` here landed at `<pkg>/lib/policies/...` (a path
    // that never exists on a packed install), so the engine's
    // `existing.filter(existsSync)` silently dropped the bundled baseline
    // and the UI showed "loadedRuleCount: 0" with no rule preview. The
    // `../` walks up one level from `lib/bootstrap.js` to the package
    // root before descending into `policies/`, matching the tarball
    // layout produced by `npm pack` (and dev paths that resolve via the
    // same package root).
    new URL('../policies/default-policy.spl.yaml', import.meta.url),
  )

  // compute the bundled-policy tamper-baseline at
  // startup (BEFORE the engine constructs) and pass it to
  // InterventionEngine as the trusted baseline. Defends against the
  // "tamper-before-first-reload" attack where an attacker writes the
  // bundled policy file between engine construction and the first
  // file read — under the legacy "first reload = baseline" logic, the
  // tampered content became the legitimate baseline. Computing the
  // hash here, at construction time, locks the baseline to whatever
  // the file content was at this moment. A subsequent write to the
  // bundled file diverges the hash and trips tamper.
  //
  // The seed MUST mirror the engine's
  // `bundledHashForTamper` shape byte-for-byte, otherwise every reload
  // trips tamper. The engine computes
  //   bundledHashForTamper = sha256( map(e => `${e.path}:${e.hash}`).join('|') )
  // where `e.hash` is sha256(content). For the single bundled file
  // shipped here this collapses to
  //   sha256( `${bundledBuiltinRulePath}:${sha256(content)}` )
  // so the seed has to be exactly that outer hash — NOT the inner
  // `sha256(content)`. The first commit of this code path shipped
  // `sha256(content)` (the inner hash), which never matches the
  // outer-shape reload hash and trips tamper on every reload.
  let trustedBaselineHash: string | undefined
  try {
    const content = readFileSync(bundledBuiltinRulePath, 'utf8')
    const contentHash = createHash('sha256').update(content).digest('hex')
    trustedBaselineHash = createHash('sha256')
      .update(`${bundledBuiltinRulePath}:${contentHash}`)
      .digest('hex')
  } catch {
    // Bundled file missing — fall back to first-reload baseline. This
    // is the path custom embedders take when they ship without the
    // bundled default; the engine still loads correctly, just without
    // the tamper-baseline guarantee.
    trustedBaselineHash = undefined
  }

  // Declare engine + onTamper here, then construct applicationCollector
  // after — onTamper closes over `let acHolder` and reads the live value
  // at emit time so the security_audit event carries the active
  // session's agent_id. Without the indirection the tamper emit would
  // fire before applicationCollector exists.
  let acHolder: ApplicationCollector | undefined
  const interventionEngine = new InterventionEngine(config, {
    builtinRulePaths: [bundledBuiltinRulePath],
    trustedBaselineHash,
    // Defer to the bundled policy file's `mode: enforce`
    // when the operator has NOT explicitly set `intervention.mode` in
    // their config. A fresh marketplace install therefore lands in
    // enforce by default (the bundled default-policy.spl.yaml declares
    // `mode: enforce`). Operators who deliberately run audit keep
    // audit because the engine only consults the policy when this
    // flag is true.
    defaultModeFromPolicy: !(options?.modeIsExplicit === true),
    // route engine warnings (policy reload
    // failures, regex compile warnings, watcher degradation) through the
    // host logger instead of raw console.
    logger: ctx.logger,
    onTamper: (info) => {
      try {
        ctx.logger.error(
          `[SecurityMonitor] security_audit/policy_tamper: policy file changed (${info.policyPath}); ` +
            `baseline=${info.baselineHash.slice(0, 12)}… current=${info.currentHash.slice(0, 12)}… — ` +
            `reload rejected, prior rules remain in effect`,
        )
        const session = acHolder?.resolveHttpSessionByPid(process.pid)
        eventCollector.report({
          comm: DEFAULT_PLATFORM_ID,
          event_id: generateEventId(),
          // security_audit unifies policy tamper reporting. The old
          // `policy_tamper` event_type is retained in audit_details for one
          // MAJOR cycle of back-compat.
          event_type: 'security_audit',
          layer: 'application',
          source_layer: 'application',
          ts: info.ts,
          timestamp: info.ts,
          pid: process.pid,
          collection_method: 'agent_api',
          session_id: session?.sessionId ?? '__plugin__',
          run_id: session?.runId ?? '__plugin__',
          agent_id: session?.agentId ?? '__plugin__',
          audit_category: 'policy',
          audit_action: 'tamper',
          // platform security_audit per-type schema requires `severity` and
          // `summary`; `reason` must be a value from the platform's accepted
          // enum (mapped to the audit_action vocabulary: block / approve /
          // warn / escalate / guide / detect / tamper / allow / deny).
          severity: 'high',
          summary: 'policy file hash diverged from baseline; reload rejected',
          target: info.policyPath,
          outcome: 'blocked',
          reason: 'tamper',
          audit_details: {
            event_type_alias: 'policy_tamper',
            policy_path: info.policyPath,
            policy_baseline_hash: info.baselineHash,
            policy_current_hash: info.currentHash,
            detail: 'policy file hash diverged from baseline; reload rejected',
          },
          ...buildHostMeta(),
        })
      } catch (error: unknown) {
        ctx.logger.warn(`[SecurityMonitor] security_audit/policy_tamper emit failed: ${String(error)}`)
      }
    },
    // onReloaded fires after every
    // successful policy reload. Pair with the tamper signal above to
    // give operators a complete "policy file activity" timeline in
    // the NDJSON stream: `policy_reloaded` (committed, with rule-set
    // fingerprint) and `policy_tamper` (rejected, hash diverged).
    onReloaded: (info) => {
      try {
        if (!info.changed) {
          // Idempotent heartbeat — same rule set as previous reload.
          // Still emit at info level so operators can correlate
          // fs.watch triggers with policy commits; the `changed:false`
          // flag tells downstream consumers to filter if they want.
          ctx.logger.info(
            `[SecurityMonitor] policy_reloaded (no change): ${info.policyPath}; ` +
              `rules=${info.ruleCount} ruleSetHash=${info.ruleSetHash.slice(0, 12)}…`,
          )
        } else {
          ctx.logger.info(
            `[SecurityMonitor] policy_reloaded (changed): ${info.policyPath}; ` +
              `rules=${info.ruleCount} ruleSetHash=${info.ruleSetHash.slice(0, 12)}… ` +
              `combinedHash=${info.combinedHash.slice(0, 12)}…`,
          )
        }
        const session = acHolder?.resolveHttpSessionByPid(process.pid)
        eventCollector.report({
          comm: DEFAULT_PLATFORM_ID,
          event_id: generateEventId(),
          event_type: 'security_audit',
          layer: 'application',
          source_layer: 'application',
          ts: info.ts,
          timestamp: info.ts,
          pid: process.pid,
          collection_method: 'agent_api',
          session_id: session?.sessionId ?? '__plugin__',
          run_id: session?.runId ?? '__plugin__',
          agent_id: session?.agentId ?? '__plugin__',
          audit_category: 'policy',
          audit_action: 'modify',
          // Platform severity enum has no 'info'; the unchanged-heartbeat
          // case keeps its 'low' severity here and stays distinguishable
          // via audit_details.changed.
          severity: 'low',
          summary: info.changed
            ? `policy reload committed; rule set fingerprint changed (${info.ruleCount} rules)`
            : `policy reload heartbeat; rule set unchanged (${info.ruleCount} rules)`,
          target: info.policyPath,
          outcome: 'success',
          reason: 'allow',
          audit_details: {
            event_type_alias: 'policy_reloaded',
            policy_path: info.policyPath,
            combined_hash: info.combinedHash,
            rule_set_hash: info.ruleSetHash,
            rule_count: info.ruleCount,
            changed: info.changed,
            detail: info.changed
              ? 'policy reload committed; rule set fingerprint diverged from previous reload'
              : 'policy reload heartbeat; rule set identical to previous reload',
          },
          ...buildHostMeta(),
        })
      } catch (error: unknown) {
        ctx.logger.warn(`[SecurityMonitor] security_audit/policy_reloaded emit failed: ${String(error)}`)
      }
    },
    // a reload that COMMITS WITH
    // ERRORS (hash verified — not tamper — but the file failed to
    // parse/validate, so the rule set was reduced to the files that
    // still load). Complements the tamper (rejected) and reloaded
    // (committed clean) signals so every reload outcome is audit-
    // visible — pre-fix this state had no production-observable signal
    // at all (the engine warning was DSH_DEBUG-gated).
    onReloadError: (info) => {
      try {
        ctx.logger.error(
          `[SecurityMonitor] security_audit/policy_reload_error: policy reload failed (${info.policyPath}); ` +
            `${info.ruleCount} rules in effect — FAIL-LOUD: fix the policy file to restore full SPL guards`,
        )
        const session = acHolder?.resolveHttpSessionByPid(process.pid)
        eventCollector.report({
          comm: DEFAULT_PLATFORM_ID,
          event_id: generateEventId(),
          // Same security_audit surface as policy_tamper / policy_reloaded.
          // audit_action 'warn' (NOT 'tamper'): the hash chain verified
          // this content is not a hostile mid-flight write — the failure
          // is a parse/validate error, i.e. operator corruption or a bad
          // first load. Severity scales with exposure: zero rules in
          // effect means the host is unguarded by SPL.
          event_type: 'security_audit',
          layer: 'application',
          source_layer: 'application',
          ts: info.ts,
          timestamp: info.ts,
          pid: process.pid,
          collection_method: 'agent_api',
          session_id: session?.sessionId ?? '__plugin__',
          run_id: session?.runId ?? '__plugin__',
          agent_id: session?.agentId ?? '__plugin__',
          audit_category: 'policy',
          audit_action: 'warn',
          severity: info.ruleCount === 0 ? 'high' : 'medium',
          summary:
            `policy reload failed (${info.firstFailure ? 'first failure' : 'error changed'}); ` +
            `${info.ruleCount} rules in effect — rule set reduced to files that still parse`,
          target: info.policyPath,
          outcome: 'failure',
          reason: 'warn',
          audit_details: {
            event_type_alias: 'policy_reload_error',
            policy_path: info.policyPath,
            error: info.error,
            rule_count: info.ruleCount,
            first_failure: info.firstFailure,
            detail: 'policy reload committed with errors; rule set reduced to files that still parse',
          },
          ...buildHostMeta(),
        })
      } catch (error: unknown) {
        ctx.logger.warn(`[SecurityMonitor] security_audit/policy_reload_error emit failed: ${String(error)}`)
      }
    },
  })
  const applicationCollector = new ApplicationCollector(
    config,
    eventCollector,
    interventionEngine,
    { logger: ctx.logger }, // surface AC warnings to operator
  )
  acHolder = applicationCollector
  // wire the session resolver into LocalNdjsonSink so that
  // collector_integrity security_audit events (audit-log deletion/truncation)
  // can carry the active agent session identity.
  eventCollector.setResolveSessionByPid((pid) => applicationCollector.resolveHttpSessionByPid(pid))

  // Self-protection guard at the `ctx.tools.guard` seam. The 3 hardcoded
  // inline rules (uninstall / kill / restart-no-patch) are evaluated
  // SYNCHRONOUSLY after every pre-execute listener and before the tool
  // body — a returned string monotonically denies the call regardless of
  // `config.mode`, with no async waterfall and no decision timeout. The
  // pre-execute path no longer evaluates inline self-protection (see
  // ApplicationCollector.evaluateTool), so a denial is audited exactly
  // once, here.
  //
  // Service-availability timing mirrors the RuntimeHook pattern below:
  // `ctx.inject(['tools'], ...)` from inside apply() may never fire its
  // callback in headless boot, so a deferred setTimeout(0) re-checks.
  // Failures are non-fatal — the spawn seam still carries the inline rules.
  const selfProtectionGuard = createSelfProtectionGuard({
    guards: config.inlineGuards,
    eventCollector,
    sessionResolve: () => applicationCollector.resolveMostRecentSessionForRuntime(),
    logger: ctx.logger,
  })
  let selfProtectionGuardInstalled = false
  const tryInstallSelfProtectionGuard = (): boolean => {
    if (selfProtectionGuardInstalled) return true
    try {
      selfProtectionGuardInstalled = installSelfProtectionGuard(ctx, selfProtectionGuard)
      if (selfProtectionGuardInstalled) {
        ctx.logger.info('[SecurityMonitor] self-protection guard installed at ctx.tools.guard seam (sync monotonic deny)')
        debugLog.write('self_protection_guard_installed', {})
      }
      return selfProtectionGuardInstalled
    } catch (error: unknown) {
      ctx.logger.warn(`[SecurityMonitor] self-protection guard install failed: ${String(error)}`)
      debugLog.write('self_protection_guard_install_failed', { error: String(error) })
      return false
    }
  }
  try {
    ctx.inject(['tools'], () => {
      tryInstallSelfProtectionGuard()
    })
  } catch (error: unknown) {
    ctx.logger.warn(`[SecurityMonitor] self-protection guard inject failed: ${String(error)}`)
  }
  setTimeout(() => {
    if (!tryInstallSelfProtectionGuard()) {
      debugLog.write('self_protection_guard_install_failed', {
        reason: 'deferred lookup: ctx.tools still not available',
      })
    }
  }, 0)

  // Runtime HMR-disable detection.
  // The plugin-manager can hot-unload this plugin through a profile-level
  // toggle — no tool call, so the
  // InlineSelfProtection guard seam cannot see it; configIntegrity only
  // validates at startup. The sentinel registers a ctx.effect disposer
  // that emits a policy_tamper-class security_audit when the plugin scope
  // is disposed while the process keeps running (and a liveness watchdog
  // for the dispose-without-disposer residual). Graceful process exits
  // (natural exit / SIGTERM path / host teardown) set the
  // graceful-shutdown flag first, so normal restarts stay silent. The
  // emit goes through the sink's synchronous writeLocalDirect path, which
  // stays functional during scope disposal.
  const unloadSentinel = installPluginUnloadSentinel(ctx, {
    eventCollector,
    sessionResolve: () => applicationCollector.resolveMostRecentSessionForRuntime(),
    logger: ctx.logger,
    pluginName: 'security-monitor',
  })
  ctx.logger.info('[SecurityMonitor] unload sentinel installed (HMR-disable detection armed)')
  debugLog.write('unload_sentinel_installed', {})

  const networkHttpCollector = new NetworkHttpCollector(config, {
    eventCollector,
    interventionEngine,
    sessionResolve: () => {
      // Prefer the current process's active session; if no session has been
      // bound to this PID, fall back to the most-recent session so
      // background HTTP requests still correlate.
      const byPid = applicationCollector.resolveHttpSessionByPid(process.pid)
      return byPid ?? applicationCollector.resolveMostRecentSessionForRuntime()
    },
  })

  eventCollector.initialize()
  applicationCollector.initialize()
  interventionEngine.initialize()

  // Probe the CLI / Remote surfaces with
  // the exact casts the register functions use, so the plugin_startup
  // `surfaces` metadata reports precisely the availability decision the
  // registrations make. `network` flips to true once the in-process
  // capture install below succeeds; `subprocess` is path-specific and
  // supplied per emit call.
  // 'commands' is in this plugin's `inject` (see src/index.ts), so the
  // proxy returns the live service when dsh-base's bundle patch
  // registered it on the host ctx. The `ctx.reflect.get` lookup is the
  // explicit safe-access pattern (returns `undefined` when absent);
  // since the field is declared, the proxy would otherwise throw
  // `cannot get required service "commands" in inactive context` if
  // the fiber happened to run before dsh-base's patch landed.
  const cliSurfaceAvailable = Boolean(ctx.reflect.get('commands'))
  // `surfaces.remote` reports the
  // HOST-side registration outcome (wired via the `onState` callback of
  // `registerSecurityMonitorRemote` below). A `ctx.reflect.get('remote')`
  // probe would read the browser-only gateway-client
  // service, never present in the host process — so the flag would stay
  // a permanent false even when the namespace registered fine. Initial
  // value false; the callback flips it when the (possibly deferred)
  // registration lands.
  const surfaceState = { cli: cliSurfaceAvailable, remote: false, network: false }

  // install application-layer HTTP request capture.
  // This patches http/https/fetch inside the harness process. Errors are
  // non-fatal — the rest of the plugin continues to work if patching fails.
  //
  // This install sits ahead of the RuntimeHook /
  // surface-registration blocks so `surfaceState.network` reaches its
  // final value BEFORE any plugin_startup emission path can run — every
  // startup event's `surfaces.network` bit is accurate, not a
  // "not-yet-installed" false negative.
  try {
    networkHttpCollector.install()
    ctx.logger.info('[SecurityMonitor] application-layer HTTP capture installed')
    surfaceState.network = true
  } catch (error: unknown) {
    ctx.logger.warn(`[SecurityMonitor] HTTP capture install failed: ${String(error)}`)
    debugLog.write('network_capture_install_failed', {
      error: String(error),
    })
    // BUG: uniform `surface_unavailable` phase so operators can
    // grep one phase name for every degraded surface.
    debugLog.write('surface_unavailable', {
      surface: 'network_capture',
      reason: 'networkHttpCollector.install() threw',
      error: String(error),
    })
  }

  // server half : register both
  // surfaces so the operator can drive the plugin via either the
  // `/security` CLI or the DSH Web settings page ( server
  // client half ships separately). Both registrations are
  // independently graceful — `registerSecurityCommand` logs a single
  // warn + no-op disposer when `@deepseek-ai/dsh-commands` is not
  // installed; `registerSecurityMonitorRemote` does the same when
  // `@deepseek-ai/dsh-typert-protocol` is missing. Both also write a
  // `surface_unavailable` debug-log breadcrumb (BUG).
  //
  // BUG: one `surfaces` block on every plugin_startup payload so
  // the first NDJSON startup event shows the whole surface map. `ui` is
  // `available: null` — the client bundle runs in the host webview
  // and the plugin process cannot observe it (documented scope
  // deviation; the client half keeps its own ctx.logger.warn path).
  const surfaceMetadata = (subprocessAvailable: boolean): Record<string, unknown> => ({
    ui: {
      available: null,
      note: 'client bundle runs in the host webview; not observable from the plugin process',
    },
    cli: { available: surfaceState.cli },
    remote: { available: surfaceState.remote },
    network: { available: surfaceState.network },
    subprocess: { available: subprocessAvailable },
  })
  const disposeSecurityCommand = registerSecurityCommand(ctx, eventCollector, interventionEngine, config, debugLog)

  // install the pre-spawn interception seam.
  //
  // Every model-facing fork (bash / pwsh / terminal / subagent / LSP) flows
  // through `ctx.subprocess.spawn(spec)`. We `ctx.inject(['subprocess'], ...)`
  // to grab the live SubprocessRuntime instance and monkey-patch its
  // `spawn` / `spawnTerminal` methods in place. The wrapper runs the same
  // inline + SPL evaluation pipeline that `tools/pre-execute` runs, so
  // existing SELF_PROTECTION_* rules (014 PROCESS_KILL / 015 UNAUTH_RESTART /
  // 016 DISABLER_SCRIPT_WRITE / 017 SCRATCH_SCRIPT_EXEC / 018 DECODE_EXECUTE)
  // fire on the actual
  // argv (not just the model's parsed arguments).
  //
  // Failures here are non-fatal — the plugin keeps working with just the
  // tool-layer interception if the seam can't be wrapped.
  const runtimeHook = new RuntimeHook({
    eventCollector,
    interventionEngine,
    runtimeHookConfig: config.runtimeHooks,
    inlineGuards: config.inlineGuards,
    // §6.2 : inline sensitive-path deny-list at the
    // pre-spawn seam. Mirrors the tool-layer `sensitivePathGuard`
    // configuration so the same hardcoded deny-list applies to both
    // tool calls and forks.
    sensitivePathGuard: config.sensitivePathGuard,
    // §6.2 第二项: inline prompt-injection guard at the
    // pre-spawn seam. Same hardcoded 24-pattern catalogue as the
    // tool-layer `inlinePromptInjection` — tag-injection /
    // role-impersonation payloads in argv cannot bypass the safety net
    // via policy YAML edits.
    inlinePromptInjection: config.inlinePromptInjection,
    // §6.2 : stdio pipe mirror. Resolves the bundled
    // wrapper path from `import.meta.url` so the rewrite stays
    // install-path-agnostic. When the mirror is enabled, the wrapper is
    // spawned by the HARNESS on a rewritten argv (the host plugin
    // itself does NOT fork) so the marketplace sandbox
    // (`dependencies: {}`, `dshWorkshop.permissions: ["network:none"]`)
    // is preserved.
    stdioMirror: {
      config: config.stdioMirror,
      wrapperPath: resolveStdioMirrorWrapperPath(),
    },
    // §6.2 : inline env-passthrough guard
    // at the pre-spawn seam. Same hardcoded 6-key deny-list as the
    // tool-layer `envPassthroughGuard` (`LD_PRELOAD` / `LD_LIBRARY_PATH`
    // / `NODE_OPTIONS` / `PYTHONPATH` / `PYTHONSTARTUP` / `NODE_PATH`)
    // — fork payloads carrying a dangerous env var via `spec.env`
    // cannot bypass the safety net via policy YAML edits.
    envPassthroughGuard: config.envPassthroughGuard,
    mode: config.mode,
    sessionResolve: () => applicationCollector.resolveMostRecentSessionForRuntime(),
    // bind real child PIDs back to the active session so
    // audit consumers can correlate spawned descendants with their
    // parent turn. : marketplace drops the Python-side
    // `systemCollector.triggerBurstScan()` follow-up — the process
    // monitor is no longer in the marketplace surface; correlation is
    // a passive audit record (the runtime_spawn_intent event itself).
    bindChildPid: (pid, sessionId) => {
      applicationCollector.bindChildPidToSession(pid, sessionId)
    },
  })

  // the livePatch manager is constructed AFTER
  // every component (including the RuntimeHook above) so it can hand each
  // one its share of an operator patch; components mutate the shared
  // normalized config in place.
  const livePatchManager = new LivePatchManager({
    config,
    sink: eventCollector,
    components: [eventCollector, interventionEngine, applicationCollector, networkHttpCollector, runtimeHook],
  })
  const disposeSecurityMonitorRemote = registerSecurityMonitorRemote(
    ctx,
    eventCollector,
    interventionEngine,
    config,
    debugLog,
    livePatchManager,
    overviewCache,
    // Truthful `surfaces.remote` — the
    // registration outcome (immediate or deferred) is reported here,
    // unlike a browser-only `ctx.remote` probe. Also lands a
    // debug-log breadcrumb so a missing bridge is diagnosable without
    // reproducing startup.
    (registered, note) => {
      surfaceState.remote = registered
      debugLog.write('typert_bridge', { registered, note })
    },
  )

  // factor out the previously-duplicated
  // `emitStartup` + install logic so both the inject and deferred-setTimeout
  // paths share a single implementation. Two real bugs were hidden behind
  // the duplication:
  //
  //   (1) The inject path registered `ctx.effect(() => () => runtimeHook
  //       .uninstall())` for plugin unload, but the deferred path did NOT —
  //       a headless boot that resolved `ctx.subprocess` only after the
  //       setTimeout fired left the seam wrapping `ctx.subprocess.spawn`
  //       across plugin unload (leaked override on the host context).
  //   (2) On a normal boot where the inject path succeeded, the deferred
  //       fallback fired unconditionally and emitted a SECOND
  //       `plugin_startup` event (the observed 2-event count, not the
  //       documented expected 1).
  //
  // The new shape: a single `tryInstallRuntimeHook(source)` helper called
  // from both paths, with a closure flag `runtimeHookInstalled` that
  // short-circuits whichever path arrives second. The disposer is
  // registered from inside the helper, so both paths leave a clean uninstall
  // hook regardless of which one fired first.
  let runtimeHookInstalled = false
  const emitStartup = (payload: Record<string, unknown>): void => {
    // This build ships no uploader: the startup record lands in the local
    // NDJSON file only, so there is no remote type registry to satisfy. If
    // an uploader is ever wired in, the event type must be a name the
    // receiving side accepts — project-scoped extension events are named
    // `x_<project>_<type>`.
    try {
      eventCollector.report({
        comm: DEFAULT_PLATFORM_ID,
        event_id: generateEventId(),
        event_type: 'plugin_startup',
        layer: 'application',
        ts: Date.now(),
        timestamp: Date.now(),
        pid: process.pid,
        collection_method: 'agent_api',
        session_id: 'plugin-startup',
        agent_id: '__plugin__',
        metadata: payload,
        ...buildHostMeta(),
      })
    } catch {
      // best-effort
    }
  }
  const tryInstallRuntimeHook = (
    source: 'inject' | 'deferred-setTimeout',
  ): boolean => {
    if (runtimeHookInstalled) return false
    // Cordis resolves `ctx.subprocess` to the live LocalSubprocessRuntime
    // instance. The harness's external.ts stub does not declare this
    // service, so we reach through a typed cast.
    const proc = (ctx as unknown as { subprocess?: SubprocessRuntimeLike }).subprocess
    if (!proc || typeof proc.spawn !== 'function') {
      ctx.logger.warn(
        `[SecurityMonitor] ctx.subprocess not available (${source}); RuntimeHook install skipped`,
      )
      debugLog.write('runtime_hook_install_failed', {
        path: source,
        reason: 'ctx.subprocess not available or spawn is not a function',
        subprocess_available: proc !== undefined && proc !== null,
      })
      emitStartup({
        runtime_hook_installed: false,
        runtime_hook_error: 'ctx.subprocess not available or spawn is not a function',
        subprocess_available: proc !== undefined && proc !== null,
        enabledAtSubprocess: config.runtimeHooks.enabledAtSubprocess,
        blockAtSubprocess: config.runtimeHooks.blockAtSubprocess,
        path: source,
        surfaces: surfaceMetadata(false),
      })
      return false
    }
    runtimeHook.install(proc)
    // warn at startup when the runtime hook
    // is configured to BLOCK (blockAtSubprocess=true) but the overall
    // mode is `audit`. The two settings are not contradictory (the
    // RuntimeHook runs its own blockAtSubprocess flip independent of
    // `mode`), but operators sometimes flip `blockAtSubprocess` in a
    // rush and forget to flip `mode` too — the warning makes the
    // intent-vs-state mismatch visible in the log without changing
    // runtime behavior. The dual condition (`mode==='audit'` AND
    // `blockAtSubprocess===true`) is the only interesting case; the
    // inverse (enforce + block=false) is the documented audit posture.
    if (config.mode === 'audit' && config.runtimeHooks.blockAtSubprocess) {
      ctx.logger.warn(
        '[SecurityMonitor] RuntimeHook config mismatch: mode=audit but ' +
          'runtimeHooks.blockAtSubprocess=true. The RuntimeHook will ' +
          'still block at the subprocess seam (its own gate), but the ' +
          'tool-layer SPL is in audit mode (records-only). If both ' +
          'layers should block, also set mode=enforce.',
      )
    }
    ctx.logger.info(
      `[SecurityMonitor] RuntimeHook installed via ${source} at subprocess seam ` +
        `(audit=on, blockAtSubprocess=${config.runtimeHooks.blockAtSubprocess}, ` +
        `resolveExecutableWrapped=${typeof proc.resolveExecutable === 'function'})`,
    )
    debugLog.write('runtime_hook_installed', {
      path: source,
      enabledAtSubprocess: config.runtimeHooks.enabledAtSubprocess,
      blockAtSubprocess: config.runtimeHooks.blockAtSubprocess,
      // Whether the resolveExecutable audit
      // seam is live on this runtime (optional on SubprocessRuntimeLike).
      resolve_executable_wrapped: typeof proc.resolveExecutable === 'function',
    })
    emitStartup({
      runtime_hook_installed: true,
      runtime_hook_error: null,
      subprocess_available: true,
      enabledAtSubprocess: config.runtimeHooks.enabledAtSubprocess,
      blockAtSubprocess: config.runtimeHooks.blockAtSubprocess,
      path: source,
      surfaces: surfaceMetadata(true),
    })
    // Effect cleanup restores the original methods when the plugin unloads.
    // Registered from the helper so both the inject path and the deferred
    // fallback leave a clean uninstall hook (was previously only in the
    // inject path — the deferred path leaked the override).
    ctx.effect(() => () => runtimeHook.uninstall())
    runtimeHookInstalled = true
    return true
  }

  try {
    ctx.inject(['subprocess'], () => {
      tryInstallRuntimeHook('inject')
    })
  } catch (error: unknown) {
    ctx.logger.warn(`[SecurityMonitor] RuntimeHook install failed: ${String(error)}`)
    debugLog.write('runtime_hook_install_failed', {
      path: 'inject',
      error: String(error),
    })
    emitStartup({
      runtime_hook_installed: false,
      runtime_hook_error: String(error),
      enabledAtSubprocess: config.runtimeHooks.enabledAtSubprocess,
      blockAtSubprocess: config.runtimeHooks.blockAtSubprocess,
      path: 'inject-throw',
      surfaces: surfaceMetadata(false),
    })
  }

  // `ctx.inject(['subprocess'], cb)` from inside our
  // `apply()` does not fire its callback in the headless harness boot — the
  // inject fiber enters PENDING and the harness-level service registration
  // notify path does not reach it (observed via plugin_startup diagnostic
  // remaining at 0). Fall back to a deferred lookup: schedule a setTimeout(0)
  // that runs after the current apply() returns and the harness has finished
  // mounting its own services, then re-check `ctx.subprocess`. This is a
  // well-known escape hatch for plugins that need a service that may not be
  // available at apply() time — see Cordis docs on `ctx.inject` vs `ctx.on`.
  // Short-circuit when the inject path already succeeded — the closure
  // flag `runtimeHookInstalled` is the coordination point.
  setTimeout(() => {
    if (runtimeHookInstalled) return
    try {
      tryInstallRuntimeHook('deferred-setTimeout')
    } catch (error: unknown) {
      debugLog.write('runtime_hook_install_failed', {
        path: 'deferred-setTimeout',
        error: String(error),
      })
      emitStartup({
        runtime_hook_installed: false,
        runtime_hook_error: `deferred lookup threw: ${String(error)}`,
        enabledAtSubprocess: config.runtimeHooks.enabledAtSubprocess,
        blockAtSubprocess: config.runtimeHooks.blockAtSubprocess,
        path: 'deferred-setTimeout',
        surfaces: surfaceMetadata(false),
      })
    }
  }, 0)

  ctx.logger.info(`[SecurityMonitor] initialized, mode=${config.mode}, collector=${config.collector.localOutputPath}`)

  // Signal handlers ------------------------------------
  //
  // Without explicit handlers, Node's default behaviour is to terminate on
  // SIGHUP / SIGTERM / SIGINT. That bites operators who:
  //   - send SIGHUP to "reload" and end up killing the engine (which, if
  //     restarted, may not re-load the patch — see plan §五 K 层)
  //   - hit Ctrl-C in a terminal and watch the entire dsh process die
  //   - send SIGTERM to a child and accidentally hit us
  //
  // We register the bare minimum: SIGHUP and SIGINT become warnings (no
  // exit), SIGTERM triggers graceful shutdown via the same effect cleanup
  // path the harness uses. SIGKILL cannot be intercepted and is intentionally
  // left to its default behaviour (kernel reaps the process).
  //
  // The plugin process IS the dsh engine process, so the harness's own
  // shutdown sequence is preserved when SIGTERM is delivered to us.
  const signalHandlerInstalled = installSignalHandlers(ctx, eventCollector, applicationCollector, interventionEngine, () => {
    try {
      unloadSentinel.markGracefulShutdown()
    } catch (error: unknown) {
      ctx.logger.warn(`[SecurityMonitor] unload-sentinel graceful mark failed: ${String(error)}`)
    }
  })
  if (signalHandlerInstalled) {
    ctx.logger.info('[SecurityMonitor] signal handlers installed (SIGHUP/SIGINT no-exit, SIGTERM graceful)')
  }

  // §6.2 : Sensitive-path watcher ------------------------
  //
  // Plugin-owned `fs.watch` on the directories backing the inline
  // sensitive-path deny-list. Catches file mutations that bypass the
  // harness's `fs/observed` event (e.g. `cat ~/.ssh/id_rsa` from a
  // bash subprocess). Observability-only — the inline guard (evaluate-
  // SensitivePathGuard) is what blocks the underlying tool call.
  if (config.sensitivePathGuard.watchEnabled) {
    try {
      const sensitivePathWatcher = new SensitivePathWatcher({
        eventCollector,
        cfg: config.sensitivePathGuard,
        sessionResolve: () => applicationCollector.resolveMostRecentSessionForRuntime(),
        logger: ctx.logger,
      })
      sensitivePathWatcher.start()
      ctx.effect(() => () => sensitivePathWatcher.stop(), 'security-monitor: sensitive-path-watcher shutdown')
      ctx.logger.info('[SecurityMonitor] sensitive-path watcher installed (observability on, deny-list enforced inline)')
    } catch (error: unknown) {
      ctx.logger.warn(`[SecurityMonitor] sensitive-path watcher install failed: ${String(error)}`)
    }
  } else {
    ctx.logger.info('[SecurityMonitor] sensitive-path watcher disabled (watchEnabled=false); inline deny-list still active')
  }

  return {
    eventCollector,
    interventionEngine,
    applicationCollector,
    networkHttpCollector,
    runtimeHook,
    disposeSecurityCommand,
    disposeSecurityMonitorRemote,
  }
}