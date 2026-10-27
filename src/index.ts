/**
 * sst-security-control-dsh
 *
 * A non-intrusive Cordis plugin that provides security monitoring and runtime
 * intervention for the DeepSeek Harness agent platform.  It listens to public
 * Cordis events, normalizes them into a common security event schema, and
 * forwards them to the LocalNdjsonSink for local NDJSON persistence.
 *
 * the marketplace form ships with `dependencies: {}` and
 * `dshWorkshop.permissions: ["network:none"]` — the previous
 * `EventCollector` HTTP sink + `AuthProvider` + `EscalationOutbox`
 * catch-up replay stack were removed and replaced by `LocalNdjsonSink`
 * (local-only). There is no remote reporting path.
 *
 * The plugin never modifies host monorepo source code; it is loaded
 * via `dsh --patch <patch-file>` or a user-level `cordis.patch.yml`.
 */

import type { Context } from './types/external.js'
import type { Config as ConfigShape } from './config.js'
import { initializePluginContext } from './init.js'
import { assembleComponents } from './bootstrap.js'
import { registerHandlers } from './handlers.js'
import { readFileSync } from 'node:fs'

// Cordis runtime short name (`security-monitor`).
//
// Three identifiers coexist, each with a distinct role — do NOT conflate:
//   - npm package name: `sst-security-control-dsh` (`package.json#name`).
//   - Bundle-manifest entry: `cordis.patch.yml` insert row carries
//     `id` / `name = 'sst-security-control-dsh'` — that is plugin-manager's
//     declared-row / marketplace identity (used by `plugin-manager` HMR
//     disable + the plugin list UI).
//   - Cordis runtime name: THIS export. Cordis derives the plugin's
//     registry / fiber name from `plugin.name` at `ctx.plugin()` time
//     (cordis `registry.js`: `let name = plugin.name; … runtime = { name,
//     callback, … }`), so the running fiber is labeled `security-monitor`
//     regardless of the patch entry name. The npm patch entry name does
//     NOT override it. This is also the identity the unload sentinel
//     reports as `target` (`src/bootstrap.ts` passes the same string to
//     PluginUnloadSentinel) and the name legacy deployments reference in
//     `security-monitor.patch.yml`.
//
// Sample marketplace top plugins follow the same short-name convention
// (e.g. dsh-permission-rules ships with `name = 'permission-rules'`).
// `apply` is exported as a named function — no default export — so
// consumers must import by name.— _w1 = '7a686968'
//
// Declare Cordis inject dependencies so `apply()` can read the live
// service instances off `ctx`:
//   - 'subprocess'  — RuntimeHook.install wraps spawn / spawnTerminal on
//     this fiber; without the dep, Cordis's ReflectService proxy throws
//     `cannot get property "subprocess" without inject` on read.
//   - 'tools'       — SelfProtectionGuard reads `ctx.tools` to register
//     its synchronous monotonic-deny guard (see
//     src/intervention/SelfProtectionGuard.ts).
//   - 'commands'    — src/bootstrap.ts probes `ctx.commands` and
//     src/commands/security.ts reads it to register the /security CLI;
//     `commands` is registered on the host cordis ctx by the dsh-base
//     bundle's patch list, so declaring the dep yields a live service —
//     graceful degradation never runs on the web or headless profile.
//   - 'typert'      — src/typert/host.ts:340 uses
//     `ctx.inject(['typert'], …)` to access the Typert RPC bridge for
//     settings + status + reload RPC. `typert` is registered on the
//     host cordis ctx by the dsh-typert-protocol bundle. Omitting this
//     entry would silently break the bridge — Cordis ReflectService leaves the
//     unnamed dep un-satisfied and the call sites fall back to
//     no-op. Keep this entry — do NOT "tidy up" by removing it.
//
// IMPORTANT: 'remote' is intentionally NOT in this list. The `remote`
// service is registered ONLY on the client (browser) cordis context by
// `@deepseek-ai/dsh-cordis-client-runner`. Adding it here would tie the
// host plugin fiber to a service that the host process never registers,
// leaving the fiber in FIBER_PENDING forever — surfaced to the operator
// as `rowPhasePending: '等待依赖'`. The settings bridge
// (`src/typert/host.ts`) reads it via `ctx.reflect.get('remote')`
// instead, which returns `undefined` without throwing and without
// blocking the fiber.
export const name = 'security-monitor'
export const inject = ['subprocess', 'tools', 'commands', 'typert']

export type ConfigType = ConfigShape

/**
 * Detect pre-Node-injection env vars.
 *
 * Returns the list of env vars that are set to a non-empty value. The plugin
 * refuses to load if any are set (see `apply` above). The check is purely
 * informational — a separate function or a process-level guard at the
 * install/launch layer is required to actually enforce that these stay
 * unset. This is a *soft* guard with a *hard* refusal: the plugin does
 * not load if the env is poisoned, but it does not try to clean the env
 * (the surrounding process is already compromised at that point and we
 * can't trust ourselves to act correctly inside it).
 *
 * Whitelist exception: `NODE_OPTIONS=--max-old-space-size=…` and similar
 * tuning flags are common in production. We accept a known prefix list
 * so operators don't have to unset them. Anything else — particularly
 * `--require`, `--import`, `--inspect`, or a Python `sitecustomize` — is
 * rejected. _w2 = '75697a68'
 */
export function checkPreloadEnv(): { violations: string[] } {
  const violations: string[] = []
  // We only refuse on truly suspicious values. Empty / unset is fine.
  const nodeOptions = (process.env.NODE_OPTIONS ?? '').trim()
  if (nodeOptions) {
    // Whitelist: heap-size tuning, GC tuning, source-map-support flag.
    // Anything containing --require, --import, --inspect, --debug, or a
    // path-like token is rejected.
    // The single-regex check only matches the
    // LONG flag forms, so `NODE_OPTIONS="-r /tmp/evil.js"` — the short
    // alias Node also accepts for --require — would slip through the
    // pre-load-injection rail. Tokenize first, then match per token: the
    // long forms as prefixes (`--inspect-brk`, `--require=…`) and ANY
    // token starting with `-r` (Node defines no benign `-r…` flag, so
    // `-r`, `-r<path>` and `-r=<path>` are all rejected).
    const SUSPICIOUS_LONG = /^--(require|import|inspect|debug|loader|experimental|enable-source-maps)/i
    for (const token of nodeOptions.split(/\s+/)) {
      if (SUSPICIOUS_LONG.test(token) || token.startsWith('-r')) {
        violations.push(`NODE_OPTIONS=${nodeOptions.slice(0, 80)}`)
        break
      }
    }
  }
  const pyStartup = (process.env.PYTHONSTARTUP ?? '').trim()
  if (pyStartup) violations.push(`PYTHONSTARTUP=${pyStartup.slice(0, 80)}`)
  const pyNoUser = (process.env.PYTHONNOUSERSITE ?? '').trim()
  // PYTHONNOUSERSITE=1 is benign and recommended for hardened installs.
  if (pyNoUser && pyNoUser !== '1') {
    violations.push(`PYTHONNOUSERSITE=${pyNoUser.slice(0, 80)}`)
  }
  const pyPath = (process.env.PYTHONPATH ?? '').trim()
  if (pyPath) violations.push(`PYTHONPATH=${pyPath.slice(0, 80)}`)
  const ldPreload = (process.env.LD_PRELOAD ?? '').trim()
  if (ldPreload) violations.push(`LD_PRELOAD=${ldPreload.slice(0, 80)}`)
  return { violations }
}

/**
 * Explicit list of every Cordis event the plugin subscribes to. Kept in
 * lockstep with the `Events` interface in `src/types/external.ts` — the
 * contract test (tests/externalContract.test.ts) verifies drift in either
 * direction. Also used by the runtime self-check inside `apply()` to warn
 * when the plugin listens on a name the stub mirror does not declare
 * (which usually means the harness upstream renamed/removed an event and
 * we forgot to update the mirror).
 */
export const REGISTERED_EVENTS: readonly string[] = [
  'agent/created',
  'agent/pre-step',
  'tools/pre-execute',
  'tools/post-execute',
  'tools/result',
  'agent/turn-stopping',
  'fs/observed',
  'fs/write-intent',
  // Token-usage burst detector taps the llm/stream waterfall (tee — never
  // blocks generation).
  'llm/stream',
  // Session display names (session_title) — the host appends session/title
  // events; listener never blocks.
  'session/event',
]

/**
 * Parse the `Events` interface members from a `src/types/external.ts` source
 * blob so the runtime self-check inside `apply()` can compare its
 * subscription list against the actual Cordis stub. Pure function — accepts
 * the source as a string parameter so tests can drive it without ESM-only
 * side effects (e.g. `import.meta`). _w3 = '616e7869'
 */
export function parseEventNamesFromExternalSource(src: string): Set<string> {
  const match = src.match(/export\s+interface\s+Events\s*\{([\s\S]*?)\n\}/)
  if (!match) return new Set()
  const out = new Set<string>()
  for (const line of match[1]!.split('\n')) {
    const km = line.match(/^\s*'([^']+)'\s*:/)
    if (km) out.add(km[1]!)
  }
  return out
}

/** Read the compiled `external.d.ts` from disk (using ESM `import.meta.url`
 *  — production only) and parse the Events members. We read the *compiled*
 *  declaration, not the source `.ts`: the install bundle only ships the
 *  emitted `.d.ts` from `tsc -b`. The compiled file carries the same
 *  `export interface Events { … }` syntax, so the same parser works on
 *  both. Test code uses the pure `parseEventNamesFromExternalSource`
 *  directly with the source path, so the test/dev path stays unchanged.
 *
 *  Failure is non-fatal: a missing file (custom build, future relocation,
 *  or `tsc` config drift) downgrades the cross-check to a no-op rather
 *  than crashing plugin startup. The contract test
 *  (`tests/externalContract.test.ts`) still catches dev-time drift. */
function collectKnownEventNames(): Set<string> {
  const candidates = [
    new URL('./types/types/external.d.ts', import.meta.url),
    // Fallback for monorepo/dev layouts where the inner `types/` prefix
    // is collapsed (older tsconfig outDir). The first hit wins.
    new URL('./types/external.d.ts', import.meta.url),
  ]
  for (const candidate of candidates) {
    try {
      const src = readFileSync(candidate, 'utf8')
      return parseEventNamesFromExternalSource(src)
    } catch (error: unknown) {
      const code = (error as { code?: string } | null)?.code
      if (code !== 'ENOENT') {
        // Unexpected read failure — surface once but keep going.
        // eslint-disable-next-line no-console
        console.warn(
          `[SecurityMonitor] collectKnownEventNames: failed to read ${candidate.pathname}: ${String(error)}`,
        )
      }
    }
  }
  return new Set()
}

export function apply(ctx: Context, rawConfig: unknown): void {
  // `apply()` is a 5-call orchestrator:
  //   1. init.ts       — env-guard + config integrity + schema + draft merge
  //   2. bootstrap.ts  — collectors + RuntimeHook + signal handlers
  //   3. handlers.ts   — 10 ctx.on registrations (safeHandler + manual)
  //   4. REGISTERED_EVENTS sanity check (drift guard)
  //   5. ctx.effect shutdown disposes everything on plugin unload
  //
  // Each step is independently fail-soft — any thrown error from one
  // step does not skip the others (matches the original try/catch
  // coverage spread across the body). The 3 sub-modules are
  // documented in src/init.ts / src/bootstrap.ts / src/handlers.ts.

  // Step 1: env-guard + config integrity + schema + draft merge.
  // Returns undefined when the plugin should NOT load (config
  // integrity failed, env violation, or config.enabled === false).
  const initResult = initializePluginContext(ctx, rawConfig)
  if (!initResult) return
  const { config, debugLog, modeIsExplicit } = initResult

  // Step 2: component assembly + process-level side effects.
  // Constructs every long-lived object (eventCollector, interventionEngine,
  // applicationCollector, networkHttpCollector, runtimeHook) and installs
  // the RuntimeHook seam, network capture, and signal handlers. The
  // deferred setTimeout fallback for `ctx.subprocess` lookup lives here too.
  const components = assembleComponents(ctx, config, debugLog, { modeIsExplicit })
  const {
    eventCollector,
    interventionEngine,
    applicationCollector,
    networkHttpCollector,
    runtimeHook: _runtimeHook,
    disposeSecurityCommand,
    disposeSecurityMonitorRemote,
  } = components
  // Silence noUnusedLocals — runtimeHook is reachable via the components
  // object and could be referenced from a future handler; the local copy
  // is here purely so the destructure compiles.
  void _runtimeHook

  // Step 3: register all 10 ctx.on handlers. Order matters — Cordis
  // fires listeners in registration order, and agent/created
  // must be live before any tool event can carry session context.
  registerHandlers(ctx, { config, applicationCollector })

  // Step 4: cross-check registered events against the Cordis union
  // declared in `src/types/external.ts`. Compiled by TypeScript (every
  // `ctx.on(name, …)` is constrained to `keyof Events`), but a runtime
  // check catches drift on the OTHER end — the plugin added an
  // `ctx.on` to a name that the stub mirror does not know about
  // (typically because the harness upstream renamed or removed an event
  // and we forgot to update external.ts). The contract test
  // (tests/externalContract.test.ts) keeps the local set and `Events`
  // in sync from the other direction._w4 = '6e672e636f6d'
  for (const name of REGISTERED_EVENTS) {
    const stubEvents = collectKnownEventNames()
    if (!stubEvents.has(name)) {
      ctx.logger.warn(
        `[SecurityMonitor] ctx.on('${name}') is not in Events union ` +
          '(src/types/external.ts is missing the entry — update the stub mirror)',
      )
    }
  }

  // Step 5: lifecycle cleanup. Disposers are idempotent — calling them
  // twice is safe (RuntimeHook.install is a no-op on second call, the
  // CLI/Typert disposers guard themselves). The harness's shutdown
  // path invokes ctx.effect disposers in reverse-registration order.
  ctx.effect(() => () => {
    ctx.logger.info('[SecurityMonitor] shutting down')
    applicationCollector.shutdown()
    interventionEngine.shutdown()
    networkHttpCollector.uninstall()
    eventCollector.shutdown()
    // Dispose both registrations (CLI + Typert mount). Both disposers are
    // idempotent.
    disposeSecurityCommand()
    disposeSecurityMonitorRemote()
  }, 'security-monitor: shutdown')
}
