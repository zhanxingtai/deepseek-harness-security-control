/**
 * RuntimeHook — pre-spawn interception seam.
 *
 * The harness's tool execution pipeline emits `tools/pre-execute` BEFORE the
 * tool body runs — at that point we have only `name` + `arguments` (the
 * model's parsed JSON), not the argv that will eventually be handed to
 * `child_process.spawn()`. For shell tools the argv is built INSIDE the tool
 * body (the host shell adapter does
 * `['bash', '-c', <command>]`), so by the time the spec reaches
 * `ctx.subprocess.spawn` the fold-bearing attacks
 * (`J="pnpm ds"; nohup $J$K`) are already in argv form.
 *
 * Phase 4 (Python monitor) sees these AFTER fork. The previous gap:
 * tool-layer SPL saw only `{command: "nohup $J$K"}` (the model's parsed
 * JSON in `arguments.command`), but the real argv arrives AFTER the
 * bash tool body has assembled it — `ctx.subprocess.spawn(['bash',
 * '-c', '…nohup $J$K…'])`. Runtime hook closes the gap by inspecting
 * the post-assembly argv, where the fold-bearing attacks are now
 * text. The system layer still catches it on the spawned process argv,
 * but only when the launcher gate fires — defence-in-depth, not primary
 * control.
 *
 * RuntimeHook closes that gap. It monkey-patches the live
 * `ctx.subprocess.spawn` instance after the harness constructs it, so every
 * model-facing fork (bash, pwsh, terminal, subagent, LSP) flows through
 * the wrapper. The wrapper:
 *
 *   1. derives a `body` string from argv (bash `-c cmd`, pwsh `-Command cmd`),
 *   2. builds an `InterventionContext` identical in shape to the one
 *      `ApplicationCollector.evaluateTool` builds for `tools/pre-execute`,
 *   3. runs the SAME `evaluateInlineSelfProtection` (L1 hardcoded) +
 *      `InterventionEngine.evaluate` (SPL) pipeline,
 *   4. emits a `runtime_spawn_intent` event for every call (audit trail),
 *   5. in enforce mode + `blockAtSubprocess: true`: inline-guard hits throw
 *      a `SpawnDeniedError` SYNCHRONOUSLY BEFORE the fork (the hardcoded
 *      decision is known pre-spawn); SPL `block` decisions arrive after the
 *      synchronous `origSpawn` has already returned the handle to the
 *      caller, so they are enforced post-spawn on a best-effort basis
 *      (`handle.terminate()` + `runtime_spawn_denied`) — a synchronous
 *      throw is physically impossible once the caller holds the handle
 *      (see `wrap()`).
 *
 * The wrapper is idempotent and self-restoring via `uninstall()`. Errors
 * in the wrapper never block the host spawn when `failOpenOnError: true`
 * (the default — matches `intervention.failStrategy: 'fail_open'`).
 *
 * Cordis duplicate-service semantics make the live `ctx.subprocess`
 * instance replaceable through `ctx.inject` but NOT through registering
 * a second `SubprocessRuntime` subclass. We monkey-patch methods on the
 * existing instance, which is permitted by Cordis (method reassignment
 * on a service instance is normal).
 */
import { realpathSync } from 'node:fs'
import { basename } from 'node:path'
import type {
  LocalNdjsonSink,
} from '../collectors/LocalNdjsonSink.js'
import type { InterventionEngine } from './InterventionEngine.js'
import { evaluateInlineSelfProtection, type InlineGuardsConfig } from './InlineSelfProtection.js'
import { evaluateSensitivePathGuard, type SensitivePathGuardConfig } from './SensitivePathGuard.js'
import { evaluateInlinePromptInjection, type InlinePromptInjectionConfig } from './InlinePromptInjection.js'
import { evaluateEnvPassthroughGuard, type EnvPassthroughGuardConfig } from './EnvPassthroughGuard.js'
import { runInlineGuardChain } from './inlineGuardChain.js'
import type { RuntimeHookSessionContext } from './InterventionEngine.js'
import type { RuntimeHooksConfig, StdioMirrorConfig } from '../config.js'
import type {
  InterventionContext,
  Mode,
  SecurityDecision,
  SecurityEvent,
} from '../types/index.js'
import { DEFAULT_PLATFORM_ID } from '../types/index.js'
import type {
  SubprocessRuntimeLike,
  SubprocessSpawnResult,
  SubprocessSpawnSpec,
  SubprocessTerminalSpawnSpec,
} from '../types/external.js'
import { generateEventId } from '../utils/eventId.js'
import { nowMs } from '../utils/time.js'
import { truncateString } from '../utils/events/redact.js'
import { buildHostMeta } from '../collectors/LocalNdjsonSink.js'
import { argvMentionsSecurityMonitorPatch, deriveBodyFromArgv, isEngineLauncher } from '../utils/argvDerive.js'
import { deriveDataLeakFlags } from '../utils/dataLeakFlags.js'
import { toMarketplaceDecision } from '../utils/decisionVocabulary.js'
import { buildStdioMirrorSpec, rewriteSpecForMirror } from '../runtime/stdioMirrorEntry.js'

/** Subset of session context the wrapper needs. The canonical
 *  definition lives in `./InterventionEngine.js`; this file
 *  re-exports it for back-compat with existing consumers. */
export type { RuntimeHookSessionContext } from './InterventionEngine.js'

/** Lookup function: returns the most-recent `tools/pre-execute` session
 *  (stamped by ApplicationCollector). Returns undefined when the spawn
 *  cannot be correlated (e.g. harness-internal bootstrap helpers). */
export type RuntimeHookSessionResolve = () => RuntimeHookSessionContext | undefined

export interface RuntimeHookDeps {
  eventCollector: LocalNdjsonSink
  interventionEngine: InterventionEngine
  runtimeHookConfig: RuntimeHooksConfig
  /** : parameterised inline self-protection safety net config
   * (engineLaunchers / pluginPackageName / patchMarkers). Mirrors the
   * tool-layer `inlineGuards` so 015 (restart-without-patch) at the
   * pre-spawn seam matches the same launchers the tool layer guards. */
  inlineGuards: InlineGuardsConfig
  /** §6.2 : inline sensitive-path deny-list. Mirrors the
   * tool-layer `sensitivePathGuard` so credential reads via fork (e.g.
   * `cat ~/.ssh/id_rsa`) hit the same hardcoded deny-list before the
   * child process can start.
   *
   * Optional — defaults to a `disabled: true` config when absent. The
   * marketplace install always supplies this; unit tests that pre-date
   * the inline guard can omit it and the seam stays inert. */
  sensitivePathGuard?: SensitivePathGuardConfig
  /**
   * §6.2 第二项: inline prompt-injection guard at the
   * pre-spawn seam. Same `patterns: []` fallback semantics as the
   * tool-layer config; the marketplace install always supplies this.
   * Fires BEFORE `sensitivePathGuard` / `inlineSelfProtection` /
   * SPL — tag-injection / role-impersonation payloads in argv cannot
   * bypass the safety net via policy YAML edits. */
  inlinePromptInjection?: InlinePromptInjectionConfig
  /**
   * §6.2 : stdio pipe mirror. When set + enabled + at
   * least one stdio stream to mirror, `wrap()` rewrites the harness's
   * spec.argv to launch the bundled wrapper which captures child
   * stdin/stdout/stderr bytes to a local NDJSON file for post-hoc
   * inspection. (The pre- gate was `spec.stdio !== 'ignore'`; the real
   * harness `stdio` is always a per-stream object, so the gate now deep-
   * checks each fd — see `buildStdioMirrorSpec`.) The wrapper is spawned by
   * the HARNESS, not by us, so the marketplace sandbox (no subprocess
   * forking on plugin side) is preserved.
   *
   * Eval happens on the ORIGINAL argv (before rewrite); mirror is
   * observability, NOT a security boundary.
   *
   * Optional — defaults to a `disabled: true` config when absent. Unit
   * tests that pre-date the mirror can omit this and the seam stays
   * inert (original argv passes through unchanged).
   */
  stdioMirror?: {
    config: StdioMirrorConfig
    /** Absolute path to the bundled wrapper script. */
    wrapperPath: string
  }
  /**
   * §6.2 : inline env-passthrough guard at
   * the pre-spawn seam. Same `keys: []` fallback semantics as the
   * tool-layer config; the marketplace install always supplies this.
   * Fires BEFORE `inlineSelfProtection` / SPL — a fork carrying
   * `LD_PRELOAD` / `NODE_OPTIONS` / `PYTHONPATH` etc. via `spec.env`
   * cannot bypass the safety net via policy YAML edits. */
  envPassthroughGuard?: EnvPassthroughGuardConfig
  /** Mode at the runtime layer — mirrors the tool-layer `mode` config. */
  mode: Mode
  /** Look up session context from the most recent `tools/pre-execute`. */
  sessionResolve: RuntimeHookSessionResolve
  /**
   * Realpath implementation backing the
   * `resolveExecutable` audit seam. Defaults to `fs.realpathSync.native`;
   * unit tests inject a stub for cross-platform determinism (Windows
   * symlink creation needs privileges / Developer Mode that CI cannot
   * assume). Returning a value !== the resolved path models the
   * `node_modules/.bin/<safe-name>` → malicious-bin symlink divergence.
   */
  realpathFn?: (path: string) => string
  /**
   * callback that binds the observed child PID to the
   * active session so audit consumers can correlate spawned
   * descendants with their parent turn. Only the TERMINAL
   * seam still calls this — the real `SubprocessHandle` exposes no
   * `pid` (subprocess/src/types.ts:169-196), so the spawn seam has no
   * pid to bind and `child_pid` is left unset on spawn events.
   * Best-effort: the wrapper tolerates a missing callback by
   * doing nothing.
   */
  bindChildPid?: (pid: number, sessionId: string) => void
}

export interface RuntimeHookStats {
  /** Total `ctx.subprocess.spawn` calls observed. */
  spawned: number
  /** Calls that produced a `block` decision. */
  blocked: number
  /** Calls that threw inside the wrapper (eval error). */
  errors: number
  /** Calls where session context was missing. */
  untracked: number
  /** Total `ctx.subprocess.resolveExecutable` calls observed. */
  resolved: number
  /** Resolve calls that produced a `block` decision. */
  resolveBlocked: number
  /** Currently installed? */
  installed: boolean
}

/**
 * Thrown by the wrapper when a block decision fires in enforce mode. The
 * underlying `ctx.subprocess.spawn` translates this into a tool-level
 * error (the harness's executor catches spawn exceptions and surfaces
 * them via `tools/post-execute`).
 */
export class SpawnDeniedError extends Error {
  readonly blockReason: string | undefined
  readonly blockCode: string | undefined
  constructor(reason: string | undefined, blockCode: string | undefined) {
    super(reason ?? 'blocked by security policy')
    this.name = 'SpawnDeniedError'
    this.blockReason = reason
    this.blockCode = blockCode
  }
}

/**
 * Thrown by the `resolveExecutable` wrapper when
 * the resolved (realpath'd) executable hits a `block` decision in enforce
 * mode. Callers expect a path string; the rejection propagates to the
 * harness's tool executor and aborts the spawn before it starts — the
 * enforce-mode block semantics are identical to `SpawnDeniedError`, the
 * distinct class name keeps the seam diagnosable in tool error surfaces.
 */
export class ResolveExecutableDeniedError extends Error {
  readonly blockReason: string | undefined
  readonly blockCode: string | undefined
  /** The realpath'd target the deny-list matched on (may differ from the
   *  resolved path when a `node_modules/.bin/<safe-name>` symlink points
   *  at a malicious bin). */
  readonly resolvedPath: string
  readonly realPath: string | undefined
  constructor(
    reason: string | undefined,
    blockCode: string | undefined,
    resolvedPath: string,
    realPath: string | undefined,
  ) {
    super(reason ?? 'executable resolution blocked by security policy')
    this.name = 'ResolveExecutableDeniedError'
    this.blockReason = reason
    this.blockCode = blockCode
    this.resolvedPath = resolvedPath
    this.realPath = realPath
  }
}

export class RuntimeHook {
  private readonly deps: RuntimeHookDeps
  private target: SubprocessRuntimeLike | null = null
  private origSpawn: SubprocessRuntimeLike['spawn'] | null = null
  private origSpawnTerminal: SubprocessRuntimeLike['spawnTerminal'] | null = null
  /** Captured `resolveExecutable` (optional on
   *  the harness runtime — absent means the seam stays inert). */
  private origResolveExecutable: SubprocessRuntimeLike['resolveExecutable'] | null = null
  private installed = false
  /**
   * Per-instance counter for status-file uniqueness when multiple
   * wrappers are spawned from the same host process. Used only to
   * build `${outputPath}.${pid}.${counter}.status.json`; no longer
   * threaded into the wrapper argv itself (event_id uniqueness
   * across processes is `wrapperPid` from the wrapper's perspective).
   */
  private statusFileCounter = 0

  readonly stats: RuntimeHookStats = {
    spawned: 0,
    blocked: 0,
    errors: 0,
    untracked: 0,
    resolved: 0,
    resolveBlocked: 0,
    installed: false,
  }

  constructor(deps: RuntimeHookDeps) {
    this.deps = deps
  }

  /** Install the wrapper on the live `ctx.subprocess` instance. Idempotent. */
  install(target: SubprocessRuntimeLike): void {
    if (this.installed) return
    if (!this.deps.runtimeHookConfig.enabledAtSubprocess) {
      // Operator disabled the seam — record nothing, log nothing (avoid noise).
      this.installed = true
      this.stats.installed = true
      return
    }
    this.target = target
    // Capture the unbound method reference for restoration. When invoking
    // we use `.call(this.target, ...)` to set `this` — avoids producing
    // a new bound-function reference at install time (which would break
    // identity comparisons in tests and the plugin-self-check heartbeat).
    this.origSpawn = target.spawn
    if (typeof target.spawnTerminal === 'function') {
      this.origSpawnTerminal = target.spawnTerminal
    }
    // Wrap executable resolution when the harness
    // runtime exposes it. Optional on SubprocessRuntimeLike — runtimes
    // without resolveExecutable keep the spawn-seam-only behaviour.
    if (typeof target.resolveExecutable === 'function') {
      this.origResolveExecutable = target.resolveExecutable
    }
    target.spawn = (spec) => this.wrap(spec)
    if (this.origSpawnTerminal) {
      target.spawnTerminal = (spec) => this.wrapTerminal(spec)
    }
    if (this.origResolveExecutable) {
      target.resolveExecutable = (command, env, signal) => this.wrapResolveExecutable(command, env, signal)
    }
    this.installed = true
    this.stats.installed = true
  }

  /** Restore the originals. Safe to call mid-spawn — in-flight closures
   *  hold `origSpawn` independently of the target's method reference. */
  uninstall(): void {
    if (!this.installed) return
    if (this.target && this.origSpawn) {
      this.target.spawn = this.origSpawn
    }
    if (this.target && this.origSpawnTerminal) {
      this.target.spawnTerminal = this.origSpawnTerminal
    }
    if (this.target && this.origResolveExecutable) {
      this.target.resolveExecutable = this.origResolveExecutable
    }
    this.origSpawn = null
    this.origSpawnTerminal = null
    this.origResolveExecutable = null
    this.target = null
    this.installed = false
    this.stats.installed = false
  }

  /**
   * apply 🟢 runtimeHooks keys in place. The deps
   * hold `runtimeHookConfig` by reference and every gate
   * (`enabledAtSubprocess` / `blockAtSubprocess` / `failOpenOnError` /
   * `excludeCommandLines`) is read per-wrap, so the next spawn sees the
   * new values with no reinstall — `blockAtSubprocess: false → true`
   * hot-upgrade is the core scenario of this ticket. `deps.mode` is a
   * boot-time scalar snapshot, so a `mode` entry in the patch (routed
   * here only by internal callers; the livePatch classifier keeps mode
   * 🟡 restart-required) is synced explicitly.
   */
  livePatch(patch: Record<string, unknown>): {
    ok: boolean
    appliedKeys: string[]
    needsRestartKeys: string[]
    error?: string
  } {
    const appliedKeys: string[] = []
    const needsRestartKeys: string[] = []
    try {
      const cfg = patch['runtimeHooks']
      if (cfg && typeof cfg === 'object' && !Array.isArray(cfg)) {
        const c = cfg as Record<string, unknown>
        const assignBool = (field: 'networkEnabled' | 'enabledAtSubprocess' | 'blockAtSubprocess' | 'failOpenOnError'): void => {
          if (typeof c[field] === 'boolean') {
            this.deps.runtimeHookConfig[field] = c[field]
            appliedKeys.push(`runtimeHooks.${field}`)
          }
        }
        assignBool('networkEnabled')
        assignBool('enabledAtSubprocess')
        assignBool('blockAtSubprocess')
        assignBool('failOpenOnError')
        if (Array.isArray(c['excludeCommandLines'])) {
          this.deps.runtimeHookConfig.excludeCommandLines = [
            ...(c['excludeCommandLines'] as unknown[]).filter((x): x is string => typeof x === 'string'),
          ]
          appliedKeys.push('runtimeHooks.excludeCommandLines')
        }
        if ('logPath' in c) needsRestartKeys.push('runtimeHooks.logPath')
        if ('hookPath' in c) needsRestartKeys.push('runtimeHooks.hookPath')
      }
      if (typeof patch['mode'] === 'string' && (patch['mode'] === 'audit' || patch['mode'] === 'enforce')) {
        this.deps.mode = patch['mode']
        appliedKeys.push('mode')
      }
      appliedKeys.sort()
      needsRestartKeys.sort()
      return { ok: true, appliedKeys, needsRestartKeys }
    } catch (error: unknown) {
      return {
        ok: false,
        appliedKeys,
        needsRestartKeys,
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }

  /**
   * Synchronous wrap for `ctx.subprocess.spawn`.
   *
   * The harness's `spawn` returns a `SubprocessHandle` SYNCHRONOUSLY
   * (`subprocess-local/src/index.ts:179`), and callers consume it
   * synchronously — `bash-local/src/index.ts:252-253` does
   * `const handle = this.ctx.subprocess.spawn(...); await handle.done`.
   * The pre- wrapper deferred `origSpawn` behind an async eval and
   * returned a Promise on every path, so callers saw
   * `Promise.done === undefined` and every shell tool call broke. The
   * wrapper therefore returns the original handle VERBATIM, synchronously.
   *
   * Pipeline:
   *   1. Inline guards (prompt-injection → sensitive-path → env-passthrough
   *      → inline self-protection) run SYNCHRONOUSLY. An inline `block` in
   *      enforce mode (`mode: 'enforce'` + `blockAtSubprocess`) throws
   *      `SpawnDeniedError` BEFORE the fork — the only path that can still
   *      prevent the spawn, because the hardcoded decision is known before
   *      `origSpawn` runs. (Note: `evaluateInlineSelfProtection` gates on
   *      `actionType === 'tool_call'`, so 001/014/015 do not fire on this
   *      seam's `process_start` contexts — those attacks are still caught,
   *      but by the SPL layer's matching SelfProtection rules, post-spawn.)
   *   2. `origSpawn` is invoked synchronously; its handle is returned to
   *      the caller identity-equal (audit AND enforce, allow AND inline-
   *      decision paths).
   *   3. The SPL decision is evaluated in the BACKGROUND against the
   *      already-spawned handle:
   *      - `allow` → `runtime_spawn_intent` (blocked=false).
   *      - `block`, audit mode (or `blockAtSubprocess: false`) →
   *        `runtime_spawn_intent` (blocked=true); the child keeps running
   *        — identical visibility to pre-.
   *      - `block`, enforce → `runtime_spawn_intent` + `runtime_spawn_denied`
   *        and a best-effort `handle.terminate()`. SEMANTIC CHANGE:
   *        pre- the wrapper threw before the fork; that required
   *        deferring the spawn until the async eval settled, which is
   *        exactly what broke the synchronous host API. A synchronous
   *        throw is physically impossible once the caller holds the handle,
   *        so post-spawn terminate is the strongest enforcement remaining.
   *      - eval error → `runtime_hook_error`; `failOpenOnError: true` lets
   *        the child run, `false` terminates it post-spawn (fail-closed).
   */
  wrap(spec: SubprocessSpawnSpec): SubprocessSpawnResult {
    // Debug marker: emit an event every time wrap fires so
    // we can verify in events.jsonl whether the monkey-patch is actually
    // being routed by the Traceable proxy. Gated on DSH_DEBUG_RUNTIME_HOOK=1
    // so test suites (which don't set this env var) stay quiet.
    if (process.env.DSH_DEBUG_RUNTIME_HOOK === '1') {
      try {
        this.deps.eventCollector.report({
          comm: DEFAULT_PLATFORM_ID,
          event_id: `evt-marker-${Date.now()}`,
          event_type: 'runtime_hook_error',
          //'layer'is the spec's 3-tier coarse enum.
          layer: 'application',
          ts: Date.now(),
          timestamp: Date.now(),
          pid: process.pid,
          collection_method: 'runtime',
          session_id: 'wrap-marker',
          cmdline: 'WRAP_CALLED',
          metadata: {
            argv: spec.argv ?? [],
            cwd: spec.cwd,
          },
          ...buildHostMeta(),
        })
      } catch {
        // best-effort
      }
    }
    if (!this.deps.runtimeHookConfig.enabledAtSubprocess || !this.origSpawn || !this.target) {
      // Bypass — operator disabled, or uninstalled.
      return this.origSpawn && this.target
        ? this.origSpawn.call(this.target, spec)
        : inertSubprocessSpawnResult()
    }
    this.stats.spawned++
    let session: RuntimeHookSessionContext | undefined
    try {
      const ctx = this.buildContext(spec)
      session = this.deps.sessionResolve()
      if (!session) this.stats.untracked++

      // Phase 1 — inline guards, synchronously. An enforce-mode block here
      // can still prevent the fork (the decision is known pre-spawn).
      const inlineDecision = this.runInlineGuards(ctx)
      if (inlineDecision && inlineDecision.decision === 'block' && this.shouldEnforceBlock()) {
        this.stats.blocked++
        // Enforce-mode block emits a single
        // `runtime_spawn_denied` event rather than a pair (intent +
        // denied). The intent event's payload is identical to denied minus
        // the isDenied flag, and emitting both doubled the audit-row count
        // for every blocked fork (an N=2 audit fan-out instead of N=1).
        // Audit consumers key off `runtime_spawn_denied.event_id` for the
        // denied record; the leading `runtime_spawn_intent` was redundant.
        this.emitIntentEvent(spec, session, inlineDecision, true)
        throw new SpawnDeniedError(inlineDecision.block_reason, inlineDecision.block_code)
      }

      // Phase 2 — synchronous passthrough. The handle the caller receives
      // is the exact object `origSpawn` returned (mirror rewrite excepted,
      // which only changes spec.argv, never the handle shape).
      const rewrittenSpec = this.maybeRewriteForMirror(spec, session)
      const result = this.origSpawn.call(this.target, rewrittenSpec)

      // Phase 3 — record the decision without blocking the caller.
      if (inlineDecision) {
        // Inline (hardcoded) decision was known synchronously — record it
        // now; the event is observable before wrap() even returns.
        this.emitIntentEvent(spec, session, inlineDecision, false)
      } else {
        void this.evaluateSplInBackground(spec, session, ctx, result)
      }
      return result
    } catch (error) {
      if (error instanceof SpawnDeniedError) throw error
      // Synchronous failure (buildContext / sessionResolve / origSpawn
      // threw). Honor failOpenOnError — same posture as pre-.
      this.stats.errors++
      this.emitHookError(spec, error)
      if (this.deps.runtimeHookConfig.failOpenOnError && this.origSpawn && this.target) {
        return this.origSpawn.call(this.target, spec)
      }
      // Re-throw — operator asked for fail-closed.
      throw error
    }
  }

  /**
   * ============================================================================
   * spawnTerminal PTY gap tombstone.
   * ============================================================================
   *
   * The stdio pipe mirror (L2.5) covers `spawn` (the
   * pipe-stdio path) — `wrap()` rewrites the spec.argv to launch the
   * bundled `lib/runtime/stdio-mirror.js` wrapper which captures
   * stdin/stdout/stderr bytes to NDJSON. The mirror is a normal
   * pipe-stdio child, so Node's `Readable` / `Writable` interfaces
   * apply and the wrapper just `appendFileSync`s each chunk.
   *
   * `spawnTerminal` (PTY-stdio path) is a DIFFERENT seam. The harness
   * hands the plugin a PTY-backed child whose stdio is multiplexed
   * over a single byte stream with terminal-discipline semantics
   * (termios: raw mode, line discipline, escape sequences, window
   * resize). The stdio-mirror wrapper CANNOT be reused here because:
   *
   *   1. The PTY child receives stdin from the agent as a STREAM OF
   *      ANSI / TTY escapes (e.g. `readline` cursor-positioning
   *      queries). A pipe-stdio wrapper would drop the TTY semantics
   *      and the child would refuse to render prompts correctly.
   *   2. The harness's PTY provider owns the underlying file
   *      descriptor (`pty.open()` on Linux, `ConPTY` on Windows) and
   *      does not expose the fd across the Cordis boundary — we
   *      cannot splice a mirror between the harness fd and the child
   *      without either forking a tee process (which loses termios
   *      state) or modifying the harness PTY provider (which violates
   *      design invariant #1, zero source-tree intrusion).
   *   3. PTY byte relay also conflicts with the agent's `readline`
   *      loop: the agent reads line-by-line, but a raw-mode byte relay
   *      would deliver escape sequences one chunk at a time and break
   *      line-buffering invariants the agent's UI depends on.
   *
   * Current posture:
   *   - `wrapTerminal` emits one `runtime_terminal_intent` event per
   *     call (argv shape + session attribution) — observability only.
   *   - No byte mirror. Audit-only
   *     is the safe default because any byte-level inspection of a PTY
   *     stream would race with the agent's `readline` and produce
   *     false-positive forensic signal (the byte stream mid-escape
   *     looks like garbage to a content redactor).
   *   - SPL evaluation on `argv` still fires — a deny-listed command
   *     launched inside `terminal` still gets caught at the argv layer.
   *
   * A PTY byte mirror needs harness-side support (a `pty/mirror`-style
   * Cordis event or a spawn-spec mirror flag); until that lands,
   * content-level inspection of terminal spawns is out of scope by design.
   *
   * Tests: `wrapTerminal` smoke-test is gated by the harness's
   * optional `target.spawnTerminal` — when absent (current Cordis
   * stub), the wrapper no-ops. The argv-layer SPL evaluation is
   * covered by the same `tests/runtimeHook.test.ts` cases that drive
   * `wrap()` (terminal-spec argv exercises the same
   * `buildTerminalContext` + `runEval` pipeline).
   * ============================================================================
   */
  /** Async wrapper for `ctx.subprocess.spawnTerminal`. Same shape as
   *  `wrap` but PTY-only — emits `runtime_terminal_intent` and never
   *  blocks in this iteration. Defer the block mode to ops after a
   *  false-positive review. */
  async wrapTerminal(spec: SubprocessTerminalSpawnSpec): Promise<unknown> {
    if (!this.deps.runtimeHookConfig.enabledAtSubprocess || !this.origSpawnTerminal || !this.target) {
      return this.origSpawnTerminal
        ? this.origSpawnTerminal.call(this.target, spec)
        : undefined
    }
    this.stats.spawned++
    let session: RuntimeHookSessionContext | undefined
    try {
      const ctx = this.buildTerminalContext(spec)
      session = this.deps.sessionResolve()
      if (!session) this.stats.untracked++
      const decision = await this.runEval(ctx)
      this.emitTerminalIntentEvent(spec, session, decision)
      const result = await this.origSpawnTerminal.call(this.target, spec)
      // terminal spawns also produce child PIDs; bind them
      // so PTY-driven tool subprocesses can be correlated by the system layer.
      this.bindChildPidFromResult(result, session)
      return result
    } catch (error) {
      this.stats.errors++
      this.emitHookError({ argv: spec.argv }, error)
      if (this.deps.runtimeHookConfig.failOpenOnError && this.origSpawnTerminal && this.target) {
        const result = await this.origSpawnTerminal.call(this.target, spec)
        this.bindChildPidFromResult(result, session)
        return result
      }
      throw error
    }
  }

  /**
   * Async wrap for `ctx.subprocess.resolveExecutable`.
   *
   * Threat model: an executable reached through a benign-looking argv name can
   * still resolve to a malicious binary. The argv layer (spawn seam + tool
   * layer) only sees the innocent-looking name; the SPL deny-list matches
   * on argv text and lets it through. This seam audits the RESOLVED
   * executable: after the original resolver returns, we realpath the
   * result and run the same `InterventionEngine.evaluate` (SPL) pipeline
   * on the real target text, so deny-list rules keyed on the malicious
   * basename/path fire even when the argv looked benign.
   *
   * Semantics (mirroring the spawn seam):
   *   - every call emits `runtime_resolve_intent` (audit trail)
   *   - `block` + enforce (`mode === 'enforce'` AND
   *     `runtimeHooks.blockAtSubprocess`) → throw
   *     `ResolveExecutableDeniedError`; the caller expects a path string,
   *     the rejection surfaces as a tool error and aborts the spawn
   *   - `block` + audit → record `runtime_resolve_denied`, return the
   *     resolved path unchanged (audit-only, invariant #4)
   *   - eval error → honor `failOpenOnError` (return the resolved path /
   *     re-throw), same posture as the spawn seam
   *
   * Errors from the ORIGINAL resolver (e.g. command-not-found) propagate
   * untouched — this wrapper never rewrites resolution failures.
   *
   * Inline self-protection / sensitive-path / prompt-injection / env
   * guards intentionally do NOT run here: the spawn seam already
   * evaluates them on the fork argv, and this seam's unique value is the
   * post-resolution deny-list check.
   */
  async wrapResolveExecutable(
    command: string,
    env?: Record<string, string>,
    signal?: AbortSignal,
  ): Promise<string> {
    if (!this.deps.runtimeHookConfig.enabledAtSubprocess || !this.origResolveExecutable || !this.target) {
      // Bypass — operator disabled, or uninstalled.
      if (this.origResolveExecutable && this.target) {
        return this.origResolveExecutable.call(this.target, command, env, signal)
      }
      throw new Error('resolveExecutable wrapper is not installed on a live subprocess runtime')
    }
    this.stats.resolved++
    // Resolution errors (command not found etc.) propagate untouched.
    const resolved = await this.origResolveExecutable.call(this.target, command, env, signal)
    try {
      const realPath = this.safeRealpath(resolved)
      const ctx = this.buildResolveContext(command, resolved, realPath, env)
      const session = this.deps.sessionResolve()
      if (!session) this.stats.untracked++
      if (session) {
        ctx.sessionId = session.sessionId
        ctx.runId = session.runId
        ctx.agentId = session.agentId
      }
      const decision = await this.deps.interventionEngine.evaluate(ctx)
      if (decision.decision === 'block') {
        this.stats.resolveBlocked++
        // Audit trail: intent (blocked=true) plus explicit denied event —
        // same pair shape as the spawn seam.
        this.emitResolveEvent(command, resolved, realPath, session, decision, false)
        this.emitResolveEvent(command, resolved, realPath, session, decision, true)
        if (this.shouldEnforceBlock()) {
          throw new ResolveExecutableDeniedError(decision.block_reason, decision.block_code, resolved, realPath)
        }
        // Audit-only: record, then fall through and return the resolved path.
      } else {
        this.emitResolveEvent(command, resolved, realPath, session, decision, false)
      }
      return resolved
    } catch (error) {
      if (error instanceof ResolveExecutableDeniedError) throw error
      this.stats.errors++
      this.emitHookError({ argv: [command] }, error)
      if (this.deps.runtimeHookConfig.failOpenOnError) {
        return resolved
      }
      // Operator asked for fail-closed — re-throw the eval error.
      throw error
    }
  }

  // --- internal helpers ------------------------------------------------------

  private buildContext(spec: SubprocessSpawnSpec): InterventionContext {
    const argv = Array.isArray(spec.argv) ? spec.argv : []
    const body = deriveBodyFromArgv(argv)
    const commandField = body || argv.join(' ')
    const executable = argv[0] ?? ''
    const params: Record<string, unknown> = {
      command: commandField,
      cmd: commandField,
      shell: commandField,
      exec: argv.join(' '),
      cwd: spec.cwd,
      env: spec.env ?? {},
      argv,
    }
    return {
      // standard audit): the SPL unified spec
      // enumerates `process_start` as the canonical actionType for
      // pre-spawn interception. `subprocess_spawn` was a private
      // alias left over from the sprint; standardising on
      // `process_start` keeps existing SELF_PROTECTION rules matching
      // (the spec also lists `process_start` as a trigger point for
      // rule action matching).
      actionType: 'process_start',
      toolName: executable || 'subprocess',
      params,
      body,
      // session/run/agent populated by the wrapper after sessionResolve.
      // Tool-call-id correlation: the ApplicationCollector records
      // tool_call_id on every pre-execute; the runtime wrapper doesn't
      // see it directly but downstream code reads session context.
      riskFlags: deriveRiskFlags(spec),
    }
  }

  private buildTerminalContext(spec: SubprocessTerminalSpawnSpec): InterventionContext {
    const argv = Array.isArray(spec.argv) ? spec.argv : []
    const body = argv.join(' ')
    const executable = argv[0] ?? ''
    return {
      // see buildContext — `process_start` is the
      // spec-canonical actionType.
      actionType: 'process_start',
      toolName: executable || 'subprocess',
      params: {
        command: body,
        exec: body,
        cwd: spec.cwd,
        argv,
      },
      body,
      riskFlags: deriveRiskFlags({ argv }),
    }
  }

  /**
   * Best-effort realpath for the resolve seam.
   * Any failure (nonexistent target, platform quirks) degrades to
   * `undefined` — the eval then runs on the resolved path alone, never
   * on a thrown error (invariant #3).
   */
  private safeRealpath(resolvedPath: string): string | undefined {
    try {
      const fn = this.deps.realpathFn ?? ((p: string): string => realpathSync.native(p))
      return fn(resolvedPath)
    } catch {
      return undefined
    }
  }

  /**
   * InterventionContext for a resolved executable.
   *
   * The matcher-visible `command`/`cmd`/`shell`/`exec`/`body` text carries
   * the realpath'd target FIRST (that is what the deny-list must see
   * through the symlink); when the realpath diverges from the resolved
   * path (symlink), the resolved path is appended so rules keyed on the
   * innocent-looking name still fire. Separators are normalised to `/`
   * so POSIX-flavoured policy regexes match on Windows too. Raw paths
   * stay available under `resolved_path` / `realpath` / `requested_command`.
   */
  private buildResolveContext(
    command: string,
    resolvedPath: string,
    realPath: string | undefined,
    env?: Record<string, string>,
  ): InterventionContext {
    const normResolved = normalizeSeparators(resolvedPath)
    const normReal = realPath ? normalizeSeparators(realPath) : undefined
    const target = normReal ?? normResolved
    const diverged = normReal !== undefined && normReal !== normResolved
    const commandText = diverged ? `${normResolved} -> ${normReal}` : target
    return {
      actionType: 'process_start',
      toolName: basename(target) || command,
      params: {
        command: commandText,
        cmd: commandText,
        shell: commandText,
        exec: commandText,
        argv: [target],
        requested_command: command,
        resolved_path: resolvedPath,
        realpath: realPath,
        env: env ?? {},
      },
      body: commandText,
      riskFlags: deriveRiskFlags({ argv: [target] }),
    }
  }

  /**
   * Synchronous inline-guard pipeline (prompt-injection → sensitive-path →
   * env-passthrough → inline self-protection). Returns the first block
   * decision, or `undefined` when no hardcoded guard fires and the SPL
   * engine must evaluate. Kept strictly synchronous so the
   * enforce-mode pre-fork throw in `wrap()` stays possible.
   *
   * the inline-guard chain is now driven by
   * `runInlineGuardChain` (shared with `ApplicationCollector.evaluateTool`).
   * Each step's `enabled()` predicate mirrors the previous inline
   * presence + `.enabled` check — when a guard dependency is missing
   * (legacy unit-test contexts, optional marketplaces), the step is
   * silently skipped.
   *
   * NOTE: `evaluateInlineSelfProtection` gates on
   * `actionType === 'tool_call'`, so the 001/014/015 rules never fire on
   * this seam's `process_start` contexts (they run on the tool-layer
   * `ctx.tools.guard` seam instead). The 3 functional guards above do fire
   * here and provide the synchronous pre-fork block.
   */
  private runInlineGuards(ctx: InterventionContext): SecurityDecision | undefined {
    const ipi = this.deps.inlinePromptInjection
    const guard = this.deps.sensitivePathGuard
    const envGuard = this.deps.envPassthroughGuard
    // thread an onError sink so a misbehaving guard is
    // surfaced as a runtime_hook_error event (audit) + console warn,
    // rather than silently swallowed. Mirrors the
    // ApplicationCollector.evaluateTool threading — same helper, same
    // per-consumer observability contract.
    const chainDecision = runInlineGuardChain(
      ctx,
      [
        {
          enabled: () => Boolean(ipi && ipi.enabled),
          label: 'inline-prompt-injection',
          evaluate: (c) => evaluateInlinePromptInjection(c, ipi!),
        },
        {
          enabled: () => Boolean(guard && guard.enabled),
          label: 'inline-sensitive-path',
          evaluate: (c) => evaluateSensitivePathGuard(c, guard!),
        },
        {
          enabled: () => Boolean(envGuard && envGuard.enabled),
          label: 'inline-env-passthrough',
          evaluate: (c) => evaluateEnvPassthroughGuard(c, envGuard!),
        },
      ],
      (label, error) => {
        // console is the last-resort logger — RuntimeHook has no logger
        // dep today; surface the failure to stderr so operators see it
        // even when NDJSON writeback is wedged. Gated behind DSH_DEBUG
        // so a guard that throws on operator-supplied content does not
        // flood stderr in production; the error still flows into
        // emitInlineGuardError (NDJSON audit channel).
        if (process.env.DSH_DEBUG === '1') {
          console.warn(`[SecurityMonitor] inline guard ${label} threw: ${String(error)}`)
        }
        this.emitInlineGuardError(label, error, ctx)
      },
    )
    if (chainDecision) return chainDecision
    return evaluateInlineSelfProtection(ctx, this.deps.inlineGuards) ?? undefined
  }

  /**
   * emit a `runtime_hook_error` event when an inline
   * guard step inside `runInlineGuardChain` throws. Mirrors the existing
   * `emitHookError` shape but distinguishes inline-guard failures from
   * outer-wrap failures (`audit_details.event_type_alias`). The chain
   * helper preserves chain execution on error, so this is observability-
   * only — the SPL fallback remains the catch-all.
   */
  private emitInlineGuardError(
    label: string,
    error: unknown,
    ctx: InterventionContext,
  ): void {
    const ts = nowMs()
    const message = error instanceof Error ? error.message : String(error)
    const className =
      error instanceof Error
        ? error.name || error.constructor.name || 'Error'
        : typeof error
    const event: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: 'security_audit',
      layer: 'application',
      source_layer: 'runtime',
      ts,
      timestamp: ts,
      pid: process.pid,
      collection_method: 'runtime',
      session_id: ctx.sessionId,
      run_id: ctx.runId,
      agent_id: ctx.agentId ?? '__plugin__',
      audit_category: 'runtime',
      audit_action: 'detect',
      severity: 'medium',
      summary: `inline_guard_error: ${label} threw ${className} — chain continued`,
      outcome: 'success',
      reason: 'inline_guard_exception_caught',
      audit_details: {
        event_type_alias: 'inline_guard_error',
        guard_label: label,
        action_type: ctx.actionType,
        tool_name: ctx.toolName,
        error_class: className,
        error_message: truncateString(message, 240),
        detail:
          `RuntimeHook.runInlineGuards caught a ${className} from the ${label} step; ` +
          `chain execution continued with the next guard (invariant #3: never throw to the host).`,
      },
      ...buildHostMeta(),
      risk_flags: ['self_protection_internal'],
    }
    try {
      this.deps.eventCollector.report(event)
    } catch {
      // ignore — invariant #3
    }
  }

  private async runEval(ctx: InterventionContext): Promise<SecurityDecision> {
    const inlineDecision = this.runInlineGuards(ctx)
    if (inlineDecision) return inlineDecision
    return this.deps.interventionEngine.evaluate(ctx)
  }

  /**
   * Background SPL evaluation for the synchronous spawn seam. The
   * caller already holds the handle when this runs — a `block` can no
   * longer prevent the fork, so enforce mode degrades to best-effort
   * termination (see `wrap()` doc comment for the rationale; the
   * pre-fork throw required deferring `origSpawn` behind the async eval,
   * which broke the host's synchronous handle consumption). The promise is
   * always handled here so no unhandled rejection can surface.
   */
  private evaluateSplInBackground(
    spec: SubprocessSpawnSpec,
    session: RuntimeHookSessionContext | undefined,
    ctx: InterventionContext,
    spawned: SubprocessSpawnResult,
  ): void {
    this.evaluateAndDecide(ctx, session).then(
      (decision) => {
        if (decision.decision === 'block') {
          if (this.shouldEnforceBlock()) {
            this.stats.blocked++
            // Enforce-mode block emits a single
            // `runtime_spawn_denied` event (see inline-guard branch above
            // for the rationale — emitting both would be N=2 audit fan-out).
            this.emitIntentEvent(spec, session, decision, true)
            this.bestEffortTerminate(spawned)
          } else {
            // Audit-only (or blockAtSubprocess:false): record, child runs —
            // identical visibility to pre-.
            this.emitIntentEvent(spec, session, decision, false)
          }
          return
        }
        this.emitIntentEvent(spec, session, decision, false)
      },
      (error: unknown) => {
        this.stats.errors++
        this.emitHookError(spec, error)
        if (!this.deps.runtimeHookConfig.failOpenOnError) {
          // Fail-closed requested but the spawn already happened — the
          // strongest remaining enforcement is terminating the child.
          this.bestEffortTerminate(spawned)
        }
      },
    )
  }

  /**
   * Post-spawn enforcement. `SubprocessHandle.terminate()` is the
   * seam's only termination verb; it is idempotent and a no-op once the
   * managed range is gone, so calling it on a late `block` decision is
   * safe. Never throws into the background promise chain.
   */
  private bestEffortTerminate(spawned: SubprocessSpawnResult): void {
    try {
      spawned.terminate()
    } catch {
      // best-effort: enforcement must never break the caller
    }
  }

  private async evaluateAndDecide(
    ctx: InterventionContext,
    session: RuntimeHookSessionContext | undefined,
  ): Promise<SecurityDecision> {
    const decision = await this.runEval(ctx)
    if (session) {
      ctx.sessionId = session.sessionId
      ctx.runId = session.runId
      ctx.agentId = session.agentId
    }
    return decision
  }

  private shouldEnforceBlock(): boolean {
    return this.deps.mode === 'enforce' && this.deps.runtimeHookConfig.blockAtSubprocess
  }

  /**
   * §6.2 : stdio pipe mirror rewrite. Returns a new spec
   * with the wrapper prepended to `argv` when the mirror is enabled and at
   * least one stdio stream is worth mirroring. Otherwise returns the input
   * spec. (The pre- gate was `spec.stdio !== 'ignore'`; the real
   * harness `stdio` is always a per-stream object, so `shouldMirror` is
   * now decided by deep-checking each fd — see `buildStdioMirrorSpec`.)
   *
   * Eval has already run on the ORIGINAL argv by the time this is called,
   * so SELF_PROTECTION rules fired on the user's real command. The
   * rewrite is observable-only — it never changes the policy decision.
   */
  private maybeRewriteForMirror(
    spec: SubprocessSpawnSpec,
    session: RuntimeHookSessionContext | undefined,
  ): SubprocessSpawnSpec {
    const mirror = this.deps.stdioMirror
    if (!mirror || !mirror.config.enabled) return spec
    const specBuild = buildStdioMirrorSpec(spec.stdio, mirror.config)
    if (!specBuild.shouldMirror) return spec
    const seq = this.statusFileCounter++
    const statusPath = `${mirror.config.outputPath}.${process.pid}.${seq}.status.json`
    return rewriteSpecForMirror(spec, mirror.wrapperPath, specBuild.spec, mirror.config, {
      sessionId: session?.sessionId,
      // stamp the same correlation keys as emitIntentEvent
      // so the wrapper's stdio_mirror events join runtime_*_intent events
      // on the identical dashboard fields (task/turn fall back to
      // session/run exactly like the intent events do).
      runId: session?.runId,
      agentId: session?.agentId,
      taskId: session?.taskId ?? session?.sessionId,
      turnId: session?.turnId ?? session?.runId,
      statusPath,
    })
  }

  /**
   * best-effort extraction of a child PID from a terminal
   * spawn result. PTY runtimes return opaque handles, but when a numeric
   * `pid` is present we bind it to the active session.
   */
  private bindChildPidFromResult(result: unknown, session: RuntimeHookSessionContext | undefined): void {
    if (!result || typeof result !== 'object' || !session || !this.deps.bindChildPid) return
    const pid = (result as { pid?: unknown }).pid
    if (typeof pid === 'number' && pid > 0) {
      try {
        this.deps.bindChildPid(pid, session.sessionId)
      } catch {
        // best-effort
      }
    }
  }

  private emitIntentEvent(
    spec: SubprocessSpawnSpec,
    session: RuntimeHookSessionContext | undefined,
    decision: SecurityDecision,
    isDenied: boolean,
  ): void {
    const ts = nowMs()
    const argv = Array.isArray(spec.argv) ? spec.argv : []
    const commandLine = argv.join(' ')
    const eventType = isDenied ? 'runtime_spawn_denied' : 'runtime_spawn_intent'
    const event: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: eventType,
      //'layer'is the spec's 3-tier coarse enum;
      // 'runtime' (the pre-spawn interception seam) lives on
      // `source_layer` for back-compat with dashboards that key on it.
      layer: 'application',
      source_layer: 'runtime',
      ts,
      timestamp: ts,
      pid: process.pid,
      // intentionally NO `child_pid` here — the real
      // `SubprocessHandle` exposes no pid (subprocess/src/types.ts:169-196),
      // and the pre- `{ handle, pid }` stub shape was a fabrication.
      // Correlation falls back to session_id / run_id / cmdline.
      collection_method: 'runtime',
      session_id: session?.sessionId,
      run_id: session?.runId,
      agent_id: session?.agentId,
      // stamp the explicit task / turn identifiers so
      // audit dashboards can correlate a fragment-variable attack spawn
      // back to its originating agent task without re-parsing run_id.
      task_id: session?.taskId ?? session?.sessionId,
      turn_id: session?.turnId ?? session?.runId,
      ...buildHostMeta(),
      // the schema uses `cmdline`/`exe`.
      cmdline: commandLine,
      exe: argv[0] ?? '',
      // Structured argv vector for audit replay of
      // fragment-variable attacks. Optional in the spec but retained
      // for back-compat.
      argv: [...argv],
      cwd: spec.cwd,
      blocked: isDenied || decision.decision === 'block',
      block_reason: isDenied ? decision.block_reason : undefined,
      risk_flags: deriveRiskFlags(spec),
      intervention: {
        // marketplace wire vocabulary.
        decision: toMarketplaceDecision(decision.decision),
        decision_internal: decision.decision,
        mode: decision.mode,
        policy_id: decision.policy_id,
        policy_name: decision.policy_name,
        block_reason: decision.block_reason,
        block_code: decision.block_code,
        appealable: decision.appealable,
        // severity trace propagated to the audit event so the
        // Recent Blocks UI can render the SEVERITY column + the ↓warn
        // downgrade marker without re-evaluating the rule.
        severity: decision.severity,
        severity_downgraded: decision.severity_downgraded,
        severity_rule_id: decision.severity_rule_id,
      },
    }
    try {
      this.deps.eventCollector.report(event)
    } catch {
      // Audit sink failure must never block the spawn.
    }
  }

  /**
   * Emit `runtime_resolve_intent` /
   * `runtime_resolve_denied` for the resolveExecutable seam. Shape mirrors
   * `emitIntentEvent` (cmdline/exe/argv trio + intervention decision block);
   * the symlink-audit fields (`requested_command` / `resolved_path` /
   * `realpath` / `symlink_diverged`) ride in `metadata` for post-hoc
   * replay of the argv-layer bypass attempt.
   */
  private emitResolveEvent(
    command: string,
    resolvedPath: string,
    realPath: string | undefined,
    session: RuntimeHookSessionContext | undefined,
    decision: SecurityDecision,
    isDenied: boolean,
  ): void {
    const ts = nowMs()
    const normResolved = normalizeSeparators(resolvedPath)
    const normReal = realPath ? normalizeSeparators(realPath) : undefined
    const target = normReal ?? normResolved
    const commandText = normReal !== undefined && normReal !== normResolved
      ? `${normResolved} -> ${normReal}`
      : target
    const event: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: isDenied ? 'runtime_resolve_denied' : 'runtime_resolve_intent',
      // 'layer' is the spec's 3-tier coarse enum; the runtime seam lives on
      // `source_layer` — same convention as the spawn events.
      layer: 'application',
      source_layer: 'runtime',
      ts,
      timestamp: ts,
      pid: process.pid,
      collection_method: 'runtime',
      session_id: session?.sessionId,
      run_id: session?.runId,
      agent_id: session?.agentId,
      task_id: session?.taskId ?? session?.sessionId,
      turn_id: session?.turnId ?? session?.runId,
      ...buildHostMeta(),
      cmdline: commandText,
      exe: target,
      argv: [target],
      blocked: isDenied || decision.decision === 'block',
      block_reason: isDenied ? decision.block_reason : undefined,
      risk_flags: deriveRiskFlags({ argv: [target] }),
      metadata: {
        requested_command: command,
        resolved_path: resolvedPath,
        realpath: realPath,
        symlink_diverged: normReal !== undefined && normReal !== normResolved,
      },
      intervention: {
        decision: toMarketplaceDecision(decision.decision),
        decision_internal: decision.decision,
        mode: decision.mode,
        policy_id: decision.policy_id,
        policy_name: decision.policy_name,
        block_reason: decision.block_reason,
        block_code: decision.block_code,
        appealable: decision.appealable,
        // propagate the per-rule severity + downgrade trace
        // onto the audit event so consumers can tell "this was a medium
        // rule that got downgraded" from "this was a critical rule that
        // stayed block" without having to dig into the rule itself.
        severity: decision.severity,
        severity_downgraded: decision.severity_downgraded,
        severity_rule_id: decision.severity_rule_id,
        // self-protection override trace. Only present when
        // a non-self_protection local allow/warn was suppressed by a
        // self_protection rule per SPL v2 spec §9.2. Operators can grep
        // Recent Blocks for `self_protection_override: true` to find
        // override attempts without needing a dedicated event type.
        self_protection_override: decision.self_protection_override,
        overridden_rule_id: decision.overridden_rule_id,
      },
    }
    try {
      this.deps.eventCollector.report(event)
    } catch {
      // Audit sink failure must never break resolution.
    }
  }

  private emitTerminalIntentEvent(
    spec: SubprocessTerminalSpawnSpec,
    session: RuntimeHookSessionContext | undefined,
    decision: SecurityDecision,
  ): void {
    const ts = nowMs()
    const argv = Array.isArray(spec.argv) ? spec.argv : []
    const commandLine = argv.join(' ')
    const event: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: 'runtime_terminal_intent',
      //'layer'is the spec's 3-tier coarse enum;
      // 'runtime' (the pre-spawn interception seam) lives on
      // `source_layer` for back-compat with dashboards that key on it.
      layer: 'application',
      source_layer: 'runtime',
      ts,
      timestamp: ts,
      pid: process.pid,
      collection_method: 'runtime',
      session_id: session?.sessionId,
      run_id: session?.runId,
      agent_id: session?.agentId,
      // see emitIntentEvent — same task/turn stamping
      // for terminal-spawn events.
      task_id: session?.taskId ?? session?.sessionId,
      turn_id: session?.turnId ?? session?.runId,
      ...buildHostMeta(),
      // the schema uses `cmdline`/`exe`.
      cmdline: commandLine,
      exe: argv[0] ?? '',
      // Structured argv vector — see emitIntentEvent.
      argv: [...argv],
      cwd: spec.cwd,
      blocked: decision.decision === 'block',
      risk_flags: deriveRiskFlags({ argv }),
      intervention: {
        // marketplace wire vocabulary.
        decision: toMarketplaceDecision(decision.decision),
        decision_internal: decision.decision,
        mode: decision.mode,
        policy_id: decision.policy_id,
        policy_name: decision.policy_name,
        block_reason: decision.block_reason,
        block_code: decision.block_code,
        appealable: decision.appealable,
        // severity trace propagated to the audit event.
        severity: decision.severity,
        severity_downgraded: decision.severity_downgraded,
        severity_rule_id: decision.severity_rule_id,
      },
    }
    try {
      this.deps.eventCollector.report(event)
    } catch {
      // ignore
    }
  }

  private emitHookError(
    spec: { argv: readonly string[] },
    error: unknown,
  ): void {
    const ts = nowMs()
    const argv = Array.isArray(spec.argv) ? spec.argv : []
    const commandLine = argv.join(' ')
    const event: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: 'runtime_hook_error',
      //'layer'is the spec's 3-tier coarse enum;
      // 'runtime' (the pre-spawn interception seam) lives on
      // `source_layer` for back-compat with dashboards that key on it.
      layer: 'application',
      source_layer: 'runtime',
      ts,
      timestamp: ts,
      pid: process.pid,
      collection_method: 'runtime',
      ...buildHostMeta(),
      // the schema uses `cmdline`/`exe`.
      cmdline: commandLine,
      exe: argv[0] ?? '',
      // Structured argv vector. Optional on hook_error
      // per the platform specification, but retained for consistency.
      argv: [...argv],
      blocked: false,
      risk_flags: ['self_protection_internal'],
      error_message: error instanceof Error ? `${error.name}: ${error.message}` : String(error),
    }
    try {
      this.deps.eventCollector.report(event)
    } catch {
      // ignore
    }
  }
}

/**
 * Fallback handle for the "wrap() called without a live original
 * spawn" race (uninstalled before wrap, or never installed). Shape-matches
 * `SubprocessSpawnResult` so callers never receive `undefined` where the
 * harness contract promises a handle.
 */
function inertSubprocessSpawnResult(): SubprocessSpawnResult {
  return {
    done: Promise.resolve({ exitCode: 0, signal: null }),
    terminate() { /* no-op — nothing was spawned */ },
    waitForExit: async () => true,
  }
}

/**
 * Normalise Windows separators to `/` for
 * matcher-visible command text. Policy regexes are authored POSIX-first
 * (`\.ssh/id_`, `/tmp/...`); the resolve seam feeds real filesystem paths
 * into `params.command`, so without normalisation a Windows realpath
 * (`C:\...\node_modules\.bin\safe-name`) would never match a deny-list.
 * Raw paths are always retained under `resolved_path` / `realpath`.
 */
function normalizeSeparators(p: string): string {
  return p.includes('\\') ? p.replace(/\\/g, '/') : p
}

/**
 * Compute risk flags derived from the spec — pure function so tests can
 * call it directly. Currently flags `unpatched_engine` for any engine-
 * launcher invocation lacking the patch flag shape.
 */
export function deriveRiskFlags(spec: { argv: readonly string[]; cwd?: string }): string[] {
  const argv = Array.isArray(spec.argv) ? spec.argv : []
  const flags: string[] = []
  if (isEngineLauncher(argv[0] ?? '', argv) && !argvMentionsSecurityMonitorPatch(argv)) {
    flags.push('unpatched_engine')
  }
  // Bash / pwsh on absolute or relative paths under /tmp, /var/tmp, or
  // /dev/shm — common attacker scratch dirs. Mirrors 017's text class.
  if (argv.length > 0) {
    const exe = basename(argv[0] ?? '')
    if ((exe === 'bash' || exe === 'sh' || exe === 'zsh' || exe === 'pwsh' || exe === 'powershell')) {
      const cwd = spec.cwd ?? ''
      if (/^(\/tmp|\/var\/tmp|\/dev\/shm|\/root|\/home)/.test(cwd)) {
        flags.push('scratch_dir_spawn')
      }
    }
  }
  // `block-process-credential-in-command`.
  // That rule is keyed on riskFlagsAny: [token_in_command]; the RuntimeHook
  // process_start path now injects the flag directly so the rule fires
  // here. The tag is a pure risk signal — whether it blocks is the rule's
  // decision to make, not the emitter's.
  const commandText = argv.join(' ')
  if (/(Bearer\s+[A-Za-z0-9._-]{8,}|--token[=\s][^\s]+|--api-key[=\s][^\s]+|sk-[A-Za-z0-9]{16,})/.test(commandText)) {
    flags.push('token_in_command')
  }
  // data-leak detection flags (标准 §5.2).
  // Like the tag above these are correlation inputs only; the policy layer
  // decides the outcome.
  const dataLeakFlags = deriveDataLeakFlags(argv.join(' '))
  for (const flag of dataLeakFlags) {
    if (!flags.includes(flag)) flags.push(flag)
  }
  return flags
}