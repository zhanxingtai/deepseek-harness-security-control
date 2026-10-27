/**
 * Plugin Unload Sentinel — runtime HMR-disable detection ( §6.2).
 *
 * Threat model: the harness plugin-manager supports HMR — a profile-level
 * toggle can hot-unload a third-party plugin at runtime WITHOUT any tool
 * call. The InlineSelfProtection deny-list only occupies the
 * `ctx.tools.guard` + pre-spawn seams — it cannot see a profile-level
 * toggle. `configIntegrity` only validates at startup. A model (or a
 * compromised operator flow) that disables the plugin would otherwise
 * silently remove the entire safety rail; this module is what makes that
 * removal loud instead of silent.
 *
 * Detection points (defense in depth, both feed the SAME verdict path):
 *
 *  1. **Scope-dispose seam** (`ctx.effect` disposer): Cordis disposes the
 *     plugin scope on HMR unload and runs every effect disposer. Our
 *     disposer fires while the process is still alive → the scope was
 *     disposed. What that MEANS (reload vs. removal) is decided later —
 *     see "Deferred verdict" below. The verdict path emits
 *     `security_audit` (`audit_action='tamper'`, policy_tamper class) +
 *     `ctx.logger.warn`. The emit goes through `LocalNdjsonSink.report()`
 *     whose `writeLocalDirect` path stays functional during disposal
 *     (`shutdown()` only clears the flush timer + drains the vestigial
 *     batch queue), so the tamper record lands in NDJSON even when the
 *     harness's own shutdown effect runs first. The event is
 * enforcement-critical under `isEnforcementCriticalEvent`
 *     (`audit_action='tamper'`), so it also survives a disk-low degraded
 *     episode.
 *
 *  2. **Liveness watchdog** (unref'd interval + probe effect): covers the
 *     residual case where the plugin scope is torn down WITHOUT running
 *     our dispose seam (harness unload bug / fiber kill). A probe effect
 *     (`probeActive = false` on dispose) is registered BEFORE the main
 *     disposer, so on a normal scope disposal the main disposer already
 *     ran (`scopeDisposed = true`) before the probe flips and the watchdog
 *     stays silent. If the probe flips while `scopeDisposed` is still
 *     false, the watchdog enters the SAME verdict path with
 *     `detection_point: 'watchdog_liveness_probe'`. The interval is
 *     `unref`'d (never keeps the process alive) and self-clears on its
 *     first tick after probe deactivation.
 *
 * Deferred verdict (2026-10-27, real-data driven):
 *
 * The sentinel used to declare "the plugin was removed at runtime" the
 * instant the scope was disposed. Real-data capture (2026-10-22 →
 * 2026-10-27, `security-events.jsonl`) showed that verdict was wrong
 * for every single occurrence:
 *
 *   - 15 of 29 tamper-class events were followed by a `plugin_startup`
 *     in the SAME pid, 1.8–140 s later → the plugin-manager had
 *     RELOADED the plugin (HMR dispose + re-instantiate); it was never
 *     removed. The installed plugin bundle is a hardlink of the repo
 *     build output, so every local rebuild triggered exactly this.
 *   - the other 14 were the LAST event of their pid → the host process
 *     was EXITING. The event's own claim ("the host process kept
 *     running") was factually false.
 *
 * So the sentinel now separates "scope disposed" (an observation) from
 * "plugin removed" (a verdict), and only the latter emits the
 * tamper-class event:
 *
 *   - the verdict is DEFERRED. A scope disposal schedules an unref'd
 *     timer; the tamper event is emitted only if the plugin has NOT
 *     come back by the end of the grace window.
 *   - "came back" is answered by `pluginInstanceRegistry`: a monotonic
 *     per-plugin activation counter kept on `globalThis` (it must
 *     survive the HMR module re-import — see that module's header). A
 *     newer generation means RELOAD, not REMOVAL → the tamper is
 *     suppressed and the suppression is recorded in the debug log.
 *   - "the host is exiting" needs no special handling: the verdict
 *     timer is unref'd, so the process exits before it fires and no
 *     event is written. That is exactly the natural-teardown case
 *     that used to produce a false high-severity tamper row.
 *
 * Trade-off: a genuine removal is now reported after the grace window
 * (`verdictMaxWaitMs`, default 180 s) instead of instantly. The window
 * covers the longest observed HMR reload gap (140 s) with margin. The
 * alarm is a notification, not a prevention — the rail is already gone
 * when it fires — so trading latency for zero false positives is the
 * right side of that trade.
 *
 * False-positive control (acceptance — normal restarts must stay
 * silent):
 *  - `gracefulShutdown` flag set by `process.once('exit', …)` (covers
 *    natural exit AND every `process.exit()`-terminated path, including
 *    the SIGTERM graceful-shutdown in `signalHandlers.ts`) and by an
 *    explicit `markGracefulShutdown()` callback wired into the SIGTERM
 *    handler so the flag is set before the 500 ms drain window opens.
 *  - SIGKILL cannot be intercepted: no disposer runs, nothing is emitted,
 *    no false positive (and no false negative worth chasing — a SIGKILL
 *    also prevents any in-process detection from writing anywhere).
 *  - The tamper event is emitted exactly once (`tamperEmitted` guard),
 *    regardless of which seam fires first.
 *  - The emitted event states only what was actually observed: the
 *    `detail` string no longer asserts "the host process kept running"
 *    (it was frequently false) and `graceful_shutdown_expected` is
 *    computed from the live flag instead of being hard-coded `false`.
 *
 * Mode independence: this is self-protection depth, not SPL enforcement —
 * the audit fires in `audit` mode too (same precedent as
 * SelfProtectionGuard's monotonic denial). It never blocks the unload
 * (Cordis disposal cannot be vetoed from a disposer); it guarantees the
 * unload is LOUD.
 */

import type { Context } from '../types/external.js'
import type { SecurityEvent } from '../types/index.js'
import { DEFAULT_PLATFORM_ID } from '../types/index.js'
import { buildHostMeta } from '../collectors/LocalNdjsonSink.js'
import { generateEventId } from '../utils/eventId.js'
import { nowMs } from '../utils/time.js'
import { currentGeneration, isReloadDetected, registerPluginInstance } from './pluginInstanceRegistry.js'

export interface PluginUnloadSentinelDeps {
  /** Local NDJSON sink — the tamper audit event is queued here. */
  eventCollector: { report(event: SecurityEvent): void }
  /** Warn sink for internal failures (invariant #3: log, never throw). */
  logger: { warn: (message: string, ...args: unknown[]) => void }
  /** Best-effort session identity for the audit event. */
  sessionResolve?: () => { sessionId: string; runId: string; agentId?: string } | undefined
  /** Cordis plugin short name recorded in audit_details. */
  pluginName?: string
  /** Watchdog probe interval in ms. Default 30_000. */
  probeIntervalMs?: number
  /** Clock override for tests. Defaults to `nowMs()`. */
  now?: () => number
  /**
   * Hook registrar for the process-exit graceful flag. Defaults to
   * `process.once('exit', fn)`. Injectable in tests so the exit path can
   * be driven without terminating the runner.
   */
  registerExitHook?: (fn: () => void) => void
  /**
   * Watchdog scheduler. Returns a cancel function. Defaults to an
   * unref'd `setInterval` / `clearInterval` pair; tests inject a manual
   * pump so no real timers are involved.
   */
  scheduleWatchdog?: (tick: () => void, ms: number) => () => void
  /**
   * Verdict scheduler for the deferred unload verdict. Returns a cancel
   * function. Defaults to an unref'd `setTimeout` — the timer MUST NOT
   * keep the host process alive, because a host that is exiting will
   * never reach the verdict (and must not emit a tamper row for its
   * own teardown). Tests inject a manual pump so no real timers are
   * involved.
   */
  scheduleVerdict?: (check: () => void, ms: number) => () => void
  /**
   * How often the deferred verdict re-checks whether the plugin came
   * back. Default 15_000 ms.
   */
  verdictPollIntervalMs?: number
  /**
   * Grace window for the deferred verdict. The tamper event is emitted
   * only if the plugin has NOT been re-installed this long after the
   * scope was disposed. Default 180_000 ms — the longest observed HMR
   * reload gap was 140 s, so the window covers it with margin.
   */
  verdictMaxWaitMs?: number
  /**
   * Optional debug-log sink (the `DebugLog` instance owned by
   * bootstrap). Used to record the suppressed-reload decision, which is
   * otherwise invisible: the tamper row is simply absent.
   */
  debug?: (phase: string, payload?: Record<string, unknown>) => void
}

export interface PluginUnloadSentinelState {
  scopeDisposed: boolean
  gracefulShutdown: boolean
  tamperEmitted: boolean
  probeActive: boolean
  /** A deferred verdict check is pending (scope disposed, grace window open). */
  verdictPending: boolean
  /** The verdict was resolved as "the plugin was reloaded", not removed. */
  reloadDetected: boolean
  /** The activation generation this instance registered under. */
  generation: number
}

export interface PluginUnloadSentinel {
  /** Set the graceful-shutdown flag (SIGTERM path / host-driven teardown). */
  markGracefulShutdown(): void
  /** Snapshot of the internal state machine (diagnostics / tests). */
  getState(): PluginUnloadSentinelState
  /**
   * Manually trigger the scope-dispose seam. Idempotent — the Cordis
   * effect disposer and this method share the same once-guarded path, so
   * double disposal (harness + manual) still yields at most one verdict
   * (and therefore at most one tamper event).
   */
  simulateScopeDispose(): void
}

const DEFAULT_PROBE_INTERVAL_MS = 30_000
const DEFAULT_PLUGIN_NAME = 'security-monitor'
/** How often the deferred verdict re-checks for a re-installed plugin. */
const DEFAULT_VERDICT_POLL_INTERVAL_MS = 15_000
/**
 * Grace window for the deferred verdict. Covers the longest observed
 * HMR reload gap (140 s in the 2026-10 real-data capture) with margin.
 */
const DEFAULT_VERDICT_MAX_WAIT_MS = 180_000

export function installPluginUnloadSentinel(
  ctx: Context,
  deps: PluginUnloadSentinelDeps,
): PluginUnloadSentinel {
  const pluginName = deps.pluginName ?? DEFAULT_PLUGIN_NAME
  const probeIntervalMs = deps.probeIntervalMs ?? DEFAULT_PROBE_INTERVAL_MS
  const verdictPollIntervalMs = deps.verdictPollIntervalMs ?? DEFAULT_VERDICT_POLL_INTERVAL_MS
  const verdictMaxWaitMs = deps.verdictMaxWaitMs ?? DEFAULT_VERDICT_MAX_WAIT_MS

  let probeActive = true
  let scopeDisposed = false
  let gracefulShutdown = false
  let tamperEmitted = false
  let verdictPending = false
  let reloadDetected = false
  let cancelVerdict: (() => void) | undefined
  /** Elapsed ms between the scope disposal and the confirmed verdict. */
  let lastVerdictWaitMs = 0

  /**
   * Register this activation in the process-level instance registry.
   *
   * The registry lives on `globalThis` so the counter survives the HMR
   * module re-import — a module-level counter would reset on reload and
   * every reload would look like a first-ever activation. The returned
   * generation is what the verdict compares against: if a NEWER
   * generation exists by verdict time, the plugin was RELOADED (it came
   * back), not removed.
   */
  const registration = registerPluginInstance(pluginName)
  const generation = registration.generation

  /**
   * Build the tamper audit event with defensive fallbacks
   * so a transient failure in any helper (session lookup, clock, env
   * metadata) does NOT cause the audit to be silently lost. Each field
   * is built inside its own try/catch; on failure the audit falls back
   * to the most permissive placeholder so the operator-visible audit
   * trail always records the unload, even if every helper misbehaves.
   */
  const buildTamperEvent = (
    detectionPoint: 'ctx.effect_dispose' | 'watchdog_liveness_probe',
  ): SecurityEvent => {
    const ts = (() => {
      try {
        return deps.now?.() ?? nowMs()
      } catch {
        return Date.now()
      }
    })()
    const session = (() => {
      try {
        return deps.sessionResolve?.()
      } catch {
        return undefined
      }
    })()
    const eventId = (() => {
      try {
        return generateEventId()
      } catch {
        // Deterministic fallback — never collides with real ids because
        // generateEventId() includes a CSPRNG sample that won't match
        // this constant.
        return `sentinel-fallback-${String(ts)}-${String(process.pid)}`
      }
    })()
    const hostMeta = (() => {
      try {
        return buildHostMeta()
      } catch {
        return {}
      }
    })()
    return {
      comm: DEFAULT_PLATFORM_ID,
      event_id: eventId,
      event_type: 'security_audit',
      layer: 'application',
      source_layer: 'application',
      ts,
      pid: process.pid,
      collection_method: 'agent_api',
      session_id: session?.sessionId ?? null,
      run_id: session?.runId ?? null,
      agent_id: session?.agentId ?? null,
      audit_category: 'policy',
      audit_action: 'tamper',
      severity: 'high',
      reason:
        `security plugin '${pluginName}' unloaded at runtime and NOT re-installed ` +
        `within ${String(lastVerdictWaitMs)} ms (${detectionPoint}); ` +
        `matches plugin-manager HMR disable path`,
      target: pluginName,
      outcome: 'failure',
      audit_details: {
        event_type_alias: 'plugin_runtime_unload',
        policy_id: 'self-unload-sentinel',
        rule_id: 'plugin-unload-sentinel',
        plugin_name: pluginName,
        detection_point: detectionPoint,
        // Computed, not hard-coded: whether a graceful-shutdown signal was
        // actually observed by the time the verdict fired. The old
        // hard-coded `false` was true for every single real-data row
        // regardless of how the process was actually going down.
        graceful_shutdown_expected: gracefulShutdown,
        // The host process was demonstrably alive at verdict time — the
        // verdict timer is unref'd, so it can only fire while the event
        // loop is still running. This is the fact the old hard-coded
        // `detail` asserted without evidence.
        host_process_alive: true,
        // No replacement instance registered during the grace window.
        reload_detected: false,
        // How long the sentinel waited before declaring the unload.
        verdict_wait_ms: lastVerdictWaitMs,
        verdict_max_wait_ms: verdictMaxWaitMs,
        detail:
          `plugin scope disposed and NOT re-installed within ${String(lastVerdictWaitMs)} ms ` +
          'while the host process kept running; consistent with a runtime ' +
          'cordis.patch.yml disabled:true toggle (plugin-manager HMR)',
      },
      ...hostMeta,
    }
  }

  const emitTamper = (detectionPoint: 'ctx.effect_dispose' | 'watchdog_liveness_probe'): void => {
    // Atomic once-guard. The once-guard `tamperEmitted`
    // is set synchronously on entry so a second caller inside the same
    // tick (scope-dispose + watchdog firing on the same flush) bails
    // before doing any work. JS is single-threaded so the check-then-set
    // pair is atomic by construction — there is no preemption point
    // between them. The audit-loss concern was that a synchronous
    // helper throw between the flag-set and the retry chain (event
    // construction failure, env-var lookup throw, …) used to drop the
    // audit entirely. `buildTamperEvent` (above) now wraps every field
    // in its own try/catch so a transient helper failure produces a
    // partial-but-valid event that still reaches the NDJSON sink. The
    // outer try/catch around the body preserves invariant #3
    // (never throw to host) — any escape is forwarded to the warn
    // logger instead of crashing the disposer.
    if (tamperEmitted) return
    tamperEmitted = true
    try {
      deps.logger.warn(
        `[SecurityMonitor] security_audit/policy_tamper: plugin '${pluginName}' was unloaded at runtime ` +
          `(${detectionPoint}) and was NOT re-installed within ${String(lastVerdictWaitMs)} ms while the host ` +
          `process kept running — this matches the plugin-manager HMR disable path. ` +
          `If this was not an authorized operator action, the safety rail has been silently removed.`,
      )
    } catch {
      // logger itself must not break the disposer (invariant #3)
    }
    try {
      const event = buildTamperEvent(detectionPoint)
      // bounded retry around the report path.
      // The previous single-shot emit could silently fail when the sink
      // is mid-tear-down (Cordis disposes effect handlers in reverse
      // registration order; the LocalNdjsonSink's flush timer / integrity
      // probe may already be cancelled by the time our disposer runs).
      // `report()` itself swallows errors internally — but if it
      // somehow throws (custom eventCollector that bypasses the public
      // surface), this retry closes the gap. 3 attempts (setImmediate
      // backoff between attempts) gives a mid-tear-down sink room to
      // finish draining without pegging CPU. Final failure falls through
      // to the warn logger (never throws).
      //
      // replaced the previous synchronous
      // `while (Date.now() < deadline)` busy-wait (3 × 50 ms of CPU spin
      // inside a Cordis effect disposer) with `setImmediate` between
      // attempts. setImmediate queues a microtask via the event loop —
      // it does NOT depend on the timer queue, so it survives dispose
      // even when `setTimeout` would be torn down.
      const maxAttempts = 3
      let attempt = 0
      let lastError: unknown
      const tryEmit = (): void => {
        if (attempt >= maxAttempts) {
          try {
            deps.logger.warn(
              `[SecurityMonitor] unload-sentinel tamper emit failed after ${String(maxAttempts)} attempts: ${String(lastError)}`,
            )
          } catch {
            // best-effort
          }
          return
        }
        try {
          deps.eventCollector.report(event)
        } catch (error: unknown) {
          lastError = error
          attempt += 1
          setImmediate(tryEmit)
        }
      }
      tryEmit()
    } catch (error: unknown) {
      try {
        deps.logger.warn(
          `[SecurityMonitor] unload-sentinel tamper emit failed: ${String(error)}`,
        )
      } catch {
        // best-effort
      }
    }
  }

  // --- Deferred verdict ----------------------------------------------------
  //
  // "The scope was disposed" is an OBSERVATION. "The plugin was removed"
  // is a VERDICT, and the verdict needs three more facts to hold:
  //
  //   1. the host process is still running — it is, by construction: the
  //      verdict timer is unref'd, so it can only fire while the event
  //      loop is alive. (This also means a host that is tearing down
  //      never reaches the verdict, so a natural exit produces NO row.)
  //   2. no graceful-shutdown signal was observed;
  //   3. no replacement instance of the plugin registered itself during
  //      the grace window (checked through the process-level instance
  //      registry — see `pluginInstanceRegistry`).
  //
  // Only when all three hold is the tamper event emitted. Facts 1 and 3
  // are precisely what the previous immediate-verdict implementation got
  // wrong on every one of the 29 real-data rows.

  /** Arm the next verdict check. Unref'd by default — never holds the host open. */
  const armVerdict = (check: () => void): void => {
    try {
      if (deps.scheduleVerdict) {
        cancelVerdict = deps.scheduleVerdict(check, verdictPollIntervalMs)
      } else {
        const timer = setTimeout(check, verdictPollIntervalMs)
        // The host must be able to exit while a verdict is pending —
        // that IS the "process is tearing down" case.
        timer.unref?.()
        cancelVerdict = () => clearTimeout(timer)
      }
    } catch (error: unknown) {
      try {
        deps.logger.warn(`[SecurityMonitor] unload-sentinel verdict scheduling failed: ${String(error)}`)
      } catch {
        /* best-effort */
      }
    }
  }

  const scheduleVerdict = (detectionPoint: 'ctx.effect_dispose' | 'watchdog_liveness_probe'): void => {
    if (verdictPending) return
    verdictPending = true
    // The grace window is counted in POLLS, not in wall-clock
    // milliseconds. A poll counter keeps the control flow independent of
    // the clock: an injected `now()` that throws (or a clock that jumps
    // backwards) can no longer make the verdict re-arm forever. The
    // clock is only used for the diagnostic `verdict_wait_ms`.
    const maxPolls = Math.max(1, Math.round(verdictMaxWaitMs / verdictPollIntervalMs))
    let pollsElapsed = 0

    const check = (): void => {
      pollsElapsed += 1
      // (2) A graceful shutdown observed at ANY point during the grace
      // window cancels the verdict outright.
      if (gracefulShutdown) {
        verdictPending = false
        cancelVerdict?.()
        cancelVerdict = undefined
        return
      }
      // (3) A newer instance registered → the plugin was RELOADED (HMR
      // dispose + re-instantiate), not removed. Suppress the tamper row.
      if (isReloadDetected(pluginName, generation)) {
        reloadDetected = true
        verdictPending = false
        cancelVerdict?.()
        cancelVerdict = undefined
        try {
          deps.debug?.('unload_sentinel_reload_detected', {
            plugin_name: pluginName,
            detection_point: detectionPoint,
            generation,
            current_generation: currentGeneration(pluginName),
            waited_ms: pollsElapsed * verdictPollIntervalMs,
          })
        } catch {
          /* best-effort */
        }
        return
      }
      // Still inside the grace window → keep waiting. A slow HMR reload
      // (the longest observed gap was 140 s) must not be mistaken for a
      // removal.
      if (pollsElapsed < maxPolls) {
        armVerdict(check)
        return
      }
      // Grace window elapsed with no replacement instance → confirmed
      // removal: the safety rail is gone while the host keeps running.
      verdictPending = false
      lastVerdictWaitMs = pollsElapsed * verdictPollIntervalMs
      emitTamper(detectionPoint)
    }

    armVerdict(check)
  }

  const handleScopeDispose = (): void => {
    if (scopeDisposed) return
    scopeDisposed = true
    if (gracefulShutdown) return
    scheduleVerdict('ctx.effect_dispose')
  }

  // --- Seam 1: scope-dispose disposer -------------------------------------
  //
  // Cordis disposes effects in reverse registration order, so the probe
  // (registered first) flips AFTER this main disposer runs — that ordering
  // is what lets the watchdog distinguish "disposed through the expected
  // path" from "probe torn down without the main disposer".
  try {
    ctx.effect(
      () => () => {
        probeActive = false
      },
      'security-monitor: unload-sentinel probe',
    )
  } catch (error: unknown) {
    try {
      deps.logger.warn(`[SecurityMonitor] unload-sentinel probe registration failed: ${String(error)}`)
    } catch {
      // best-effort
    }
  }
  try {
    ctx.effect(() => () => handleScopeDispose(), 'security-monitor: unload-sentinel')
  } catch (error: unknown) {
    try {
      deps.logger.warn(`[SecurityMonitor] unload-sentinel effect registration failed: ${String(error)}`)
    } catch {
      // best-effort
    }
  }

  // --- Seam 2: liveness watchdog ------------------------------------------
  let cancelWatchdog: (() => void) | undefined
  const watchdogTick = (): void => {
    if (probeActive) return
    // Probe deactivated → the plugin scope is being / has been torn down.
    // Self-clear so an HMR-unloaded plugin does not leak a running timer.
    cancelWatchdog?.()
    cancelWatchdog = undefined
    if (scopeDisposed || gracefulShutdown || tamperEmitted) return
    scheduleVerdict('watchdog_liveness_probe')
  }
  try {
    if (deps.scheduleWatchdog) {
      cancelWatchdog = deps.scheduleWatchdog(watchdogTick, probeIntervalMs)
    } else {
      const timer = setInterval(watchdogTick, probeIntervalMs)
      // Never keep the host process alive just for the probe.
      timer.unref?.()
      cancelWatchdog = () => clearInterval(timer)
    }
  } catch (error: unknown) {
    try {
      deps.logger.warn(`[SecurityMonitor] unload-sentinel watchdog start failed: ${String(error)}`)
    } catch {
      // best-effort
    }
  }

  // --- Graceful-shutdown flags --------------------------------------------
  try {
    ;(deps.registerExitHook ?? ((fn) => process.once('exit', fn)))(() => {
      gracefulShutdown = true
    })
  } catch (error: unknown) {
    try {
      deps.logger.warn(`[SecurityMonitor] unload-sentinel exit hook registration failed: ${String(error)}`)
    } catch {
      // best-effort
    }
  }

  return {
    markGracefulShutdown(): void {
      gracefulShutdown = true
      // A graceful shutdown cancels a pending verdict outright — the
      // host is going down on purpose, so there is nothing to report.
      if (verdictPending) {
        verdictPending = false
        cancelVerdict?.()
        cancelVerdict = undefined
      }
    },
    getState(): PluginUnloadSentinelState {
      return {
        scopeDisposed,
        gracefulShutdown,
        tamperEmitted,
        probeActive,
        verdictPending,
        reloadDetected,
        generation,
      }
    },
    simulateScopeDispose(): void {
      handleScopeDispose()
    },
  }
}
