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
 * Detection points (defense in depth, both emit exactly ONE tamper event):
 *
 *  1. **Scope-dispose seam** (`ctx.effect` disposer): Cordis disposes the
 *     plugin scope on HMR unload and runs every effect disposer. Our
 *     disposer fires while the process is still alive → emit
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
 *     false, the watchdog emits with `detection_point:
 *     'watchdog_liveness_probe'`. The interval is `unref`'d (never keeps
 *     the process alive) and self-clears on its first tick after probe
 *     deactivation.
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
}

export interface PluginUnloadSentinelState {
  scopeDisposed: boolean
  gracefulShutdown: boolean
  tamperEmitted: boolean
  probeActive: boolean
}

export interface PluginUnloadSentinel {
  /** Set the graceful-shutdown flag (SIGTERM path / host-driven teardown). */
  markGracefulShutdown(): void
  /** Snapshot of the internal state machine (diagnostics / tests). */
  getState(): PluginUnloadSentinelState
  /**
   * Manually trigger the scope-dispose seam. Idempotent — the Cordis
   * effect disposer and this method share the same once-guarded path, so
   * double disposal (harness + manual) still emits exactly one event.
   */
  simulateScopeDispose(): void
}

const DEFAULT_PROBE_INTERVAL_MS = 30_000
const DEFAULT_PLUGIN_NAME = 'security-monitor'

export function installPluginUnloadSentinel(
  ctx: Context,
  deps: PluginUnloadSentinelDeps,
): PluginUnloadSentinel {
  const pluginName = deps.pluginName ?? DEFAULT_PLUGIN_NAME
  const probeIntervalMs = deps.probeIntervalMs ?? DEFAULT_PROBE_INTERVAL_MS

  let probeActive = true
  let scopeDisposed = false
  let gracefulShutdown = false
  let tamperEmitted = false

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
      timestamp: ts,
      pid: process.pid,
      collection_method: 'agent_api',
      session_id: session?.sessionId ?? '__plugin__',
      run_id: session?.runId ?? '__plugin__',
      agent_id: session?.agentId ?? '__plugin__',
      audit_category: 'policy',
      audit_action: 'tamper',
      severity: 'high',
      summary:
        `security plugin '${pluginName}' unloaded at runtime (${detectionPoint}); ` +
        `matches plugin-manager HMR disable path`,
      target: pluginName,
      outcome: 'failure',
      reason: 'tamper',
      audit_details: {
        event_type_alias: 'plugin_runtime_unload',
        policy_id: 'self-unload-sentinel',
        plugin_name: pluginName,
        detection_point: detectionPoint,
        graceful_shutdown_expected: false,
        detail:
          'plugin scope disposed while the host process kept running and no ' +
          'graceful-shutdown signal was observed; consistent with a runtime ' +
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
          `(${detectionPoint}) while the process kept running — this matches the plugin-manager HMR disable path. ` +
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

  const handleScopeDispose = (): void => {
    if (scopeDisposed) return
    scopeDisposed = true
    if (gracefulShutdown) return
    emitTamper('ctx.effect_dispose')
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
    emitTamper('watchdog_liveness_probe')
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
    },
    getState(): PluginUnloadSentinelState {
      return { scopeDisposed, gracefulShutdown, tamperEmitted, probeActive }
    },
    simulateScopeDispose(): void {
      handleScopeDispose()
    },
  }
}
