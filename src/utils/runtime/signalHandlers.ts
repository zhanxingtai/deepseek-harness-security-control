/**
 * Signal handlers (trimmed) — protect
 * the plugin from accidental process kill via SIGHUP / SIGINT / SIGTERM.
 *
 * Default Node.js behaviour: terminate on these signals. For the dsh engine,
 * termination has two costs:
 *  1. The audit log is cut short (events buffered in LocalNdjsonSink may not
 *     reach the NDJSON sink).
 *  2. If the process is restarted by an operator / supervisor, the restart
 *     may not carry `--patch security-monitor.patch.yml` — the very scenario
 *     SELF_PROTECTION_RESTART_WITHOUT_PATCH_015 / K 层 are designed to defend against.
 *
 * Therefore:
 *  - SIGHUP: log a warning and IGNORE. Operators sometimes use `kill -HUP`
 *    to "reload" daemons; for the plugin this is meaningless and dangerous.
 *  - SIGINT: same as SIGHUP. Ctrl-C in a terminal should not silently
 *    disable the plugin.
 *  - SIGTERM: trigger a graceful shutdown via the same collector.shutdown
 *    path the harness effect cleanup uses, then exit.
 *  - SIGKILL: cannot be intercepted; left to default behaviour.
 *
 * trimmed from 6 args to 4 args. The marketplace plugin no
 * longer has SystemCollector / AssetCollector (those were platform-deployment
 * backstops; the marketplace uses ApplicationCollector + NetworkHttpCollector
 * + RuntimeHook for everything).
 *
 * The function returns `true` when handlers were installed (signal handlers
 * are only available on POSIX; Windows lacks reliable SIGHUP / SIGTERM
 * dispatch to Node — `process.on('SIGTERM', ...)` is silently ignored on
 * Windows and is no-op here).
 */

import type { Context } from '../../types/external.js'
import { LocalNdjsonSink } from '../../collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../../collectors/ApplicationCollector.js'
import { InterventionEngine } from '../../intervention/InterventionEngine.js'

export function installSignalHandlers(
  ctx: Context,
  localNdjsonSink: LocalNdjsonSink,
  applicationCollector: ApplicationCollector,
  interventionEngine: InterventionEngine,
  // set the unload-sentinel's graceful-shutdown
  // flag BEFORE the drain window opens, so a scope disposal racing the
  // SIGTERM graceful path is not misclassified as an HMR disable.
  onGracefulShutdownBegin?: () => void,
): boolean {
  // Windows: signal events are not delivered to Node in the way POSIX
  // requires. The handlers would silently no-op; just bail out so the caller
  // can log a "not supported on this platform" message if it wants.
  if (process.platform === 'win32') {
    return false
  }

  let shuttingDown = false
  const triggerGracefulShutdown = (signal: NodeJS.Signals, source: 'signal' | 'manual') => {
    if (shuttingDown) return
    shuttingDown = true
    try {
      try {
        onGracefulShutdownBegin?.()
      } catch (e) {
        ctx.logger.warn(`[SecurityMonitor] graceful-shutdown callback: ${String(e)}`)
      }
      ctx.logger.warn(
        `[SecurityMonitor] received ${signal} (${source}); running graceful shutdown`,
      )
      // Mirror the effect cleanup ordering (see ctx.effect in src/index.ts):
      // application → intervention → eventCollector.
      try {
        applicationCollector.shutdown()
      } catch (e) {
        ctx.logger.warn(`[SecurityMonitor] app shutdown: ${String(e)}`)
      }
      try {
        interventionEngine.shutdown()
      } catch (e) {
        ctx.logger.warn(`[SecurityMonitor] intervention shutdown: ${String(e)}`)
      }
      try {
        localNdjsonSink.shutdown()
      } catch (e) {
        ctx.logger.warn(`[SecurityMonitor] localNdjsonSink shutdown: ${String(e)}`)
      }
    } finally {
      // Give the async drain a short window, then exit. A real SIGTERM is
      // typically followed by SIGKILL if the process doesn't exit promptly,
      // so don't sleep too long.
      setTimeout(() => {
        process.exit(0)
      }, 500).unref()
    }
  }

  // SIGHUP and SIGINT: warn and ignore. Returning `false` from the handler
  // doesn't stop the default action (Node exits on SIGHUP by default), but
  // installing a handler AT ALL prevents the default — Node only runs the
  // default when no handler is registered.
  process.on('SIGHUP', () => {
    ctx.logger.warn('[SecurityMonitor] received SIGHUP — ignored (use SIGTERM to gracefully shut down)')
  })

  process.on('SIGINT', () => {
    ctx.logger.warn('[SecurityMonitor] received SIGINT (Ctrl-C) — ignored (use SIGTERM to gracefully shut down)')
  })

  process.on('SIGTERM', () => {
    triggerGracefulShutdown('SIGTERM', 'signal')
  })

  return true
}