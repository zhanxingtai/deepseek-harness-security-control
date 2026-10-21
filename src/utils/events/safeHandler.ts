/**
 * safeHandler — wrap a Cordis listener with try/catch so a handler bug
 * can never crash the host (invariant: never throw to the host).
 *
 * Behavior on error:
 *   1. ctx.logger.warn(`[SecurityMonitor] <event-name> failed: <err>`)
 *   2. If the listener received a trailing `next` callback (Cordis's
 *      convention for chainable events: `agent/pre-step`,
 *      `tools/execute`, `tools/post-execute`), fall through to it so
 *      the agent pipeline continues — equivalent to the chain-handler
 *      contract `try { ... } catch { warn } ; return next()`.
 *   3. If an `auditSink` is provided, emit a
 *      `security_audit/fail_safe` event so operators can see how often
 *      the safety net fires. The sink is invoked AFTER the warn (the
 *      log line is preserved for back-compat) and AFTER any `next()`
 *      fall-through so a sink crash cannot break the chain.
 *
 * Two listeners are intentionally NOT routed through safeHandler:
 *   - `tools/pre-execute`: returns `{ kind: 'deny', reason }` from
 *     inside an internal try/catch around `evaluateTool`; the helper
 *     would intercept that error and bypass the deny path.
 *   - `fs/write-intent`: re-throws on error to let Cordis surface the
 *     failure to the policy owner (single-slot waterfall); swallowing
 *     would silently break the fs-observation-policy version guard.
 *
 * Both stay manual in `src/index.ts`; this helper exists for the 8
 * listeners that only need `try / warn / next`.
 */
import type { Context, EventListener, Events } from '../../types/external.js'

/**
 * Sink contract for the fail-safe observability hook.
 *
 * Receives the wrapped Cordis event name (e.g. `'agent/pre-step'`)
 * and the raw caught error. Implementations should be best-effort
 * and never throw — the safety net itself must not become a fault
 * source. `ApplicationCollector.emitFailSafeAudit` is the canonical
 * implementation; tests pass a recording stub.
 */
export type FailSafeAuditSink = (handlerName: string, error: unknown) => void

export function safeHandler<K extends keyof Events>(
  ctx: Context,
  name: K,
  listener: EventListener<K>,
  auditSink?: FailSafeAuditSink,
): void {
  ctx.on(name, ((...args: unknown[]) => {
    // track whether the trailing `next` callback
    // (Cordis chainable events: agent/pre-step / tools/execute /
    // tools/post-execute) was already invoked by the listener. The
    // pre-fix code re-invoked `next` from the safety-net catch path
    // even when the listener had already called it, doubling chain
    // continuation (e.g. double tool-result delivery / double
    // post-step side-effects on downstream listener throws).
    let nextCalled = false
    let listenerArgs = args
    const lastIdx = args.length - 1
    if (typeof args[lastIdx] === 'function') {
      const origNext = args[lastIdx] as (...a: unknown[]) => unknown
      listenerArgs = args.slice(0, -1).concat([
        ((...nextArgs: unknown[]) => {
          if (nextCalled) return undefined
          nextCalled = true
          return origNext(...nextArgs)
        }) as unknown,
      ])
    }
    try {
      const result = (listener as (...a: unknown[]) => unknown)(...listenerArgs)
      if (isPromiseLike(result)) {
        return Promise.resolve(result).catch((error: unknown) => {
          ctx.logger.warn(`[SecurityMonitor] ${String(name)} failed: ${String(error)}`)
          invokeAuditSink(auditSink, name, error)
          if (nextCalled) return undefined
          nextCalled = true
          return fallbackToNext(args)
        })
      }
      return result
    } catch (error: unknown) {
      ctx.logger.warn(`[SecurityMonitor] ${String(name)} failed: ${String(error)}`)
      invokeAuditSink(auditSink, name, error)
      if (nextCalled) return undefined
      nextCalled = true
      return fallbackToNext(args)
    }
  }) as EventListener<K>)
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    !!value &&
    (typeof value === 'object' || typeof value === 'function') &&
    typeof (value as { then?: unknown }).then === 'function'
  )
}

/**
 * Cordis chain events pass their `next` callback as the last positional
 * argument (e.g. `agent/pre-step` = `(payload, next) => next()`).
 * If the listener threw before invoking `next`, calling it here lets
 * the agent pipeline continue — same semantics as a hand-written
 * `try/catch ; return next()` block.
 *
 * For listeners without a `next` (sync events like `agent/created`
 * or `tools/result`), returns undefined. Errors thrown by `next()` are
 * swallowed — at that point the host is already past the listener and
 * a secondary failure should not cascade.
 */
function fallbackToNext(args: unknown[]): unknown {
  const last = args[args.length - 1]
  if (typeof last === 'function') {
    try {
      return (last as () => unknown)()
    } catch {
      return undefined
    }
  }
  return undefined
}

/**
 * Defensive sink invocation: a buggy audit sink must not turn the
 * safety net into a fault source. Per invariant #3 the entire
 * safeHandler path is best-effort; we wrap the sink call in its
 * own try/catch and silently swallow any throw, since the warn
 * line above is already the authoritative observability record.
 */
function invokeAuditSink(
  sink: FailSafeAuditSink | undefined,
  name: keyof Events,
  error: unknown,
): void {
  if (!sink) return
  try {
    sink(String(name), error)
  } catch {
    // sink failures are silent — the warn is the authoritative record
  }
}
