/**
 * Plugin event-listener registrations.
 *
 * pulled out of src/index.ts so `apply ` stays a 5-call
 * orchestrator. The order of registrations matters — handlers are
 * processed in declaration order by Cordis, and the agent/created
 * dependency means session cache is warm by the time tools/pre-execute
 * fires. The previous block lived in the middle of apply() with no
 * visual cue to that ordering; this file is the canonical home for it.
 *
 * Handler matrix (invariant: never throw to host):
 *
 *   safeHandler — wrapped (8 handlers, all fall back to next() on err):
 *     - agent/created, agent/pre-step, tools/post-execute,
 *       tools/result, tools/execute, agent/turn-stopping, fs/observed
 *
 *   manual — preserve special semantics:
 *     - tools/pre-execute: deny + internal evaluateTool try/catch
 *     - fs/write-intent: re-throw so fs-observation-policy gets the err
 */
import type { Context } from './types/external.js'
import type { ApplicationCollector } from './collectors/ApplicationCollector.js'
import type { Config as ConfigShape } from './config.js'
import { safeHandler, type FailSafeAuditSink } from './utils/safeHandler.js'

export interface HandlerDeps {
  config: ConfigShape
  applicationCollector: ApplicationCollector
}

/**
 * Register every plugin event listener. Order matters — Cordis fires
 * listeners in registration order, and agent/created must be
 * live before any tool event can carry session context.
 */
export function registerHandlers(ctx: Context, deps: HandlerDeps): void {
  const { config, applicationCollector } = deps

  // Wrap ApplicationCollector's fail-safe audit
  // emitter as a sink for safeHandler. Every handler wrapped below
  // reports its swallowed exception as a `security_audit/fail_safe`
  // event so operators can spot sustained bursts of handler failures.
  // The sink is best-effort; see invokeAuditSink in safeHandler.ts.
  const failSafeSink: FailSafeAuditSink = (name, error) => {
    applicationCollector.emitFailSafeAudit(name, error)
  }

  // Marketplace no longer maintains a session-level system-layer binding.
  // Tool-stack correlation still works via ApplicationCollector's session
  // cache.

  safeHandler(ctx, 'agent/created', (payload) => {
    applicationCollector.runWithHttpContext(payload, () => applicationCollector.onAgentSessionStart(payload))
  }, failSafeSink)

  safeHandler(ctx, 'agent/pre-step', async (payload, _next) => {
    await applicationCollector.runWithHttpContext(payload, async () => applicationCollector.onAgentPreStep(payload))
    // helper falls through to the trailing `next` on error; on the
    // happy path the listener must return next() to chain.
    return _next()
  }, failSafeSink)

  // tools/pre-execute keeps manual try/catch: returns `{kind:'deny', reason}`
  // for enforce-mode blocks; swallows evaluateTool errors so a single
  // broken policy cannot wedge every tool call.
  ctx.on('tools/pre-execute', async (exec, next) => {
    return applicationCollector.runWithHttpContext(exec, async () => {
      let decision: Awaited<ReturnType<ApplicationCollector['evaluateTool']>>
      try {
        decision = await applicationCollector.evaluateTool(exec)
      } catch (error: unknown) {
        ctx.logger.warn(`[SecurityMonitor] intervention evaluation failed: ${String(error)}`)
        decision = undefined
      }

      if (decision?.decision === 'block' && config.mode === 'enforce') {
        applicationCollector.onToolPreExecute(exec, decision)
        const reason = decision.block_reason ?? decision.intervention?.block_reason ?? 'blocked by security policy'
        ctx.logger.warn(`[SecurityMonitor] blocked tool ${exec.name}: ${reason}`)
        // fix (invariant #5): denied tool calls never
        // reach `tools/post-execute`, so the post-execute cleanup branch
        // never fires — leaving `blockedCalls` / `pendingToolStarts` set
        // permanently. Clean them up here so long-running sessions do not
        // accumulate unbounded entries. The `onToolPreExecute` call
        // above already records the block in `blockedCalls` (line 635 of
        // ApplicationCollector); we remove + re-add the block_reason
        // marker below to keep the invariant: after deny-return the map
        // entries for this callId must be gone.
        const sessionContext = applicationCollector.resolveSessionContext(exec)
        sessionContext?.blockedCalls?.delete(exec.callId)
        sessionContext?.pendingToolStarts?.delete(exec.callId)
        return { kind: 'deny', reason }
      }

      try {
        applicationCollector.onToolPreExecute(exec, decision ?? undefined)
      } catch (error: unknown) {
        ctx.logger.warn(`[SecurityMonitor] tools/pre-execute failed: ${String(error)}`)
      }

      return next()
    })
  })

  safeHandler(ctx, 'tools/post-execute', async (exec, result, _next) => {
    await applicationCollector.runWithHttpContext(exec, () => applicationCollector.onToolPostExecute(exec, result))
    return _next()
  }, failSafeSink)

  safeHandler(ctx, 'tools/result', (exec, result) => {
    applicationCollector.runWithHttpContext(exec, () => applicationCollector.onToolResult(exec, result))
  }, failSafeSink)

  safeHandler(ctx, 'agent/turn-stopping', async (payload) => {
    await applicationCollector.runWithHttpContext(payload, () => applicationCollector.onAgentTurnStopping(payload))
  }, failSafeSink)

  // --- fs/* audit-only subscriptions ------------------------------------------
  //
  // fs/observed fires after every successful fs read/write/edit with an
  // authoritative FsObservation. We translate it to the platform-standard
  // `file_read` / `file_write` classes (intent absorbed → file_write).
  //
  // fs/write-intent is a SINGLE-SLOT Cordis waterfall already owned by
  // `fs-observation-policy` in the harness (it performs the version guard
  // that can upgrade `createIfAbsent` to `replaceIfVersion` to force a
  // conflict). We do NOT compete for the decision slot — we audit the
  // resolved payload AFTER calling next() and return it untouched so the
  // policy continues to function. SPL write blocking continues to flow
  // through tools/pre-execute (a separate decision point).
  safeHandler(ctx, 'fs/observed', (target, observation, actor) => {
    applicationCollector.onFsObserved(target, observation, actor)
  }, failSafeSink)

  // fs/write-intent must re-throw on error to surface the failure to the
  // fs-observation-policy waterfall owner; safeHandler swallows. Kept manual.
  ctx.on('fs/write-intent', async (target, actor, next) => {
    try {
      return await applicationCollector.onFsWriteIntent(target, actor, next)
    } catch (error: unknown) {
      ctx.logger.warn(`[SecurityMonitor] fs/write-intent failed: ${String(error)}`)
      throw error
    }
  })

  // --- llm/stream tee -----------------------------------------------------
  //
  // `llm/stream` is a waterfall returning AsyncIterable<StreamChunk>. The
  // listener MUST return the (wrapped) stream — safeHandler's error fallback
  // calls the trailing `next()` and returns its stream, so even a synchronous
  // listener failure degrades to the unwrapped downstream instead of breaking
  // generation. The tee inside ApplicationCollector swallows per-chunk detector
  // errors (invariant #3: never throw to the host).
  safeHandler(ctx, 'llm/stream', (options, _next) => {
    return applicationCollector.onLlmStream(options, _next())
  }, failSafeSink)
}