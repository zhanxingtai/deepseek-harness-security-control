/**
 * Inline-guard chain helper.
 *
 * The four hardcoded inline guards (InlinePromptInjection,
 * SensitivePathGuard, EnvPassthroughGuard, InlineSelfProtection) are
 * evaluated in a fixed order BEFORE the SPL pipeline. Both
 * `ApplicationCollector.evaluateTool` (tool-layer seam) and
 * `RuntimeHook.runInlineGuards` (pre-spawn seam) repeated the same
 * sequence with the same defensive `if (decision) return decision`
 * short-circuit pattern. Each site also had its own "is the guard
 * available + enabled" precondition, with subtle differences between
 * the two sites (collector = unconditional, runtime-hook = guard
 * presence + enabled flag).
 *
 * This helper centralises the loop:
 *
 *   1. Iterate `steps` in declaration order.
 *   2. A step whose `enabled()` predicate returns false (or whose
 *      `evaluate` itself returns null) is skipped — the chain continues.
 *   3. The first step whose `evaluate` returns a non-null
 *      `SecurityDecision` short-circuits the chain; that decision is
 *      returned to the caller.
 *   4. If every step is exhausted without a decision, the chain returns
 *      `undefined` so the caller falls through to its SPL evaluation.
 *
 * The helper is synchronous and never throws — a defensive `try/catch`
 * wraps each step so a misbehaving guard cannot break the chain
 * (invariant #3: never throw to the host). The catch path calls the
 * optional `onError` callback (if supplied) so each consumer can
 * route the error to its own audit sink without coupling the helper
 * to a logger or to the LocalNdjsonSink surface.
 *
 * **Two consumers, two shapes**:
 *  - `ApplicationCollector.evaluateTool` builds a chain where each
 *    step's `evaluate` is unconditional (the collector's guards are
 *    always wired up after the bootstrap assembly).
 *  - `RuntimeHook.runInlineGuards` builds a chain where each step
 *    first gates on `deps.<guard> && deps.<guard>.enabled`. The
 *    helper supports both via the `enabled` predicate.
 *
 * The helper preserves the on-call cost of the previous direct
 * `evaluate…(ctx, cfg)` calls (one extra method dispatch per step,
 * trivially bounded — there are 4 steps today).
 */
import type { InterventionContext, SecurityDecision } from '../types/index.js'

export interface InlineGuardStep {
  /**
   * Predicate that returns true when this step should run. Pass
   * `undefined` to always run (the default for tool-layer sites).
   * The runtime-hook site uses this to skip a guard when the
   * dependency was not injected (e.g. legacy unit-test contexts).
   */
  readonly enabled?: () => boolean
  /**
   * Diagnostic label — included in the warn line when a step's
   * `evaluate` throws (invariant #3: log + swallow).
   */
  readonly label: string
  /**
   * The actual guard evaluator. Returns a `block` SecurityDecision on
   * hit, or `null` when the guard declines to fire.
   */
  readonly evaluate: (ctx: InterventionContext) => SecurityDecision | null
}

/**
 * Optional sink for step errors. Receives the step label and the raw
 * caught error. Implementations should be best-effort and never throw —
 * the safety net itself must not become a fault source. Both consumers
 * (`ApplicationCollector`, `RuntimeHook`) thread their own warn+audit
 * helper so the inline-guard error is recorded once and the SPL
 * fallback remains the catch-all.
 */
export type InlineGuardErrorSink = (label: string, error: unknown) => void

export function runInlineGuardChain(
  ctx: InterventionContext,
  steps: readonly InlineGuardStep[],
  onError?: InlineGuardErrorSink,
): SecurityDecision | undefined {
  for (const step of steps) {
    try {
      if (step.enabled && !step.enabled()) continue
      const decision = step.evaluate(ctx)
      if (decision) return decision
    } catch (error: unknown) {
      // Invariant — a misbehaving guard cannot break the chain.
      // Route the error to the consumer's sink (warn + audit) so the
      // failure is observable but does not block the SPL fallback.
      if (onError) {
        try {
          onError(step.label, error)
        } catch {
          // sink failures are silent — invariant #3
        }
      }
    }
  }
  return undefined
}
