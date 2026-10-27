/**
 * Shared builder for inline-guard `block` SecurityDecisions.
 *
 * four inline guards each rolled
 * their own near-identical `buildInlineBlock()` / `buildXxxBlock()`
 * function — every site produced the same shape (`block` decision,
 * `mode: 'enforce'`, `appealable: false`, `fail_strategy:
 * 'inline_self_protection'`, `latency_ms: 0`) with only `policy_id`,
 * `policy_name`, `block_code`, and `block_reason` differing. Centralising
 * the construction here keeps the four guards byte-equivalent on every
 * shared field, so an audit consumer can rely on the invariant that an
 * `INLINE_*` block always carries the same shape.
 *
 * If a future inline guard needs a field outside this set (e.g. a
 * different `fail_strategy` or a non-zero `latency_ms`) it should NOT
 * call this helper — it should write its own builder. The four current
 * inline guards are intentionally identical on the shape, and that
 * sameness is the contract.
 */
import type { SecurityDecision } from '../../types/index.js'
import { toMarketplaceDecision } from './decisionVocabulary.js'

export interface InlineGuardIdentity {
  /** Wire-level `policy_id` (e.g. `'inline-env-passthrough-guard'`). */
  readonly policyId: string
  /** Human-readable policy name shown in audit consumers. */
  readonly policyName: string
  /** Wire-level `block_code` (e.g. `'INLINE_ENV_PASSTHROUGH_001'`). */
  readonly blockCode: string
}

export function buildInlineGuardDecision(
  identity: InlineGuardIdentity,
  reason: string,
): SecurityDecision {
  return {
    decision: 'block',
    // Inline safety net is always enforce — cannot be downgraded by
    // an operator editing the policy file or the patch YAML. Mirrors
    // the policy module's `inline_self_protection` fail_strategy.
    mode: 'enforce',
    block_reason: reason,
    block_code: identity.blockCode,
    appealable: false,
    fail_strategy: 'inline_self_protection',
    latency_ms: 0,
    policy_id: identity.policyId,
    policy_name: identity.policyName,
    intervention: {
      decision: toMarketplaceDecision('block'),
      decision_internal: 'block',
      mode: 'enforce',
      // The verdict stands regardless of the runtime mode: an inline
      // safety net is not a policy rule, so `intervention.mode:
      // 'audit'` does not soften it. The marker lets a consumer
      // reading `policy_evaluation.mode` (the runtime posture) tell
      // "denied in audit mode, by design" apart from a mislabelled
      // row.
      mode_independent: true,
      policy_id: identity.policyId,
      policy_name: identity.policyName,
      block_reason: reason,
      block_code: identity.blockCode,
      appealable: false,
      fail_strategy: 'inline_self_protection',
    },
  }
}