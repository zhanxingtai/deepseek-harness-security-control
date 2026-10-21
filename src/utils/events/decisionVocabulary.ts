/**
 * SPL → marketplace vocabulary translator.
 *
 * SPL (Security Policy Language) internally models 10 distinct decisions
 * (`allow`, `warn`, `guide`, `context_adjust`, `modify`, `substitute`,
 * `escalate`, `degrade`, `block`, `approve`). The marketplace wire format
 * only exposes 3 actions — `allow`, `deny`, `ask` — and downstream
 * consumers (the DSH Workshop, audit dashboards, session-log event
 * consumers) key off this 3-action vocabulary.
 *
 * This module is the boundary between SPL semantics and the wire format.
 * The translator is a **lossy** projection: every non-`allow` decision
 * collapses to either `deny` (block-equivalent) or `ask` (operator
 * review / interactive approval). The original SPL decision is preserved
 * on `decision_internal` so audit consumers can still see what the
 * policy actually said, but the `decision` field carries the
 * marketplace-conformant value.
 *
 * Mapping rationale:
 *   - `allow`  → `allow`  — no transformation
 *   - `block`  → `deny`   — block is the SPL term for marketplace `deny`
 *   - `approve`→ `ask`    — SPL approve maps to marketplace ask
 * `ask` → `ask` — direct pass-through ( inbound translator)
 *   - `warn`/`guide`/`context_adjust`/`modify`/`substitute`/`escalate`/
 *     `degrade` → `ask`  — advisory decisions that need operator attention
 *
 * See: the decision-vocabulary spec §3 (advisory markers).
 */

/**
 * SPL internal 6-action decision vocabulary.
 *
 * this was 10 values. SPL v2 spec §5.1 narrows to 6:
 * `block` / `warn` / `allow` / `audit` / `modify` / `escalate`. The
 * deprecated v1 values (`guide` / `context_adjust` / `substitute` /
 * `degrade` / `approve`) are rejected by `RuleLoader.compilePolicy`
 * before they can reach the marketplace projection here.
 */
export type SplDecision =
  | 'allow'
  | 'warn'
  | 'audit'
  | 'modify'
  | 'escalate'
  | 'block'

/** Marketplace wire-format 3-action vocabulary. */
export type MarketplaceDecision = 'allow' | 'deny' | 'ask'

const DECISION_MAP: Record<SplDecision, MarketplaceDecision> = {
  allow: 'allow',
  warn: 'ask',
  audit: 'allow',
  modify: 'ask',
  escalate: 'ask',
  block: 'deny',
}

/**
 * Translate an SPL internal decision into the marketplace 3-action
 * vocabulary. Lossy: the original SPL value is preserved on
 * `decision_internal` for audit consumers.
 */
export function toMarketplaceDecision(spl: SplDecision | string): MarketplaceDecision {
  if (spl === 'allow' || spl === 'deny' || spl === 'ask') {
    // Already marketplace vocabulary (e.g. a marketplace-friendly YAML
    // rule that bypassed the SPL normalization). Pass through.
    return spl
  }
  const mapped = DECISION_MAP[spl as SplDecision]
  if (!mapped) {
    // Unknown decision — fail safe to `ask` so the operator sees it
    // (rather than silently dropping to allow).
    return 'ask'
  }
  return mapped
}