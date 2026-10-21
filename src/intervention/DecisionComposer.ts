import type {
  DegradeDetail,
  EscalateDetail,
  Guidance,
  Intervention,
  Mode,
  RiskAssessment,
  SecurityDecision,
} from '../types/index.js'
import type {
  ActionClause,
  CompiledRule,
  EvaluateClause,
  GuidanceClause,
  InternalDecision,
  InterventionLogger,
  ModifyAction,
} from './InterventionEngine.js'
import { toMarketplaceDecision } from '../utils/decisionVocabulary.js'

/**
 * Dedup set for the SPL v2 aggregate-input WARN.
 * Aggregation is invoked per `composeDecision` call; without dedup a hot
 * path would flood the host log on every tool call. Dedup is per rule id
 * (the head matched rule) for one WARN per rule per process lifetime —
 * the file:line fallback covers the rare case of a compiled rule without
 * a stable id, where `<no-id>` collapses all such rules to a single WARN.
 */
const aggregateInputEmptyWarnedKeys = new Set<string>()

/**
 * silent no-op fallback for the WARN channel. The production
 * path always injects a real logger (`InterventionEngine` passes its
 * `this.log`). In unit tests where `composeDecision` is called without
 * a logger, we intentionally route to a no-op rather than `console` —
 * the WARN is meant for operators, not for polluting test stderr.
 */
const SILENT_LOGGER: InterventionLogger = {
  warn: () => {},
}

/** Test-only: reset the dedup state so each `it()` starts clean. */
export function _resetAggregateInputEmptyWarnDedupForTests(): void {
  aggregateInputEmptyWarnedKeys.clear()
}

/**
 * Numeric weight per SPL `evaluate.risk_level`. Summed across ALL matched
 * rules into `risk_assessment.risk_score`, so the scale is deliberately
 * super-additive at the top: one `critical` (100) alone outweighs the
 * default aggregation threshold, while it takes two `medium` hits (80) or
 * four `low` hits (60) to reach it. Rules with no `evaluate.risk_level`
 * contribute 0.
 */
export const RISK_LEVEL_SCORES: Record<NonNullable<EvaluateClause['risk_level']>, number> = {
  critical: 100,
  high: 75,
  medium: 40,
  low: 15,
}

/** Aggregate score at/above which accumulated medium hits may promote. */
export const DEFAULT_MEDIUM_AGGREGATION_THRESHOLD = 60
/** How many `medium` rules must fire together before promotion is considered. */
export const DEFAULT_MEDIUM_AGGREGATION_COUNT = 2

/** Tuning knobs for multi-rule aggregation. */
export interface ComposeOptions {
  /** Risk score threshold (0-100+) above which medium hits promote to block/escalate. Default 60. */
  mediumAggregationThreshold?: number
  /** How many medium hits must accumulate to trigger promotion. Default 2. */
  mediumAggregationCount?: number
}

/**
 * Compose a final decision from all matched rules.
 *
 * Strategy:
 * - Matched rules arrive priority-descending — `RuleLoader.compilePolicy`
 *   sorts at compile time — so `matched[0]` is the top-priority rule and its
 *   action clause is the BASE verdict.
 * - The FULL matched set is then walked to build an aggregate
 *   `risk_assessment`: summed `risk_score` from every rule's
 *   `evaluate.risk_level`, per-level `dimensions`, `matched_policies[]`
 *   (rule names) and `evaluation_path[]` (rule ids, in evaluation order).
 * - Multi-medium promotion: when enough `medium` rules fire together AND
 *   their aggregate score crosses the threshold, an `allow` base verdict is
 *   raised to `escalate`. `block` / `escalate` are never downgraded.
 *
 * ─── Decision-to-host mapping ────────────
 * The Cordis `tools/pre-execute` contract expresses a single outcome:
 * `deny`. The engine emits a wider decision vocabulary, so the mapping is:
 * `block` becomes `{ kind: 'deny', reason }` in `enforce` mode; every other
 * decision travels on the emitted event as a recommendation for downstream
 * consumers rather than as an outcome the host can act on directly.
 *
 * `modify` / `substitute` carry the proposed change inline (via
 * `modified_params` / `substituted_tool_name`). The plugin marks them
 * `advisory: true` so audit
 * consumers know the change is a recommendation, not an enforced
 * outcome. The caller — typically the platform / HITL workflow —
 * is expected to read the event and apply the modification
 * manually if desired.
 * ──────────────────────────────────────────────────────────────────────
 */

/**
 * Single source of truth for the
 * self-protection rule predicate. Used by the override seam
 * (composeDecision) and reusable by audit consumers that want to
 * classify rules the same way the engine does. Backed by both the
 * top-level `category: self_protection` (spec §7.2 — the canonical
 * identifier current) and the legacy `id` prefix (covers the 42
 * `self-protection-rule` rules shipped today, until category coverage
 * reaches 100% under).
 */
export function isSelfProtectionRule(rule: CompiledRule): boolean {
  return rule.category === 'self_protection' || rule.id.startsWith('self-protection-')
}

export function composeDecision(
  matched: CompiledRule[],
  mode: Mode,
  failStrategy: 'fail_open' | 'fail_closed' | 'fail_open_high_risk_only',
  options?: ComposeOptions,
  logger?: InterventionLogger,
): SecurityDecision {
  if (matched.length === 0) {
    /**
     * No rule matched: allow with NO risk assessment attached. Deliberately
     * not an empty `{}` — `ApplicationCollector` copies `risk_signal` onto
     * every emitted event (`if (decision.risk_signal)`), and the no-match
     * path is the hot path for ordinary tool calls; stamping a zero-valued
     * assessment there would add a no-information field to the majority of
     * records in the NDJSON stream. Nothing to aggregate, nothing to
     * promote.
     */
    return {
      decision: 'allow',
      mode,
      fail_strategy: failStrategy,
      latency_ms: 0,
    }
  }

  const head = matched[0]

  /**
   * Self-protection override seam.
   *
   * SPL v2 spec §9.2 forbids a local allow/warn rule from suppressing a
   * self-protection rule (otherwise the local exemption channel becomes a
   * legitimate plugin-disabling channel). Multi-file merge
   * (`src/intervention/RuleLoader.ts:683-725`) is a stable priority sort —
   * without this seam, an operator who writes a high-priority local
   * `allow` rule can outrank the priority=1200 self-protection block
   * rules and disable plugin enforcement entirely.
   *
   * Arbitration rule (matches the §9.2 contract, narrow scope):
   *   - If any `self_protection` rule is in `matched` AND
   *     `head` is a non-self_protection allow/warn AND
   *     `head.priority` >= the highest self_protection rule's priority
   *       (which is always the case when head would otherwise win
   *        because matched is already priority-sorted),
   *   - Then the highest-priority self_protection rule wins instead of
   *     head. `overridden_rule_id` records the suppressed head rule so
   *     operators can grep `policy_id` + `self_protection_override: true`
   *     on Recent Blocks to see override attempts.
   *
   * Self-protection allow rules are also protected — the spec protects
   * the entire category, not just block/warn.
   *
   * The trace fields ride the same seam as `severity_downgraded` /
   * `severity_rule_id`, keeping audit consumers on one
   * trace pattern.
   */
  const headIsSelfProtection = isSelfProtectionRule(head)
  const selfProtRule = headIsSelfProtection ? null : matched.find(isSelfProtectionRule)
  const headWouldSuppress =
    selfProtRule !== undefined &&
    (head.action?.decision === 'allow' || head.action?.decision === 'warn')
  const rule = selfProtRule ?? head
  const overridden_rule_id =
    selfProtRule && headWouldSuppress ? head.id : undefined
  const self_protection_override = overridden_rule_id !== undefined ? true : undefined

  const action = rule.action ?? { decision: 'allow' }

  /**
   * severity-based block→warn downgrade.
   * `critical`/`high` keep `block`; `medium`/`low` downgrade to `warn`.
   * Self-protection rules (top-level `category: self_protection` OR id
   * prefix `self-protection-`) bypass the downgrade — meta-rule: the
   * plugin's own protection is never weakened by operator severity
   * config. Non-block decisions (`modify`, `substitute`, `escalate`,
   * `allow`) are never downgraded — severity only acts on `block`
   * decisions. Absence of severity falls through to the legacy behavior
   * (block stays block) for back-compat with operator policies that
   * haven't migrated yet.
   *
   * Full matrix (category × severity × action.decision → engine final)
   * is documented in `docs/severity-decision-matrix.md` §2. This
   * block is the only `block → warn` downgrade path; nothing else
   * demotes a matched rule's action.
   */
  const isSelfProtection = isSelfProtectionRule(rule)
  const shouldDowngrade =
    !isSelfProtection &&
    action.decision === 'block' &&
    (rule.severity === 'medium' || rule.severity === 'low')
  const downgradedAction = shouldDowngrade
    ? { ...action, decision: 'warn' as InternalDecision }
    : action

  const guidance = downgradedAction.guidance ? toGuidance(downgradedAction.guidance) : undefined
  /**
   * `modify` is advisory-only — the harness contract does not honor it today;
   * the plugin emits the proposed change on the event so an external consumer
   * can apply it. Multi-medium promotion never promotes INTO nor OUT OF this
   * decision, so this flag keeps its advisory-only semantics.
   *
   * `substitute` is not part of the SPL v2 decision enum, so only `modify`
   * can carry the advisory flag here.
   */
  const advisory = downgradedAction.decision === 'modify'

  const aggregate = aggregateMatched(matched, options)
  /**
   * SPL v2 aggregate-input visibility WARN.
   * The bundled policy no longer feeds `evaluate.risk_level`, so
   * `aggregate.riskScore` is 0 whenever no matched rule carries the
   * legacy field and no severity-driven aggregate fallback exists yet.
   * Until the standards v2.1 verdict on which field feeds the
   * aggregate, fire a one-time operator-visible WARN
   * so the silent regression is observable. Dedup is per rule id so a
   * hot path with N matched rule ids yields at most N WARNs per
   * process lifetime; `host.logger.warn` is the channel (not stderr,
   * not the NDJSON audit sink) so the marketplace audit stream stays
   * clean. When `logger` is omitted (unit-test entry points), fall
   * back to a no-op so test stderr stays clean — production always
   * injects a logger via the engine.
   */
  if (matched.length > 0 && aggregate.riskScore === 0) {
    const headId = matched[0].id
    const dedupKey = headId && headId.length > 0 ? headId : '<no-id>'
    if (!aggregateInputEmptyWarnedKeys.has(dedupKey)) {
      aggregateInputEmptyWarnedKeys.add(dedupKey)
      const warnTarget: InterventionLogger = logger ?? SILENT_LOGGER
      warnTarget.warn(
        `[SPL v2] rule "${dedupKey}": riskScore aggregate unavailable (no evaluate.risk_level + no severity-driven aggregate fallback); promotion disabled; aggregate input is empty`,
      )
    }
  }
  const promotion = resolvePromotion(downgradedAction.decision, aggregate)
  const decision = promotion?.decision ?? downgradedAction.decision
  // When the final verdict is `modify`, merge the modify payloads from ALL
  // matched modify rules in priority order. Later rules override earlier
  // ones for map-valued fields; list-valued fields are unioned so no
  // redaction is silently dropped.
  const mergedModify = decision === 'modify' ? mergeModifyActions(matched) : undefined
  const riskAssessment = buildRiskAssessment(rule.evaluate, downgradedAction, aggregate, promotion)
  const reason = buildReason(rule, downgradedAction, aggregate, promotion)

  const intervention: Intervention = {
    // Wire-level decision is the marketplace 3-action projection; the SPL
    // internal 10-action decision is preserved on `decision_internal` for
    // audit consumers.
    decision: toMarketplaceDecision(decision),
    decision_internal: decision,
    mode,
    policy_id: rule.id,
    policy_name: rule.name,
    block_reason: downgradedAction.blockReason,
    block_code: downgradedAction.blockCode,
    appealable: downgradedAction.appealable ?? false,
    reason,
    fail_strategy: failStrategy,
    // trace fields — propagate the rule's severity to the
    // audit row so downstream consumers can see "this was a medium rule
    // that got downgraded" vs "this was a critical rule that stayed
    // block". `severity_downgraded` is true ONLY when this seam
    // actually flipped block→warn; `severity_rule_id` names the rule
    // that drove the downgrade (matching how `policy_id` works).
    severity: rule.severity,
    severity_downgraded: shouldDowngrade || undefined,
    severity_rule_id: shouldDowngrade ? rule.id : undefined,
    // self-protection override trace. Only emitted when
    // a non-self_protection local allow/warn was suppressed by a
    // self_protection rule per the §9.2 arbitration contract.
    self_protection_override,
    overridden_rule_id,
    ...(advisory ? { advisory: true } : {}),
    ...(mergedModify ? { modify: mergedModify, modified_params: mergedModify.setFields } : {}),
    ...(downgradedAction.escalate ? { escalate: { ...downgradedAction.escalate } } : {}),
    ...(downgradedAction.degrade ? { degrade: { ...downgradedAction.degrade, removed_tools: downgradedAction.degrade.removed_tools ? [...downgradedAction.degrade.removed_tools] : undefined } } : {}),
    ...(guidance ? { guidance } : {}),
    ...(riskAssessment ? { risk_assessment: riskAssessment } : {}),
  }

  return {
    decision,
    mode,
    policy_id: rule.id,
    policy_name: rule.name,
    policy_version: undefined,
    block_reason: downgradedAction.blockReason,
    block_code: downgradedAction.blockCode,
    appealable: downgradedAction.appealable ?? false,
    reason,
    fail_strategy: failStrategy,
    latency_ms: 0,
    risk_signal: riskAssessment,
    // trace fields on the top-level SecurityDecision too, so
    // the `Decision` shape that callers already see carries the same
    // downgrade signal without forcing them to dig into `intervention`.
    severity: rule.severity,
    severity_downgraded: shouldDowngrade || undefined,
    severity_rule_id: shouldDowngrade ? rule.id : undefined,
    // same trace on the top-level shape so the audit row
    // (RuntimeHook) can surface `self_protection_override: true` without
    // re-deriving the arbitration from `intervention`.
    self_protection_override,
    overridden_rule_id,
    ...(advisory ? { advisory: true } : {}),
    ...(mergedModify ? { modified_params: mergedModify.setFields } : {}),
    ...(downgradedAction.escalate ? { escalate: { ...downgradedAction.escalate } } : {}),
    ...(downgradedAction.degrade ? { degrade: { ...downgradedAction.degrade, removed_tools: downgradedAction.degrade.removed_tools ? [...downgradedAction.degrade.removed_tools] : undefined } } : {}),
    ...(guidance ? { guidance } : {}),
    intervention,
  }
}

function toGuidance(g: GuidanceClause): Guidance {
  const out: Guidance = {}
  if (g.adjustment_id !== undefined) out.adjustment_id = g.adjustment_id
  if (g.template_id !== undefined) out.template_id = g.template_id
  if (g.template_version !== undefined) out.template_version = g.template_version
  if (g.rendered !== undefined) out.rendered = g.rendered
  if (g.allowed_scope !== undefined) out.allowed_scope = g.allowed_scope
  if (g.alternatives !== undefined) out.alternatives = [...g.alternatives]
  if (g.escalate_threshold !== undefined) out.escalate_threshold = g.escalate_threshold
  if (g.max_attempts !== undefined) out.max_attempts = g.max_attempts
  return out
}

/**
 * Merge multiple `modify` actions into a single payload. Rules are already
 * priority-sorted, so iteration order is the application order: earlier
 * rules establish defaults, later rules override specific keys.
 */
function mergeModifyActions(matched: CompiledRule[]): ModifyAction | undefined {
  let out: ModifyAction | undefined
  for (const r of matched) {
    if (r.action?.decision !== 'modify' || !r.action.modify) continue
    const m = r.action.modify
    out = out ?? {}
    if (m.redactFields) {
      out.redactFields = [...(out.redactFields ?? []), ...m.redactFields]
    }
    if (m.substitutePatterns) {
      out.substitutePatterns = { ...(out.substitutePatterns ?? {}), ...m.substitutePatterns }
    }
    if (m.whitelistConstraint) {
      out.whitelistConstraint = { ...(out.whitelistConstraint ?? {}), ...m.whitelistConstraint }
    }
    if (m.setFields) {
      out.setFields = { ...(out.setFields ?? {}), ...m.setFields }
    }
  }
  return out
}

// Re-export for tests; not strictly needed by callers.
export type { EscalateDetail, DegradeDetail }

/** Everything the aggregation pass derives from the full matched set. */
interface Aggregate {
  /** Sum of RISK_LEVEL_SCORES across every matched rule carrying a risk_level. */
  riskScore: number
  /** Per-level summed contribution + `aggregate_score`. */
  dimensions: Record<string, number>
  /** Names of every matched rule (falls back to the rule id — see RuleLoader). */
  matchedPolicies: string[]
  /** Ids of every matched rule, in the order they were evaluated / matched. */
  evaluationPath: string[]
  /** How many matched rules declared `risk_level: 'medium'`. */
  mediumCount: number
  /** Up to 3 matched rule names, highest priority first (for the reason text). */
  topNames: string[]
  /** Effective threshold / count in play, echoed into the reason text. */
  threshold: number
  requiredMediumCount: number
}

/**
 * Walk the FULL matched set and accumulate the aggregate risk picture.
 * Rules without `evaluate.risk_level` still appear in `matched_policies` /
 * `evaluation_path` but contribute 0 to the score.
 */
function aggregateMatched(matched: CompiledRule[], options?: ComposeOptions): Aggregate {
  const dimensions: Record<string, number> = {}
  const matchedPolicies: string[] = []
  const evaluationPath: string[] = []
  let riskScore = 0
  let mediumCount = 0

  for (const r of matched) {
    matchedPolicies.push(r.name)
    evaluationPath.push(r.id)
    const level = r.evaluate?.risk_level
    if (!level) continue
    const score = RISK_LEVEL_SCORES[level]
    riskScore += score
    // Per-level dimension = summed contribution of the rules at that level;
    // the rule count at a level is `dimensions[level] / RISK_LEVEL_SCORES[level]`.
    dimensions[level] = (dimensions[level] ?? 0) + score
    if (level === 'medium') mediumCount += 1
  }
  dimensions.aggregate_score = riskScore

  // The loader already sorts priority-descending, but direct callers may not;
  // sort a COPY (stable via original-index tiebreak) purely for the reason
  // text. The verdict rule stays `matched[0]` — see composeDecision.
  const topNames = matched
    .map((r, i) => ({ r, i }))
    .sort((a, b) => b.r.priority - a.r.priority || a.i - b.i)
    .slice(0, 3)
    .map((x) => x.r.name)

  return {
    riskScore,
    dimensions,
    matchedPolicies,
    evaluationPath,
    mediumCount,
    topNames,
    threshold: options?.mediumAggregationThreshold ?? DEFAULT_MEDIUM_AGGREGATION_THRESHOLD,
    requiredMediumCount: options?.mediumAggregationCount ?? DEFAULT_MEDIUM_AGGREGATION_COUNT,
  }
}

interface Promotion {
  decision: SecurityDecision['decision']
  kind: 'medium_aggregation'
}

/**
 * Multi-medium promotion. Fires only when BOTH conditions hold:
 *   1. at least `mediumAggregationCount` matched rules are `medium`, and
 *   2. the aggregate score is >= `mediumAggregationThreshold`.
 *
 * Both are required by design: (1) alone would let four `low` rules promote
 * (that is not a medium stack), and (2) alone would let a single `critical`
 * promote (its own action clause already speaks for it). A returned
 * Promotion is stamped on `risk_assessment.promotion` even when the decision
 * itself is unchanged (`block` / `escalate` already dominate), so audit
 * consumers can see the stacking condition was met.
 */
function resolvePromotion(
  base: ActionClause['decision'],
  agg: Aggregate,
): Promotion | undefined {
  // `mediumCount > 0` guards a caller passing `mediumAggregationCount: 0`:
  // "medium aggregation" with zero medium hits is not a thing.
  if (agg.mediumCount === 0) return undefined
  if (agg.mediumCount < agg.requiredMediumCount) return undefined
  if (agg.riskScore < agg.threshold) return undefined

  // Stacking rule: a plain allow becomes an escalate.
  if (base === 'allow') return { decision: 'escalate', kind: 'medium_aggregation' }
  // Never downgrade an already-stronger verdict.
  if (base === 'block' || base === 'escalate') return { decision: base, kind: 'medium_aggregation' }
  // `modify` / `substitute` (advisory) / `context_adjust` / `degrade`
  // carry payloads the promotion cannot rewrite — leave them untouched and
  // unstamped rather than emitting a promotion that changed nothing.
  return undefined
}

function buildRiskAssessment(
  evaluate: EvaluateClause | undefined,
  action: ActionClause,
  agg: Aggregate,
  promotion: Promotion | undefined,
): RiskAssessment | undefined {
  // Pre- gate, preserved: a lone `allow` rule that declares no risk level
  // produces no risk assessment. Extended by one case — if any OTHER matched
  // rule contributed a score, the aggregate is real signal and worth emitting.
  const hasBaseSignal = Boolean(evaluate?.risk_level) || action.decision !== 'allow'
  if (!hasBaseSignal && agg.riskScore === 0) return undefined
  return {
    risk_score: agg.riskScore,
    risk_level: evaluate?.risk_level ?? 'medium',
    dimensions: { ...agg.dimensions },
    matched_policies: [...agg.matchedPolicies],
    evaluation_path: [...agg.evaluationPath],
    ...(promotion ? { promotion: promotion.kind } : {}),
  }
}

/**
 * Free-text `intervention.reason`: a
 * human-readable one-liner naming the deciding rule, the aggregate score and
 * the top-3 contributing rules, plus the promotion clause when one fired.
 */
function buildReason(
  rule: CompiledRule,
  action: ActionClause,
  agg: Aggregate,
  promotion: Promotion | undefined,
): string {
  const head = action.blockReason
    ? `Block reason: ${action.blockReason} (rule: ${rule.name}).`
    : `Decision: ${action.decision} (rule: ${rule.name}).`
  const n = agg.matchedPolicies.length
  let out = `${head} Aggregate risk: ${agg.riskScore} from ${n} matched rule${n === 1 ? '' : 's'}: ${agg.topNames.join(', ')}.`
  if (promotion && promotion.decision !== action.decision) {
    out += ` Promoted ${action.decision} → ${promotion.decision} by medium aggregation (${agg.mediumCount} medium rules >= ${agg.requiredMediumCount}, score ${agg.riskScore} >= ${agg.threshold}).`
  }
  return out
}
