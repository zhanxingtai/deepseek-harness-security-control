import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import type { Config } from '../config.js'
import type { InterventionContext, Mode, SecurityDecision } from '../types/index.js'
import { DEFAULT_PLATFORM_ID } from '../types/index.js'
import { expandHome } from '../utils/expandHome.js'
import { composeDecision } from './DecisionComposer.js'
import type { GuidanceRecordLimits } from './GuidanceStateMachine.js'
import { GuidanceStateMachine } from './GuidanceStateMachine.js'
import { extractPolicyMode, loadMultiplePoliciesFromEntries } from './RuleLoader.js'
import { matchRule, canonicalizeCommand } from './RuleMatcher.js'
import { toMarketplaceDecision } from '../utils/decisionVocabulary.js'
import type { MarketplaceDecision } from '../utils/decisionVocabulary.js'
import { DEFAULT_RISK_FLAGS } from '../utils/riskFlags.js'
import { PolicyWatcher } from '../utils/policyWatcher.js'

// SPL schema types were inlined here. The standalone schema file is
// fully consumed by InterventionEngine + ApplicationCollector +
// intervention.test.ts — keeping it as its own module was a grouping
// convenience, not a boundary. Exports are preserved so external
// importers just change their import path (no API drift).

/**
 * SPL (Security Policy Language) schema types.
 *
 * Defines the TypeScript shape used by InterventionEngine and the JSON/YAML
 * policy documents loaded from `policies/`.
 */

export interface PolicyMetadata {
  id: string
  name?: string
  version?: string
  description?: string
  source?: string
  /**
   * spec v2 §2 recommended fields. Loader does not
   * consume them (audit / supply-chain attribution belongs to the
   * platform-side bundle manifest, not the runtime policy file), but
   * the loader MUST emit a spec §0.5 WARN when any of these appear so
   * operators don't think attribution is silently tracked.
   */
  author?: string
  tags?: string[]
  references?: string[]
}

export interface PolicyScope {
  platforms?: string[]
  agents?: string[]
  tenants?: string[]
  /**
   * spec v2 §1 added `workflows`. Migration §9f lists
   * this as a tiny additive field — loader is INTENTIONALLY SILENT on
   * it (宽容忽略), no warning. Multi-collector-plugin workflows are
   * not in scope for the deepseek single-collector model.
   */
  workflows?: string[]
}

/**
 * Every sub-clause is independently optional. A rule with `match: {}`
 * (or with `match` omitted entirely) matches EVERY context — the SPL
 * spec's "always-on" guard semantic. Use this for pure riskFlags rules
 * (a rule that says "if the event carries flag X, decision Y") without
 * enumerating an actionType or toolName constraint.
 */
export interface MatchClause {
  actionType?: string[]
  toolName?: string[]
  /**
   * For asset events: list of asset types to match (`agent_config`,
   * `skill`, `mcp_server`).  Unset / empty = match any.
   */
  assetType?: string[]
  riskFlagsAny?: string[]
  riskFlagsAll?: string[]
  /**
   * paramsRegex maps a parameter field to a list of regex patterns (any match).
   * For asset events the canonical field name is `asset_path` (keeps `path`
   * / `file_path` aliases working for tool events via RuleMatcher's
   * FIELD_ALIASES).
   *
   * spec v2 §4 allows each entry to be either a
   * plain regex string OR an object `{ pattern, flags?, }`
   * with an optional `input` pre-processing flag; `compileRegexList`
   * accepts both shapes. The matcher treats the compiled result the
   * same way regardless of source form.
   */
  paramsRegex?: Record<string, Array<string | ParamsRegexObjectEntry>>
  /**
   * Standard / alias for exact field equality (`fieldEquals`). The canonical
   * location for exact-match conditions; `params` is retained as a
   * backward-compatible alias.
   */
  fieldEquals?: Record<string, string | number | boolean | null>
  /** bodyRegex is a list of regex patterns matched against the request body. */
  bodyRegex?: string[]
  sessionRegex?: string[]
  /**
   * spec v2 §4 fields the matcher does not yet
   * consume. Per spec §0.5 the loader must WARN when any of these
   * appear (silently-dropped rules give a false sense of protection),
   * but does NOT drop the rule — the surrounding clauses can still
   * match. fieldEquals / paramsRegex stay narrow: fieldIn is the
   * "is-in-enum" matcher, paramsNotRegex is the negative form of
   * paramsRegex, paramsContains is a literal substring match, and
   * chain is the multi-step link matcher.
   */
  paramsNotRegex?: Record<string, string[]>
  paramsContains?: Record<string, string[]>
  fieldIn?: Record<string, string[]>
  chain?: {
    withinSteps?: number
    prior?: Array<{
      ruleId?: string
      match?: MatchClause
    }>
  }
}

/**
 * per-entry object form for `match.paramsRegex` (spec
 * §4). `pattern` is the JS regex source string; `flags` is restricted
 * to a tiny whitelist (only `i` is currently accepted — see
 * `compileRegexList` for the full rejection set); `input` is the
 * pre-processing mode selector — `lowercased` lowercases the
 * comparison surface before regex matching (handy for case-stable
 * keywords like env-var names), `raw` skips pre-processing.
 */
export interface ParamsRegexObjectEntry {
  pattern: string
  flags?: string
  input?: 'lowercased' | 'raw'
}

export interface ModifyAction {
  redactFields?: string[]
  substitutePatterns?: Record<string, string>
  whitelistConstraint?: Record<string, string>
  /** the `modify.setFields` schema. */
  setFields?: Record<string, unknown>
}

/**
 * Union widens to include the marketplace 3-action vocabulary
 * (`allow` / `deny` / `ask`). The marketplace surface ships with the
 * simpler 3-action vocabulary; RuleLoader.normalizeRule translates
 * `deny → block` and `ask → escalate` so downstream DecisionComposer
 * still consumes the SPL v2 §5.1 internal vocabulary.
 *
 * SPL v2 spec §5.1 narrows the internal vocabulary
 * from 10 values to 6 — `guide` / `context_adjust` / `substitute` /
 * `degrade` / `approve` are deprecated v1 values that the loader
 * rejects at load time. The type union here matches what the loader
 * is willing to compile — see `RuleLoader.compilePolicy`.
 *
 * Internal 6-action values (`warn`, `audit`, `modify`, `escalate`,
 * `block`, `allow`) keep working unchanged — `policies/default-policy.
 * spl.yaml` uses them verbatim, and a marketplace rule may also use
 * them.
 */
export type { MarketplaceDecision } from '../utils/decisionVocabulary.js'
export type InternalDecision =
  | 'allow'
  | 'warn'
  | 'audit'
  | 'modify'
  | 'escalate'
  | 'block'
export type Decision = MarketplaceDecision | InternalDecision

/**
 * The rule ACTION shape used inside compiled rules and emitted on
 * `SecurityDecision`. The `decision` field is narrowed to
 * `InternalDecision` so downstream consumers (DecisionComposer,
 * ApplicationCollector, RuleMatcher) don't have to widen their type
 * guard. `ActionClause` keeps the public-facing `Decision` union so
 * rule authors can still write `decision: deny` in YAML.
 */
export interface CompiledActionClause {
  decision: InternalDecision
  blockReason?: string
  blockCode?: string
  appealable?: boolean
  modify?: ModifyAction
  escalate?: ActionClause['escalate']
  degrade?: ActionClause['degrade']
  substitute?: ActionClause['substitute']
  guidance?: GuidanceClause
}

export interface ActionClause {
  // Marketplace vocabulary (`allow | deny | ask`) is the canonical
  // public-facing surface; the engine normalizes to internal vocabulary
  // via RuleLoader.normalizeRule.
  decision: Decision
  /** the canonical reason field field. */
  blockReason?: string
  /** Legacy wire alias for `blockReason`. */
  message?: string
  blockCode?: string
  appealable?: boolean
  modify?: ModifyAction
  /**
   * Legacy wire aliases for modify sub-fields.
   * RuleLoader normalizes these into `modify.*` at load time.
   */
  modifiedParams?: Record<string, unknown>
  modifiedRedactFields?: string[]
  modifiedWhitelistConstraint?: Record<string, string>
  /**
   * Paired with `decision: 'escalate'`. Field names match the SPL `escalate`
   * action schema.
   */
  escalate?: {
    approval_request_id?: string
    approval_route?: string
    timeout_seconds?: number
    /** Legacy wire alias for `timeout_seconds`. */
    escalateTimeoutSeconds?: number
    /** Legacy wire alias for approval list. */
    escalateApprovers?: string[]
  }
  /**
   * Paired with `decision: 'degrade'`. Field names match the SPL `degrade`
   * action schema.
   */
  degrade?: {
    mode: 'readonly' | 'chat_only' | 'no_external' | 'sandbox' | 'limited_tools'
    removed_tools?: string[]
    /** Legacy wire alias for `removed_tools`. */
    degradedTools?: string[]
  }
  /**
   * Paired with `decision: 'substitute'`. The canonical SPL field is
   * `substitute`; `substitutedTool` is the legacy alias.
   */
  substitute?: {
    toolName: string
    paramMapping?: Record<string, string>
  }
  substitutedTool?: string
  /** Paired with `decision: 'context_adjust'` / `decision: 'guide'`. */
  guidance?: GuidanceClause
  /** Legacy wire alias for `evaluate.risk_level`. */
  riskLevel?: 'critical' | 'high' | 'medium' | 'low'
}

export interface GuidanceClause {
  adjustment_id?: string
  template_id?: string
  template_version?: string
  rendered?: string
  allowed_scope?: string
  alternatives?: string[]
  escalate_threshold?: number
  max_attempts?: number
}

/**
 * The platform's standardised SPL vocabulary restricts
 * `evaluate.risk_level` to the four actionable tiers
 * `critical` / `high` / `medium` / `low`. The `info` tier carries no
 * enforcement semantics; this narrows the union so accidental use
 * surfaces a type error at policy-load time.
 */
export interface EvaluateClause {
  risk_level?: 'critical' | 'high' | 'medium' | 'low'
  /** Legacy wire alias for `risk_level`. */
  riskLevel?: 'critical' | 'high' | 'medium' | 'low'
}

export interface PolicyRule {
  id: string
  name?: string
  enabled?: boolean
  priority?: number
  match?: MatchClause
  evaluate?: EvaluateClause
  action?: ActionClause
  /**
   * Rule category — declared in YAML as a top-level field
   * (e.g. `category: self_protection`, `category: data_leak_monitoring`).
   * Currently only `self_protection` is acted on by the engine; other
   * values are informational and surface in audit/UI sorting.
   */
  category?: string
  /**
   * optional severity driving block→warn downgrade.
   * See `CompiledRule.severity` for semantics. Unknown values are
   * dropped silently by `RuleLoader.normalizeRule` (with a warning)
   * so a typo doesn't break the load.
   */
  severity?: 'critical' | 'extreme' | 'high' | 'medium' | 'low'
  /**
   * spec v2 §3 / §5.2 fields.
   * `testCases` is reserved for (Tier名单 + CI校验); the loader
   * does not consume it but the type is declared so the schema
   * accepts it. `notes` and `regClause` move up from the deprecated
   * `evaluate` section per spec §3 / migration §1.
   *
   * `decisionChain` / `conditionalDecisions` are spec §5.2 progressive
   * escalation fields the deepseek engine does not yet implement
   * (spec §0.5 mandates a WARN when they appear).
   */
  testCases?: unknown
  notes?: string
  regClause?: string | string[]
  decisionChain?: unknown
  conditionalDecisions?: unknown
}

export interface PolicyDocument {
  apiVersion: string
  kind: 'Policy'
  metadata: PolicyMetadata
  scope?: PolicyScope
  mode?: Mode
  resources?: Record<string, unknown>
  rules: PolicyRule[]
}

export interface LoadResult {
  policy?: PolicyDocument
  rules: CompiledRule[]
  error?: string
  /**
   * non-fatal load diagnostics — regexes that
   * failed to compile or were rejected by the catastrophic-backtracking
   * guard (`src/utils/regexSafety.ts`). Present (possibly empty) on
   * successful loads; absent on hard errors (the `error` field carries
   * the story there).
   */
  warnings?: string[]
}

/** Normalized rule ready for matching. */
export interface CompiledRule {
  id: string
  name: string
  enabled: boolean
  priority: number
  /** Policy-level scope inherited at compile time. */
  scope?: PolicyScope
  match?: CompiledMatchClause
  evaluate?: EvaluateClause
  /**
   * Rule category propagated from YAML top-level `category:` field.
   * Used by the severity seam to identify self-protection rules
   * (category === 'self_protection') so they bypass the block→warn
   * downgrade.
   */
  category?: string
  /**
   * optional per-rule severity driving block→warn downgrade.
   * Lives at compile-time top-level (sibling of `evaluate`, `action`) —
   * NOT nested under `evaluate`, because the two have distinct roles:
   * `evaluate.risk_level` is the per-rule scoring axis used by medium
   * promotion; `severity` is the per-rule decision threshold.
   * `critical`/`high` keep `block`; `medium`/`low` downgrade
   * `block → warn` in `DecisionComposer.composeDecision`. Self-protection
   * rules bypass the downgrade (meta-rule). Absence of `severity` keeps
   * the legacy block-vs-warn behavior for back-compat with operator
   * policies that haven't migrated yet.
   */
  severity?: 'critical' | 'extreme' | 'high' | 'medium' | 'low'
  /** `action.decision` is narrowed to `InternalDecision` after
   * `RuleLoader.normalizeRule`. Marketplace values (`deny`, `ask`)
   * never reach DecisionComposer — the translation is one-way. */
  action?: CompiledActionClause
}

export interface CompiledMatchClause {
  actionType?: Set<string>
  toolName?: Set<string>
  assetType?: Set<string>
  riskFlagsAny?: Set<string>
  riskFlagsAll?: Set<string>
  paramsRegex?: Record<string, RegExp[]>
  /**
   * Negative form of `paramsRegex`. When a rule declares both
   * `paramsRegex` and `paramsNotRegex`, the rule must match at least one
   * positive pattern AND must NOT match any negative pattern — typical
   * use is "kill -9 PID is dangerous UNLESS the target is a dev server".
   * If a field is declared in `paramsNotRegex` but the corresponding
   * `ctx.params[field]` is absent, the rule is excluded (defensive: do
   * not silently let missing-field samples through). See spec §4.
   */
  paramsNotRegex?: Record<string, RegExp[]>
  bodyRegex?: RegExp[]
}

/**
 * The session shape the RuntimeHook (subprocess seam) needs — the same
 * one ApplicationCollector already tracks (`mostRecentSession`). Lives
 * alongside the SPL schema rather than alongside the seam itself; both
 * RuntimeHook and ApplicationCollector import it from here.
 */
export interface RuntimeHookSessionContext {
  sessionId: string
  runId: string
  agentId?: string
  /**
   * Explicit task identifier, when a producer upstream can supply a REAL
   * one. Never derived from `sessionId` — the platform identity rule
   * forbids a task_id that duplicates session_id (SOC false
   * correlation), so absent a genuine task id this stays undefined and
   * the wire events write null.
   */
  taskId?: string
  /**
   * Monotonic turn identifier within a task. Same rule as `taskId`:
   * never a mirror of `runId`; undefined → null on the wire.
   */
  turnId?: string
}

/**
 * Phase 2 intervention engine.
 *
 * Loads SPL policy rules from disk, matches them against normalized intervention
 * contexts, and returns a SecurityDecision.  In `audit` mode the decision is
 * only recorded; in `enforce` mode the caller can turn a `block` decision into
 * a Cordis `deny` to prevent the action.
 */

/** Callback fired when policy file tamper is detected (hash diverged from baseline). */
export type PolicyTamperCallback = (info: PolicyTamperInfo) => void

export interface PolicyTamperInfo {
  policyPath: string
  baselineHash: string
  currentHash: string
  ts: number
}

/**
 * callback fired when a policy
 * reload SUCCEEDS. Emitted on every committed reload (first-load and
 * subsequent), distinct from `onTamper` (which fires when the reload is
 * REJECTED because the file hash diverged from baseline). The
 * `changed` flag distinguishes "rule set actually changed" from
 * "reload completed but rules identical" so operators can filter
 * idempotent heartbeats if desired.
 */
export type PolicyReloadedCallback = (info: PolicyReloadedInfo) => void

export interface PolicyReloadedInfo {
  /** Path(s) of the successfully loaded policy file(s) (joined with ','). */
  policyPath: string
  /** sha256 over the combined (path, content) hash map of readable files. */
  combinedHash: string
  /** Number of rules that committed into the rule set (after priority sort). */
  ruleCount: number
  /**
   * sha256 over `${id}|${priority}|${enabled}` of the committed rule set.
   * Stable across reloads that don't actually change anything —
   * operators can correlate two events to detect "no change" without
   * diffing rule lists.
   */
  ruleSetHash: string
  /** True iff ruleSetHash differs from the previous successful reload. */
  changed: boolean
  /** Wall-clock time of the reload. */
  ts: number
}

/**
 * callback fired when a policy reload
 * COMMITS WITH ERRORS — the file hash verified (this is not tamper: an
 * operator edit under the bundled-baseline mode, or a broken file at
 * first load) but one or more files failed to parse/validate, so the
 * rule set was reduced to the files that still load (possibly zero
 * rules → host unguarded by SPL). Previously the only signal was a
 * `console.warn` gated behind `DSH_DEBUG === '1'`, leaving production
 * hosts with zero observable signal — contradicting the fail-loud
 * promise in `src/utils/policy/policyWatcher.ts`. bootstrap wires this
 * to a `security_audit/policy_reload_error` event; the engine itself
 * always logs the loud warning through the injected logger.
 *
 * Fires only on error TRANSITIONS (new error, or changed error text) —
 * a watcher re-fire against an unchanged broken file does not re-emit.
 */
export type PolicyReloadErrorCallback = (info: PolicyReloadErrorInfo) => void

export interface PolicyReloadErrorInfo {
  /** Path(s) of the policy file(s) involved in the failed reload. */
  policyPath: string
  /** Combined per-file load error text (same text as `LoadResult.error`). */
  error: string
  /** Rules in effect after the failed reload (0 = host unguarded by SPL). */
  ruleCount: number
  /** True when the previous committed state was error-free. */
  firstFailure: boolean
  /** Wall-clock time of the failed reload. */
  ts: number
}

/**
 * Minimal logger the engine needs. Deliberately structural — bootstrap
 * injects the host's `ctx.logger`; tests inject a spy; when absent the
 * engine falls back to `console`.
 */
export interface InterventionLogger {
  warn: (message: string, ...args: unknown[]) => void
  error?: (message: string, ...args: unknown[]) => void
  info?: (message: string, ...args: unknown[]) => void
}

export interface PolicyTamperState {
  /** Hash of the first load (trusted baseline). null = no policy loaded yet. */
  baselineHash: string | null
  /** Cumulative number of reloads that were rejected because of hash divergence. */
  tamperCount: number
  /** Hash of the most recent rejected reload. */
  lastTamperHash: string | null
  /** When the most recent tamper was detected. */
  lastTamperAt: number | null
}

export class InterventionEngine {
  private config: Config['intervention']
  private loaded: LoadResult = { rules: [] }
  private reloadTimer?: ReturnType<typeof setInterval>
  // HMR policy watcher. Replaces the setInterval polling
  // reload with native fs.watch + a polling fallback (auto-engaged on
  // WSL / 9P / virtiofs where inotify is unreliable). The `gcTimer`
  // stays independent of the watcher so guidance/httpDecisionCache GC
  // doesn't get pinned to a policy-file event.
  private policyWatcher?: PolicyWatcher
  private gcTimer?: ReturnType<typeof setInterval>
  /**
   * baseline hash of the policy file as first loaded.
   * Subsequent reloads compute the current hash and compare; divergence
   * (a write between the first load and a reload) is treated as tamper
   * and the reload is rejected. `null` = no policy successfully loaded yet.
   */
  private baselineHash: string | null = null
  private tamperCount = 0
  private lastTamperHash: string | null = null
  private lastTamperAt: number | null = null
  private onTamper?: PolicyTamperCallback
  /**
   * fires when a policy reload
   * successfully commits a new rule set (or the same one as a
   * heartbeat). Distinct from `onTamper` which fires when a reload is
   * REJECTED because the file hash diverged from baseline. Wired by
   * bootstrap to emit a `security_audit/policy_reloaded` audit row.
   */
  private onReloaded?: PolicyReloadedCallback
  /**
   * fires when a reload COMMITS WITH ERRORS (hash
   * verified, parse/validate failed). Wired by bootstrap to emit a
   * `security_audit/policy_reload_error` audit row; without it the
   * engine only logs the loud warning.
   */
  private onReloadError?: PolicyReloadErrorCallback
  /**
   * operator-visible warning sink. Injected by
   * bootstrap as the host's `ctx.logger`; falls back to `console` so
   * engine-level tests and custom embedders keep working without one.
   */
  private readonly log: InterventionLogger
  /**
   * sha256 over the last successfully committed rule set
   * (`${id}|${priority}|${enabled}` joined), used by `onReloaded` to
   * derive the `changed` flag — `null` until the first successful
   * reload completes.
   */
  private lastCommittedRuleSetHash: string | null = null
  /**
   * cumulative count of evaluations that exceeded
   * `decisionTimeoutMs` and fell back to the failStrategy decision.
   * Surfaced via getEvaluationTimeoutState() for stats / heartbeats.
   */
  private evaluationTimeoutCount = 0
  private lastEvaluationTimeoutAt: number | null = null
  /**
   * network_http hot-path gating + decision cache.
   * Every captured outbound HTTP request used to pay a full O(N) rule scan;
   * the harness's own LLM API round-trips amplify that cost structurally.
   * `evaluateHttp()` therefore:
   *   1. gates evaluation to the active tool-call window — outside the
   *      window the caller only
   *      collects the audit event, evaluation is skipped and counted in
   *      `httpSkippedOutsideToolWindowCount`;
   *   2. caches `allow` decisions per (actionType, method, host, URL,
   *      agent, tenant) with a TTL, so homogeneous high-frequency requests
   *      are O(1) cache hits instead of full scans.
   * Only `allow` decisions are cached: block / guidance / escalate
   * decisions always re-evaluate (guidance counters are per-session state
   * and must not be replayed from a cache). Timed-out fallback decisions
   * are never cached either — a timeout is transient load, and freezing it
   * into the cache would extend the degradation past the engine's own
   * recovery.
   * Cache soundness invariant (must hold for every match dimension in
   * RuleMatcher): for network_http contexts the match outcome may only
   * depend on (a) the key fields above and (b) the request body. Headers
   * and riskFlags are not match dimensions in the collector-built context.
   * Dimension (b) is covered by a bodyRegex pre-screen on every cache hit:
   * if the current body matches any loaded bodyRegex (verbatim or
   * canonical), the cache is bypassed and the full scan runs. If a future
   * rule dimension inspects per-request content, it must be added to the
   * key or to the pre-screen before this cache may serve decisions.
   * The cache is cleared on every policy reload (rules changed → cached
   * verdicts may no longer hold) and on overflow (simple full clear; the
   * working set is tiny in practice).
   */
  private readonly httpDecisionCache = new Map<string, { decision: SecurityDecision; expiresAt: number }>()
  private httpSkippedOutsideToolWindowCount = 0
  private httpDecisionCacheHitCount = 0
  private httpDecisionCacheMissCount = 0
  private readonly httpDecisionCacheTtlMs: number
  private readonly httpDecisionCacheMaxSize: number
  /**
   * shipped builtin rule file paths. The engine appends
   * these AFTER the user-provided `policyPaths` so a marketplace install
   * gets the matching baseline. Injected at construction so the engine
   * stays decoupled from filesystem layout (and so tests can stub the
   * resolver). `null` is the default — the engine then disables the
   * builtin append entirely (legacy operators who haven't migrated to
   * `policyPaths` see no behavior change). There is deliberately no
   * environment-variable fallback here.
   */
  private readonly builtinRulePaths: readonly string[] | null
  /**
   * see constructor option `trustedBaselineHash`.
   * When set, tamper detection tracks bundled-file integrity separately
   * from user-file changes (operators can freely edit `policyPaths[]`
   * without tripping tamper, but a write to the bundled source IS
   * tamper). When null, tamper detection falls back to the legacy
   * combined-hash semantics (any change is tamper).
   */
  private readonly trustedBaselineHash: string | null
  /**
   * see constructor option `defaultModeFromPolicy`.
   * Cached at construction; consulted on every successful policy
   * reload to decide whether the policy file's `mode:` field
   * should drive `this.config.mode` as the runtime default.
   */
  private readonly defaultModeFromPolicy: boolean
  /**
   * per-file errors from the last multi-file load.
   * Surfaced via `getLastLoadErrors()` so operators can diagnose a
   * bad user-supplied path without enabling debug logging.
   */
  private lastLoadErrors: ReadonlyArray<{ path: string; error: string }> = []
  /** Derived list of body-carrying rules, invalidated by reference when `loaded` is replaced. */
  private bodyScreenRulesCache: { loaded: LoadResult; rules: CompiledRule[] } | null = null
  /**
   * per-(session, policy, template) counter that detects
   * repeated-guidance loops and flips the engine's `context_adjust`
   * decision to `escalate` once the rule's `max_attempts` /
   * `escalate_threshold` is reached. Constructed once per engine (so
   * tests are isolated by virtue of constructing fresh engines). GC is
   * piggy-backed on the existing reloadTimer so we don't add a second
   * interval.
   */
  private readonly guidanceMachine = new GuidanceStateMachine()

  constructor(config: Config, options?: {
    onTamper?: PolicyTamperCallback
    /**
     * fires after every
     * SUCCESSFUL policy reload (rule set committed, not rejected). Used
     * by bootstrap to emit `security_audit/policy_reloaded` for audit
     * visibility of "operator edited the file and the new rules took
     * effect". Pair with `onTamper` for the rejection signal.
     */
    onReloaded?: PolicyReloadedCallback
    /**
     * fires after a reload that COMMITS WITH
     * ERRORS (the file hash verified — not tamper — but parse/validate
     * failed and the rule set was reduced to the files that still
     * load). Used by bootstrap to emit
     * `security_audit/policy_reload_error`.
     */
    onReloadError?: PolicyReloadErrorCallback
    /**
     * logger for engine warnings (policy reload
     * failures, regex compile warnings, watcher degradation). Falls
     * back to `console` when omitted.
     */
    logger?: InterventionLogger
    /** : overrides for the network_http decision cache. */
    httpDecisionCache?: { ttlMs?: number; maxSize?: number }
    /**
     * explicit override for the builtin rule-file
     * paths. When the operator sets `policyPaths: [...]` the engine
     * appends these AFTER the user paths. Pass an empty array to
     * disable the append entirely (legacy single-file behavior). Pass
     * `null` = no builtin append. Pass an array to opt in.
     */
    builtinRulePaths?: readonly string[] | null
    /**
     * pre-computed sha256 of the bundled policy
     * file content, supplied by bootstrap.ts at engine construction
     * time. When provided:
     *   - the tamper-detection baseline is THIS hash (not the first
     *     reload's currentHash), closing the "tamper-before-first-reload"
     *     attack where an attacker writes the bundled policy file BEFORE
     *     the engine's first file read and the old "first reload =
     *     baseline" logic would have locked in the tampered content as
     *     legitimate.
     *   - the tamper check compares the bundled-only hash on every
     *     reload against this trusted baseline, so operator edits to
     *     their own `policyPaths[]` files do NOT trip tamper — only
     *     changes to the bundled (shipped-via-npm-tarball) sources.
     *
     * Tests that don't pass this option fall back to the legacy
     * combined-hash baseline + tamper check, preserving the existing
     * test contract (tests use a single user policy file with no
     * builtins).
     */
    trustedBaselineHash?: string
    /**
     * default-mode-from-policy seam.
     *
     * When `true` (the default), the engine consults the loaded policy
     * files' `mode:` declaration as the runtime `config.mode` default
     * — but only IF the operator's `Config` came in with the schema
     * default mode (i.e. the operator did NOT explicitly set
     * `intervention.mode` or top-level `mode`). The bundled
     * `policies/default-policy.spl.yaml` declares `mode: enforce`,
     * so a fresh install with no operator config lands in `enforce`
     * by default — secure-by-default without a hard breaking change
     * for existing operators who already chose `audit`.
     *
     * Resolution order (highest priority first):
     *   1. Operator-explicit config — `intervention.mode` or `mode`
     *      in the operator's input. Bootstrap detects this via
     *      `isModeExplicit(rawConfig)` and passes
     *      `defaultModeFromPolicy: false` when explicit.
     *   2. Bundled policy file's `mode:` declaration
     *      (first non-null in load order; user policies first, then
     *      builtins — same order as the rule merge).
     *   3. The schema default (`'enforce'`; previously `'audit'`).
     *
     * The re-apply happens on every successful policy reload so an
     * operator who edits the policy file to flip `mode` sees the new
     * default take effect on the next reload.
     *
     * Pass `false` to opt out and keep the historical "config is
     * authoritative, policy is decorative" semantics.
     */
    defaultModeFromPolicy?: boolean
  }) {
    this.config = config.intervention
    if (options?.onTamper) this.onTamper = options.onTamper
    if (options?.onReloaded) this.onReloaded = options.onReloaded
    if (options?.onReloadError) this.onReloadError = options.onReloadError
    this.log = options?.logger ?? console
    this.httpDecisionCacheTtlMs = options?.httpDecisionCache?.ttlMs ?? 30_000
    this.httpDecisionCacheMaxSize = options?.httpDecisionCache?.maxSize ?? 1024
    this.builtinRulePaths =
      options?.builtinRulePaths !== undefined ? options.builtinRulePaths : null
    this.trustedBaselineHash = options?.trustedBaselineHash ?? null
    this.defaultModeFromPolicy = options?.defaultModeFromPolicy !== false
  }

  initialize(): void {
    this.reloadPolicy()
    // HMR via native fs.watch + WSL polling fallback.
    // The watcher's poll interval is derived from `reloadIntervalMs` (the
    // legacy knob) so existing patch YAMLs that tune the cadence still
    // take effect on the polling fallback path.
    this.policyWatcher = this.buildPolicyWatcher()
    this.policyWatcher.subscribe((event) => this.handlePolicyWatchEvent(event))
    this.policyWatcher.start()
    this.startGcTimer()
  }

  /**
   * construct the policy watcher. `livePatch` rebuilds
   * the watcher when `reloadIntervalMs` changes at runtime (the poll
   * interval is baked in at construction).
   */
  private buildPolicyWatcher(): PolicyWatcher {
    const policyPath = expandHome(this.config.policyPath)
    return new PolicyWatcher([policyPath], {
      pollIntervalMs: this.config.reloadIntervalMs > 0 ? this.config.reloadIntervalMs : 1000,
      logger: {
        warn: (m, ...a) => this.log.warn(m, ...a),
        error: (m, ...a) => this.log.warn(m, ...a),
      },
    })
  }

  /** Policy-watch event handler, shared by every watcher registration. */
  private handlePolicyWatchEvent(event: {
    path: string
    reason: 'change' | 'rename' | 'error'
    error?: string
  }): void {
    const { path, reason, error } = event
    if (reason === 'error') {
      this.log.warn(`[InterventionEngine] policy watcher error on ${path}: ${error ?? 'unknown'}`)
      return
    }
    // invalid YAML / corruption must fail-loud. The reload itself
    // (and the loud warning + `onReloadError` audit emission on error
    // transitions) lives in `reloadMultiPolicy` — see the
    // defect-2 block there. We DROP the failing file's rules (the host
    // is never silently guarded by stale policy for that file) and the
    // next successful load re-populates.
    this.reloadPolicy()
  }

  /**
   * (re)start the guidance / HTTP-decision-cache
   * GC timer at the current `reloadIntervalMs`. No-op when the interval
   * is 0 (legacy "disable reloads" knob disables GC too). `livePatch`
   * rebuilds the timer on cadence changes.
   */
  private startGcTimer(): void {
    if (this.gcTimer) {
      clearInterval(this.gcTimer)
      this.gcTimer = undefined
    }
    if (this.config.reloadIntervalMs > 0) {
      this.gcTimer = setInterval(
        () => {
          // guidance GC. Cheap O(N); N is bounded by
          // live sessions × policies × templates.
          this.guidanceMachine.gc()
          // drop expired network_http
          // decision-cache entries.
          this.gcHttpDecisionCache()
        },
        this.config.reloadIntervalMs,
      )
    }
  }

  /**
   * apply 🟢 intervention keys in place.
   * `decisionTimeoutMs` / `failStrategy` are read per-eval off the shared
   * config reference, so they take effect on the very next evaluation.
   * `reloadIntervalMs` drives both the GC timer and the watcher's
   * poll fallback interval — both are rebuilt here so the new cadence is
   * genuinely in effect (timer/watcher rebuild was the evaluation
   * decision for interval fields). `mode` is a shared-reference field
   * too but stays 🟡 at the classifier level; a direct `mode` entry
   * (internal callers only) is synced for parity with RuntimeHook's
   * `deps.mode` snapshot. `policyPath` / `policyPaths` are 🟡 (policy
   * hash baseline re-pinning is a restart-scoped operation).
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
      const cfg = patch['intervention']
      if (cfg && typeof cfg === 'object' && !Array.isArray(cfg)) {
        const c = cfg as Record<string, unknown>
        if (typeof c['decisionTimeoutMs'] === 'number' && Number.isFinite(c['decisionTimeoutMs'])) {
          this.config.decisionTimeoutMs = c['decisionTimeoutMs']
          appliedKeys.push('intervention.decisionTimeoutMs')
        }
        if (
          c['failStrategy'] === 'fail_open' ||
          c['failStrategy'] === 'fail_closed' ||
          c['failStrategy'] === 'fail_open_high_risk_only'
        ) {
          this.config.failStrategy = c['failStrategy']
          appliedKeys.push('intervention.failStrategy')
        }
        if (typeof c['reloadIntervalMs'] === 'number' && Number.isFinite(c['reloadIntervalMs']) && c['reloadIntervalMs'] >= 0) {
          this.config.reloadIntervalMs = c['reloadIntervalMs']
          appliedKeys.push('intervention.reloadIntervalMs')
          this.startGcTimer()
          // Rebuild the watcher only when it was started (initialize ran);
          // a not-yet-initialized engine picks the new cadence up itself.
          //
          // Atomic-swap rebuild. The previous order
          // (close-old → build-new → start-new) left the engine without a
          // watcher if `buildPolicyWatcher` / `subscribe` / `start` threw —
          // the OLD watcher was already closed, so policy reload detection
          // silently disappeared until the next livePatch. The atomic
          // order is: build-new → start-new → close-old → swap-reference.
          // If anything in the new path throws, we close the half-built
          // new watcher and re-raise; the OLD watcher keeps running.
          if (this.policyWatcher) {
            const oldWatcher = this.policyWatcher
            const newWatcher = this.buildPolicyWatcher()
            try {
              newWatcher.subscribe((event) => this.handlePolicyWatchEvent(event))
              newWatcher.start()
            } catch (error) {
              try {
                newWatcher.close()
              } catch {
                /* best-effort cleanup */
              }
              throw error
            }
            // Atomic swap — only reached if the new watcher is fully alive.
            this.policyWatcher = newWatcher
            try {
              oldWatcher.close()
            } catch {
              /* best-effort close; the new watcher is already running */
            }
          }
        }
        if ('policyPath' in c) needsRestartKeys.push('intervention.policyPath')
        if ('policyPaths' in c) needsRestartKeys.push('intervention.policyPaths')
      }
      if (typeof patch['mode'] === 'string' && (patch['mode'] === 'audit' || patch['mode'] === 'enforce')) {
        this.config.mode = patch['mode']
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

  shutdown(): void {
    this.policyWatcher?.close()
    this.policyWatcher = undefined
    if (this.gcTimer) {
      clearInterval(this.gcTimer)
      this.gcTimer = undefined
    }
    // Legacy reloadTimer is kept as a no-op for back-compat with any
    // external holders; clear if present.
    if (this.reloadTimer) {
      clearInterval(this.reloadTimer)
      this.reloadTimer = undefined
    }
    this.guidanceMachine.resetAll()
  }

  async evaluate(ctx: InterventionContext): Promise<SecurityDecision> {
    // the default policy scope filters on the project
    // identifier. Callers that do not supply a platformId (e.g. unit tests)
    // inherit the canonical value so existing rules continue to match.
    const scopedCtx: InterventionContext = {
      ...ctx,
      platformId: ctx.platformId ?? DEFAULT_PLATFORM_ID,
    }
    return this.evaluateScoped(scopedCtx).decision
    // audit: the engine does NOT cache
    // generic SPL evaluations — every `evaluate()` call runs the full
    // `matchRule()` + `composeDecision()` pipeline. Only the network_http
    // hot-path carries an allow-decision cache
    // (`httpDecisionCache`, see its header comment for the design).
    //
    // A general-purpose SPL cache is intentionally absent:
    //   - Rule matching is context-dependent (`paramsRegex` walks the
    //     call's `params.command` / `params.body` / `body`, the runtime
    //     hook's argv carries the literal command line, the inline
    //     folding (`canonicalizeCommand`) mutates the text). Cache keys
    //     would have to capture every variable that enters the matcher.
    //   - Block / modify / substitute decisions MUST NOT be cached —
    //     a bypassed block re-fires the rule's `block_reason` and any
    //     subsequent `modify` payload, and any drift between cached and
    //     recomputed output is a security regression. The HTTP cache
    //     only caches `allow` for exactly this reason.
    // Tool-layer SPL is already under 50 ms for the default
    // policy (fragment-fold included); the speedup from
    //     caching is marginal and the bypass risk is non-zero.
    // If a future use case needs cached block / modify, the key must
    // include a content hash of every matched-text field, the policy
    // rule id, and the `evaluate.risk_level` / `decision` shape — see
    // the HTTP cache's `expiresAt` for the staleness-bound pattern.
  }

  /**
   * hot-path evaluation for network_http events.
   * See the field comment on `httpDecisionCache` for the full design.
   *
   * Returns `undefined` when the request falls outside the active
   * tool-call window — the caller must still collect the audit event, it
   * just skips rule evaluation entirely (counted in
   * `getHttpEvaluationState().skippedOutsideToolWindow`).
   *
   * The 50ms cooperative deadline and failStrategy semantics are
   * unchanged: cache misses run the exact same `evaluateScoped` path as
   * every other evaluation, and timeout fallbacks are never cached.
   */
  async evaluateHttp(
    ctx: InterventionContext,
    opts: { toolActive: boolean },
  ): Promise<SecurityDecision | undefined> {
    if (!opts.toolActive) {
      this.httpSkippedOutsideToolWindowCount += 1
      return undefined
    }
    const key = this.httpDecisionCacheKey(ctx)
    const now = Date.now()
    if (key) {
      const cached = this.httpDecisionCache.get(key)
      if (cached) {
        // Body pre-screen: a cached allow is only sound for bodies that
        // no loaded bodyRegex can match. A hit here means the varying
        // dimension changed the verdict space — pay the full scan.
        if (cached.expiresAt > now && !this.httpBodyPreScreenHits(ctx)) {
          this.httpDecisionCacheHitCount += 1
          return cached.decision
        }
        this.httpDecisionCache.delete(key)
      }
    }
    this.httpDecisionCacheMissCount += 1
    const scopedCtx: InterventionContext = {
      ...ctx,
      platformId: ctx.platformId ?? DEFAULT_PLATFORM_ID,
    }
    const { decision, timedOut } = this.evaluateScoped(scopedCtx)
    if (key && !timedOut && decision.decision === 'allow' && this.httpDecisionCacheTtlMs > 0) {
      if (this.httpDecisionCache.size >= this.httpDecisionCacheMaxSize) {
        this.httpDecisionCache.clear()
      }
      this.httpDecisionCache.set(key, { decision, expiresAt: now + this.httpDecisionCacheTtlMs })
    }
    return decision
  }

  /**
   * observability for the network_http evaluation
   * gate + decision cache, following the getEvaluationTimeoutState()
   * pattern. `cacheMisses` is also the number of real (full-scan)
   * evaluations on the HTTP hot path — the ratio cacheHits /
   * (cacheHits + cacheMisses) is the measured evaluation reduction.
   */
  getHttpEvaluationState(): {
    skippedOutsideToolWindow: number
    cacheHits: number
    cacheMisses: number
    cacheSize: number
  } {
    return {
      skippedOutsideToolWindow: this.httpSkippedOutsideToolWindowCount,
      cacheHits: this.httpDecisionCacheHitCount,
      cacheMisses: this.httpDecisionCacheMissCount,
      cacheSize: this.httpDecisionCache.size,
    }
  }

  /**
   * Cache key for the network_http decision cache. Deliberately uses the
   * concrete URL (not a folded template): every paramsRegex dimension on
   * an http context derives from method/host/url, so the concrete URL is
   * the coarsest sound key, and homogeneous hot-path traffic (the LLM API
   * round-trips this cache exists for) is already identical-request, so
   * template folding buys nothing on the measured path.
   */
  private httpDecisionCacheKey(ctx: InterventionContext): string | null {
    const p = ctx.params
    if (!p) return null
    const method = typeof p.method === 'string' ? p.method : ''
    const host = typeof p.host === 'string' ? p.host : ''
    const url = typeof p.url === 'string' ? p.url : typeof p.path === 'string' ? p.path : ''
    if (!method && !host && !url) return null
    return [ctx.actionType, method, host, url, ctx.agentId ?? '', ctx.tenantId ?? ''].join('\n')
  }

  /**
   * True when the current request body matches any loaded bodyRegex rule
   * (verbatim or canonical form, mirroring `matchesRegexList`). Derived
   * rule list is cached by reference identity of `this.loaded`, so it is
   * recomputed exactly when reloadPolicy() replaces the rule set.
   */
  private httpBodyPreScreenHits(ctx: InterventionContext): boolean {
    const body = ctx.body
    if (typeof body !== 'string' || body.length === 0) return false
    if (!this.bodyScreenRulesCache || this.bodyScreenRulesCache.loaded !== this.loaded) {
      this.bodyScreenRulesCache = {
        loaded: this.loaded,
        rules: this.loaded.rules.filter((r) => (r.match?.bodyRegex?.length ?? 0) > 0),
      }
    }
    const rules = this.bodyScreenRulesCache.rules
    for (let i = 0; i < rules.length; i++) {
      const regexes = rules[i].match?.bodyRegex
      if (!regexes) continue
      for (let j = 0; j < regexes.length; j++) {
        if (regexes[j].test(body)) return true
      }
    }
    const canonical = canonicalizeCommand(body)
    if (canonical === body) return false
    for (let i = 0; i < rules.length; i++) {
      const regexes = rules[i].match?.bodyRegex
      if (!regexes) continue
      for (let j = 0; j < regexes.length; j++) {
        if (regexes[j].test(canonical)) return true
      }
    }
    return false
  }

  private gcHttpDecisionCache(): void {
    if (this.httpDecisionCache.size === 0) return
    const now = Date.now()
    for (const [key, entry] of this.httpDecisionCache) {
      if (entry.expiresAt <= now) this.httpDecisionCache.delete(key)
    }
  }

  /**
   * Shared evaluation body: platform scoping happens in the callers, the
   * cooperative deadline / failStrategy fallback / guidance promotion all
   * live here. Returns whether the deadline fallback fired so callers
   * (the HTTP decision cache) can avoid caching transient verdicts.
   */
  private evaluateScoped(scopedCtx: InterventionContext): {
    decision: SecurityDecision
    timedOut: boolean
  } {
    const start = Date.now()
    // Enforce the configured evaluation deadline. Matching is synchronous
    // CPU work, so a Promise.race timer cannot preempt it — the deadline is
    // checked cooperatively inside `matchRules` (every 32 rules), which caps
    // the worst-case overshoot at 32 rules' cost. On timeout we return a
    // failStrategy fallback instead of blocking the caller indefinitely.
    const deadline =
      this.config.decisionTimeoutMs > 0 ? start + this.config.decisionTimeoutMs : Infinity
    const { matched, timedOut, canonicalizationUsed } = this.matchRules(scopedCtx, deadline)

    if (timedOut) {
      return { decision: this.fallbackDecision(scopedCtx, start, 'evaluation deadline exceeded'), timedOut: true }
    }

    if (matched.length === 0) {
      const failClosed = this.maybeFailClosed(scopedCtx, start)
      if (failClosed) return { decision: failClosed, timedOut: false }
    }

    const decision = composeDecision(matched, this.config.mode, this.config.failStrategy, undefined, this.log)
    decision.latency_ms = Date.now() - start
    // propagate the
    // canonicalization-applied signal from the rule scan. When set,
    // the matched rule(s) fired on the canonical form (folded /
    // normalised / spaced) rather than verbatim text — an obfuscation
    // signal operators want to see in the audit stream. Surfaced via
    // the `canonicalization_applied` audit row in ApplicationCollector.
    if (canonicalizationUsed) {
      decision.canonicalization_applied = true
    }
    // guidance counter → escalate flip. Runs AFTER
    // composeDecision() so the matched rule set (and thus the rule whose
    // action.guidance carries the limit) is stable. No-op when the rule
    // isn't a context_adjust or the limit isn't set.
    this.applyGuidancePromotion(decision, matched, scopedCtx)
    return { decision, timedOut: false }
  }

  getLoadedPolicy(): LoadResult {
    return this.loaded
  }

  /**
  /**
   * shared base): externally request a
   * policy reload. Used by `/security reload` and
   * `ctx.remote.securityMonitor.reload` to give the operator /
   * browser-side UI a manual nudge without having to touch the policy
   * file (the PolicyWatcher already auto-reloads on file change;
   * this is the complement for "I just edited the file in my editor
   * and want to force a refresh now").
   *
   * Returns a small status object so the caller can render either a
   * success or an error message without having to know about the
   * tamper-detection / multi-file branches. The internal `reloadPolicy`
   * is private because it depends on the file-system state and the
   * tamper hash — this wrapper just exposes it under a contract that
   * the CLI / Typert handlers can rely on.
   */
  requestReload(): { ok: boolean; ruleCount?: number; error?: string } {
    const before = this.loaded
    this.reloadPolicy()
    const after = this.loaded
    if (after.error) {
      return { ok: false, error: after.error }
    }
    // Reload was rejected because of tamper (the engine keeps the prior
    // rules in effect, so `after === before`). Surface that distinctly
    // so the caller can tell "no change" from "rejected due to tamper".
    if (after === before && this.tamperCount > 0) {
      const tamper = this.getPolicyTamperState()
      return {
        ok: false,
        ruleCount: before.rules.length,
        error: `policy tamper detected (count=${tamper.tamperCount}); reload rejected, prior rules remain in effect`,
      }
    }
    return { ok: true, ruleCount: after.rules.length }
  }

  /**
   * snapshot the policy tamper state for the host to
   * inspect (or to surface via stats). Tamper is a write that changed the
   * file between two loads — the rejected reload keeps the prior rules
   * in effect (no half-updated state).
   */
  getPolicyTamperState(): PolicyTamperState {
    return {
      baselineHash: this.baselineHash,
      tamperCount: this.tamperCount,
      lastTamperHash: this.lastTamperHash,
      lastTamperAt: this.lastTamperAt,
    }
  }

  /**
   * filter the loaded rule set by policy scope before any
   * rule matching. Rules whose scope mentions platforms/agents/tenants that
   * do not match the current context are treated as non-existent for this
   * evaluation. A missing context dimension causes a mismatch for that
   * dimension (conservative — if the rule cares about tenant and we don't
   * know the tenant, we don't fire it).
   */
  private matchRules(
    ctx: InterventionContext,
    deadline = Infinity,
  ): { matched: CompiledRule[]; timedOut: boolean; canonicalizationUsed: boolean } {
    const matched: CompiledRule[] = []
    // shared observer for
    // canonicalization-applied signals across every rule in this
    // scan. Any rule that fires via the canonical / spaced views
    // flips this flag; the caller surfaces it on the decision so the
    // collector can emit the `canonicalization_applied` audit row.
    const traceSink = { canonicalizationUsed: false }
    for (let i = 0; i < this.loaded.rules.length; i++) {
      // Cooperative deadline check — every 32 rules, so the
      // worst-case overshoot past `decisionTimeoutMs` is bounded by 32
      // rules' matching cost. A synchronous regex cannot be preempted
      // by a timer, which is why this lives inside the loop rather than
      // in a Promise.race wrapper.
      if (i > 0 && (i & 31) === 0 && Date.now() > deadline) {
        return { matched, timedOut: true, canonicalizationUsed: traceSink.canonicalizationUsed }
      }
      const rule = this.loaded.rules[i]
      if (!this.ruleInScope(rule, ctx)) continue
      try {
        if (matchRule(ctx, rule, traceSink)) matched.push(rule)
      } catch {
        // Rule matching should never throw; ignore broken rules.
      }
    }
    return { matched, timedOut: false, canonicalizationUsed: traceSink.canonicalizationUsed }
  }

  /**
   * deadline-exceeded fallback. Counts the occurrence, logs it
   * (a non-zero steady-state timeout rate means the rule set or a single
   * pathological regex is too expensive — operators must see it), and
   * returns a decision according to the configured failStrategy:
   * - fail_closed → block
   * - fail_open_high_risk_only → block when the context carries a high-risk
   *   flag, otherwise allow
   * - fail_open (default) → allow
   */
  private fallbackDecision(
    ctx: InterventionContext,
    start: number,
    message: string,
  ): SecurityDecision {
    this.evaluationTimeoutCount += 1
    this.lastEvaluationTimeoutAt = Date.now()
    // Timeouts are operator-actionable (a non-zero steady-state timeout
    // rate means the rule set or a single pathological regex is too
    // expensive), so emit one warn line per occurrence through the
    // injected logger (  added the logger dependency;
    // it falls back to `console`).
    this.log.warn(`[InterventionEngine] ${message}; failStrategy=${this.config.failStrategy}`)

    if (this.config.failStrategy === 'fail_closed') {
      const blockReason = 'Intervention evaluation timed out; fail-closed per policy'
      return {
        decision: 'block',
        mode: this.config.mode,
        fail_strategy: this.config.failStrategy,
        block_reason: blockReason,
        reason: message,
        latency_ms: Date.now() - start,
        // marketplace wire vocabulary.
        intervention: { decision: toMarketplaceDecision('block'), decision_internal: 'block', mode: this.config.mode, block_reason: blockReason, reason: message },
      }
    }

    if (this.config.failStrategy === 'fail_open_high_risk_only') {
      const flags = ctx.riskFlags ?? []
      if (flags.some((f) => DEFAULT_RISK_FLAGS.includes(f as typeof DEFAULT_RISK_FLAGS[number]))) {
        const blockReason =
          'High-risk activity blocked: intervention evaluation timed out under fail_open_high_risk_only'
        return {
          decision: 'block',
          mode: this.config.mode,
          fail_strategy: this.config.failStrategy,
          block_reason: blockReason,
          reason: message,
          latency_ms: Date.now() - start,
          intervention: { decision: toMarketplaceDecision('block'), decision_internal: 'block', mode: this.config.mode, block_reason: blockReason, reason: message },
        }
      }
    }

    return {
      decision: 'allow',
      mode: this.config.mode,
      fail_strategy: this.config.failStrategy,
      reason: `${message}; fail-open per policy`,
      latency_ms: Date.now() - start,
      // marketplace wire vocabulary.
      intervention: {
        decision: toMarketplaceDecision('allow'),
        decision_internal: 'allow',
        mode: this.config.mode,
        reason: `${message}; fail-open per policy`,
      },
    }
  }

  /**
   * deadline-fallback observability for the host's stats /
   * heartbeat surfaces.
   */
  getEvaluationTimeoutState(): { timeoutCount: number; lastTimeoutAt: number | null } {
    return {
      timeoutCount: this.evaluationTimeoutCount,
      lastTimeoutAt: this.lastEvaluationTimeoutAt,
    }
  }

  private ruleInScope(rule: CompiledRule, ctx: InterventionContext): boolean {
    const scope = rule.scope
    if (!scope) return true
    if (scope.platforms && scope.platforms.length > 0 && !scope.platforms.includes('*')) {
      if (!ctx.platformId || !scope.platforms.includes(ctx.platformId)) return false
    }
    if (scope.agents && scope.agents.length > 0 && !scope.agents.includes('*')) {
      if (!ctx.agentId || !scope.agents.includes(ctx.agentId)) return false
    }
    if (scope.tenants && scope.tenants.length > 0 && !scope.tenants.includes('*')) {
      if (!ctx.tenantId || !scope.tenants.includes(ctx.tenantId)) return false
    }
    return true
  }

  /**
   * when the engine has no matching rule and the configured
   * fail strategy is `fail_open_high_risk_only`, treat high-risk contexts as
   * fail-closed. High-risk is determined by the intersection of the event's
   * `riskFlags` and the marketplace's `DEFAULT_RISK_FLAGS` (the
   * `intervention.highRiskFlags` config knob was retired in — the
   * marketplace exposes a fixed enum so operators cannot widen the
   * fail-closed set by editing the patch).
   *
   * Returns `undefined` when the strategy does not call for a block, allowing
   * the normal `allow` path to proceed.
   */
  private maybeFailClosed(ctx: InterventionContext, start: number): SecurityDecision | undefined {
    if (this.config.failStrategy !== 'fail_open_high_risk_only') return undefined
    const flags = ctx.riskFlags ?? []
    if (!flags.some((f) => DEFAULT_RISK_FLAGS.includes(f as typeof DEFAULT_RISK_FLAGS[number]))) return undefined
    const reason =
      'fail_open_high_risk_only: high-risk flag detected while no policy rule matched; treating as fail-closed'
    const blockReason = 'High-risk activity blocked under fail_open_high_risk_only policy'
    return {
      decision: 'block',
      mode: this.config.mode,
      fail_strategy: this.config.failStrategy,
      block_reason: blockReason,
      reason,
      latency_ms: Date.now() - start,
      intervention: {
        // marketplace wire vocabulary.
        decision: toMarketplaceDecision('block'),
        decision_internal: 'block',
        mode: this.config.mode,
        block_reason: blockReason,
        reason,
      },
    }
  }

  private reloadPolicy(): void {
    // The bundled builtin rules apply in BOTH single-file and multi-file
    // modes. The branch logic:
    //
    //   policyPaths.length > 0  → multi-file mode: user paths load
    //                              first, builtins append after,
    //                              legacy `policyPath` is IGNORED
    //                              (operator has explicitly migrated).
    //   policyPaths.length === 0 → single-file mode: `policyPath`
    //                              loads as the only user entry,
    //                              builtins append after. Operators
    //                              with `policyPath: ~/.dsh/...`
    //                              automatically pick up the bundled
    //                              baseline.
    //
    // Both modes append builtins. The tamper detector's combined-hash
    // semantics are unchanged.
    this.reloadMultiPolicy()
  }

  /**
   * public entry point for
   * triggering a synchronous policy reload. Same path as the
   * internal `reloadPolicy()` but exposed so tests + future
   * programmatic-relax callers can force a reload (e.g. an admin
   * "reload now" button) without waiting for fs.watch.
   */
  triggerReload(): void {
    this.reloadPolicy()
  }

  /** Multi-file reload.
   *  User paths load first; builtin rule files (resolved at
   *  construction) append AFTER. The combined hash is sha256 over
   *  the concatenation of every file's path + sha256(content),
   *  sorted by path so the order is stable across reloads. A write
   *  to any single file diverges the hash and trips tamper
   *  detection. Per-file errors do NOT block the merge — a malformed
   *  user file produces an audit-visible error (loud warning +
   * `onReloadError`) but the rest of the
   *  rules still load. Every file is read exactly once per reload and
   *  the same bytes feed both the tamper hash and the parser. */
  private reloadMultiPolicy(): void {
    // Decide whether legacy `policyPath`
    // contributes as a user entry. When `policyPaths` is non-empty
    // the operator has migrated to the layered format; we IGNORE
    // `policyPath` so the default `~/.dsh/security-policy.spl.yaml`
    // (which usually doesn't exist after marketplace install) doesn't
    // generate a spurious "policy file not found" error. When
    // `policyPaths` is empty, the legacy single-file knob is the
    // operator's only user entry — bundled builtins still append
    // after.
    const hasExplicitPolicyPaths = this.config.policyPaths.length > 0
    const userPaths: string[] = []
    if (!hasExplicitPolicyPaths) {
      const legacyPath = expandHome(this.config.policyPath)
      if (legacyPath) {
        userPaths.push(legacyPath)
      }
    } else {
      for (const p of this.config.policyPaths) {
        const expanded = expandHome(p)
        if (expanded) userPaths.push(expanded)
      }
    }
    const builtinPaths = this.resolveBuiltinPaths()
    const allPaths = [...userPaths, ...builtinPaths]

    // Filter to existing paths only; missing user paths are reported
    // as errors below. Missing builtins are silently skipped — the
    // plugin should still work if an operator deleted `rules/` from
    // their install (they'd just lose the default baseline).
    const existing = allPaths.filter((p) => existsSync(p))
    const missing = allPaths.filter((p) => !existsSync(p))

    // When no policy files exist (every
    // path missing — operator has no file AND no builtins), stay in
    // the "no policy loaded" state. Baseline hash stays null and no
    // tamper is flagged, matching the legacy single-file behaviour
    // so the policy-tamper contract tests keep passing. Missing
    // entries are still surfaced via getLastLoadErrors() so operators
    // see them.
    if (existing.length === 0) {
      this.loaded = { rules: [] }
      this.lastLoadErrors = missing.map((p) => ({ path: p, error: 'policy file not found' }))
      this.httpDecisionCache.clear()
      this.guidanceMachine.resetAll()
      return
    }

    // Combined hash: hash every (path, content) pair, then sha256 the
    // joined string. Sort by path so the order is deterministic across
    // reloads (otherwise priority sort + append-after-user would still
    // work, but the hash would shift on a benign filesystem reorder).
    //
    // (TOCTOU): each file is read
    // EXACTLY ONCE per reload and the same bytes feed BOTH the tamper
    // hash below AND the policy parser (`parsedEntries` →
    // `loadMultiplePoliciesFromEntries`). An attacker who swapped the
    // file between a separate hash read and parse read would pass the
    // hash check while rules load from the swapped content.
    //
    // A transient EACCES / EBUSY during an operator
    // edit (vim's atomic save, gedit, brief chmod race) must not
    // fall back to a `:read_error` sentinel that flows into the combined
    // hash, which then diverged from baseline and tripped tamper. Train
    // the rail to cry wolf and the real tamper signal gets ignored.
    // Soft-fail: skip `:read_error` files from the hash entirely and
    // keep the OLD hash in place; only flip to tamper when a SUSTAINED
    // read failure clears the whole readable set (i.e. every readable
    // file's hash matches AND the readable-set count diverges from
    // baseline, indicating a structural change rather than a race).
    const readableEntries: Array<{ path: string; hash: string }> = []
    const unreadable: string[] = []
    const bytesByPath = new Map<string, string>()
    for (const p of existing.slice().sort()) {
      let raw: string
      try {
        raw = readFileSync(p, 'utf8')
      } catch {
        unreadable.push(p)
        continue
      }
      bytesByPath.set(p, raw)
      readableEntries.push({ path: p, hash: createHash('sha256').update(raw, 'utf8').digest('hex') })
    }
    // The merge must see files in USER-FIRST-then-builtin order
    // (`existing` order) so equal-priority ties shadow builtin rules
    // with user rules — only the HASH above is path-sorted.
    const parsedEntries: Array<{ path: string; raw: string }> = existing
      .filter((p) => bytesByPath.has(p))
      .map((p) => ({ path: p, raw: bytesByPath.get(p) as string }))
    const perFileHashes = readableEntries.map((e) => `${e.path}:${e.hash}`).join('|')
    const currentHash = createHash('sha256').update(perFileHashes).digest('hex')

    // when `trustedBaselineHash` is provided at
    // construction, the tamper check uses the bundled-only hash on
    // each reload (NOT the combined hash) so operator edits to their
    // own `policyPaths[]` don't trip tamper. The bundled-only hash is
    // computed over the subset of `existing` paths that match
    // `builtinPaths` — the shipped-via-npm-tarball sources. A write
    // to any bundled source diverges this hash and triggers tamper
    // (the original attack vector). Combined-hash tamper detection
    // remains the test contract when `trustedBaselineHash` is null.
    const useBundledBaseline = this.trustedBaselineHash !== null
    let bundledHashForTamper: string | null = null
    let bundledTamperPaths: string[] = []
    if (useBundledBaseline) {
      // Mirror the readable-set skip from above.
      const builtinReadable = readableEntries.filter((e) => builtinPaths.includes(e.path))
      if (builtinReadable.length > 0) {
        bundledHashForTamper = createHash('sha256')
          .update(builtinReadable.map((e) => `${e.path}:${e.hash}`).join('|'))
          .digest('hex')
        bundledTamperPaths = builtinReadable.map((e) => e.path)
      }
    }
    const tamperBaselineHash = useBundledBaseline
      ? this.trustedBaselineHash
      : this.baselineHash
    const tamperCurrentHash = useBundledBaseline
      ? (bundledHashForTamper ?? currentHash)
      : currentHash
    const tamperPolicyPath = useBundledBaseline
      ? bundledTamperPaths.join(',')
      : existing.join(',')

    if (tamperBaselineHash !== null && tamperCurrentHash !== tamperBaselineHash) {
      this.tamperCount += 1
      this.lastTamperHash = tamperCurrentHash
      this.lastTamperAt = Date.now()
      try {
        this.onTamper?.({
          policyPath: tamperPolicyPath,
          baselineHash: tamperBaselineHash,
          currentHash: tamperCurrentHash,
          ts: this.lastTamperAt,
        })
      } catch {
        /* callback must never break the engine */
      }
      return
    }
    if (this.baselineHash === null) {
      this.baselineHash = useBundledBaseline ? this.trustedBaselineHash : currentHash
    }

    // loadMultiplePoliciesFromEntries already sorts by priority desc +
    // stable by input order for ties — user rules beat builtin rules at
    // equal priority, because user paths come first in the input.
    const prevLoadError = this.loaded.error
    const result = loadMultiplePoliciesFromEntries(parsedEntries)
    this.loaded = {
      policy: result.documents[parsedEntries[0]?.path ?? ''],
      rules: result.rules,
      warnings: result.warnings.map((w) => `${w.path}: ${w.warning}`),
      error: result.errors.length > 0 ? result.errors.map((e) => `${e.path}: ${e.error}`).join('; ') : undefined,
    }
    // default-mode-from-policy seam: after every
    // successful reload, consult the policy files' `mode:` field
    // and upgrade `this.config.mode` if the operator did NOT set
    // it explicitly (defaultModeFromPolicy is true) AND the
    // current mode is 'audit'. The check is conservative: we only
    // switch when the policy declares a NON-default mode (enforce),
    // so the legacy "config is authoritative" path stays untouched.
    //
    // Note: the schema/normalize default is now 'enforce'
    // (previously 'audit'), so this seam is a no-op for fresh
    // installs (config.mode is already enforce). It still
    // serves as a safety net for operators who explicitly set
    // mode: audit in their patch YAML — bootstrap flips
    // defaultModeFromPolicy to false in that case, so the seam won't
    // downgrade their choice either.
    if (this.defaultModeFromPolicy && this.config.mode === 'audit') {
      const policyMode = extractPolicyMode(
        result.documents,
        parsedEntries.map((e) => e.path),
      )
      if (policyMode === 'enforce') {
        const previousMode = this.config.mode
        this.config.mode = 'enforce'
        this.log.warn(
          `[InterventionEngine] runtime mode upgraded from '${previousMode}' to 'enforce' ` +
            `by policy file's \`mode: enforce\` declaration (no operator override detected). ` +
            `To keep audit mode, set \`intervention.mode: 'audit'\` or top-level \`mode: 'audit'\` ` +
            `in your config.`,
        )
      }
    }
    // Per-file load errors are exposed via the dedicated accessor so the
    // audit stream can render them without re-running the loader.
    //
    // Surface transient `:read_error` files as
    // `policy_file_unreadable` entries here so the audit stream shows
    // them, but DO NOT include them in the tamper-detector's combined
    // hash (already skipped above). The same path can oscillate between
    // readable / unreadable across reloads (operator edit race); each
    // oscillation is now an audit breadcrumb, never a tamper signal.
    const readErrors = unreadable.map((p) => ({
      path: p,
      error: 'policy file unreadable (transient — soft-warned, not tamper)',
    }))
    this.lastLoadErrors = [
      ...result.errors,
      ...missing.map((p) => ({ path: p, error: 'policy file not found' })),
      ...readErrors,
    ]
    this.httpDecisionCache.clear()
    this.guidanceMachine.resetAll()

    // regex compile failures / rejected
    // catastrophic-backtracking patterns are operator-actionable — one
    // warning line per finding, always (no debug gate).
    for (const warning of result.warnings) {
      this.log.warn(`[InterventionEngine] policy warning ${warning.path}: ${warning.warning}`)
    }

    // a reload that commits WITH ERRORS must be
    // observable in production. The pre-fix code gated the only loud
    // warning behind DSH_DEBUG === '1', leaving nothing but the
    // in-memory `lastLoadErrors`. Always warn through the injected
    // logger and fire `onReloadError` so bootstrap can emit the
    // `security_audit/policy_reload_error` audit row. Emission is
    // transition-keyed (new/changed error text only) so a watcher
    // re-fire against an unchanged broken file does not spam.
    if (this.loaded.error && this.loaded.error !== prevLoadError) {
      const firstFailure = prevLoadError === undefined
      this.log.warn(
        `[InterventionEngine] POLICY RELOAD FAILED${firstFailure ? '' : ' (error changed)'} for ` +
          `${existing.join(',')}: ${this.loaded.error}. ` +
          'This is FAIL-LOUD: rules were reduced to the files that still parse ' +
          '(possibly none) — fix the policy file to restore SPL guards.',
      )
      this.emitReloadError(existing.join(','), firstFailure)
    }

    // notify bootstrap that a
    // successful reload committed. Fires AFTER the rule set is in
    // place (callers can read `this.loaded.rules`) and AFTER the
    // guidance / http-cache GC ran (so downstream handlers see a
    // consistent post-reload snapshot). Distinct from `onTamper`
    // which fires only when the reload is REJECTED — these two
    // signals together give operators a complete "policy file
    // activity" timeline.
    if (this.onReloaded) {
      // Compute a stable fingerprint over the committed rule set so
      // the `changed` flag is idempotent across same-content reloads.
      const ruleSetFingerprint = result.rules
        .map((r) => `${r.id}|${r.priority}|${r.enabled !== false ? '1' : '0'}`)
        .join('\n')
      const ruleSetHash = createHash('sha256').update(ruleSetFingerprint).digest('hex')
      const changed = this.lastCommittedRuleSetHash !== ruleSetHash
      this.lastCommittedRuleSetHash = ruleSetHash
      const info: PolicyReloadedInfo = {
        policyPath: existing.join(','),
        combinedHash: currentHash,
        ruleCount: result.rules.length,
        ruleSetHash,
        changed,
        ts: Date.now(),
      }
      try {
        this.onReloaded(info)
      } catch {
        /* callback must never break the engine */
      }
    }
  }

  /**
   * emit the `onReloadError` callback, guarded so a
   * throwing callback can never break the engine (invariant #3).
   */
  private emitReloadError(policyPath: string, firstFailure: boolean): void {
    if (!this.onReloadError) return
    try {
      this.onReloadError({
        policyPath,
        error: this.loaded.error ?? '',
        ruleCount: this.loaded.rules.length,
        firstFailure,
        ts: Date.now(),
      })
    } catch {
      /* callback must never break the engine */
    }
  }

  /** Resolve the shipped builtin rule-file paths. Two sources:
   *   1. Constructor `builtinRulePaths` option (operator override)
   *   2. Empty list (disable append)
   *  The constructor option always wins — an empty array disables the
   *  append, so operators who want to ship without a baseline can do so
   *  explicitly. There is no environment-variable override: a bare
   *  `process.env` read would let anyone who can set the process
   *  environment swap the baseline rule file. */
  private resolveBuiltinPaths(): string[] {
    if (this.builtinRulePaths !== null) {
      return [...this.builtinRulePaths]
    }
    return []
  }

  /**
   * per-file errors from the last multi-file load.
   * Empty for the legacy single-file path. Operators can inspect this
   * to diagnose a bad user-supplied path without enabling debug
   * logging. The accessor returns a fresh array on each call so the
   * caller can safely retain / serialize it.
   */
  getLastLoadErrors(): ReadonlyArray<{ path: string; error: string }> {
    return this.lastLoadErrors.map((e) => ({ ...e }))
  }

  /**
   * closes the loop on `context_adjust`. When a rule
   * fires with `decision: 'context_adjust'` and the action's `guidance`
   * carries a limit (`max_attempts` / `escalate_threshold`), this method
   * asks the GuidanceStateMachine whether the (sessionId, policyId,
   * templateId) tuple has crossed the limit; if so, it flips the
   * decision to `escalate` and mirrors the original guidance into
   * `escalate.guidance_ref` so audit consumers see both the user-facing
   * guidance text and the promotion that pulled it out of the loop.
   *
   * Why AFTER `composeDecision()`: the matched rule list is already
   * sorted priority-descending by `RuleLoader.compilePolicy`, so
   * `matched[0]` is the deciding rule — same as the verdict rule that
   * `composeDecision()` picked. No risk of "promoted by a rule that
   * wasn't the top one".
   *
   * Why per-key, not per-decision: cross-session bleed would let one
   * session's noisy guidance exhaust another session's budget. The
   * machine's per-engine scoping keeps tests isolated (every test
   * builds a fresh engine) without needing a global reset hook.
   *
   * No-op when:
   *   - the top rule isn't `context_adjust` (other decisions don't carry
   *     a guidance counter — `block` is already a hard stop, `escalate`
   *     is already escalated, `modify`/`substitute` are advisory),
   *   - the rule's `guidance` has neither `max_attempts` nor
   *     `escalate_threshold` (the rule author opted out of the loop
   *     detector — guidance just plays every time),
   *   - `ctx.sessionId` is missing (no key → no counter; documented
   *     limitation — asset paths / tool calls without a session
   *     header never escalate, by design).
   */
  private applyGuidancePromotion(
    decision: SecurityDecision,
    matched: CompiledRule[],
    ctx: InterventionContext,
  ): void {
    if (decision.decision !== 'context_adjust') return
    const rule = matched[0]
    if (!rule) return
    const guidance = rule.action?.guidance
    if (!guidance) return
    const limits: GuidanceRecordLimits = {}
    if (guidance.max_attempts !== undefined) limits.maxAttempts = guidance.max_attempts
    if (guidance.escalate_threshold !== undefined) {
      limits.escalateThreshold = guidance.escalate_threshold
    }
    if (limits.maxAttempts === undefined && limits.escalateThreshold === undefined) {
      // Rule author declared context_adjust but didn't set a limit; that
      // means "play this guidance every time" — no escalation possible.
      return
    }
    const sessionId = ctx.sessionId
    if (!sessionId) return
    const policyId = rule.id
    const templateId = guidance.template_id
    const result = this.guidanceMachine.record(
      { sessionId, policyId, templateId },
      limits,
    )
    // Always stamp the count, even when not escalating — audit consumers
    // rely on this to reconstruct "how many times did we re-issue this
    // guidance before flipping".
    decision.guidance_count = result.state.count
    if (!result.shouldEscalate) return
    // Promotion: context_adjust → escalate, with the original guidance
    // payload mirrored into escalate.guidance_ref so audit sees the
    // user-facing text that triggered the loop. Pairs with
    // `decision.escalate_promoted: true` so downstream code can tell
    // "SPL author wrote escalate" from "engine auto-promoted".
    decision.decision = 'escalate'
    decision.escalate_promoted = true
    decision.escalate = {
      ...(decision.escalate ?? {}),
      guidance_ref: {
        adjustment_id: guidance.adjustment_id,
        template_id: guidance.template_id,
        template_version: guidance.template_version,
        rendered: guidance.rendered,
        allowed_scope: guidance.allowed_scope,
        alternatives: guidance.alternatives ? [...guidance.alternatives] : undefined,
        escalate_threshold: guidance.escalate_threshold,
        max_attempts: guidance.max_attempts,
        guidance_count: result.state.count,
      },
    }
  }
}
