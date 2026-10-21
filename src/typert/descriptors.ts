/**
 * Typert method descriptors — server-side.
 *
 * These seven methods are the contract between the host (server)
 * plugin process and the DSH Web client (browser) UI. The
 * browser-side component consumes them through the
 * `ctx.remote.securityMonitor.*` bridge that the client half of this
 * ships — see `src/client/remote.ts`.
 *
 * Keep this file minimal: it only carries the method name list and a
 * human-readable description per method. The wire-level signature
 * (input/output types) lives on `registerSecurityMonitorRemote` and
 * the matching client-side `RemoteResult<T>` type wrappers in
 * `src/client/remote.ts`. Sharing a single source-of-truth here lets the host
 * test (`tests/typert/host.test.ts`) cross-check against the
 * client-side expectations.
 */

export const SECURITY_MONITOR_INVOCATIONS = [
  { method: 'overview', description: 'mode / event counts / uptime / loaded rule count' },
  { method: 'recentBlocks', description: 'last N SPL rule-hit decisions (default 20; scope=blocked|all-hits, default blocked — all-hits includes warn-marked non-intercepted hits; includeRaw=true adds the capped raw event per row for detail expansion)' },
  { method: 'rules', description: 'list enabled SPL rules with priority / risk / decision' },
  { method: 'reload', description: 'force a policy reload; returns {ok, ruleCount, error?}' },
  { method:'getConfig', description:'current effective Config snapshot — read-only mirror for the Config tab'},
  // Config form + draft. The client-side Config tab
  // calls these on every field onChange (debounced 500ms) and on the
  // Save Draft button. They never hot-apply — the result is a draft
  // file that the next `apply()` call merges on top of the patch YAML.
  { method: 'validateConfigPatch', description: 'validate a partial Config patch against the marketplace schema — returns errors / warnings / normalized' },
  { method: 'saveConfigDraft', description: 'persist a validated Config patch to ~/.dsh/security-monitor-config.draft.json; takes effect on next apply()' },
  { method: 'getConfigDraftStatus', description: 'check whether a pending draft file exists; returns its path + timestamp + operator' },
  // Config livePatch. previewLivePatch classifies
  // every dotted key of a partial Config patch into 🟢 safe-apply / 🟡
  // restart-required / 🔴 rejected (self-protection switches) with no
  // side effects; applyLivePatch applies the 🟢 subset to the running
  // components (shared-config in-place mutation + timer/watcher rebuilds)
  // and returns needsRestart for the 🟡 remainder. Orthogonal to
  // saveConfigDraft (draft still restart-scoped); never persists anything.
  { method: 'previewLivePatch', description: 'classify a Config patch: safeKeys / needsRestartKeys / rejectedKeys / warnings — read-only' },
  { method: 'applyLivePatch', description: 'apply the safe-apply subset of a Config patch to the running plugin at runtime; returns appliedKeys / needsRestartKeys' },
  // Events: raw event-stream view. The operator
  // clicks the Events tab to browse / filter the underlying
  // NDJSON without leaving the DSH Web settings page. The wire
  // contract is a filter object (event_type / outcome / search)
  // plus a clampable limit. `RawEventRow.raw_json` is the full
  // event JSON string (truncated to a safe size with a
  // `...[truncated]` breadcrumb so the marketplace bundle stays
  // under the per-row shipping budget).
  { method: 'events', description: 'browse / filter raw collected events from the local NDJSON; newest first' },
] as const

export type SecurityMonitorMethod = (typeof SECURITY_MONITOR_INVOCATIONS)[number]['method']

/**
 * Overview payload — mirrors the `SecurityStatus` shape used by the
 * `/security status` CLI handler so a single client-side render
 * can drive both surfaces (status tab + CLI status text).
 *
 * `last24hTotalCount` + `byLayer` feed the Metrics page
 * (BY LAYER bucket + Last-24h total events). Both are
 * full-log streaming scans on the host (`scanOverviewAggregates`);
 * `loadedRuleCount` stays because the `/security rules` CLI surface
 * (and the Metrics "SPL rules loaded" stat) still report it.
 */
import type { Mode } from '../types/index.js'

export interface OverviewSnapshot {
  mode: Mode
  totalEvents: number
  blockCount: number
  last24hBlockCount: number
  /** 威胁事件(规则命中,含 warn 级"标记但未拦截";
   *  拦截是其子集),全时间 + 近 24h 两个计数。Metrics 页第 4 张卡片。 */
  threatCount: number
  last24hThreatCount: number
  /** ALL events (not just blocks) with `ts` in the last 24 h. */
  last24hTotalCount: number
  /** Per-`layer` event counts over the whole log; layerless rows
   *  bucket under `'unknown'`. */
  byLayer: Record<string, number>
  uptimeSec: number
  loadedRuleCount: number
  localOutputPath: string
}

/** Per-row payload for `recentBlocks`. Mirrors the BlockRow. */
export interface BlockRow {
  ts: number
  session_id?: string
  agent_id?: string
  tool_name?: string
  /** runtime 层命中行(spawn_intent/denied)的可执行文件,
   *  客户端 TOOL 列回退显示 `spawn: <exe>`。 */
  exe?: string
  tool_call_id?: string
  /** 审计发现档(security_audit 无 intervention)的
   *  `audit_action`(tamper / detect / …),客户端决策列回退显示,
   *  避免审计行只有 "unknown"。决策命中行为 undefined。 */
  audit_action?: string
  decision: string
  decision_internal?: string
  block_reason?: string
  block_code?: string
  policy_id?: string
  /** 规则作者声明的严重等级(`critical`/`high`/`medium`/
   *  `low`),由 `DecisionComposer` 通过 runtime seam 决定是否降级为
   *  `warn`。缺失表示未声明 severity 字段(向后兼容旧策略)。 */
  severity?: 'critical' | 'extreme' | 'high' | 'medium' | 'low'
  /** 当本次命中的规则 severity 为 medium/low 且 decision
   *  从 authored `block` 降级为 runtime `warn` 时为 `true`。自审策略
   *  (`self-protection-*`)无视 severity 永远保留 block,本字段保持
   *  `undefined`。审计行让 UI 能区分"作者意图 block"和"运行时降级
   *  warn"。 */
  severity_downgraded?: boolean
  /**
   * 惰性明细:仅 `recentBlocks({includeRaw:true})` 请求时
   * 携带;3 s 自动轮询的摘要模式不返回此字段,轮询载荷与缺省
   * 摘要模式一致。内容为该命中事件的完整 NDJSON 记录(经 `truncateRawJson`
   * 截断,与 Events tab 的 `raw_json` 同一语义),UI 展开详情时一次性
   * 拉取并缓存。
   */
  raw_json?: string
}

/** Summary row for `rules` — same fields the `/security rules` handler surfaces. */
export interface RuleSummary {
  id: string
  name: string
  enabled: boolean
  priority: number
  /** The rule's declared `severity:` (spec §3). `null` when the rule
   *  declares none. `extreme` is the top SPL tier — above `critical`. */
  risk_level: 'extreme' | 'critical' | 'high' | 'medium' | 'low' | 'info' | null
  decision: string
  block_reason?: string
}

/** Return shape for the `reload` RPC. */
export interface ReloadResult {
  ok: boolean
  ruleCount?: number
  error?: string
}

/**
 * Events tab wire contract.
 *
 * `events()` returns the most-recent N raw NDJSON events, with an
 * optional filter (event_type allow-list + outcome + case-insensitive
 * substring search on the JSON string). The per-row payload carries
 * only the operator-visible summary fields PLUS the full event as a
 * JSON string (`raw_json`), so the UI can expand each row to show
 * the complete record without a separate RPC.
 *
 * `raw_json` is truncated to `MAX_RAW_JSON_BYTES` (16 KiB) with a
 * `...[truncated]` breadcrumb so a single event with a 4 KiB body +
 * 50 KiB `raw_params` does not blow up the marketplace bundle. The
 * UI surfaces a "raw truncated" hint when the breadcrumb is present.
 *
 * Filter normalisation happens server-side in `normaliseEventsFilter`
 * — unknown `event_type` values are silently dropped (the marketplace
 * never rejects an RPC, invariant #3), `outcome` is lowercased + matched
 * against a known set, `search` is trimmed and capped at 64 chars
 * (never regex-compiled, see filter predicate).
 */
export interface EventsFilter {
  /** Allow-list of event types. Unknown entries are dropped. */
  event_type?: string[]
  /** Lower-cased; only `'blocked' | 'denied' | 'allow'` are accepted. */
  outcome?: string
  /** Case-insensitive substring on the JSON-serialised raw row. */
  search?: string
}

export interface EventsArgs {
  /** Defaults to 100; clamped to `[1, 1000]`. */
  limit?: number
  /** Skip the newest `offset` rows (newest-first), then return the
   *  next `limit`. Load more cursor; see wire client `EventsArgs`. */
  offset?: number
  filter?: EventsFilter
}

/** `events()` return shape. `rows` is the requested
 *  page (newest-first); `total` is the filter-aware count of all
 *  matching events in the file, so the Events tab footer can
 *  render "Showing N of M events". */
export interface EventsPage {
  rows: RawEventRow[]
  total: number
}

/** `recentBlocks()` return shape. Mirrors `EventsPage`:
 *  the visible page plus the filter-aware total for the footer. */
export interface RecentBlocksPage {
  rows: BlockRow[]
  total: number
}

export interface RawEventRow {
  ts: number
  event_id?: string
  event_type: string
  session_id?: string
  agent_id?: string
  tool_name?: string
  block_code?: string
  block_reason?: string
  policy_id?: string
  outcome?: string
  /** Full event JSON; truncated to MAX_RAW_JSON_BYTES with a
   *  `...[truncated]` breadcrumb when the original exceeded the cap. */
  raw_json: string
}

/** Per-row raw JSON byte cap. Above this we keep the head and append
 *  the breadcrumb; the rest is lost. */
export const MAX_RAW_JSON_BYTES = 16 * 1024

/**
 * Serialise-and-cap helper shared by every wire surface that carries a
 * full raw event (`events()` / `RawEventRow.raw_json`, and Policy Hits
 * `BlockRow.raw_json` in `includeRaw` mode). Keeping the truncation in
 * one place guarantees the two tabs cap byte-identically.
 */
export function truncateRawJson(serialised: string): string {
  return serialised.length > MAX_RAW_JSON_BYTES
    ? serialised.slice(0, MAX_RAW_JSON_BYTES) + '...[truncated]'
    : serialised
}

/** Search-term character cap. Above this we truncate (silently) so a
 *  pathological RPC body cannot exhaust the matcher. */
export const MAX_SEARCH_CHARS = 64

/** Allow-list of `event_type` values the Events tab can filter on. The
 *  list mirrors the platform-standard types observed in the local
 * NDJSON : tool layer, network layer, runtime seam
 *  inline-guard audits. Unknown values from the RPC are silently
 *  dropped server-side. */
export const ALLOWED_EVENT_TYPES: ReadonlySet<string> = new Set([
  'agent_tool_call',
  'agent_tool_result',
  'agent_message',
  'agent_session_start',
  'agent_stop',
  'agent_start',
  'network_http',
  'security_audit',
  'runtime_spawn_intent',
  'runtime_spawn_denied',
  'runtime_terminal_intent',
  'runtime_resolve_intent',
  'runtime_resolve_denied',
  'file_read',
  'file_write',
  'runtime_stdio_mirror',
  'runtime_stdio_mirror_exit',
  'runtime_stdio_mirror_error',
])

/** Allow-list of `outcome` values. Anything else is dropped
 *  server-side (no error to the client — invariant #3). */
export const ALLOWED_OUTCOMES: ReadonlySet<string> = new Set([
  'blocked',
  'denied',
  'allow',
])

/**
 * Config tab snapshot.
 *
 * Mirrors the normalised Config shape from `src/config.ts`.
 * Platform-deployment-only fields
 * (`endpoint`, `auth.*`, `outbox.*`, `system.*`, `environment.*`)
 * are not part of the marketplace surface, so they cannot appear
 * in the snapshot.
 *
 * The UI consumes this snapshot in the Config tab as a
 * read-only mirror. The client edits a copy of the snapshot and
 * persists via `saveConfigDraft`; livePatch hot-applies a
 * sub-set of these keys via `applyLivePatch` after signoff.
 *
 * Field parity with `Config` is the contract; the dedicated test
 * `tests/typert/host.test.ts` (> 'getConfig() returns 9-group
 * snapshot') walks every group and asserts the field set matches.
 *
 * Inline-guards: the actual `InlineGuardsConfig` carries
 * `engineLaunchers / pluginPackageName / patchMarkers` — no
 * boolean `enabled` field. The snapshot mirrors the actual shape; the
 * UI shows every field with a lock icon to convey"immutable
 * design".
 */
export interface ConfigSnapshot {
  mode: Mode
  enabled: boolean
  hostId: string
  containerId: string
  collector: ConfigSnapshotCollector
  application: ConfigSnapshotApplication
  networkCapture: ConfigSnapshotNetworkCapture
  runtimeHooks: ConfigSnapshotRuntimeHooks
  intervention: ConfigSnapshotIntervention
  inlineGuards: ConfigSnapshotInlineGuards
  // The 7 §6.2 sub-block mirrors.
  // The UI iterates `Object.keys(snapshot)` for the Config
  // tab section headers; missing keys would silently drop sections.
  // The dedicated parity test (`tests/configParity.test.ts`) walks
  // every key on the live Config interface and asserts the matching
  // snapshot field is present.
  sensitivePathGuard: ConfigSnapshotSensitivePathGuard
  inlinePromptInjection: ConfigSnapshotInlinePromptInjection
  stdioMirror: ConfigSnapshotStdioMirror
  envPassthroughGuard: ConfigSnapshotEnvPassthroughGuard
  sensitiveHeaderGuard: ConfigSnapshotSensitiveHeaderGuard
  loopedToolDetector: ConfigSnapshotLoopedToolDetector
  tokenUsageDetector: ConfigSnapshotTokenUsageDetector
  sinkDiskLow: ConfigSnapshotSinkDiskLow
}

export interface ConfigSnapshotCollector {
  localOutputPath: string
  batchSize: number
  flushIntervalMs: number
  validateEvents: boolean
  maxFileBytes: number
  diskWarnWatermarkBytes: number
  diskLowWatermarkBytes: number
  redactRawParams: boolean
  /** Optional — collectors may set or omit. Empty string = unset. */
  debugLogPath: string
}

export interface ConfigSnapshotApplication {
  captureUserPrompt: boolean
  captureSystemPrompt: boolean
  captureAgentPlan: boolean
  captureReasoning: boolean
  toolResultMaxChars: number
  sessionTtlMs: number
}

export interface ConfigSnapshotNetworkCapture {
  enabled: boolean
  redactBodies: boolean
  captureResponseBody: boolean
  maxBodyBytes: number
  sseSummaryChunks: number
  sseSummaryLastChunks: number
  includeHosts: string[]
  excludeHosts: string[]
  excludeUrls: string[]
  sensitiveKeyPatterns: string[]
  captureDns: boolean
}

export interface ConfigSnapshotRuntimeHooks {
  enabled: boolean
  networkEnabled: boolean
  logPath: string
  hookPath: string
  excludeCommandLines: string[]
  enabledAtSubprocess: boolean
  blockAtSubprocess: boolean
  failOpenOnError: boolean
}

export interface ConfigSnapshotIntervention {
  enabled: boolean
  mode: Mode
  policyPath: string
  policyPaths: string[]
  reloadIntervalMs: number
  decisionTimeoutMs: number
  failStrategy: 'fail_open' | 'fail_closed' | 'fail_open_high_risk_only'
}

export interface ConfigSnapshotInlineGuards {
  engineLaunchers: string[]
  pluginPackageName: string
  patchMarkers: string[]
}

// ---------------------------------------------------------------------------
// §6.2 sub-block snapshots
// ---------------------------------------------------------------------------
//
// Every block below mirrors its sibling interface in src/config.ts
// verbatim so the UI is a read-only window over the LIVE normalised
// Config (no drift).
//
// The dedicated parity test `tests/configParity.test.ts` walks
// every key on these sub-block interfaces and asserts it matches the
// corresponding entry in src/config.ts. Adding a new field to a
// Config sub-block without mirroring it here will fail the test
// rather than silently shipping a UI that lags the live config.

// §6.2 — inline sensitive-path deny-list
export interface ConfigSnapshotSensitivePathGuard {
  enabled: boolean
  paths: string[]
  watchEnabled: boolean
  watchDebounceMs: number
}

// §6.2 — inline prompt-injection deny-list
export interface ConfigSnapshotInlinePromptInjection {
  enabled: boolean
  patterns: string[]
  excerptMaxChars: number
}

// §6.2 — stdio pipe mirror
export interface ConfigSnapshotStdioMirror {
  enabled: boolean
  payloadLimitBytes: number
  outputPath: string
}

// §6.2 — inline env-passthrough deny-list
export interface ConfigSnapshotEnvPassthroughGuard {
  enabled: boolean
  keys: string[]
}

// §6.2 — inline sensitive-header deny-list (outbound HTTP)
// `harnessPlaneHosts` is the allow-list for harness-
// plane hosts whose headers are exempted from the deny-list;
// `enforceOutOfFrame` is the audit-only vs hard-block switch for hits
// outside the harness plane. Both fields exist on the live Config
// interface (`src/config/types.ts` SensitiveHeaderGuardConfig); if the
// host snapshot drops them, the Config tab UI renders controls that
// cannot round-trip through validateConfigPatch. See the migration
// note in README.md and the RESTART_FIELDS entry in
// src/config/livePatch.ts.
export interface ConfigSnapshotSensitiveHeaderGuard {
  enabled: boolean
  keys: string[]
  harnessPlaneHosts: string[]
  enforceOutOfFrame: boolean
}

// §6.2 — per-tool loop detector (audit-only)
export interface ConfigSnapshotLoopedToolDetector {
  enabled: boolean
  windowMs: number
  thresholdPerWindow: number
}

// §6.2 — token-usage burst detector (audit-only)
export interface ConfigSnapshotTokenUsageDetector {
  enabled: boolean
  windowMs: number
  burstFactor: number
  minBaselineSamples: number
}

// §6.2 — sink disk-low degradation
export interface ConfigSnapshotSinkDiskLow {
  recoverMarginBytes: number
}

/* ---------------------------------------------------------------- *
 * Config tab form + draft persistence.    *
 *                                                                    *
 * The client-side Config tab is upgraded from a read-only mirror     *
 * to a controlled form. The client NEVER edits the live Config *
 * — every field change ships a `Partial<Config>` patch to the host   *
 * which validates it against the marketplace schema and writes the   *
 * result to `~/.dsh/security-monitor-config.draft.json`. The next    *
 * `apply()` call reads the file and deep-merges it on top of the     *
 * patch YAML (see `src/config/draft.ts`).                            *
 *                                                                    *
 * The two new methods below are the wire contract — the host side    *
 * in `src/typert/host.ts` implements them, the client mirror in      *
 * `src/client/wire.ts` re-declares the same types.                  *
 * ---------------------------------------------------------------- */

/**
 * Partial Config — the body of `validateConfigPatch` and
 * `saveConfigDraft`. We accept the full `Config` shape (every key
 * optional) so the client can send arbitrary sub-block edits; the
 * server rejects unknown top-level keys via the Schemastery schema.
 */
export type ConfigPatch = Partial<{
  mode: Mode
  enabled: boolean
  hostId: string
  containerId: string
  collector: Record<string, unknown>
  application: Record<string, unknown>
  networkCapture: Record<string, unknown>
  intervention: Record<string, unknown>
  runtimeHooks: Record<string, unknown>
  inlineGuards: Record<string, unknown>
  // The 7 §6.2 sub-blocks.
  // ALLOWED_TOP_KEYS in src/config/validate.ts accepts the same keys;
  // without these declarations, a client sending a
  // `{ sensitivePathGuard: {...} }` patch would be rejected by the
  // type system even though the runtime accepts it.
  sensitivePathGuard: Record<string, unknown>
  inlinePromptInjection: Record<string, unknown>
  stdioMirror: Record<string, unknown>
  envPassthroughGuard: Record<string, unknown>
  sensitiveHeaderGuard: Record<string, unknown>
  loopedToolDetector: Record<string, unknown>
  tokenUsageDetector: Record<string, unknown>
  sinkDiskLow: Record<string, unknown>
}>

/**
 * Return shape for `validateConfigPatch`. The client renders the
 * `errors[]` list inline (one per field) and the `warnings[]` list
 * in a confirm dialog. `normalized` carries the post-validation
 * form — `saveConfigDraft` re-validates anyway, so this is purely
 * informational ("this is what the file will contain").
 */
export interface ConfigValidationResult {
  ok: boolean
  /** Per-field error messages (e.g. "intervention.failStrategy: expected fail_open|..."). */
  errors: string[]
  /** Non-blocking warnings (e.g. "mode=enforce but policyPath does not exist"). */
  warnings: string[]
  /** When `ok=true`, the normalized Config the patch would produce. `null` on failure. */
  normalized: ConfigSnapshot | null
}

/**
 * Return shape for `saveConfigDraft`. The `path` is the absolute
 * resolved path to the draft file (after `~` expansion); the
 * `restartRequired` flag is always `true` — the draft is
 * picked up on the next `apply()` call.
 */
export interface ConfigDraftResult {
  ok: boolean
  /** Absolute path to the draft file. Empty string on failure. */
  path: string
  /** Always `true` for restart-scoped drafts; live-apply keys may flip this to `false`. */
  restartRequired: true
  /** On failure, the error message (also logged on the host). */
  error?: string
}

/**
 * `getConfigDraftStatus` is a passive read — the client uses it to
 * show the "Config draft pending" banner on first render so the
 * operator knows there is an unmerged change waiting for the next
 * restart. The shape is intentionally narrow: presence + timestamp
 * is enough; the patch body is intentionally NOT included (the
 * snapshot the operator sees comes from `getConfig()`, which is
 * the LIVE config, not the draft).
 */
export interface ConfigDraftStatus {
  /** Absolute path to the draft file when one exists, else empty. */
  path: string
  /** ISO 8601 timestamp from the draft envelope. Empty when none. */
  patchedAt: string
  /** Operator tag from the draft envelope (env / auth context). Empty when none. */
  operator: string
}

/* ---------------------------------------------------------------- *
 * Config livePatch wire contract.          *
 *                                                                    *
 * `previewLivePatch` / `applyLivePatch` accept the same partial      *
 * Config shape as `saveConfigDraft` (every sub-block optional) plus  *
 * the earlier blocks the livePatch classifier knows about             *
 * (sensitivePathGuard / inlinePromptInjection / stdioMirror /        *
 * envPassthroughGuard / loopedToolDetector / tokenUsageDetector /    *
 * sinkDiskLow). The three-way classification is server-side truth:   *
 *   🟢 safe-apply       — applied to the running components          *
 *   🟡 restart-required — returned, never applied                    *
 *   🔴 rejected         — self-protection switches; ANY rejected key *
 *                         refuses the WHOLE patch + emits a high-    *
 *                         severity security_audit                    *
 * ---------------------------------------------------------------- */

/** Body of `previewLivePatch` / `applyLivePatch`. */
export interface LivePatchPatch {
  mode?: Mode
  enabled?: boolean
  hostId?: string
  containerId?: string
  collector?: Record<string, unknown>
  application?: Record<string, unknown>
  networkCapture?: Record<string, unknown>
  intervention?: Record<string, unknown>
  runtimeHooks?: Record<string, unknown>
  inlineGuards?: Record<string, unknown>
  sensitivePathGuard?: Record<string, unknown>
  inlinePromptInjection?: Record<string, unknown>
  stdioMirror?: Record<string, unknown>
  envPassthroughGuard?: Record<string, unknown>
  sensitiveHeaderGuard?: Record<string, unknown>
  loopedToolDetector?: Record<string, unknown>
  tokenUsageDetector?: Record<string, unknown>
  sinkDiskLow?: Record<string, unknown>
}

/** Return shape for `previewLivePatch` — pure classification, no side effects. */
export interface LivePatchPreview {
  ok: boolean
  /** 🟢 dotted keys that applyLivePatch would apply immediately. */
  safeKeys: string[]
  /** 🟡 dotted keys that need a restart; applyLivePatch will NOT apply them. */
  needsRestartKeys: string[]
  /** 🔴 dotted keys that can never be live-patched; their presence refuses the whole apply. */
  rejectedKeys: string[]
  /** Non-blocking operator hints (e.g. blockAtSubprocess is a no-op in audit mode). */
  warnings: string[]
  /** Schema / shape errors (ok=false). */
  errors: string[]
}

/** Return shape for `applyLivePatch`. */
export interface LivePatchApplyResult {
  ok: boolean
  /** 🟢 dotted keys actually applied to the running components. */
  appliedKeys: string[]
  /** 🟡 dotted keys observed but left untouched (restart to take effect). */
  needsRestartKeys: string[]
  /** 🔴 dotted keys that refused the patch (empty when ok=true). */
  rejectedKeys: string[]
  warnings: string[]
  /** Human-readable error when ok=false. */
  error?: string
}

/* ------------------------------------------------------------------ *
 * Wire-shape TypertContribution / InvocationDescriptor
 * builder.
 *
 * The harness `ctx.typert.register(contribution)` populates
 * `ctx.typert.local` with the strict descriptors the TypertGateway
 * uses to look up the receiver per endpoint
 * (the host gateway). Each descriptor
 * carries the routing fields (`id`, `service`, `namespace`, `method`,
 * `invocation`, `parameters`, `result`) — the harness resolves
 * `(service, method)` to a Cordis Service method via
 * `receiverContext.get(service)` + `Reflect.get(receiver, method)`.
 *
 * `SECURITY_MONITOR_INVOCATIONS` is the single source of truth for
 * which methods the bridge exposes (matching the client-side
 * `SecurityMonitorMethod` union in `src/client/wire.ts`). The descriptor builder
 * below lifts that list into the harness's wire shape.
 * ------------------------------------------------------------------ */

import type { InvocationDescriptor } from '@deepseek-ai/dsh-typert-protocol'

const SECURITY_MONITOR_NAMESPACE = 'securityMonitor' as const

/**
 * Payload codecs must be STRICT, not
 * `src-json`: the browser-side `ctx.remote.$mount(contribution)`
 * rejects any descriptor whose input parameter lacks a strict codec
 * (the host gateway client `requireStrictCodec`),
 * so a src-json parameter codec makes the namespace unmountable and
 * the settings page never gets a bridge.
 *
 * The validator is hand-rolled (no zod dependency — marketplace
 * zero-runtime-dep contract): payloads are plain JSON objects whose
 * field-level validation already happens inside the host handlers
 * (`validateConfigPatch` / livePatch classifier / clampLimit). The
 * boundary codec only guarantees "plain object or undefined".
 * `create()` materializes a fresh validator per call, matching the
 * per-realm semantics of generated codecs.
 */
function makePayloadCodec(pkgName: string, method: string) {
  return {
    mode: 'strict' as const,
    typeSymbol: `${pkgName}#${SECURITY_MONITOR_NAMESPACE}/${method}/payload`,
    create: () => ({
      parse(value: unknown): unknown {
        if (value === undefined) return value
        if (typeof value !== 'object' || value === null || Array.isArray(value)) {
          throw new Error(`securityMonitor/${method}: payload must be a plain object`)
        }
        return value
      },
    }),
  }
}

/**
 * Build one `InvocationDescriptor` for a single method. The result
 * codec stays pass-through (`src-json`) — only INPUT parameters are
 * required to be strict by the client assembly; results are host-
 * trusted JSON. Payload parameters declare `acceptsUndefined` so a
 * client may omit the payload entirely (e.g. `recentBlocks()`).
 */
function makeInvocationDescriptor(
  pkgName: string,
  method: string,
  hasPayload: boolean,
): InvocationDescriptor {
  const id = `${pkgName}#${SECURITY_MONITOR_NAMESPACE}/${method}`
  const parameters = hasPayload
    ? [
        {
          name: 'payload',
          wire: 'payload',
          source: 'json' as const,
          codec: makePayloadCodec(pkgName, method),
          acceptsUndefined: true as const,
        },
      ]
    : []
  return {
    id,
    service: SECURITY_MONITOR_NAMESPACE,
    namespace: SECURITY_MONITOR_NAMESPACE,
    method,
    invocation: { kind: 'direct' },
    parameters,
    result: { mode: 'src-json' },
  }
}

/**
 * Map of methods that take a single `payload` argument (vs methods
 * that take no arguments). Mirrors the `payload` parameter shape the
 * host-side handlers in `host.ts` already expect
 * (`recentBlocks({limit,scope})`, `validateConfigPatch(patch)`,
 * `saveConfigDraft(patch)`, `events({limit,filter})`).
 */
const METHODS_WITH_PAYLOAD = new Set<SecurityMonitorMethod>([
  'recentBlocks',
  'validateConfigPatch',
  'saveConfigDraft',
  'previewLivePatch',
  'applyLivePatch',
  'events',
])

/**
 * Build the full `InvocationDescriptor[]` for the
 * `sst-security-control-dsh#securityMonitor/*` endpoint family.
 *
 * Returns descriptors with NO `handler` field — the harness's
 * TypertGateway looks up the receiver via `descriptor.service` and
 * calls `Reflect.get(receiver, descriptor.method)`. The methods
 * themselves live on the `SecurityMonitorService` Cordis Service
 * registered via `ctx.reflect.provide('securityMonitor', service)`
 * in `host.ts`.
 */
export function buildSecurityMonitorDescriptors(
  pkgName: string,
): InvocationDescriptor[] {
  return SECURITY_MONITOR_INVOCATIONS.map((inv) =>
    makeInvocationDescriptor(pkgName, inv.method, METHODS_WITH_PAYLOAD.has(inv.method)),
  )
}
