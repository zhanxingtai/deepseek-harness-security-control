/**
 * client-side wire types.
 *
 * The client half of the securityMonitor Remote namespace. Mirrors the
 * host's `src/typert/descriptors.ts` so the two compile projects agree
 * on the same shape. The dedicated test in
 * `tests/client/wire.test.ts` parses the host descriptors file and
 * asserts the method name list matches — the shared types are
 * intentionally duplicated because the two `tsconfig` projects have
 * different `rootDir`s and cannot import across each other.
 *
 * Why a mirror instead of a shared file: the host (`tsconfig.json`,
 * `rootDir: ./src`) and the client (`tsconfig.client.json`,
 * `rootDir: ./src/client`) are independent `tsc -b` projects. Any file
 * imported by the client would be required to live under
 * `src/client/`, which would force the host to import from a `client/`
 * path — the wrong direction. A mirror keeps the two surfaces
 * independent and the contract is enforced by a single test.
 */

/**
 * The bridge object the client receives via
 * `ctx.inject(['remote.securityMonitor'], scope => scope.get('remote.securityMonitor'))`.
 *
 * Each method is async because the host-side handlers in
 * `src/typert/host.ts` use `async` wrappers around NDJSON readers
 * (file IO) and the InterventionEngine reload path. The client always
 * `await`s the result.
 *
 * Failure mode: any of these methods may reject if the host has not
 * registered the namespace (e.g. when running in a unit-test
 * environment that does not load `src/index.ts`). The client treats
 * every rejection as "degraded snapshot" and renders an error banner
 * instead of crashing the page.
 */
/**
 * Mirror of the host's authoritative `Mode` union
 * (`src/types/index.ts`). The client compiles under a
 * separate `tsconfig.client.json` rootDir and cannot import host files
 * (see the header docblock) — this local copy is the sanctioned
 * mirror, kept in sync by the wire-contract test.
 */
export type Mode = 'audit' | 'enforce'

export interface SecurityMonitorBridge {
  overview(): Promise<OverviewSnapshot>
  // Returns `{ rows, total }` so the
  // Policy Hits footer can render "Showing N of M blocks"
  // `total` is the filter-aware count of all
  // matching blocks in the file.
  recentBlocks(args?: { limit?: number; offset?: number; scope?: 'blocked' | 'all-hits'; includeRaw?: boolean }): Promise<{ rows: BlockRow[]; total: number }>
  // The client does not carry a `rules()` call —
  // the SPL rules tab is removed (Metrics / Event Stream / Top Blocks /
  // Config only). The HOST still exposes the `rules` RPC for the
  // `/security rules` CLI surface; the wire-contract test treats it as
  // a host-only method (see tests/client/wire.test.ts).
  reload(): Promise<ReloadResult>
  getConfig(): Promise<ConfigSnapshot>
  validateConfigPatch(patch: ConfigPatch): Promise<ConfigValidationResult>
  saveConfigDraft(patch: ConfigPatch): Promise<ConfigDraftResult>
  getConfigDraftStatus(): Promise<ConfigDraftStatus>
  // Config livePatch. Mirrors the host's
  // `src/typert/descriptors.ts#LivePatchPatch` — same partial-Config
  // shape as ConfigPatch plus the earlier blocks the classifier knows.
  previewLivePatch(patch: LivePatchPatch): Promise<LivePatchPreview>
  applyLivePatch(patch: LivePatchPatch): Promise<LivePatchApplyResult>
  // Returns `{ rows, total }` so the
  // Events tab footer can render "Showing N of M events"
  // `total` is the filter-aware count of all
  // matching events in the file.
  events(args?: EventsArgs): Promise<{ rows: RawEventRow[]; total: number }>
}

/**
 * Overview payload — mirrors the host's
 * `src/typert/descriptors.ts#OverviewSnapshot` and the
 * `/security status` handler's `SecurityStatus` so a single render
 * drives both the settings page and the CLI status text.
 *
 * `last24hTotalCount` + `byLayer` mirror the host's
 * Metrics-page fields.
 */
export interface OverviewSnapshot {
  mode: Mode
  totalEvents: number
  blockCount: number
  last24hBlockCount: number
  /** 威胁事件(规则命中,含 warn 级"标记但未拦截";
   *  拦截是其子集),全时间 + 近 24h 两个计数。 */
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
  /** runtime 层命中行的可执行文件,TOOL 列回退
   *  显示 `spawn: <exe>`。 */
  exe?: string
  tool_call_id?: string
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
  /** 仅 `includeRaw:true` 请求时返回:该命中事件的完整
   *  NDJSON 记录(`truncateRawJson` 截断,与 Events tab `raw_json` 同
   *  一语义);摘要轮询不带此字段。镜像 host 侧 BlockRow。 */
  raw_json?: string
}

/** Return shape for the `reload` RPC. */
export interface ReloadResult {
  ok: boolean
  ruleCount?: number
  error?: string
}

/**
 * Config tab snapshot. Mirrors the host's
 * `src/typert/descriptors.ts#ConfigSnapshot`. The client treats the
 * shape as opaque data and renders it field-by-field via the Config
 * tab component — no client-side mutation, no draft or livePatch
 * fields. See the
 * host descriptor for the platform-deployment-only fields that are
 * intentionally NOT exposed (the marketplace Config strips them).
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
  // The client iterates `Object.keys(snapshot)` to render section
  // headers in the Config tab; missing keys would silently
  // drop sections. See the dedicated parity test
  // (`tests/configParity.test.ts`) for the cross-file contract.
  sensitivePathGuard: ConfigSnapshotSensitivePathGuard
  inlinePromptInjection: ConfigSnapshotInlinePromptInjection
  stdioMirror: ConfigSnapshotStdioMirror
  envPassthroughGuard: ConfigSnapshotEnvPassthroughGuard
  loopedToolDetector: ConfigSnapshotLoopedToolDetector
  tokenUsageDetector: ConfigSnapshotTokenUsageDetector
  sinkDiskLow: ConfigSnapshotSinkDiskLow
}

// The 7 §6.2 sub-block client mirrors.
// Each interface is byte-identical to the corresponding host entry
// in src/typert/descriptors.ts. The dedicated parity test asserts
// this — adding a field to one side without mirroring the other
// will fail `tests/configParity.test.ts > client ↔ host mirror`.
export interface ConfigSnapshotSensitivePathGuard {
  enabled: boolean
  paths: string[]
  watchEnabled: boolean
  watchDebounceMs: number
}

export interface ConfigSnapshotInlinePromptInjection {
  enabled: boolean
  patterns: string[]
  excerptMaxChars: number
}

export interface ConfigSnapshotStdioMirror {
  enabled: boolean
  payloadLimitBytes: number
  outputPath: string
}

export interface ConfigSnapshotEnvPassthroughGuard {
  enabled: boolean
  keys: string[]
}

export interface ConfigSnapshotLoopedToolDetector {
  enabled: boolean
  windowMs: number
  thresholdPerWindow: number
}

export interface ConfigSnapshotTokenUsageDetector {
  enabled: boolean
  windowMs: number
  burstFactor: number
  minBaselineSamples: number
}

export interface ConfigSnapshotSinkDiskLow {
  recoverMarginBytes: number
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

/**
 * Config patch payload. Mirrors the host's
 * `src/typert/descriptors.ts#ConfigPatch`. The client sends a partial
 * Config — every sub-block is optional, the patch only carries the
 * fields the operator actually changed. The host rejects unknown
 * top-level keys via the Schemastery Config schema.
 */
export interface ConfigPatch {
  mode?: Mode
  enabled?: boolean
  hostId?: string
  containerId?: string
  collector?: Partial<ConfigSnapshotCollector>
  application?: Partial<ConfigSnapshotApplication>
  networkCapture?: Partial<ConfigSnapshotNetworkCapture>
  runtimeHooks?: Partial<ConfigSnapshotRuntimeHooks>
  intervention?: Partial<ConfigSnapshotIntervention>
  inlineGuards?: Partial<ConfigSnapshotInlineGuards>
  // The 7 §6.2 sub-blocks.
  // ALLOWED_TOP_KEYS in src/config/validate.ts accepts the same keys;
  // without these declarations, a client sending a
  // `{ sensitivePathGuard: {...} }` patch would be rejected by the
  // type system even though the runtime accepts it.
  sensitivePathGuard?: Partial<ConfigSnapshotSensitivePathGuard>
  inlinePromptInjection?: Partial<ConfigSnapshotInlinePromptInjection>
  stdioMirror?: Partial<ConfigSnapshotStdioMirror>
  envPassthroughGuard?: Partial<ConfigSnapshotEnvPassthroughGuard>
  loopedToolDetector?: Partial<ConfigSnapshotLoopedToolDetector>
  tokenUsageDetector?: Partial<ConfigSnapshotTokenUsageDetector>
  sinkDiskLow?: Partial<ConfigSnapshotSinkDiskLow>
}

/**
 * Return shape for `validateConfigPatch`. The client renders
 * `errors[]` inline (one per field) and `warnings[]` in a confirm
 * dialog before Save Draft. `normalized` is the post-validation
 * snapshot the client renders as the "what will apply() see"
 * preview, so the operator can confirm the field coercion before
 * committing the draft to disk.
 */
export interface ConfigValidationResult {
  ok: boolean
  errors: string[]
  warnings: string[]
  /** When `ok=true`, the normalized ConfigSnapshot the patch would produce. */
  normalized: ConfigSnapshot | null
}

/**
 * Return shape for `saveConfigDraft`. A saved draft never hot-applies:
 * `restartRequired` is always `true` so the client can render the
 * "restart to apply" banner without branching. `path` is the
 * absolute path to the persisted draft file
 * (`~/.dsh/security-monitor-config.draft.json`).
 */
export interface ConfigDraftResult {
  ok: boolean
  path: string
  /** Always `true` for restart-scoped drafts; live-apply keys may flip this to `false`. */
  restartRequired: true
  /** On failure, the error message (also logged on the host). */
  error?: string
}

/**
 * Passive read shape for `getConfigDraftStatus`. The client uses it
 * to show the "Config draft pending" banner on first render so the
 * operator knows there is an unmerged change waiting for the next
 * restart. `path=''` when no draft is present (the client hides the
 * banner in that case).
 */
export interface ConfigDraftStatus {
  path: string
  patchedAt: string
  operator: string
}

/**
 * Config livePatch wire types. Mirrors the
 * host's `src/typert/descriptors.ts` LivePatch* shapes (the two tsconfig
 * projects cannot share files — see the header docblock).
 */
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
  loopedToolDetector?: Record<string, unknown>
  tokenUsageDetector?: Record<string, unknown>
  sinkDiskLow?: Record<string, unknown>
}

export interface LivePatchPreview {
  ok: boolean
  safeKeys: string[]
  needsRestartKeys: string[]
  rejectedKeys: string[]
  warnings: string[]
  errors: string[]
}

export interface LivePatchApplyResult {
  ok: boolean
  appliedKeys: string[]
  needsRestartKeys: string[]
  rejectedKeys: string[]
  warnings: string[]
  error?: string
}

/**
 * Events tab wire types. Mirrors the
 * host's `src/typert/descriptors.ts#EventsFilter` / `#EventsArgs` /
 * `#RawEventRow` so the bridge signature stays in sync. The
 * dedicated `tests/client/wire.test.ts` parses the host descriptors
 * file and asserts the method list matches.
 */
export interface EventsFilter {
  /** Allow-list of event types. Unknown entries are dropped server-side. */
  event_type?: string[]
  /** Lower-cased; only 'blocked' | 'denied' | 'allow' are accepted. */
  outcome?: string
  /** Case-insensitive substring on the JSON-serialised raw row. */
  search?: string
}

export interface EventsArgs {
  /** Defaults to 100; clamped to [1, 1000]. */
  limit?: number
  /** Skip the newest `offset` rows (newest-first), then return the
   *  next `limit`. Combined with a stable page size this is the
   *  Load more cursor; a successful call with `offset=0` returns
   *  the first page, `offset=50` returns the second, etc.
   *  Clamped to `[0, ∞)`; an out-of-range offset returns `[]`. */
  offset?: number
  filter?: EventsFilter
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

/**
 * Method name list — keep in sync with
 * `src/typert/descriptors.ts#SECURITY_MONITOR_INVOCATIONS`. The
 * `tests/client/wire.test.ts` test parses the host file and asserts
 * that this list matches the host's `method` fields, so the
 * contract is verified at test time.
 *
 * `'rules'` is intentionally ABSENT — the host keeps
 * the `rules` RPC for the `/security rules` CLI, but no client tab
 * consumes it after the SPL rules page removal. The wire test asserts
 * client methods == host methods minus the host-only set.
 */
export const SECURITY_MONITOR_METHODS = [
  'overview',
  'recentBlocks',
  'reload',
  'getConfig',
  'validateConfigPatch',
  'saveConfigDraft',
  'getConfigDraftStatus',
  'previewLivePatch',
  'applyLivePatch',
  'events',
] as const

export type SecurityMonitorMethod = (typeof SECURITY_MONITOR_METHODS)[number]
