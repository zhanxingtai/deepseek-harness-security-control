/**
 * Config interface declarations.
 *
 * Pure type module: no runtime values, no side-effects. Consumers
 * (`src/collectors/*`, `src/intervention/*`, `src/typert/host.ts`,
 * `src/commands/security.ts`) continue to import types from
 * `'../config.js'` via the barrel re-export in `src/config.ts`.
 *
 * The runtime defaults + normalize logic live in:
 *   - `src/config/defaults.ts` — DEFAULTS_* constants + fallback lists
 *   - `src/config/normalize.ts` — `normalizeConfig` + `withDefaults` helper
 *
 * The companion modules `livePatch.ts` / `validate.ts` / `draft.ts` stay
 * as separate concerns (config mutation lifecycle + draft-file I/O).
 */

import type { Mode } from '../types/index.js'

/**
 * application-layer HTTP request capture configuration.
 * moved from `application.httpCapture` to top-level
 * `networkCapture` so the marketplace plugin has a clean surface.
 *
 * The collector monkey-patches Node's built-in `http`/`https` modules and
 * `global.fetch` inside the harness process. It emits `network_http` events
 * with method/url/host/headers/body/response_body. Default mode is audit
 * (collect-only); enforce blocking is a future extension.
 */
export interface NetworkCaptureConfig {
  enabled: boolean
  redactBodies: boolean
  captureResponseBody: boolean
  /**
   * RESPONSE body budget (bytes) for persisted `network_http` recv rows.
   * Pre-split this single key bounded both directions; configs that only
   * carry `maxBodyBytes` inherit it as the request budget too (see
   * `inheritLegacyRequestBodyBudget` in normalize.ts).
   */
  maxBodyBytes: number
  /**
   * REQUEST body budget (bytes) for persisted `network_http` send rows
   * (e.g. LLM prompts). SPL / data-leak rule evaluation ALWAYS runs on
   * the full pre-truncation body — this cap is persistence-only.
   * Defaults to 64 KiB; falls back to the operator's `maxBodyBytes` when
   * a legacy config does not set it.
   */
  maxRequestBodyBytes: number
  /**
   * SSE stream folding. For `text/event-stream` responses
   * keep the first N chunks and the last M chunks, replacing the middle with
   * a summary chunk. Set to 0 to disable folding and keep the full stream.
   */
  sseSummaryChunks: number
  sseSummaryLastChunks: number
  includeHosts: string[]
  excludeHosts: string[]
  excludeUrls: string[]
  /**
   * Noise-suppression prefix table for the OBSERVATION stream (the
   * send/recv network_http events). Requests whose path prefix matches
   * (case-insensitive, trailing-slash tolerant) are NOT emitted — the
   * expensive body redaction / SSE fold is skipped entirely — but the
   * policy engine still evaluates the raw body (blocking surface is
   * untouched) and the sensitive-header guard still runs at the seam.
   * Defaults cover the OpenAI-compatible LLM main link (`/v1/chat/
   * completions`), Anthropic (`/v1/messages`) and OTLP telemetry
   * (`/v1/logs|traces|metrics`) — vendor-neutral by path, not domain.
   * Clearing this list disables the filter; the collector emits a
   * one-shot config/warn audit row so the change is never silent.
   */
  ignoreUrls: string[]
  /** Companion host table for `ignoreUrls` — exact host match
   * (lowercased, trailing-dot stripped, optional `host:port` form).
   * Default: `registry.npmjs.org`. Same suppression semantics as
   * `ignoreUrls`. */
  ignoreHosts: string[]
  sensitiveKeyPatterns: string[]
  /** : opt-in `dns.lookup` / `dns.resolve*` capture. */
  captureDns: boolean
}

export interface CollectorConfig {
  localOutputPath: string
  batchSize: number
  flushIntervalMs: number
  validateEvents: boolean
  /** : surfaced from implicit collector state — 50 MiB default. */
  maxFileBytes: number
  /**
   * Operator declaration: the audit log file's LIFECYCLE is owned by an
   * external tool (a log rotator, a shipper, a volume manager).
   *
   * When `true`, a file-lifecycle anomaly — the log disappeared, shrank,
   * or was swapped for another file — is treated as an expected lifecycle
   * event: the sink re-baselines and logs a WARN instead of raising an
   * `integrity/detect` gap.
   *
   * Default `false` (every anomaly is reported). Turn it on only when
   * the rotation strategy cannot be recognised by the archive-sibling
   * heuristic (e.g. `copytruncate`, or a rotator that moves the file to
   * another directory). The trade-off is explicit: with the flag on, a
   * hostile deletion of the audit trail is no longer reported.
   */
  externallyManagedLog: boolean
  /** Free disk space below which the collector emits a warn. Default 500 MiB. */
  diskWarnWatermarkBytes: number
  /** Free disk space below which the collector stops accepting events. Default 100 MiB. */
  diskLowWatermarkBytes: number
  /**
   * redact the `tool_params` JSON-string carrier before
   * persistence. The redacted JSON lands on `tool_params`; the list of
   * masked key paths lands on `redacted_keys` for post-hoc audit replay.
   * `tool_params` is the sole tool-args carrier.
   *
   * hardcoded to `true` in marketplace form —
   * `normalizeConfig` rejects `redactRawParams: false` input and
   * silently re-asserts the safe default. The literal type prevents
   * TypeScript code from compiling against a `false` value.
   */
  redactRawParams: true
  /**
   * Sliding-window content dedup for repetitive `security_audit` rows
   * (policy reload heartbeats, watcher re-fires). Same target + same
   * content hash within the window are merged into one emission's
   * bookkeeping; a different hash always emits immediately. 0 disables.
   */
  auditDedupWindowMs: number
  /**
   * install / deploy diagnostic log path. Empty = disabled.
   * The path is auto-created and chmod 0o600 after every write.
   */
  debugLogPath?: string
}

export interface ApplicationConfig {
  captureUserPrompt: boolean
  captureSystemPrompt: boolean
  captureAgentPlan: boolean
  captureReasoning: boolean
  /** Full `agent_tool_result.result` is emitted when under this char cap;
   *  oversized results fall back to 4k `result_preview` + full-length hash. */
  toolResultMaxChars: number
  sessionTtlMs: number
}

export interface InterventionConfig {
  enabled: boolean
  mode: Mode
  /** Legacy single-file policy path. New deployments should use `policyPaths[]`. */
  policyPath: string
  /** : additional policy paths layered on top of `policyPath`. */
  policyPaths: string[]
  reloadIntervalMs: number
  decisionTimeoutMs: number
  failStrategy: 'fail_open' | 'fail_closed' | 'fail_open_high_risk_only'
}

export interface RuntimeHooksConfig {
  enabled: boolean
  networkEnabled: boolean
  logPath: string
  hookPath?: string
  excludeCommandLines: string[]
  /** : install gate for the pre-spawn interception seam. */
  enabledAtSubprocess: boolean
  /** : when true AND `mode ==='enforce'`, a block throws to abort fork. */
  blockAtSubprocess: boolean
  /** : when true, SPL errors fall through to original spawn. */
  failOpenOnError: boolean
}

export interface InlineGuardsConfig {
  /**
   * token strings identifying the engine launcher surface.
   * Powers the 015 restart-without-patch rule. The marketplace default
   * covers `pnpm dsh` / `npx dsh` / `node bin.ts` / `systemd-run` /
   * `systemctl`. Operators may add additional launchers but the safety
   * net cannot be disabled by removing entries — `normalizeConfig`
   * re-asserts the defaults if the array is empty.
   */
  engineLaunchers: string[]
  /** npm package name of the plugin itself; powers the 001 uninstall rule. */
  pluginPackageName: string
  /** File-name markers that, when present alongside `--patch`, indicate a legitimate restart. */
  patchMarkers: string[]
}

/**
 * §6.2 : inline sensitive-path deny-list + plugin-owned
 * `fs.watch` observer. The `enabled` switch is honoured at runtime;
 * `paths` falls back to the hardcoded deny-list when the operator
 * supplies an empty array (the safety net cannot be downgraded — same
 * pattern as `inlineGuards.engineLaunchers`).
 */
export interface SensitivePathGuardConfig {
  /** Master switch for the inline guard. Defaults to true. */
  enabled: boolean
  /** Additional deny-list patterns. Empty → fallback to the marketplace
   *  hardcoded list (mirrors `inlineGuards.engineLaunchers`). */
  paths: string[]
  /** Master switch for the `fs.watch` observer (observability only). */
  watchEnabled: boolean
  /** Debounce window in ms for change events. */
  watchDebounceMs: number
}

/**
 * §6.2 第二项: inline prompt-injection guard. Mirrors
 * `SensitivePathGuardConfig` — `patterns: []` silently re-asserts the
 * marketplace hardcoded `DEFAULT_INLINE_PROMPT_INJECTION_PATTERNS` list.
 * Operators can append their own regex sources via `patterns`, but the
 * safety net cannot be downgraded by clearing the list.
 *
 * See `src/intervention/InlinePromptInjection.ts` for the catalogue +
 * matcher implementation.
 */
export interface InlinePromptInjectionConfig {
  /** Master switch for the inline guard. Defaults to true. */
  enabled: boolean
  /** Additional fingerprint regex source strings. Empty → fallback to the
   *  marketplace hardcoded 24-pattern catalogue. */
  patterns: string[]
  /** Sample-excerpt context window in chars. Default 80. */
  excerptMaxChars: number
}

/**
 * §6.2 : stdio pipe mirror — argv-sidecar wrapper at the
 * pre-spawn seam. When enabled, `RuntimeHook.wrap()` rewrites the harness's
 * spec.argv to launch the bundled `lib/runtime/stdio-mirror.js` wrapper
 * which captures child stdin/stdout/stderr bytes to a local NDJSON file
 * for post-hoc inspection. The wrapper is spawned by the HARNESS, not by
 * the plugin, so the marketplace sandbox (`dependencies: {}`,
 * `dshWorkshop.permissions: ["network:none"]`) is preserved.
 *
 * Eval happens on the ORIGINAL argv (before rewrite); mirror is a
 * reconstruction observability tool, NOT a security boundary. SELF_PROTECTION
 * 014/015 fire on the user's real command, never on the wrapper's argv.
 */
export interface StdioMirrorConfig {
  /** Master switch for the stdio pipe mirror. Defaults to true. */
  enabled: boolean
  /** Per-chunk cap applied to mirror payloads (UTF-8 bytes). Default
   *  `1024 * 1024` (1 MiB) per ticket acceptance. */
  payloadLimitBytes: number
  /** NDJSON output file path. Defaults to the SAME
   * `collector.localOutputPath` (stdio mirror
   *  NDJSON unification). Wrapper events are appended to the host
   *  plugin's NDJSON stream on the same ts axis — audit consumers
   *  read ONE file. Operators may set this to a custom path for
   *  forensic isolation (e.g. routing mirror bytes to a separate
   *  volume); the host plugin's disk-low / integrity checks only
   *  apply to the path it writes to (the default), so a custom
   *  output path is the operator's responsibility. */
  outputPath: string
}

/**
 * §6.2 : inline env-passthrough guard config.
 * Mirrors `SensitivePathGuardConfig` / `InlinePromptInjectionConfig` —
 * `keys: []` silently re-asserts the marketplace hardcoded 10-key deny-list
 * (`DEFAULT_DANGEROUS_ENV_KEYS`: `LD_PRELOAD` / `LD_LIBRARY_PATH` /
 * `NODE_OPTIONS` / `PYTHONPATH` / `PYTHONSTARTUP` / `NODE_PATH` /
 * `BASH_ENV` / `ENV` / `PROMPT_COMMAND` / `SSH_AUTH_SOCK`).
 * `BASH_FUNC_*` is prefix-matched separately via
 * `DEFAULT_DANGEROUS_ENV_PREFIXES`.
 *
 * See `src/intervention/EnvPassthroughGuard.ts` for the comparator
 * implementation and the per-key rationale.
 */
export interface EnvPassthroughGuardConfig {
  /** Master switch for the inline guard. Defaults to true. */
  enabled: boolean
  /** Operator-added env-var keys (matched case-insensitively against
   *  `params.env`). Empty → fallback to the marketplace hardcoded 6-key
   *  list. */
  keys: string[]
}

/**
 * Inline sensitive-header deny-list. Blocks outbound
 * HTTP requests that propagate a known-dangerous authentication /
 * authorization header (`Authorization` / `Cookie` /
 * `Proxy-Authorization` / `X-API-Key`). Mirrors the InlineSelfProtection
 * / SensitivePathGuard / InlinePromptInjection / EnvPassthroughGuard
 * pattern: deny-list is hardcoded and non-overridable — `keys: []` in
 * `normalizeConfig` is silently re-asserted to the marketplace
 * fallback list. `enabled: false` is rejected by `normalizeConfig`.
 */
export interface SensitiveHeaderGuardConfig {
  /** Master switch for the inline guard. Defaults to true. */
  enabled: boolean
  /** Operator-added header keys (matched case-insensitively against
   *  request headers). Empty → fallback to the marketplace hardcoded
   *  4-key list. */
  keys: string[]
  /**
   * Hosts whose out-of-frame (no ALS tool frame) requests
   *  are exempt from the guard. The harness plane — the llm-pi-ai adapter's
   *  own provider calls, plugin telemetry — runs outside the agent/tool
   *  AsyncLocalStorage frame and legitimately carries `Authorization:
   *  Bearer <key>`, which is exactly what the deny-list blocks. Previously
   *  EVERY out-of-frame request was exempt (silently opening an
   *  exfiltration path for fetches scheduled out of the tool frame), and
   *  no operator could narrow that exemption. Now the exemption is this
   *  explicit allow-list: list your LLM provider / telemetry hosts here.
   *  Out-of-frame requests to any OTHER host are guard-evaluated; on a hit
   *  they are audited (`outcome: 'detected'`) and only hard-blocked when
   *  `enforceOutOfFrame` is true. 🔴 restart-required (not a livePatch key).
   */
  harnessPlaneHosts: string[]
  /**
   * When false (default), out-of-frame non-exempt hits are
   *  audit-only so the guard can never brick the product's own LLM traffic
   *  before the operator has populated `harnessPlaneHosts`. When true they
   *  are hard-blocked exactly like in-frame requests. 🔴 restart-required.
   */
  enforceOutOfFrame: boolean
  /**
   * Auto-discover LLM provider hosts from the host settings document
   *  (`<harness home>/settings.yaml`, `llm-pi-ai.providers.*.baseURL`)
   *  and exempt them from the guard exactly like `harnessPlaneHosts`.
   *  Customers add/replace models through the host's own configuration,
   *  so discovered hosts are operator-trusted by construction — the
   *  plugin never needs a manual list update per provider. Discovery
   *  failures degrade to "no hosts" (audit-only noise), never to a
   *  throw. Default true. 🔴 restart-required (not a livePatch key).
   */
  providerDiscovery: boolean
  /**
   * Explicit override for the settings document path used by
   *  `providerDiscovery` (non-standard deployments / tests). Empty →
   *  `defaultSettingsPath()` (`$DSH_HOME` or `~/.dsh`). 🔴 restart-required.
   */
  providerDiscoveryPath: string
  /**
   * Seed exemption hosts covering provider routes that inherit their
   *  endpoint from the installed pi-ai catalog (no explicit `baseURL`
   *  in the settings document). Operator entries UNION with the
   *  marketplace baseline. `*.`-prefixed entries match any subdomain
   *  (enterprise gateway / Azure deployment shapes). 🟢 livePatch key
   *  (`seedHosts`).
   */
  seedHosts: string[]
}

/**
 * §6.2 : per-tool call-counter loop detector.
 * Audit-only (does NOT block tool calls); emits `security_audit/looped_tool`
 * when a single `(sessionId, toolName)` pair crosses the threshold within
 * the sliding window. Operators decide policy based on the audit signal —
 * the detector is intentionally orthogonal to the SPL pipeline.
 *
 * Defaults match ticket: 60 s window, 100 calls / window.
 *
 * See `src/intervention/LoopedToolDetector.ts` for the rate-limiter
 * implementation. The detector is fail-safe (no clock dependency — the
 * host injects `ts` per call) and pure (no I/O, no event emission —
 * the host wires the hit handler).
 */
export interface LoopedToolDetectorConfig {
  /** Master switch. Defaults to true. */
  enabled: boolean
  /** Sliding-window size in ms. Default 60_000 (60 seconds). */
  windowMs: number
  /** Calls / window threshold. Default 100. */
  thresholdPerWindow: number
}

/**
 * §6.2 : per-session token-usage burst
 * detector. Audit-only (does NOT block the LLM stream); emits
 * `security_audit/anomalous_token_usage` when a single call's token total
 * exceeds `burstFactor` × the in-window mean baseline for the session.
 * The first `minBaselineSamples` calls per session only learn — no ratio
 * is computed, so a cold session cannot fire on its own early calls.
 *
 * Defaults match ticket: 60 s window, ≥3× burst factor, 5-sample
 * learning floor.
 *
 * See `src/utils/tokenUsage.ts` for the detector + the mean-vs-median
 * baseline rationale. The detector is pure (no I/O, no event emission —
 * the host wires the hit handler) and fail-safe (the host injects `ts`).
 */
export interface TokenUsageDetectorConfig {
  /** Master switch. Defaults to true. */
  enabled: boolean
  /** Sliding-window size in ms. Default 60_000 (60 seconds). */
  windowMs: number
  /** Baseline multiplier that constitutes a burst. Default 3 (≥3×). */
  burstFactor: number
  /** Learning-floor sample count — calls below this only populate the
   *  baseline. Default 5. */
  minBaselineSamples: number
}

/**
 * §6.2 : sink disk-low degradation signalling.
 * When free disk space drops below `collector.diskLowWatermarkBytes` the
 * local NDJSON sink emits `security_audit/sink_disk_low` and enters a
 * temporary degraded mode ("enforce-only persistence"): only
 * enforcement-critical events (blocked / denied / tamper / integrity-failure
 * class) keep landing; everything else is counted and dropped. On recovery
 * (free > low watermark + `recoverMarginBytes` — hysteresis so a disk
 * hovering at the watermark does not flap the mode) the sink switches back
 * and emits a recovery event carrying the dropped-event summary.
 */
export interface SinkDiskLowConfig {
  /** Hysteresis margin above the low watermark before recovery is declared.
   *  Default 50 MiB. Non-finite / negative values fall back to the default. */
  recoverMarginBytes: number
}

export interface Config {
  /** Master plugin switch. Default true. */
  enabled?: boolean
  mode: Mode
  /** Stable host identifier. Default `os.hostname()`. */
  hostId?: string
  /** Container identifier; bare-metal token is the literal `'host'`. */
  containerId?: string
  collector: CollectorConfig
  application: ApplicationConfig
  networkCapture: NetworkCaptureConfig
  intervention: InterventionConfig
  runtimeHooks: RuntimeHooksConfig
  /**
   * parameterisation for the hardcoded inline self-protection
   * safety net. See `DEFAULT_INLINE_GUARDS` in
   * `src/intervention/InlineSelfProtection.ts`.
   */
  inlineGuards: InlineGuardsConfig
  /**
   * §6.2 : inline sensitive-path deny-list + plugin-owned
   * `fs.watch` observer. Mirrors `inlineGuards` safety-net semantics —
   * `paths: []` silently re-asserts the marketplace hardcoded list.
   */
  sensitivePathGuard: SensitivePathGuardConfig
  /**
   * §6.2 第二项: inline prompt-injection guard. Hardcoded
   * 24-pattern fingerprint matcher covering instruct-override /
   * role-impersonation / tag-injection / unicode-normalize /
   * known-jailbreak-prefix payloads. `patterns: []` silently re-asserts
   * the marketplace default list (same fallback pattern as
   * `sensitivePathGuard.paths`).
   */
  inlinePromptInjection: InlinePromptInjectionConfig
  /**
   * §6.2 : stdio pipe mirror — argv-sidecar wrapper that
   * captures child stdin/stdout/stderr bytes to a local NDJSON file for
   * post-hoc inspection. The wrapper is spawned by the HARNESS on a
   * rewritten argv; eval happens on the ORIGINAL argv so SELF_PROTECTION
   * rules fire on the user's real command. See `StdioMirrorConfig` for
   * the per-stream mirror/relay dispatch.
   */
  stdioMirror: StdioMirrorConfig
  /**
   * §6.2 : inline env-passthrough guard.
   * Hardcoded 10-key deny-list (`LD_PRELOAD` / `LD_LIBRARY_PATH` /
   * `NODE_OPTIONS` / `PYTHONPATH` / `PYTHONSTARTUP` / `NODE_PATH` /
   * `BASH_ENV` / `ENV` / `PROMPT_COMMAND` / `SSH_AUTH_SOCK`) +
   * 1 prefix (`BASH_FUNC_*`). `keys: []` silently re-asserts the
   * marketplace hardcoded list so the safety net cannot be downgraded
   * by removing entries.
   */
  envPassthroughGuard: EnvPassthroughGuardConfig
  /**
   * Inline sensitive-header deny-list. Blocks
   * outbound HTTP requests carrying Authorization / Cookie /
   * Proxy-Authorization / X-API-Key. See `SensitiveHeaderGuardConfig`.
   */
  sensitiveHeaderGuard: SensitiveHeaderGuardConfig
  /**
   * §6.2 : per-tool call-counter loop detector.
   * Audit-only; fires `security_audit/looped_tool` when the configured
   * `(sessionId, toolName)` call rate crosses the threshold within the
   * sliding window. Operators decide policy based on the audit signal
   * — the detector does NOT block tool calls.
   */
  loopedToolDetector: LoopedToolDetectorConfig
  /**
   * §6.2 : per-session token-usage burst
   * detector fed by the `llm/stream` tee. Audit-only; fires
   * `security_audit/anomalous_token_usage` when a call's token total
   * exceeds `burstFactor` × the in-window mean baseline. The detector
   * never blocks or modifies the LLM stream.
   */
  tokenUsageDetector: TokenUsageDetectorConfig
  /**
   * §6.2 : sink disk-low degradation signalling
   * — `security_audit/sink_disk_low` + temporary enforce-only persistence
   * with hysteresis-gated recovery. See `SinkDiskLowConfig`.
   */
  sinkDiskLow: SinkDiskLowConfig
}