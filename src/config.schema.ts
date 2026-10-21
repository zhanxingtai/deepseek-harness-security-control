/**
 * Schemastery Config schema.
 *
 * Every nested block has typed fields with the same defaults
 * `normalizeConfig` produces, so a marketplace install gets fast-fail on
 * misspelled sub-keys and explicit error messages on out-of-range numeric
 * fields.
 *
 * Strategy (mirrors src/config.ts defaults):
 *   - Strict on fields whose shape is closed (booleans, enum unions,
 *     known-size numbers).
 *   - Loose on collections (`excludeCommandLines`, `sensitiveKeyPatterns`,
 *     etc.) — Schemastery's `Schema.array(Schema.string())` accepts any
 *     string array and `normalizeConfig` later coerces element types.
 *   - Deep discriminated unions (AuthConfig bearer/machine-v1) stay as
 *     `Schema.object({})` — they're normalized in
 *     `defaultCollectorConfig` and re-validating them here would
 *     duplicate the logic.
 *
 * The validated object is then passed to `normalizeConfig` so the
 * downstream code stays unchanged. validateConfig never throws — it
 * returns undefined on failure so the caller can fall back to
 * `normalizeConfig` with a warn.
 */

import Schema from '@deepseek-ai/schemastery'

// `Schema` is the runtime callable. The d.ts declares a global
// `Schemastery` interface (not a namespace) whose `<S, T>` parameter
// list IS the instance type. `SchemaT<S>` is a convenience alias so
// callers can declare `SchemaT<ConfigShape>` without re-spelling the
// type parameter pair. Note: `Schemastery.Schema` does NOT exist —
// the instance interface IS named `Schemastery` itself.
type SchemaT<S = unknown> = Schemastery<S, S>

/** Mode switch — re-exported from the authoritative union in `src/types/index.js`. */
import type { Mode } from './types/index.js'
export type { Mode }

// ---------------------------------------------------------------------------
// Collector sub-block
// ---------------------------------------------------------------------------

export const CollectorConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  localOutputPath: Schema.string().default('~/.dsh/security-events.jsonl'),
  batchSize: Schema.number().default(100),
  flushIntervalMs: Schema.number().default(1000),
  validateEvents: Schema.boolean().default(true),
  // surfaced from implicit collector state — 50 MiB default.
  maxFileBytes: Schema.number().default(50 * 1024 * 1024),
  // Free disk space below which the collector emits a warn. Default 500 MiB.
  diskWarnWatermarkBytes: Schema.number().default(500 * 1024 * 1024),
  // Free disk space below which the collector stops accepting events.
  // Default 100 MiB; the disk-low degraded mode is hooked here.
  diskLowWatermarkBytes: Schema.number().default(100 * 1024 * 1024),
  // redact the tool_params JSON-string carrier before
  // persistence — `tool_params` is the sole tool-args carrier.
  redactRawParams: Schema.boolean().default(true),
  // Install / deploy diagnostic log path
  // (operator opt-in, default off). See Config['collector'] doc for
  // the full phase list.
  debugLogPath: Schema.string().default(''),
})

// ---------------------------------------------------------------------------
// Application sub-block
// ---------------------------------------------------------------------------

// Top-level `networkCapture` marketplace config block — see
// `NetworkCaptureConfig` in src/config.ts. Mirrored here so the
// Schemastery `Config` schema covers every block on the live `Config`
// interface (parity asserted by tests/configParity.test.ts).
export const NetworkCaptureConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  redactBodies: Schema.boolean().default(true),
  captureResponseBody: Schema.boolean().default(true),
  maxBodyBytes: Schema.number().default(1024 * 1024),
  sseSummaryChunks: Schema.number().default(5),
  sseSummaryLastChunks: Schema.number().default(1),
  includeHosts: Schema.array(Schema.string()).default([]),
  excludeHosts: Schema.array(Schema.string()).default([]),
  excludeUrls: Schema.array(Schema.string()).default([]),
  sensitiveKeyPatterns: Schema.array(Schema.string()).default([]),
  captureDns: Schema.boolean().default(false),
})

// Top-level `runtimeHooks` block.
export const RuntimeHooksConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  networkEnabled: Schema.boolean().default(true),
  logPath: Schema.string().default('~/.dsh/security-events-runtime.jsonl'),
  hookPath: Schema.string().default(''),
  excludeCommandLines: Schema.array(Schema.string()).default([]),
  // pre-spawn interception seam.
  enabledAtSubprocess: Schema.boolean().default(true),
  blockAtSubprocess: Schema.boolean().default(false),
  failOpenOnError: Schema.boolean().default(true),
})

export const ApplicationConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  captureUserPrompt: Schema.boolean().default(true),
  captureSystemPrompt: Schema.boolean().default(true),
  captureAgentPlan: Schema.boolean().default(true),
  captureReasoning: Schema.boolean().default(true),
  // 100k chars matches `defaultApplicationConfig`; oversized tool
  // results fall back to the 4k `result_preview` (see collector code).
  toolResultMaxChars: Schema.number().default(100000),
  sessionTtlMs: Schema.number().default(1800000),
})

// ---------------------------------------------------------------------------
// System sub-block
// ---------------------------------------------------------------------------

export const InterventionConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  // `intervention.mode` has NO default at the Schema
  // layer. `normalizeConfig` reads `obj.intervention.mode ?? defaultMode`
  // where `defaultMode` is the top-level `mode` field. A Schema default
  // of `'audit'` would always win over the parent's `mode: 'enforce'`,
  // breaking the propagation contract — see the regression test in
  // `tests/configSchema.test.ts > a user override flows through Schema
  // then normalizeConfig`.
  mode: Schema.union(['audit', 'enforce'] as const),
  // Default policy path uses the .spl.yaml extension per the SPL
  // specification (canonical name: `security-policy.spl.yaml`);
  // `.json` / `.yaml` extensions still resolve via the RuleLoader
  // extension-less fallback.
  policyPath: Schema.string().default('~/.dsh/security-policy.spl.yaml'),
  // marketplace multi-file policy loader. Empty array
  // (= default) keeps the legacy single-file `policyPath` flow active.
  // When non-empty the engine switches to `loadMultiplePolicies`, which
  // loads each user-supplied path in order and sorts the merged set by
  // priority (ties keep the user's rule ahead).
  policyPaths: Schema.array(Schema.string()).default([]),
  reloadIntervalMs: Schema.number().default(30000),
  // Matches DEFAULTS_INTERVENTION.decisionTimeoutMs (150 ms — the
  // empirical value, see the `rm -rf /` false-positive rationale in
  // config.ts). Schema and normalize defaults must stay in parity.
  decisionTimeoutMs: Schema.number().default(150),
  failStrategy: Schema.union([
    'fail_open',
    'fail_closed',
    'fail_open_high_risk_only',
  ] as const).default('fail_open'),
})

// ---------------------------------------------------------------------------
// InlineGuards sub-block (schema mirror)
// ---------------------------------------------------------------------------

export const InlineGuardsConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  // token strings identifying the engine launcher surface
  // that powers the 015 restart-without-patch rule. Empty array is
  // silently re-asserted to the marketplace fallback by
  // `normalizeConfig` so the safety net cannot be downgraded by
  // removing entries.
  engineLaunchers: Schema.array(Schema.string()).default([]),
  // npm package name of the plugin itself; powers the 001 uninstall
  // rule.
  pluginPackageName: Schema.string().default('sst-security-control-dsh'),
  // File-name markers that, when present alongside `--patch`,
  // indicate a legitimate restart.
  patchMarkers: Schema.array(Schema.string()).default([]),
})

// ---------------------------------------------------------------------------
// Sensitive-path guard sub-block (  §6.2)
// ---------------------------------------------------------------------------

export const SensitivePathGuardConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  paths: Schema.array(Schema.string()).default([]),
  watchEnabled: Schema.boolean().default(true),
  watchDebounceMs: Schema.number().default(500),
})

// ---------------------------------------------------------------------------
// Inline prompt-injection guard sub-block (  §6.2 第二项)
// ---------------------------------------------------------------------------

export const InlinePromptInjectionConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  patterns: Schema.array(Schema.string()).default([]),
  excerptMaxChars: Schema.number().default(80),
})

// ---------------------------------------------------------------------------
// Stdio pipe mirror sub-block (  §6.2)
// ---------------------------------------------------------------------------

export const StdioMirrorConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  // Matches DEFAULTS_STDIO_MIRROR.enabled: marketplace default-off
  // posture — the wrapper is Linux-only validated, Windows was the
  // original failure surface.
  enabled: Schema.boolean().default(false),
  // Per-chunk cap applied to mirror payloads. Default 1 MiB per ticket
  // acceptance (`>1 MiB 截断`).
  payloadLimitBytes: Schema.number().default(1024 * 1024),
  // NDJSON output path. Empty string means "derive from
  // collector.localOutputPath" in normalizeConfig — the Schema layer
  // accepts the empty default and lets normalizeConfig fill in the path.
  outputPath: Schema.string().default(''),
})

// ---------------------------------------------------------------------------
// Inline env-passthrough guard sub-block (  §6.2)
// ---------------------------------------------------------------------------

export const EnvPassthroughGuardConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  // Operator-added env-var keys. Empty → `normalizeConfig` re-asserts the
  // marketplace hardcoded 10-key deny-list (`DEFAULT_DANGEROUS_ENV_KEYS`).
  // `BASH_FUNC_*` lives in `DEFAULT_DANGEROUS_ENV_PREFIXES` and is not
  // exposed for operator override (no legitimate use).
  keys: Schema.array(Schema.string()).default([]),
})

// ---------------------------------------------------------------------------
// Inline sensitive-header guard sub-block
// ---------------------------------------------------------------------------

export const SensitiveHeaderGuardConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  // Operator-added header keys. Empty → `normalizeConfig` re-asserts the
  // marketplace hardcoded 4-key deny-list (`DEFAULT_DANGEROUS_HEADER_KEYS`).
  // The marketplace rejects `enabled: false` (mirrors sibling inline guards).
  keys: Schema.array(Schema.string()).default([]),
  // Out-of-frame harness-plane exemption allow-list +
  // audit-only vs hard-block switch for out-of-frame traffic. See
  // `SensitiveHeaderGuardConfig` in src/config/types.ts for the threat
  // model. Both are 🔴 restart-required (not livePatch keys).
  harnessPlaneHosts: Schema.array(Schema.string()).default([]),
  enforceOutOfFrame: Schema.boolean().default(false),
})

// ---------------------------------------------------------------------------
// Looped-tool detector sub-block (  §6.2)
// ---------------------------------------------------------------------------

export const LoopedToolDetectorConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  enabled: Schema.boolean().default(true),
  windowMs: Schema.number().default(60000),
  thresholdPerWindow: Schema.number().default(100),
})

// ---------------------------------------------------------------------------
// Token-usage detector sub-block (  §6.2)
// ---------------------------------------------------------------------------

export const TokenUsageDetectorConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  // Master switch for the llm/stream tee + burst detector. Defaults to true
  // per ticket — the tap is audit-only and never modifies the stream.
  enabled: Schema.boolean().default(true),
  // Sliding-window size for the per-session baseline. Default 60 s.
  windowMs: Schema.number().default(60000),
  // Baseline multiplier that constitutes a burst (≥3× per ticket).
  burstFactor: Schema.number().default(3),
  // Learning-floor sample count — calls below this only populate the
  // baseline (前几次调用只学习不告警).
  minBaselineSamples: Schema.number().default(5),
})

// ---------------------------------------------------------------------------
// Sink disk-low degradation sub-block (  §6.2)
// ---------------------------------------------------------------------------

export const SinkDiskLowConfigSchema: SchemaT<Record<string, unknown>> = Schema.object({
  // Hysteresis margin above `collector.diskLowWatermarkBytes` before the
  // degraded mode is lifted. Default 50 MiB; non-finite / negative values
  // are re-clamped to the default inside `normalizeConfig`.
  recoverMarginBytes: Schema.number().default(50 * 1024 * 1024),
})

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

/** : top-level Config shape. Each nested block is
 *  strongly typed (see the per-block Schema constants above). Field
 *  types are the public-facing vocabulary; `normalizeConfig` accepts
 *  this shape and fills in any deeper defaults that the Schema does
 *  not cover (AuthConfig discriminated union, hostname fallback, etc.).
 *
 *  The parity test in `tests/configParity.test.ts` catches any future
 *  drift.
 */
export interface ConfigShape {
  enabled?: boolean
  mode?: Mode
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

/** Top-level Config Schema. Per-field strictness:
 *   - `enabled` / `mode`: strict (boot-time decisions; misconfig must
 *     fail loudly). Note: schemastery's `Schema.object(...).loose(true)`
 *     would silently downgrade these to defaults-on-failure, so we
 *     intentionally do NOT call `.loose(true)` at the top level. The
 *     `autofix: true` option (set at call site) tolerates unknown
 *     top-level keys without weakening field-level strictness.
 *   - Nested blocks: each has its own strict Schema (see per-block
 *     definitions). The strict Schema blocks unknown sub-keys from
 *     slipping through silently — marketplace authors get an early
 *     error on a misspelled `redactRawparams` vs the canonical
 *     `redactRawParams`.
 *
 */
export const Config: SchemaT<ConfigShape> = Schema.object({
  enabled: Schema.boolean().default(true),
  // Default 'enforce' so a fresh install lands in enforce directly,
  // matching the bundled `policies/default-policy.spl.yaml` and
  // `cordis.patch.yml` `mode: enforce` declarations (three surfaces
  // agree on install). Operators who explicitly set `mode: audit` still
  // get audit (explicit overrides default at the normalize layer).
  mode: Schema.union(['audit', 'enforce'] as const).default('enforce'),
  // Default values are filled in by `normalizeConfig` (hostname
  // fallback / bare-metal token `'host'`); the empty-string schema
  // default is overwritten on every entry.
  hostId: Schema.string().default(''),
  containerId: Schema.string().default(''),
  collector: CollectorConfigSchema,
  application: ApplicationConfigSchema,
  networkCapture: NetworkCaptureConfigSchema,
  intervention: InterventionConfigSchema,
  runtimeHooks: RuntimeHooksConfigSchema,
  inlineGuards: InlineGuardsConfigSchema,
  sensitivePathGuard: SensitivePathGuardConfigSchema,
  inlinePromptInjection: InlinePromptInjectionConfigSchema,
  stdioMirror: StdioMirrorConfigSchema,
  envPassthroughGuard: EnvPassthroughGuardConfigSchema,
  sensitiveHeaderGuard: SensitiveHeaderGuardConfigSchema,
  loopedToolDetector: LoopedToolDetectorConfigSchema,
  tokenUsageDetector: TokenUsageDetectorConfigSchema,
  sinkDiskLow: SinkDiskLowConfigSchema,
})

/**
 * Run Schema validation, returning the validated object on success or
 * `undefined` on failure. Never throws — callers should branch on the
 * return value and fall back to `normalizeConfig`.
 *
 * Implementation detail: Schemastery throws `ValidationError` on
 * invalid input. We catch and convert to `undefined` so the caller
 * can do `const validated = validateConfig(raw); if (validated) … else
 * fallback()`. Logging the actual error is the caller's responsibility
 * (the apply() handler already has the logger).
 *
 * when the input passes, the returned object carries the
 * Schemastery-filled defaults for every known sub-field. The caller
 * passes it to `normalizeConfig` which treats it as authoritative
 * (overwriting any deeper custom defaults like AuthConfig).
 */
export function validateConfig(rawConfig: unknown): ConfigShape | undefined {
  try {
    // autofix:true drops unknown top-level keys without downgrading
    // strict fields like `mode`. The schemastery default of strict
    // would throw on any unknown key — bad for marketplace forward
    // compatibility where future releases add new top-level knobs.
    return Config(rawConfig ?? {}, { autofix: true })
  } catch {
    return undefined
  }
}