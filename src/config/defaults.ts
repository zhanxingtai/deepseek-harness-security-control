/**
 * Config defaults — single source of truth for every Config sub-block.
 *
 * Pure constants module: no normalization logic, no I/O.
 *
 * Why split out:
 *   - The companion `normalizeConfig()` (see `src/config/normalize.ts`) only
 *     needs the constants at one well-defined boundary; consumers
 *     (`localNdjsonSink`, `applicationCollector`, etc.) only need the
 *     final merged `Config` object — they should never reach into defaults.
 *   - The fallback lists (`SENSITIVE_PATH_FALLBACK`,
 *     `INLINE_PROMPT_INJECTION_FALLBACK`, `ENV_PASSTHROUGH_FALLBACK`,
 *     `INLINE_GUARD_LAUNCHER_FALLBACK` / pluginPackageName / patchMarkers)
 *     mirror the deny-lists in the corresponding
 *     `src/intervention/<Guard>.ts` modules — they are duplicated here
 *     verbatim to avoid a circular import during first-load from
 *     `bootstrap.ts`. The header comments in each block name the
 *     sibling module so future edits keep them in sync.
 */

import type {
  ApplicationConfig,
  CollectorConfig,
  EnvPassthroughGuardConfig,
  InlineGuardsConfig,
  InlinePromptInjectionConfig,
  InterventionConfig,
  LoopedToolDetectorConfig,
  NetworkCaptureConfig,
  RuntimeHooksConfig,
  SensitiveHeaderGuardConfig,
  SensitivePathGuardConfig,
  SinkDiskLowConfig,
  StdioMirrorConfig,
  TokenUsageDetectorConfig,
} from './types.js'

export const DEFAULTS_COLLECTOR: CollectorConfig = {
  localOutputPath: '~/.dsh/security-events.jsonl',
  batchSize: 100,
  flushIntervalMs: 1000,
  validateEvents: true,
  maxFileBytes: 50 * 1024 * 1024,
  // The audit log's lifecycle is the PLUGIN's by default: a missing /
  // shrunk / swapped log is reported as an integrity gap. Operators who
  // rotate the log with an external tool can declare it (see
  // CollectorConfig.externallyManagedLog).
  externallyManagedLog: false,
  diskWarnWatermarkBytes: 500 * 1024 * 1024,
  diskLowWatermarkBytes: 100 * 1024 * 1024,
  redactRawParams: true,
  auditDedupWindowMs: 10_000,
  debugLogPath: '',
}

export const DEFAULTS_APPLICATION: ApplicationConfig = {
  captureUserPrompt: true,
  captureSystemPrompt: true,
  captureAgentPlan: true,
  captureReasoning: true,
  toolResultMaxChars: 100_000,
  sessionTtlMs: 1_800_000,
}

export const DEFAULTS_NETWORK_CAPTURE: NetworkCaptureConfig = {
  enabled: true,
  redactBodies: true,
  captureResponseBody: true,
  // Response body budget (1 MiB). The request body budget is split out
  // to maxRequestBodyBytes (64 KiB) — LLM prompts dominated the NDJSON
  // volume and are rarely worth replaying in full.
  maxBodyBytes: 1024 * 1024,
  maxRequestBodyBytes: 64 * 1024,
  sseSummaryChunks: 5,
  sseSummaryLastChunks: 1,
  includeHosts: [],
  excludeHosts: [],
  excludeUrls: [],
  // Noise-suppression defaults (observation events only; blocking and
  // the sensitive-header guard are unaffected). Path prefixes cover the
  // OpenAI-compatible LLM main link, Anthropic messages, and OTLP
  // telemetry — vendor-neutral by path. Operators widen/narrow via
  // `networkCapture.ignoreUrls` / `ignoreHosts` (livePatch-able).
  ignoreUrls: ['/v1/chat/completions', '/v1/messages', '/v1/logs', '/v1/traces', '/v1/metrics'],
  ignoreHosts: ['registry.npmjs.org'],
  sensitiveKeyPatterns: [],
  captureDns: false,
}

export const DEFAULTS_INTERVENTION: InterventionConfig = {
  enabled: true,
  // Matches the Schema default (`src/config.schema.ts:381`) and the
  // normalize layer's `topMode` fallback (`src/config/normalize.ts:153`).
  // The constant is still consulted as a last-resort input shape for partial
  // operator patches; grep-survivors should follow the schema
  // default, not this literal.
  mode: 'enforce',
  // Default policy path uses the .spl.yaml extension per the SPL
  // specification. .json / .yaml extensions still resolve via the
  // RuleLoader extension-less fallback.
  policyPath: '~/.dsh/security-policy.spl.yaml',
  policyPaths: [],
  reloadIntervalMs: 30_000,
  // with the rule set grown to 69+ entries
  // (paste/upload service coverage, multilang reverse-shell, capabilities
  // manipulation, expanded self-protection), synchronous V8 regex evaluation
  // against an arbitrary agent payload now spends ~30–60 ms in worst-case
  // paths. The original 50 ms deadline was tuned for the ~20-rule baseline
  // and now trips `fail_open` on legitimate traffic — verified empirically
  // (e.g. `rm -rf /` against `rm\s+-rf\s+/($|\s)` returning allow). The
  // deadline remains small enough that no single tool call blocks the
  // event loop for any meaningful wall-clock, but gives headroom for the
  // current rule count. Operators wanting a tighter posture can override
  // via `intervention.decisionTimeoutMs` in cordis.patch.yml.
  decisionTimeoutMs: 150,
  failStrategy: 'fail_open',
}

export const DEFAULTS_RUNTIME_HOOKS: RuntimeHooksConfig = {
  enabled: true,
  networkEnabled: true,
  logPath: '~/.dsh/security-events-runtime.jsonl',
  hookPath: '',
  excludeCommandLines: [],
  enabledAtSubprocess: true,
  blockAtSubprocess: false,
  failOpenOnError: true,
}

export const VALID_FAIL_STRATEGIES = new Set<InterventionConfig['failStrategy']>([
  'fail_open',
  'fail_closed',
  'fail_open_high_risk_only',
])

// Inline-self-protection safety net: a tampered `engineLaunchers: []` must
// not silently disable the 015 restart rule. The marketplace ships a
// 7-launcher fallback; `normalizeConfig` re-applies it on empty input.
// C : include systemd-run + systemctl in the fallback so
// the safety net catches the detached-systemd-unit launch pattern that
// survived a `systemd-run --scope --property=KillMode=none` disarm test.
export const INLINE_GUARD_LAUNCHER_FALLBACK: string[] = [
  'pnpm dsh',
  'pnpm exec dsh',
  'npx dsh',
  'npx dshe',
  'node bin.ts',
  'systemd-run',
  'systemctl',
]

// Hardcoded fallbacks for the OTHER two inline-guard
// fields. The `engineLaunchers` list is UNION-merged with
// INLINE_GUARD_LAUNCHER_FALLBACK; without a fallback here `pluginPackageName`
// and `patchMarkers` flow through `...inlineGuardsInput` (spread), which
// lets operator input OVERRIDE the defaults. A tampered `cordis.patch.yml`
// could set `inlineGuards: { pluginPackageName: 'safe-package' }` to
// rename the actual string the uninstall / restart-without-patch rules
// match — neutralising the inline layer. livePatch correctly rejects
// these keys (🔴 class), but the initial-config path was unguarded.
// Apply UNION semantics here too, mirroring engineLaunchers /
// sensitivePathGuard.paths. pluginPackageName is a single string so
// the "fallback wins" rule applies; patchMarkers is an array so we
// deduped-concat.
export const INLINE_GUARD_PLUGIN_PACKAGE_NAME_FALLBACK = 'sst-security-control-dsh'
export const INLINE_GUARD_PATCH_MARKERS_FALLBACK: string[] = [
  'security-monitor.patch.yml',
  'security-monitor.patch.yaml',
]

export const DEFAULTS_INLINE_GUARDS: InlineGuardsConfig = {
  engineLaunchers: [
    'pnpm dsh',
    'pnpm exec dsh',
    'npx dsh',
    'npx dshe',
    'node bin.ts',
    'systemd-run',
    'systemctl',
  ],
  pluginPackageName: 'sst-security-control-dsh',
  patchMarkers: ['security-monitor.patch.yml', 'security-monitor.patch.yaml'],
}

// §6.2 : defaults for the inline sensitive-path guard.
// `paths` is intentionally empty — `normalizeConfig` re-asserts the
// hardcoded `SENSITIVE_PATH_FALLBACK` list on empty input so the safety
// net cannot be downgraded by the operator setting `paths: []`.
export const DEFAULTS_SENSITIVE_PATH_GUARD: SensitivePathGuardConfig = {
  enabled: true,
  paths: [],
  watchEnabled: true,
  watchDebounceMs: 500,
}

// `DEFAULT_SENSITIVE_PATHS` lives in
// `src/intervention/SensitivePathGuard.ts`; importing it here would
// introduce a circular import during the first load of `config.ts` from
// `bootstrap.ts`. The fallback list below is the SAME literal that the
// module exports — keep them in sync when extending the deny-list.
export const SENSITIVE_PATH_FALLBACK: string[] = [
  '~/.ssh/',
  '~/.ssh/id_rsa',
  '~/.ssh/id_ed25519',
  '~/.ssh/id_ecdsa',
  '~/.ssh/id_dsa',
  '~/.ssh/authorized_keys',
  '~/.ssh/known_hosts',
  '~/.ssh/config',
  '~/.aws/',
  '~/.aws/credentials',
  '~/.aws/config',
  '~/.gnupg/',
  '~/.docker/config.json',
  '~/.git-credentials',
  '~/.netrc',
  '~/.npmrc',
  '~/.pypirc',
  '/etc/shadow',
  '/etc/sudoers',
  '/etc/sudoers.d/',
  '/etc/gshadow',
  '/proc/*/environ',
  '/var/lib/dpkg/info/*',
  '169.254.169.254/',
  '169.254.169.254/latest/meta-data/',
]

// §6.2 第二项: defaults for the inline prompt-injection
// guard. `patterns` is intentionally empty — `normalizeConfig` re-asserts
// the hardcoded `INLINE_PROMPT_INJECTION_FALLBACK` list on empty input so
// the safety net cannot be downgraded by the operator setting `patterns:
// []`.
export const DEFAULTS_INLINE_PROMPT_INJECTION_GUARD: InlinePromptInjectionConfig = {
  enabled: true,
  patterns: [],
  excerptMaxChars: 80,
}

// §6.2 : defaults for the per-tool loop detector.
// windowMs + thresholdPerWindow match ticket — a tight loop
// (>100 calls / minute / tool / session) is the canonical signal.
export const DEFAULTS_LOOPED_TOOL_DETECTOR: LoopedToolDetectorConfig = {
  enabled: true,
  windowMs: 60_000,
  thresholdPerWindow: 100,
}

// §6.2 : defaults for the token-usage burst
// detector. windowMs / burstFactor / minBaselineSamples match ticket —
// a ≥3× burst over the 60 s mean baseline after a 5-call learning floor is
// the canonical runaway-context signal.
export const DEFAULTS_TOKEN_USAGE_DETECTOR: TokenUsageDetectorConfig = {
  enabled: true,
  windowMs: 60_000,
  burstFactor: 3,
  minBaselineSamples: 5,
}

// §6.2 : sink disk-low degradation. The
// recovery threshold is low watermark + 50 MiB — enough hysteresis that a
// disk hovering just above the watermark cannot flap the degraded mode
// on every write.
export const DEFAULTS_SINK_DISK_LOW: SinkDiskLowConfig = {
  recoverMarginBytes: 50 * 1024 * 1024,
}

// `DEFAULT_INLINE_PROMPT_INJECTION_PATTERNS` lives in
// `src/intervention/InlinePromptInjection.ts`; importing it here would
// introduce a circular import during the first load of `config.ts` from
// `bootstrap.ts`. The fallback list below is the SAME regex source
// literals that the module exports — keep them in sync when extending the
// catalogue.
export const INLINE_PROMPT_INJECTION_FALLBACK: string[] = [
  // ----- literal family (L01–L08): classic "ignore / disregard /
  // forget / override" payload patterns.
  '\\bignore\\s+(?:all\\s+)?(?:previous|prior|above|earlier)\\s+(?:instructions|prompts|rules|directives)\\b',
  '\\bdisregard\\s+(?:all\\s+)?(?:previous|prior|above|earlier)\\b',
  '\\bforget\\s+(?:everything|all)\\s+(?:above|before|so\\s+far)\\b',
  '\\boverride\\s+(?:your|the)\\s+(?:system|safety|guidelines?)\\b',
  '\\byou\\s+are\\s+now\\s+(?:in\\s+)?(?:developer|dev|debug|admin|root|god)\\s+mode\\b',
  '\\bact\\s+as\\s+(?:an?\\s+)?(?:unrestricted|unfiltered|jailbroken|evil)\\b',
  '\\bdo\\s+not\\s+tell\\s+the\\s+user\\b',
  '\\bbypass\\s+(?:all\\s+)?(?:filters?|safety|content\\s+policy)\\b',
  // ----- unicode_normalize family (U01–U04): character-class detectors.
  '[\\uFF21-\\uFF3A\\uFF41-\\uFF5A]',
  '[\\u200B-\\u200F\\u2028-\\u202F\\u2060-\\u2064\\uFEFF]',
  '[\\u202A-\\u202E\\u2066-\\u2069]',
  '[\\u00A0\\u2000-\\u200A\\u202F\\u205F\\u3000]',
  // ----- role_impersonation family (R01–R05).
  '\\byou\\s+are\\s+(?:chatgpt|gpt-?4|gpt-?3|claude|bard|gemini|llama|deepseek)\\b',
  '\\bpretend\\s+(?:to\\s+be|you\\s+are)\\b',
  '\\bfrom\\s+now\\s+on\\s+you\\s+(?:are|will\\s+act\\s+as)\\b',
  '\\benter\\s+(?:roleplay|role-play)\\s+mode\\b',
  '\\bsimulate\\s+(?:an?\\s+)?(?:unrestricted|unfiltered|evil|hacker)\\b',
  // ----- tag_injection family (T01–T04): ChatML / OpenAI / Llama-2.
  '<\\|\\s*im[_-]?start\\s*\\|?>',
  '<\\|\\s*im[_-]?end\\s*\\|?>',
  '<\\|\\s*(?:endoftext|sep|system|user|assistant)\\s*\\|?>',
  '\\[\\s*INST\\s*\\]|<\\s*\\/?\\s*system\\s*>',
  // ----- known_jailbreak_prefix family (J01–J03).
  '\\b(?:DAN|stan\\s+dolan|do\\s+anything\\s+now)\\b',
  '\\bdeveloper\\s+mode\\s+(?:enabled|activated|output)\\b',
  '\\bjailbreaks?\\b|\\bjailbroken\\b|\\bjailbreak(?:ed|ing)\\b',
]

// §6.2 : defaults for the stdio pipe mirror. The wrapper
// is opt-out (default enabled=true) per ticket acceptance
// criteria; `outputPath` is filled in lazily in `normalizeConfig` from the
// collector's `localOutputPath` so operators do not have to repeat the
// path twice.
// `stdioMirror.enabled` defaults to `false`.
// Rationale: the stdio-mirror wrapper (lib/runtime/stdio-mirror.js) is
// a separate Node.js subprocess spawned by the harness via the
// `RuntimeHook.wrap()` argv rewrite. While the wrapper is technically
// harness-side forking (not plugin-side, so `dependencies: {}` +
// `dshWorkshop.permissions: ["network:none"]` are not violated), the
// marketplace invariant in AGENTS.md says "marketplace 形态不允许派生子进程".
// Default-off keeps the marketplace form aligned with the documented
// posture; operators who want byte-level stdio capture flip
// `stdioMirror.enabled: true` after confirming the wrapper behaves
// on their target OS (real-fork test coverage is Linux-only; the
// Windows path was the original failure surface).
export const DEFAULTS_STDIO_MIRROR: StdioMirrorConfig = {
  enabled: false,
  payloadLimitBytes: 1024 * 1024,
  outputPath: '',
}

// §6.2 : defaults for the inline
// env-passthrough guard. `keys` is intentionally empty — `normalizeConfig`
// re-asserts the hardcoded `ENV_PASSTHROUGH_FALLBACK` list on empty input
// so the safety net cannot be downgraded by the operator setting
// `keys: []`.
export const DEFAULTS_ENV_PASSTHROUGH_GUARD: EnvPassthroughGuardConfig = {
  enabled: true,
  keys: [],
}

// Inline sensitive-header deny-list. `keys: []`
// re-asserts the hardcoded `SENSITIVE_HEADER_FALLBACK` list on empty
// input so the safety net cannot be downgraded by the operator
// setting `keys: []` or `enabled: false`.
export const DEFAULT_SEED_HOSTS: readonly string[] = [
  'api.openai.com',
  '*.openai.azure.com',
  'api.deepseek.com',
  'api.minimax.chat',
  'api.minimaxi.com',
  'api.moonshot.cn',
  'api.moonshot.ai',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'aiplatform.googleapis.com',
  'dashscope.aliyuncs.com',
  'api.groq.com',
  'openrouter.ai',
  'api.siliconflow.cn',
  'api.mistral.ai',
]

export const DEFAULTS_SENSITIVE_HEADER_GUARD: SensitiveHeaderGuardConfig = {
  enabled: true,
  keys: [],
  // Empty by default — out-of-frame non-exempt hits are
  // audit-only (enforceOutOfFrame: false) until the operator lists their
  // LLM provider / telemetry hosts here and opts into hard blocking.
  harnessPlaneHosts: [],
  enforceOutOfFrame: false,
  providerDiscovery: true,
  providerDiscoveryPath: '',
  seedHosts: [...DEFAULT_SEED_HOSTS],
}

// `DEFAULT_DANGEROUS_ENV_KEYS` lives in
// `src/intervention/EnvPassthroughGuard.ts`; importing it here would
// introduce a circular import during the first load of `config.ts` from
// `bootstrap.ts`. The fallback list below is the SAME literal that the
// module exports — keep them in sync when extending the deny-list.
// The `BASH_FUNC_*` prefix match lives separately in
// `DEFAULT_DANGEROUS_ENV_PREFIXES` and is not representable in this
// string[] shape — keep the two lists distinct.
export const ENV_PASSTHROUGH_FALLBACK: string[] = [
  // glibc dynamic-loader hijack surfaces.
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  // Node CLI flag passthrough.
  'NODE_OPTIONS',
  // Python module search-path override + startup script.
  'PYTHONPATH',
  'PYTHONSTARTUP',
  // Node module resolution override.
  'NODE_PATH',
  // Shell startup-file injection vectors.
  'BASH_ENV',
  'ENV',
  // Shell pre-prompt code-injection hook (bash).
  'PROMPT_COMMAND',
  // SSH agent forwarding — fork inherits the agent and stored keys.
  'SSH_AUTH_SOCK',
]

// Hardcoded fallback for the inline sensitive-header
// guard. Mirrors `DEFAULT_DANGEROUS_HEADER_KEYS` in
// `src/intervention/SensitiveHeaderGuard.ts`; duplicated as a literal here
// to keep `config.ts` load-order independent of the intervention modules
// (same rationale as `ENV_PASSTHROUGH_FALLBACK`).
export const SENSITIVE_HEADER_FALLBACK: string[] = [
  // Standard credential-bearing headers (RFC 7235 / 6265).
  'Authorization',
  'Cookie',
  'Proxy-Authorization',
  // Non-standard but ubiquitous API-key header.
  'X-API-Key',
]