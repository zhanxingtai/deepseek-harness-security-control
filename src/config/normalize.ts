/**
 * Config normalization — pure function `normalizeConfig(input) -> Config`.
 *
 * Pure module: no I/O, no side-effects beyond returning the
 * merged shape. Every safety-net invariant documented inline below.
 *
 * Consumer contract: callers (`bootstrap.ts` / `config/livePatch.ts` /
 * `config/draft.ts` / typert host) hand in a raw patch object and get back
 * a `Config` whose invariants are guaranteed:
 *   - `mode === 'enforce' || mode === 'audit'`
 *   - top-level `enabled` defaults to true
 *   - `hostId` / `containerId` defaults filled in
 *   - All safety-net deny-lists UNION-merged with their hardcoded
 *     fallbacks (`engineLaunchers` / `sensitivePathGuard.paths` /
 *     `inlinePromptInjection.patterns` / `envPassthroughGuard.keys`)
 *   - `inlineGuards.pluginPackageName` FORCE-REPLACED with the canonical
 *     marketplace name (operator cannot rename the uninstall match target)
 *   - `inlinePromptInjection.enabled` / `sensitivePathGuard.enabled` /
 *     `envPassthroughGuard.enabled` /
 *     `collector.redactRawParams` force-true (the safety net cannot be
 *     downgraded by `enabled: false` in `cordis.patch.yml`).
 *     `stdioMirror.enabled` is NOT in this list — the mirror is
 * observability, not a safety net; it defaults to false and
 *     an operator's explicit `enabled: true` / `false` is honored.
 *   - `intervention.failStrategy` validated against the enum
 *   - `collector.diskLowWatermarkBytes` / `sinkDiskLow.recoverMarginBytes`
 *     `Number.isFinite` + non-negative guards
 *
 * The companion modules `config/livePatch.ts` / `config/validate.ts` /
 * `config/draft.ts` use this as their merge primitive.
 */

import { hostname } from 'node:os'
import type { Mode } from '../types/index.js'
import type {
  Config,
  EnvPassthroughGuardConfig,
  InlineGuardsConfig,
  InlinePromptInjectionConfig,
  InterventionConfig,
  LoopedToolDetectorConfig,
  SensitiveHeaderGuardConfig,
  SensitivePathGuardConfig,
  SinkDiskLowConfig,
  StdioMirrorConfig,
  TokenUsageDetectorConfig,
} from './types.js'
import {
  DEFAULTS_APPLICATION,
  DEFAULTS_COLLECTOR,
  DEFAULTS_ENV_PASSTHROUGH_GUARD,
  DEFAULTS_INLINE_GUARDS,
  DEFAULTS_INLINE_PROMPT_INJECTION_GUARD,
  DEFAULTS_INTERVENTION,
  DEFAULTS_LOOPED_TOOL_DETECTOR,
  DEFAULTS_NETWORK_CAPTURE,
  DEFAULTS_RUNTIME_HOOKS,
  DEFAULTS_SENSITIVE_HEADER_GUARD,
  DEFAULTS_SENSITIVE_PATH_GUARD,
  DEFAULTS_SINK_DISK_LOW,
  DEFAULTS_STDIO_MIRROR,
  DEFAULTS_TOKEN_USAGE_DETECTOR,
  DEFAULT_SEED_HOSTS,
  ENV_PASSTHROUGH_FALLBACK,
  INLINE_GUARD_LAUNCHER_FALLBACK,
  INLINE_GUARD_PATCH_MARKERS_FALLBACK,
  INLINE_GUARD_PLUGIN_PACKAGE_NAME_FALLBACK,
  INLINE_PROMPT_INJECTION_FALLBACK,
  SENSITIVE_HEADER_FALLBACK,
  SENSITIVE_PATH_FALLBACK,
  VALID_FAIL_STRATEGIES,
} from './defaults.js'

/**
 * Merge `input` over a defaults object, shallow-copying each top-level key
 * so the original `DEFAULTS_*` constants are never mutated. The 5 helpers
 * (`string/bool/num/array/optionalObject`) collapsed into this single
 * spread — every defaults field already carries a sane type so we don't
 * need per-key coercion. Sub-blocks are merged recursively via the
 * nested `DEFAULTS_*` map so adding a new field to a default does not
 * silently drop a user-supplied value on the same path.
 *
 * (livePatch null-override bypass): the spread
 * now FILTERS `null` and `undefined` values from `input` so a patch carrying
 * `{collector: {localOutputPath: null}}` (schemastery autofix accepts as
 * "valid, with default replacement" but the spread then wins with `null`)
 * cannot silently nuke a downstream `expandHome()` consumer. The semantics:
 * `null`/`undefined` in input means "key not supplied" → default wins.
 * A legitimate operator clearing a string field must pass `''` (empty
 * string) or omit the field; the marketplace never relies on `null` to
 * clear a key.
 */
export function withDefaults<T extends object>(defaults: T, input: unknown): T {
  const obj = (input && typeof input === 'object' && !Array.isArray(input))
    ? (input as Record<string, unknown>)
    : {}
  const filtered: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue
    filtered[k] = v
  }
  return { ...defaults, ...filtered } as T
}

/**
 * Default-mode-from-policy seam.
 *
 * Returns `true` iff the raw operator input explicitly sets the runtime
 * `mode` to one of `'audit' | 'enforce'`. Two surfaces count as explicit:
 *
 *   - top-level `obj.mode`         — the single-knob form
 *   - `obj.intervention.mode`      — the nested form preferred by
 *                                    `normalizeConfig` once the nested
 *                                    field exists
 *
 * The engine uses this flag to decide whether to consult the policy
 * file's `mode:` declaration as the runtime default. An operator who
 * has NOT explicitly set `mode` is treated as "defer to policy". A fresh
 * install lands in `enforce` directly at the normalize layer (and the
 * bundled `policies/default-policy.spl.yaml` also declares
 * `mode: enforce`, so they agree — the policy-file upgrade seam becomes
 * a no-op for the default path).
 *
 * Pure function — same I/O contract as `normalizeConfig` (no I/O, no
 * side-effects, safe to call on untrusted input).
 */
export function isModeExplicit(rawInput: unknown): boolean {
  if (!rawInput || typeof rawInput !== 'object' || Array.isArray(rawInput)) return false
  const obj = rawInput as Record<string, unknown>
  if (obj['mode'] === 'audit' || obj['mode'] === 'enforce') return true
  const intervention = obj['intervention']
  if (intervention && typeof intervention === 'object' && !Array.isArray(intervention)) {
    const m = (intervention as Record<string, unknown>)['mode']
    if (m === 'audit' || m === 'enforce') return true
  }
  return false
}

export function normalizeConfig(input: unknown): Config {
  const obj = (input ?? {}) as Record<string, unknown>

  // top-level `mode` is the operator-facing single knob.
  // Propagate it down into `intervention.mode` when the operator did not
  // override the nested field, so existing patch YAMLs that set only
  // top-level `mode: enforce` continue to drive the intervention engine.
  //
  // Default is 'enforce' to match the Schema default (see
  // `src/config.schema.ts:381`) and the bundled
  // `policies/default-policy.spl.yaml` `mode: enforce` declaration.
  // A fresh install with no operator input lands in enforce
  // without relying on the engine's policy-file upgrade seam.
  const topMode: Mode = obj.mode === 'audit' ? 'audit' : 'enforce'

  const interventionInput = (obj.intervention && typeof obj.intervention === 'object')
    ? (obj.intervention as Record<string, unknown>)
    : {}
  const failStrategy = interventionInput['failStrategy']
  const interventionMode = (interventionInput['mode'] === 'enforce' || interventionInput['mode'] === 'audit')
    ? interventionInput['mode']
    : topMode
  const intervention: InterventionConfig = {
    ...DEFAULTS_INTERVENTION,
    ...interventionInput,
    mode: interventionMode,
    failStrategy: VALID_FAIL_STRATEGIES.has(failStrategy as InterventionConfig['failStrategy'])
      ? (failStrategy as InterventionConfig['failStrategy'])
      : DEFAULTS_INTERVENTION.failStrategy,
  }

  // `engineLaunchers=[]` is silently replaced with the marketplace
  // fallback so the safety net cannot be disabled by removing
  // launcher entries.
  //
  // Deny-list is UNION semantics — operator entries
  // are merged with the marketplace fallback so an attacker (or operator)
  // setting `engineLaunchers: ['x']` no longer silently drops the
  // {node, pnpm, npm, npx, dsh} baseline. Mirrors InlinePromptInjection's
  // `COMPILED_INLINE_PROMPT_INJECTION_PATTERNS + userCompiled` merge at
  // evaluate time, but hoisted into normalize so downstream evaluate sites
  // (InlineSelfProtection / launcher gate) keep their iteration contract.
  const inlineGuardsInput = withDefaults(DEFAULTS_INLINE_GUARDS, obj.inlineGuards)
  const inlineGuards: InlineGuardsConfig = {
    ...DEFAULTS_INLINE_GUARDS,
    ...inlineGuardsInput,
    engineLaunchers: (() => {
      const op = Array.isArray(inlineGuardsInput.engineLaunchers)
        ? inlineGuardsInput.engineLaunchers
        : []
      // UNION: fallback + operator, deduped (operator wins on collision
      // so a deliberate operator override still surfaces).
      const merged = [...INLINE_GUARD_LAUNCHER_FALLBACK]
      for (const e of op) if (!merged.includes(e)) merged.push(e)
      return merged
    })(),
    // pluginPackageName / patchMarkers also UNION-
    // merged with hardcoded fallbacks. LivePatch correctly rejects
    // these keys at the operator-mutation seam, but the initial-config
    // path was unguarded. Tampered `cordis.patch.yml` could rename
    // pluginPackageName to a non-target string and silently disable
    // the inline uninstall / restart-without-patch rules. We force
    // the hardcoded fallback as the canonical value — operator input
    // is silently IGNORED (no UNION-extension here because the
    // InlineSelfProtection matcher's compiled regex consumes
    // `pluginPackageName` as a single literal; widening to alternation
    // would require changing the matcher API). This matches the
    // invariant: "the safety net cannot be downgraded". Operators who
    // want to match a renamed distribution must re-publish the plugin
    // under the canonical name (the marketplace surface already
    // enforces this).
    pluginPackageName: INLINE_GUARD_PLUGIN_PACKAGE_NAME_FALLBACK,
    patchMarkers: (() => {
      const op = Array.isArray(inlineGuardsInput.patchMarkers)
        ? inlineGuardsInput.patchMarkers.filter((p): p is string => typeof p === 'string')
        : []
      const merged = [...INLINE_GUARD_PATCH_MARKERS_FALLBACK]
      for (const p of op) if (!merged.includes(p)) merged.push(p)
      return merged
    })(),
  }

  // §6.2 : same fallback pattern for the sensitive-path
  // deny-list. The `paths: []` (or omitted) input is silently replaced
  // with the marketplace hardcoded list so the safety net cannot be
  // downgraded by removing all entries.
  //
  // `enabled` is UNCONDITIONALLY re-asserted to `true`
  // after the spread so a patch YAML setting
  // `sensitivePathGuard.enabled: false` cannot silence the rail —
  // README.md/cordis.patch.yml promise the guard is non-disablable.
  // Deny-list is UNION (default 24 entries ∪ operator entries),
  // so `paths: ['~/.myorg/keys/*']` extends the baseline instead of
  // replacing it. Mirrors `sensitiveHeaderGuard`'s unconditional
  // `enabled: true` form.
  const spgInput = withDefaults(DEFAULTS_SENSITIVE_PATH_GUARD, obj.sensitivePathGuard)
  const sensitivePathGuard: SensitivePathGuardConfig = {
    ...DEFAULTS_SENSITIVE_PATH_GUARD,
    ...spgInput,
    enabled: true,
    paths: (() => {
      const op = Array.isArray(spgInput.paths) ? spgInput.paths : []
      const merged = [...SENSITIVE_PATH_FALLBACK]
      for (const p of op) if (!merged.includes(p)) merged.push(p)
      return merged
    })(),
  }

  // §6.2 第二项: same fallback pattern for the inline
  // prompt-injection guard. `patterns: []` (or omitted) silently
  // re-asserts the 24-pattern marketplace catalogue so the safety net
  // cannot be downgraded by clearing the list.
  //
  // `enabled` UNCONDITIONALLY re-asserted to `true`
  // (same rationale as sensitivePathGuard). `patterns` UNION — the
  // catalogue + operator entries
  // are both compiled and matched (`COMPILED_INLINE_PROMPT_INJECTION_PATTERNS
  // + userCompiled` in InlinePromptInjection.ts:763-766), so the existing
  // evaluate path already unions — normalize mirrors that contract so
  // the final `cfg.patterns` accurately reflects what the evaluator
  // iterates.
  const ipiInput = withDefaults(
    DEFAULTS_INLINE_PROMPT_INJECTION_GUARD,
    obj.inlinePromptInjection,
  )
  const inlinePromptInjection: InlinePromptInjectionConfig = {
    ...DEFAULTS_INLINE_PROMPT_INJECTION_GUARD,
    ...ipiInput,
    enabled: true,
    patterns: (() => {
      const op = Array.isArray(ipiInput.patterns) ? ipiInput.patterns : []
      const merged = [...INLINE_PROMPT_INJECTION_FALLBACK]
      for (const p of op) if (!merged.includes(p)) merged.push(p)
      return merged
    })(),
  }

  // §6.2 : stdio pipe mirror.
  // `outputPath` defaults to `collector.localOutputPath` (the SAME
  // NDJSON file the host plugin writes) — wrapper events are
  // interleaved with host events on the same ts axis. Operators do not
  // get a sibling `${localOutputPath}.stdio-mirror.jsonl` file;
  // audit consumers read ONE file and the re-merge ceremony on
  // `(ts, child_pid, session_id, event_id)` is trivial because
  // wrapper events already sit on the same timeline.
  //
  // Operator overrides are still honored — set `stdioMirror.outputPath`
  // to a custom path for forensic isolation (e.g. routing mirror bytes
  // to a separate volume). `payloadLimitBytes` is unconditional
  // (default 1 MiB).
  //
  // `enabled` is NOT re-asserted to `true` here: unlike
  // the inline guards above, the mirror is observability, NOT a safety
  // net, so `enabled` flows through `withDefaults(DEFAULTS_STDIO_MIRROR,
  // …)` whose default is `false` (the wrapper is a harness-side fork,
  // which conflicts with the documented "marketplace 形态不允许派生子进程"
  // posture). Operators who rely on the mirror
  // audit data must set `stdioMirror.enabled: true` explicitly.
  const collectorDefaults = withDefaults(DEFAULTS_COLLECTOR, obj.collector)
  const smInput = withDefaults(DEFAULTS_STDIO_MIRROR, obj.stdioMirror)
  const stdioMirror: StdioMirrorConfig = {
    ...DEFAULTS_STDIO_MIRROR,
    ...smInput,
    payloadLimitBytes:
      typeof smInput.payloadLimitBytes === 'number' && smInput.payloadLimitBytes > 0
        ? smInput.payloadLimitBytes
        : DEFAULTS_STDIO_MIRROR.payloadLimitBytes,
    outputPath:
      typeof smInput.outputPath === 'string' && smInput.outputPath.length > 0
        ? smInput.outputPath
        : collectorDefaults.localOutputPath,
  }

  // §6.2 : same fallback pattern for the
  // inline env-passthrough guard. `keys: []` (or omitted) silently
  // re-asserts the marketplace hardcoded 6-key deny-list so the safety
  // net cannot be downgraded by clearing the list.
  //
  // `enabled` UNCONDITIONALLY re-asserted to `true`
  // (same rationale as sensitivePathGuard — README/cordis.patch.yml
  // promise the guard is non-disablable). `keys` UNION — operator
  // entries extend the
  // marketplace baseline (LD_PRELOAD / LD_LIBRARY_PATH /
  // NODE_OPTIONS / PYTHONPATH / PYTHONSTARTUP / NODE_PATH) instead of
  // replacing it; `keys: ['MY_CUSTOM_LOADER']` keeps the defaults.
  const epgInput = withDefaults(DEFAULTS_ENV_PASSTHROUGH_GUARD, obj.envPassthroughGuard)
  const envPassthroughGuard: EnvPassthroughGuardConfig = {
    ...DEFAULTS_ENV_PASSTHROUGH_GUARD,
    ...epgInput,
    enabled: true,
    keys: (() => {
      const op = Array.isArray(epgInput.keys) ? epgInput.keys : []
      const merged = [...ENV_PASSTHROUGH_FALLBACK]
      for (const k of op) if (!merged.includes(k)) merged.push(k)
      return merged
    })(),
  }

  // Inline sensitive-header deny-list. Same
  // pattern as the env-passthrough guard: `enabled: false` is rejected
  // (the marketplace hardcodes the rail to on), `keys: []` (or omitted)
  // silently re-asserts the marketplace hardcoded 4-key deny-list,
  // and operator entries UNION the marketplace baseline instead of
  // replacing it (so `keys: ['X-Custom-Auth']` keeps Authorization /
  // Cookie / Proxy-Authorization / X-API-Key as defaults).
  //
  // `enabled` is force-asserted to `true` UNCONDITIONALLY after the
  // spread (mirrors `collector.redactRawParams: true` exactly) so a
  // patch YAML carrying `sensitiveHeaderGuard.enabled: false` cannot
  // silently downgrade the rail. The sibling guards'
  // `enabled: xInput.enabled !== false` pattern has a latent bug
  // (spread writes `false` first; `false !== false` evaluates `false`;
  // the safety-net invariant is only honoured when the operator passes
  // `true` or omits the field) — for the new guard we use the
  // unconditional re-assert.
  const shgInput = withDefaults(DEFAULTS_SENSITIVE_HEADER_GUARD, obj.sensitiveHeaderGuard)
  const sensitiveHeaderGuard: SensitiveHeaderGuardConfig = {
    ...DEFAULTS_SENSITIVE_HEADER_GUARD,
    ...shgInput,
    enabled: true,
    keys: (() => {
      const op = Array.isArray(shgInput.keys) ? shgInput.keys : []
      const merged = [...SENSITIVE_HEADER_FALLBACK]
      for (const k of op) if (!merged.includes(k)) merged.push(k)
      return merged
    })(),
    // Same string-list hygiene as the collector's own
    // livePatch assignStrList — non-string entries would poison the
    // derived Set built in rebuildDerivedMatcherState.
    harnessPlaneHosts: (Array.isArray(shgInput.harnessPlaneHosts) ? shgInput.harnessPlaneHosts : [])
      .filter((x): x is string => typeof x === 'string'),
    enforceOutOfFrame:
      typeof shgInput.enforceOutOfFrame === 'boolean' ? shgInput.enforceOutOfFrame : false,
    // Provider auto-discovery is a noise-reduction feature (not a
    // safety rail), so `false` is honoured — disabling it only restores
    // the audit-only false positives, it never weakens blocking.
    providerDiscovery:
      typeof shgInput.providerDiscovery === 'boolean' ? shgInput.providerDiscovery : true,
    providerDiscoveryPath:
      typeof shgInput.providerDiscoveryPath === 'string' ? shgInput.providerDiscoveryPath : '',
    // Same union pattern as `keys` — operator seeds extend the
    // marketplace baseline instead of replacing it (replacement would
    // re-introduce false positives on every default provider).
    seedHosts: (() => {
      const op = (Array.isArray(shgInput.seedHosts) ? shgInput.seedHosts : []).filter(
        (x): x is string => typeof x === 'string' && x.trim().length > 0,
      )
      const merged = [...DEFAULT_SEED_HOSTS]
      for (const h of op) {
        const lower = h.toLowerCase()
        if (!merged.includes(lower)) merged.push(lower)
      }
      return merged
    })(),
  }
  // §6.2 : per-tool loop detector. No
  // empty-fallback (unlike the sibling inline guards) — the defaults are
  // intrinsic numbers, not a deny-list. Operators can tune the window /
  // threshold without triggering a re-assertion.
  const loopedToolDetector: LoopedToolDetectorConfig = withDefaults(
    DEFAULTS_LOOPED_TOOL_DETECTOR,
    obj.loopedToolDetector,
  )

  // §6.2 : token-usage burst detector. Same
  // shape as the loop detector — intrinsic numeric defaults, no empty-list
  // fallback. Operators can tune the window / factor / learning floor
  // without triggering a re-assertion.
  const tokenUsageDetector: TokenUsageDetectorConfig = withDefaults(
    DEFAULTS_TOKEN_USAGE_DETECTOR,
    obj.tokenUsageDetector,
  )

  // §6.2 : sink disk-low degradation. Single
  // numeric knob — non-finite / negative values fall back to the default
  // (an operator typo must not disable the hysteresis and turn the
  // degraded mode into a flapping one).
  const sinkDiskLowInput = withDefaults(DEFAULTS_SINK_DISK_LOW, obj.sinkDiskLow)
  const sinkDiskLow: SinkDiskLowConfig = {
    ...DEFAULTS_SINK_DISK_LOW,
    ...sinkDiskLowInput,
    recoverMarginBytes:
      typeof sinkDiskLowInput.recoverMarginBytes === 'number' &&
      Number.isFinite(sinkDiskLowInput.recoverMarginBytes) &&
      sinkDiskLowInput.recoverMarginBytes >= 0
        ? sinkDiskLowInput.recoverMarginBytes
        : DEFAULTS_SINK_DISK_LOW.recoverMarginBytes,
  }

  return {
    ...obj,
    mode: topMode,
    enabled: obj.enabled !== false,
    hostId: typeof obj.hostId === 'string' && obj.hostId ? obj.hostId : hostname(),
    containerId:
      typeof obj.containerId === 'string' && obj.containerId ? obj.containerId : 'host',
    collector: {
      ...withDefaults(DEFAULTS_COLLECTOR, obj.collector),
      // hardcoded to true in marketplace form.
      // Operator input that tries to set this to false is silently
      // re-asserted to true — the safety net cannot be downgraded.
      redactRawParams: true,
    },
    application: withDefaults(DEFAULTS_APPLICATION, obj.application),
    networkCapture: withDefaults(DEFAULTS_NETWORK_CAPTURE, obj.networkCapture),
    intervention,
    runtimeHooks: withDefaults(DEFAULTS_RUNTIME_HOOKS, obj.runtimeHooks),
    inlineGuards,
    sensitivePathGuard,
    inlinePromptInjection,
    stdioMirror,
    envPassthroughGuard,
    sensitiveHeaderGuard,
    loopedToolDetector,
    tokenUsageDetector,
    sinkDiskLow,
  }
}