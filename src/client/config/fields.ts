/**
 * Config form field metadata — mechanism clause
 * Visibility flag (essential vs advanced).
 *
 * SINGLE SOURCE OF TRUTH for the Config tab form: every operator-
 * configurable leaf key of the host `Config` surface has exactly one
 * entry here, and `Config.tsx` renders purely from this table (no
 * scattered hardcoded field definitions). The enforcement is the
 * parity test in `tests/configParity.test.ts` — it asserts the
 * metadata key set equals the host-side leaf-key set derived from
 * `normalizeConfig({})` in `src/config.ts`, so adding a Config field
 * without a metadata entry (or vice versa) fails `pnpm test`.
 *
 * Entry shape (per the mechanism clause):
 *
 *   - `key` — dotted config path ('collector.batchSize'; top-level
 *     scalars carry their bare key 'mode').
 *   - `section` — the Config top-level block the field belongs to;
 *     sections render as collapsible panels in declaration order of
 *     `CONFIG_SECTIONS`.
 *   - `label` — locale key (zh + en) for the human label.
 *   - `kind` — boolean | number | string | enum, driving the control.
 *   - `visibility` — 'essential' (always rendered) or 'advanced'
 *     (only rendered when the operator toggles "Show advanced").
 *     Omitting the flag is equivalent to 'essential', so existing
 *     entries ship visible by default.
 *   - `csv` — string kind backed by `string[]` in the Config; edited
 *     as a comma-separated text input, split on change.
 *   - `enumValues` — the allowed values for kind 'enum'.
 *   - `help` — brown-orange hint text under the control.
 *   - `danger` + `warning` — the field is a dangerous key: the label
 *     carries a red `⚠ danger` badge and the control shows the red
 *     warning text. The save-time confirmation derives the dangerous
 *     key set from these flags (see `resolveDangerHits`) — never
 *     hand-written ifs in the component.
 *   - `dependsOn` — the control disables while the referenced field's
 *     effective value is strictly `false`.
 * `locked` — read-only (inlineGuards): rendered as plain text
 *     no inputs, so the safety net cannot be edited from the form.
 */
import type { LocaleKey } from '../locales.js'
import type { ConfigPatch, ConfigSnapshot } from '../wire.js'

export type FieldKind = 'boolean' | 'number' | 'string' | 'enum'

/** Render tier. `essential` fields always render
 *  in the form; `advanced` fields render only when the operator
 *  toggles "Show advanced" in the toolbar. Filtering happens in
 *  `Config.tsx`, not here — the metadata table is the single source
 *  of truth and contains every field regardless of visibility. */
export type FieldVisibility = 'essential' | 'advanced'

/** Config top-level block ids — the section ids of the form. */
export type ConfigSectionId =
  | 'top'
  | 'collector'
  | 'application'
  | 'networkCapture'
  | 'runtimeHooks'
  | 'intervention'
  | 'inlineGuards'
  | 'sensitivePathGuard'
  | 'inlinePromptInjection'
  | 'stdioMirror'
  | 'envPassthroughGuard'
  | 'sensitiveHeaderGuard'
  | 'loopedToolDetector'
  | 'tokenUsageDetector'
  | 'sinkDiskLow'

export interface ConfigSectionMeta {
  id: ConfigSectionId
  label: LocaleKey
  /** When `true` the section is moved entirely
   * under the "advanced" drawer (the inlineGuards locked block
   *  is the prototype — read-only by construction). */
  advancedOnly?: boolean
}

/** Section render order (declaration order = display order). */
export const CONFIG_SECTIONS: ReadonlyArray<ConfigSectionMeta> = [
  { id: 'top', label: 'config_section_top' },
  { id: 'collector', label: 'config_section_collector' },
  { id: 'application', label: 'config_section_application' },
  { id: 'networkCapture', label: 'config_section_network' },
  { id: 'runtimeHooks', label: 'config_section_runtime' },
  { id: 'intervention', label: 'config_section_intervention' },
  { id: 'inlineGuards', label: 'config_section_inline' },
  { id: 'sensitivePathGuard', label: 'config_section_sensitive' },
  { id: 'inlinePromptInjection', label: 'config_section_prompt_injection' },
  { id: 'stdioMirror', label: 'config_section_stdio_mirror' },
  { id: 'envPassthroughGuard', label: 'config_section_env_passthrough' },
  { id: 'sensitiveHeaderGuard', label: 'config_section_sensitive_header' },
  { id: 'loopedToolDetector', label: 'config_section_looped_tool' },
  { id: 'tokenUsageDetector', label: 'config_section_token_usage' },
  { id: 'sinkDiskLow', label: 'config_section_sink_disk_low' },
]

export interface ConfigFieldMeta {
  /** Dotted config path: 'collector.batchSize' or 'mode'. */
  key: string
  section: ConfigSectionId
  label: LocaleKey
  kind: FieldKind
  /** Render tier. Defaults to 'essential' (visible
   *  by default); mark 'advanced' for tuning knobs the operator rarely
   *  touches. The toggle in the Config toolbar controls rendering. */
  visibility?: FieldVisibility
  /** kind 'enum' → allowed values. */
  enumValues?: readonly string[]
  /** kind 'string' backed by string[] → comma-separated editing. */
  csv?: boolean
  /** Brown-orange help text under the control. */
  help?: LocaleKey
  /** Dangerous key — save requires an explicit confirmation. */
  danger?: boolean
  /** Red warning text under the control (danger fields). */
  warning?: LocaleKey
  /** Control disables while the referenced field resolves to false. */
  dependsOn?: string
  /** read-only — rendered as text, no inputs. */
  locked?: boolean
}

export const CONFIG_FIELD_METADATA: ReadonlyArray<ConfigFieldMeta> = [
  // ----- top level -----
  // essential: the operator's master switch. The runtime `mode` is
  // surfaced under `intervention.mode` below (engine reads
  // `config.intervention.mode` as the authoritative enforcement switch
  // — see `src/config/normalize.ts:151-153` and
  // `src/intervention/InterventionEngine.ts:755`); the top-level
  // `Config.mode` field is preserved in the type for backward
  // compatibility with old patch YAMLs that set `mode: enforce` at
  // the top level, but the UI no longer surfaces it (otherwise the
  // operator sees two parallel "mode" controls and has to guess which
  // one actually drives the engine).
  { key: 'enabled', section: 'top', label: 'config_field_enabled', kind: 'boolean' },
  // advanced: host auto-populated identifiers — operator rarely edits.
  { key: 'hostId', section: 'top', label: 'config_field_hostId', kind: 'string', visibility: 'advanced' },
  { key: 'containerId', section: 'top', label: 'config_field_containerId', kind: 'string', visibility: 'advanced' },
  // ----- collector -----
  // essential: where events land — the operator MUST know / set this.
  { key: 'collector.localOutputPath', section: 'collector', label: 'config_field_collector_localOutputPath', kind: 'string', help: 'config_help_collector_localOutputPath' },
  // advanced: throughput / durability tuning knobs.
  { key: 'collector.batchSize', section: 'collector', label: 'config_field_collector_batchSize', kind: 'number', visibility: 'advanced' },
  { key: 'collector.flushIntervalMs', section: 'collector', label: 'config_field_collector_flushIntervalMs', kind: 'number', visibility: 'advanced' },
  { key: 'collector.validateEvents', section: 'collector', label: 'config_field_collector_validateEvents', kind: 'boolean', visibility: 'advanced' },
  { key: 'collector.maxFileBytes', section: 'collector', label: 'config_field_collector_maxFileBytes', kind: 'number', visibility: 'advanced' },
  { key: 'collector.diskWarnWatermarkBytes', section: 'collector', label: 'config_field_collector_diskWarnWatermarkBytes', kind: 'number', visibility: 'advanced' },
  { key: 'collector.diskLowWatermarkBytes', section: 'collector', label: 'config_field_collector_diskLowWatermarkBytes', kind: 'number', visibility: 'advanced' },
  // advanced: only for operators whose log rotator is not recognisable
  // by the archive-sibling heuristic (copytruncate, cross-directory
  // moves). Off by default — on, a hostile deletion is no longer reported.
  { key: 'collector.externallyManagedLog', section: 'collector', label: 'config_field_collector_externallyManagedLog', kind: 'boolean', visibility: 'advanced', help: 'config_help_collector_externallyManagedLog' },
  { key: 'collector.auditDedupWindowMs', section: 'collector', label: 'config_field_collector_auditDedupWindowMs', kind: 'number', visibility: 'advanced', help: 'config_help_collector_auditDedupWindowMs' },
  // normalizeConfig force-asserts `true` — the
  // switch cannot be turned off, so it renders locked (read-only truth).
  { key: 'collector.redactRawParams', section: 'collector', label: 'config_field_collector_redactRawParams', kind: 'boolean', visibility: 'advanced', locked: true, help: 'config_help_guard_baseline_locked' },
  { key: 'collector.debugLogPath', section: 'collector', label: 'config_field_collector_debugLogPath', kind: 'string', visibility: 'advanced' },
  // ----- application -----
  // all advanced: capture toggles + cap knobs (rarely changed from defaults).
  { key: 'application.captureUserPrompt', section: 'application', label: 'config_field_application_captureUserPrompt', kind: 'boolean', visibility: 'advanced' },
  { key: 'application.captureSystemPrompt', section: 'application', label: 'config_field_application_captureSystemPrompt', kind: 'boolean', visibility: 'advanced' },
  { key: 'application.captureAgentPlan', section: 'application', label: 'config_field_application_captureAgentPlan', kind: 'boolean', visibility: 'advanced' },
  { key: 'application.captureReasoning', section: 'application', label: 'config_field_application_captureReasoning', kind: 'boolean', visibility: 'advanced' },
  { key: 'application.toolResultMaxChars', section: 'application', label: 'config_field_application_toolResultMaxChars', kind: 'number', visibility: 'advanced' },
  { key: 'application.sessionTtlMs', section: 'application', label: 'config_field_application_sessionTtlMs', kind: 'number', visibility: 'advanced' },
  // ----- networkCapture -----
  // essential: master switch — operator must know the collector can be turned off.
  { key: 'networkCapture.enabled', section: 'networkCapture', label: 'config_field_networkCapture_enabled', kind: 'boolean' },
  // advanced: detail knobs (body size, SSE summary, allow/deny lists, sensitive keys, DNS).
  { key: 'networkCapture.redactBodies', section: 'networkCapture', label: 'config_field_networkCapture_redactBodies', kind: 'boolean', visibility: 'advanced' },
  { key: 'networkCapture.captureResponseBody', section: 'networkCapture', label: 'config_field_networkCapture_captureResponseBody', kind: 'boolean', visibility: 'advanced' },
  { key: 'networkCapture.maxBodyBytes', section: 'networkCapture', label: 'config_field_networkCapture_maxBodyBytes', kind: 'number', visibility: 'advanced' },
  { key: 'networkCapture.maxRequestBodyBytes', section: 'networkCapture', label: 'config_field_networkCapture_maxRequestBodyBytes', kind: 'number', visibility: 'advanced', help: 'config_help_networkCapture_maxRequestBodyBytes' },
  { key: 'networkCapture.sseSummaryChunks', section: 'networkCapture', label: 'config_field_networkCapture_sseSummaryChunks', kind: 'number', visibility: 'advanced' },
  { key: 'networkCapture.sseSummaryLastChunks', section: 'networkCapture', label: 'config_field_networkCapture_sseSummaryLastChunks', kind: 'number', visibility: 'advanced' },
  { key: 'networkCapture.includeHosts', section: 'networkCapture', label: 'config_field_networkCapture_includeHosts', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_csv' },
  { key: 'networkCapture.excludeHosts', section: 'networkCapture', label: 'config_field_networkCapture_excludeHosts', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_csv' },
  { key: 'networkCapture.excludeUrls', section: 'networkCapture', label: 'config_field_networkCapture_excludeUrls', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_csv' },
  { key: 'networkCapture.ignoreUrls', section: 'networkCapture', label: 'config_field_networkCapture_ignoreUrls', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_networkCapture_ignoreUrls' },
  { key: 'networkCapture.ignoreHosts', section: 'networkCapture', label: 'config_field_networkCapture_ignoreHosts', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_csv' },
  { key: 'networkCapture.sensitiveKeyPatterns', section: 'networkCapture', label: 'config_field_networkCapture_sensitiveKeyPatterns', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_networkCapture_sensitiveKeyPatterns' },
  { key: 'networkCapture.captureDns', section: 'networkCapture', label: 'config_field_networkCapture_captureDns', kind: 'boolean', visibility: 'advanced' },
  // ----- runtimeHooks -----
  // essential: the 3 fork-seam dials (audit, enforce, fail posture).
  { key: 'runtimeHooks.enabledAtSubprocess', section: 'runtimeHooks', label: 'config_field_runtimeHooks_enabledAtSubprocess', kind: 'boolean' },
  { key: 'runtimeHooks.blockAtSubprocess', section: 'runtimeHooks', label: 'config_field_runtimeHooks_blockAtSubprocess', kind: 'boolean', help: 'config_help_runtimeHooks_blockAtSubprocess' },
  { key: 'runtimeHooks.failOpenOnError', section: 'runtimeHooks', label: 'config_field_runtimeHooks_failOpenOnError', kind: 'boolean' },
  // advanced: kept for parity (read-only knobs in the marketplace form).
  { key: 'runtimeHooks.enabled', section: 'runtimeHooks', label: 'config_field_runtimeHooks_enabled', kind: 'boolean', visibility: 'advanced' },
  { key: 'runtimeHooks.networkEnabled', section: 'runtimeHooks', label: 'config_field_runtimeHooks_networkEnabled', kind: 'boolean', visibility: 'advanced' },
  { key: 'runtimeHooks.logPath', section: 'runtimeHooks', label: 'config_field_runtimeHooks_logPath', kind: 'string', visibility: 'advanced' },
  { key: 'runtimeHooks.hookPath', section: 'runtimeHooks', label: 'config_field_runtimeHooks_hookPath', kind: 'string', visibility: 'advanced' },
  { key: 'runtimeHooks.excludeCommandLines', section: 'runtimeHooks', label: 'config_field_runtimeHooks_excludeCommandLines', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_runtimeHooks_excludeCommandLines' },
  // ----- intervention -----
  // essential: SPL policy posture — the operator's main policy dials.
  // NOT a master switch — it only gates
  // agent-message-level evaluation (audit marking); tool / fork / HTTP
  // interception is unaffected. Hence advanced visibility + scoped help text.
  { key: 'intervention.enabled', section: 'intervention', label: 'config_field_intervention_enabled', kind: 'boolean', visibility: 'advanced', help: 'config_help_intervention_enabled_scope' },
  { key: 'intervention.mode', section: 'intervention', label: 'config_field_intervention_mode', kind: 'enum', enumValues: ['audit', 'enforce'], danger: true, warning: 'config_warning_mode' },
  // legacy single-file fallback — used only
  // when policyPaths is empty (the engine ignores it otherwise). The
  // operator-facing dial is policyPaths; the fallback stays hidden.
  { key: 'intervention.policyPath', section: 'intervention', label: 'config_field_intervention_policyPath', kind: 'string', visibility: 'advanced' },
  { key: 'intervention.policyPaths', section: 'intervention', label: 'config_field_intervention_policyPaths', kind: 'string', csv: true, help: 'config_help_intervention_policyPaths' },
  { key: 'intervention.failStrategy', section: 'intervention', label: 'config_field_intervention_failStrategy', kind: 'enum', enumValues: ['fail_open', 'fail_closed', 'fail_open_high_risk_only'], danger: true, warning: 'config_warning_failStrategy' },
  // advanced: timing knobs.
  { key: 'intervention.reloadIntervalMs', section: 'intervention', label: 'config_field_intervention_reloadIntervalMs', kind: 'number', visibility: 'advanced' },
  { key: 'intervention.decisionTimeoutMs', section: 'intervention', label: 'config_field_intervention_decisionTimeoutMs', kind: 'number', visibility: 'advanced' },
  // inlineGuards ( locked) — entire section is advancedOnly.
  { key: 'inlineGuards.engineLaunchers', section: 'inlineGuards', label: 'config_field_inlineGuards_engineLaunchers', kind: 'string', csv: true, locked: true, help: 'config_help_inlineGuards_locked' },
  { key: 'inlineGuards.pluginPackageName', section: 'inlineGuards', label: 'config_field_inlineGuards_pluginPackageName', kind: 'string', locked: true, help: 'config_help_inlineGuards_locked' },
  { key: 'inlineGuards.patchMarkers', section: 'inlineGuards', label: 'config_field_inlineGuards_patchMarkers', kind: 'string', csv: true, locked: true, help: 'config_help_inlineGuards_locked' },
  // ----- sensitivePathGuard -----
  // enabled is force-asserted true by
  // normalizeConfig (safety net cannot be disabled) — locked read-only.
  { key: 'sensitivePathGuard.enabled', section: 'sensitivePathGuard', label: 'config_field_sensitivePathGuard_enabled', kind: 'boolean', locked: true, help: 'config_help_guard_baseline_locked' },
  // advanced: deny-list override + watcher knobs (locked-fallback semantics).
  { key: 'sensitivePathGuard.paths', section: 'sensitivePathGuard', label: 'config_field_sensitivePathGuard_paths', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_sensitivePathGuard_paths' },
  { key: 'sensitivePathGuard.watchEnabled', section: 'sensitivePathGuard', label: 'config_field_sensitivePathGuard_watchEnabled', kind: 'boolean', visibility: 'advanced' },
  { key: 'sensitivePathGuard.watchDebounceMs', section: 'sensitivePathGuard', label: 'config_field_sensitivePathGuard_watchDebounceMs', kind: 'number', visibility: 'advanced', dependsOn: 'sensitivePathGuard.watchEnabled' },
  // ----- inlinePromptInjection -----
  // enabled is force-asserted true — locked.
  { key: 'inlinePromptInjection.enabled', section: 'inlinePromptInjection', label: 'config_field_inlinePromptInjection_enabled', kind: 'boolean', locked: true, help: 'config_help_guard_baseline_locked' },
  // advanced: pattern override + excerpt size (locked-fallback semantics).
  { key: 'inlinePromptInjection.patterns', section: 'inlinePromptInjection', label: 'config_field_inlinePromptInjection_patterns', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_inlinePromptInjection_patterns' },
  { key: 'inlinePromptInjection.excerptMaxChars', section: 'inlinePromptInjection', label: 'config_field_inlinePromptInjection_excerptMaxChars', kind: 'number', visibility: 'advanced' },
  // ----- stdioMirror -----
  // `enabled` is default-OFF — operators opt in via
  // `stdioMirror.enabled: true` in cordis.patch.yml. The UI field stays
  // `locked` because the runtime livePatch seam still rejects
  // `stdioMirror.enabled` (the wrapper config binds at bootstrap — a
  // toggle needs a restart, not a hot patch).
  { key: 'stdioMirror.enabled', section: 'stdioMirror', label: 'config_field_stdioMirror_enabled', kind: 'boolean', locked: true, help: 'config_help_stdioMirror_enabled' },
  // advanced: payload cap + output path.
  { key: 'stdioMirror.payloadLimitBytes', section: 'stdioMirror', label: 'config_field_stdioMirror_payloadLimitBytes', kind: 'number', visibility: 'advanced', dependsOn: 'stdioMirror.enabled' },
  { key: 'stdioMirror.outputPath', section: 'stdioMirror', label: 'config_field_stdioMirror_outputPath', kind: 'string', visibility: 'advanced', dependsOn: 'stdioMirror.enabled' },
  // ----- envPassthroughGuard -----
  // enabled is force-asserted true — locked.
  { key: 'envPassthroughGuard.enabled', section: 'envPassthroughGuard', label: 'config_field_envPassthroughGuard_enabled', kind: 'boolean', locked: true, help: 'config_help_guard_baseline_locked' },
  // advanced: deny-list override (locked-fallback semantics).
  { key: 'envPassthroughGuard.keys', section: 'envPassthroughGuard', label: 'config_field_envPassthroughGuard_keys', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_envPassthroughGuard_keys' },
  // ----- sensitiveHeaderGuard -----
  // enabled is force-asserted true — locked.
  { key: 'sensitiveHeaderGuard.enabled', section: 'sensitiveHeaderGuard', label: 'config_field_sensitiveHeaderGuard_enabled', kind: 'boolean', locked: true, help: 'config_help_guard_baseline_locked' },
  // advanced: deny-list override (locked-fallback semantics).
  { key: 'sensitiveHeaderGuard.keys', section: 'sensitiveHeaderGuard', label: 'config_field_sensitiveHeaderGuard_keys', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_sensitiveHeaderGuard_keys' },
  // out-of-frame exemption allow-list + enforcement
  // switch. Both are 🔴 restart-required — the Config form edits a draft
  // that is applied on restart, matching the livePatch classification.
  { key: 'sensitiveHeaderGuard.harnessPlaneHosts', section: 'sensitiveHeaderGuard', label: 'config_field_sensitiveHeaderGuard_harnessPlaneHosts', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_sensitiveHeaderGuard_harnessPlaneHosts' },
  { key: 'sensitiveHeaderGuard.enforceOutOfFrame', section: 'sensitiveHeaderGuard', label: 'config_field_sensitiveHeaderGuard_enforceOutOfFrame', kind: 'boolean', visibility: 'advanced', help: 'config_help_sensitiveHeaderGuard_enforceOutOfFrame' },
  // provider auto-discovery + seed exemption hosts. providerDiscovery /
  // providerDiscoveryPath are 🔴 restart-required (same draft-applied-on-
  // restart path as the two entries above); seedHosts is 🟢 livePatch.
  { key: 'sensitiveHeaderGuard.providerDiscovery', section: 'sensitiveHeaderGuard', label: 'config_field_sensitiveHeaderGuard_providerDiscovery', kind: 'boolean', visibility: 'advanced', help: 'config_help_sensitiveHeaderGuard_providerDiscovery' },
  { key: 'sensitiveHeaderGuard.providerDiscoveryPath', section: 'sensitiveHeaderGuard', label: 'config_field_sensitiveHeaderGuard_providerDiscoveryPath', kind: 'string', visibility: 'advanced', help: 'config_help_sensitiveHeaderGuard_providerDiscoveryPath' },
  { key: 'sensitiveHeaderGuard.seedHosts', section: 'sensitiveHeaderGuard', label: 'config_field_sensitiveHeaderGuard_seedHosts', kind: 'string', csv: true, visibility: 'advanced', help: 'config_help_sensitiveHeaderGuard_seedHosts' },
  // ----- loopedToolDetector -----
  // essential: master switch.
  { key: 'loopedToolDetector.enabled', section: 'loopedToolDetector', label: 'config_field_loopedToolDetector_enabled', kind: 'boolean' },
  // advanced: window / threshold.
  { key: 'loopedToolDetector.windowMs', section: 'loopedToolDetector', label: 'config_field_loopedToolDetector_windowMs', kind: 'number', visibility: 'advanced', dependsOn: 'loopedToolDetector.enabled' },
  { key: 'loopedToolDetector.thresholdPerWindow', section: 'loopedToolDetector', label: 'config_field_loopedToolDetector_thresholdPerWindow', kind: 'number', visibility: 'advanced', dependsOn: 'loopedToolDetector.enabled' },
  // ----- tokenUsageDetector -----
  // kept visible — the harness llm/stream
  // grammar carries `usage` chunks (provider translate yields them) and
  // a burst fires security_audit/anomalous_token_usage, visible in the
  // Event Stream tab. Help text states there are no cumulative stats.
  { key: 'tokenUsageDetector.enabled', section: 'tokenUsageDetector', label: 'config_field_tokenUsageDetector_enabled', kind: 'boolean', help: 'config_help_tokenUsageDetector_enabled' },
  // advanced: burst-detection knobs.
  { key: 'tokenUsageDetector.windowMs', section: 'tokenUsageDetector', label: 'config_field_tokenUsageDetector_windowMs', kind: 'number', visibility: 'advanced', dependsOn: 'tokenUsageDetector.enabled' },
  { key: 'tokenUsageDetector.burstFactor', section: 'tokenUsageDetector', label: 'config_field_tokenUsageDetector_burstFactor', kind: 'number', visibility: 'advanced', dependsOn: 'tokenUsageDetector.enabled', help: 'config_help_tokenUsageDetector_burstFactor' },
  { key: 'tokenUsageDetector.minBaselineSamples', section: 'tokenUsageDetector', label: 'config_field_tokenUsageDetector_minBaselineSamples', kind: 'number', visibility: 'advanced', dependsOn: 'tokenUsageDetector.enabled' },
  // ----- sinkDiskLow (all advanced — single knob, hidden by default) -----
  { key: 'sinkDiskLow.recoverMarginBytes', section: 'sinkDiskLow', label: 'config_field_sinkDiskLow_recoverMarginBytes', kind: 'number', visibility: 'advanced', help: 'config_help_sinkDiskLow_recoverMarginBytes' },
]

/** The dangerous VALUE for each danger-flagged field: saving a draft
 *  whose effective value equals this triggers the unconditional
 *  confirmation dialog. Keyed by the same dotted key as the metadata —
 *  the save path derives the check entirely from these two tables.
 *
 *  `intervention.mode` is the engine's sole authoritative enforcement
 *  switch (see `normalizeConfig` in
 *  `src/config/normalize.ts:151-153`). Old patch YAMLs that set
 *  top-level
 *  `mode: enforce` still work (normalize propagates down to
 *  `intervention.mode` when the nested field is unset), they just
 *  cannot be edited from this form.
 */
export const DANGER_FIELD_VALUES: Readonly<Record<string, string>> = {
  'intervention.mode': 'enforce',
  'intervention.failStrategy': 'fail_closed',
}

/** Locale message key describing each danger hit, listed in the
 *  confirmation dialog body. */
export const DANGER_FIELD_MESSAGES: Readonly<Record<string, LocaleKey>> = {
  'intervention.mode': 'config_field_danger_mode',
  'intervention.failStrategy': 'config_field_danger_failStrategy',
}

/** Read the effective value of a dotted config key: the draft's
 *  override wins over the snapshot baseline. Returns undefined when
 *  neither side carries the key. */
export function readFieldValue(
  snapshot: ConfigSnapshot,
  draft: ConfigPatch,
  key: string,
): unknown {
  const dot = key.indexOf('.')
  if (dot < 0) {
    const d = (draft as Record<string, unknown>)[key]
    if (d !== undefined) return d
    return (snapshot as unknown as Record<string, unknown>)[key]
  }
  const block = key.slice(0, dot)
  const field = key.slice(dot + 1)
  const dBlock = (draft as Record<string, unknown>)[block] as Record<string, unknown> | undefined
  if (dBlock && dBlock[field] !== undefined) return dBlock[field]
  const sBlock = (snapshot as unknown as Record<string, unknown>)[block] as
    | Record<string, unknown>
    | undefined
  return sBlock?.[field]
}

/** Danger hits for a draft — one entry per danger-flagged metadata
 *  field the DRAFT explicitly sets to the dangerous value (mode →
 *  'enforce', intervention.failStrategy → 'fail_closed'). Reading the
 * draft only (not the snapshot baseline) matches the mechanism
 *  clause: the confirmation fires when the draft TURNS a dangerous key
 *  on, not when the host already runs that value and the operator is
 *  saving an unrelated change. The Config tab save path consumes this
 *  to decide whether the unconditional confirmation dialog opens. */
export function resolveDangerHits(
  draft: ConfigPatch,
): ReadonlyArray<{ key: string; message: LocaleKey }> {
  const hits: Array<{ key: string; message: LocaleKey }> = []
  const draftRecord = draft as Record<string, unknown>
  for (const field of CONFIG_FIELD_METADATA) {
    if (!field.danger) continue
    const dangerValue = DANGER_FIELD_VALUES[field.key]
    if (dangerValue === undefined) continue
    const dot = field.key.indexOf('.')
    let value: unknown
    if (dot < 0) {
      value = draftRecord[field.key]
    } else {
      const block = draftRecord[field.key.slice(0, dot)] as Record<string, unknown> | undefined
      value = block?.[field.key.slice(dot + 1)]
    }
    if (value === dangerValue) {
      const message = DANGER_FIELD_MESSAGES[field.key]
      if (message) hits.push({ key: field.key, message })
    }
  }
  return hits
}
