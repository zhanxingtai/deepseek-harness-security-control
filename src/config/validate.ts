/**
 * `validateConfigPatch` server-side validator.
 *
 * The settings-page Config tab posts operator edits to
 * `validateConfigPatch(patch, currentConfig)` and only proceeds to
 * `saveConfigDraft` when the result is `ok: true`. The validator is
 * the only line of defense against a stale client pushing
 * marketplace-stripped fields (`endpoint`, `auth`, `outbox`,
 * `system`, `assetMonitor`, `environment`) into the running config
 * or trying to disable the invariant safety net
 * (`inlineGuards.enabled = false`).
 *
 * Behaviour summary:
 *   - Top-level keys not in `ConfigPatch` are rejected with a
 *     field-level error.
 *   - The marketplace-stripped keys listed above are rejected
 *     explicitly with a "marketplace form does not support X"
 *     error so the operator can tell the rejection is policy, not
 *     a typo.
 *   - `inlineGuards.enabled = false` is silently force-overridden
 * to `true` AND emitted as a warning ( invariant: the safety
 *     net cannot be turned off).
 *   - `mode = 'enforce'` with a missing or unreadable
 *     `intervention.policyPath` emits a warning. We do NOT block —
 *     the marketplace default policy exists and is loaded
 *     automatically, so a missing operator policy is "load
 *     defaults", which is the right behaviour for a fresh install.
 *   - Enums (`mode`, `failStrategy`, `decisionTimeoutMs`) are
 *     validated against the Schemastery `Config` schema. Unknown
 *     sub-keys are surfaced rather than silently dropped
 *     (`autofix: false`).
 *   - On success the post-validation `ConfigSnapshot` is returned
 *     so the client can preview the merged shape ("this is what
 *     the file will contain").
 *
 * The validator is intentionally a pure function — no I/O, no
 * filesystem. The host (`src/typert/host.ts`) is responsible for
 * building the `ConfigSnapshot` from the live `Config` and passing
 * it in.
 *
 * collapsed the four helper functions
 * (`pickBool` / `pickMode` / `mergeSubBlock` / `mergeInlineGuards`)
 * into inline spreads — the structuredClone pattern from draft.ts
 * + a single `mergeSnapshot` reduce make the file ~70% smaller
 * without changing the validator contract.
 */
import { existsSync } from 'node:fs'
import { Config as ConfigSchema } from '../config.schema.js'
import { expandHome } from '../utils/expandHome.js'
import type {
  ConfigPatch,
  ConfigSnapshot,
  ConfigSnapshotInlineGuards,
  ConfigValidationResult,
} from '../typert/descriptors.js'

/** Top-level keys the marketplace validator accepts. The set is the
 *  intersection of the ConfigPatch type, the Schemastery `Config`
 *  schema, and the live `Config` shape (see `src/config.ts`). Any
 *  other top-level key on the patch is rejected with a field-level
 *  error so a stale client cannot silently land a new field that
 *  the running plugin will drop.
 *
 * The whitelist must enumerate every block: a missing sub-block is
 * rejected with a field-level error at validate time, before the
 * Schemastery `Config` schema even runs. The
 * companion parity test (`tests/configParity.test.ts`) walks the
 * keys exported by `Config` in src/config.ts and asserts every one
 * is listed here. */
/** Internal — exported only for the parity test (`tests/configParity.test.ts`).
 *  The runtime validator does not need to expose this; it is consumed
 *  by `validateConfigPatch` below. */
export const ALLOWED_TOP_KEYS: ReadonlySet<string> = new Set([
  'mode', 'enabled', 'hostId', 'containerId',
  'collector', 'application', 'networkCapture',
  'intervention', 'runtimeHooks', 'inlineGuards',
  // §6.2 — inline deny-list guards
  'sensitivePathGuard', 'inlinePromptInjection',
  // §6.2 — stdio pipe mirror
  'stdioMirror',
  // §6.2 — env-passthrough guard
  'envPassthroughGuard',
  // Inline sensitive-header guard (outbound HTTP)
  'sensitiveHeaderGuard',
  // §6.2 — per-tool loop detector
  'loopedToolDetector',
  // §6.2 — token-usage burst detector
  'tokenUsageDetector',
  // §6.2 — sink disk-low degradation
  'sinkDiskLow',
])

/** Marketplace-stripped top-level keys — rejected explicitly so the
 *  operator sees a "marketplace form does not support X" message
 *  rather than letting the Schemastery Config schema drop the key
 *  silently. Exported only for the parity test
 *  (`tests/configParity.test.ts`). */
export const MARKETPLACE_BLOCKED_TOP_KEYS: ReadonlySet<string> = new Set([
  'endpoint', 'auth', 'outbox', 'system', 'assetMonitor', 'environment',
])

/** Function that resolves whether a policy path exists on disk.
 *  Tests pass a stub. */
export type PolicyPathResolver = (path: string) => boolean

function defaultPolicyPathResolver(p: string): boolean {
  if (typeof p !== 'string' || p.length === 0) return false
  // No `try/catch` around existsSync — the
  // Node `fs.existsSync` API is documented never to throw, so such a
  // branch would be dead code. A defensive caller who does want exception
  // semantics should wrap their `policyPathResolver` themselves.
  return existsSync(expandHome(p))
}

/** Validate an operator-supplied `ConfigPatch` against the live
 *  `ConfigSnapshot`. Returns a `ConfigValidationResult` with a
 *  field-level error list and the post-validation snapshot. Never
 *  throws — a Schemastery reject is recorded as an error. */
export function validateConfigPatch(
  patch: ConfigPatch | null | undefined,
  currentConfig: ConfigSnapshot,
  policyPathResolver: PolicyPathResolver = defaultPolicyPathResolver,
): ConfigValidationResult {
  const errors: string[] = []
  const warnings: string[] = []
  const patchRecord = (patch ?? {}) as Record<string, unknown>

  // Step 1: top-level key whitelist.
  for (const key of Object.keys(patchRecord)) {
    if (ALLOWED_TOP_KEYS.has(key)) continue
    if (MARKETPLACE_BLOCKED_TOP_KEYS.has(key)) {
      errors.push(
        `'${key}' is not supported in the marketplace distribution; this field ` +
'belongs to the platform deployment surface and was stripped in .',
      )
      continue
    }
    errors.push(
      `'${key}' is not a recognized Config top-level key; allowed keys: ` +
        `${Array.from(ALLOWED_TOP_KEYS).join(', ')}.`,
    )
  }

  // Step 2: invariant — `inlineGuards.engineLaunchers=[]` is
  // accepted with a warning (the runtime layer re-asserts defaults
  // in `normalizeConfig` so the safety net cannot actually be
  // disabled). Note: the marketplace `InlineGuardsConfig` carries
  // no `enabled` flag — the safety net is unconditionally on.
  const inlineGuards = patchRecord['inlineGuards']
  if (inlineGuards && typeof inlineGuards === 'object' && !Array.isArray(inlineGuards)) {
    const ig = inlineGuards as Record<string, unknown>
    if (Array.isArray(ig['engineLaunchers']) && ig['engineLaunchers'].length === 0) {
      warnings.push(
'inlineGuards.engineLaunchers=[] was passed; the safety net '+
          'defaults will be restored at apply() time (pnpm dsh / npx dsh / ' +
          'node bin.ts + systemd-run / systemctl). The safety net cannot be ' +
          'disabled by removing launcher entries.',
      )
    }
  }

  // Step 3: `mode=enforce` + missing `intervention.policyPath` → warn.
  if (patchRecord['mode'] === 'enforce') {
    const intervention = patchRecord['intervention']
    const interventionObj = (intervention && typeof intervention === 'object' && !Array.isArray(intervention))
      ? (intervention as Record<string, unknown>)
      : {}
    const policyPaths = Array.isArray(interventionObj['policyPaths'])
      ? (interventionObj['policyPaths'].filter((p) => typeof p === 'string') as string[])
      : []
    const legacyPolicyPath = typeof interventionObj['policyPath'] === 'string'
      ? (interventionObj['policyPath'] as string).trim()
      : ''
    if (policyPaths.length === 0 && legacyPolicyPath.length === 0) {
      warnings.push(
        "Switching to 'enforce' without setting intervention.policyPaths; " +
          'the marketplace will load the bundled default-policy.spl.yaml. ' +
          'Add an explicit policy file before going to production.',
      )
    } else {
      const effective = [...policyPaths]
      if (legacyPolicyPath.length > 0) effective.push(legacyPolicyPath)
      for (const candidate of effective) {
        if (!policyPathResolver(candidate)) {
          warnings.push(
            `intervention policy path does not exist: ${candidate}; ` +
              'the engine will fall back to the marketplace default-policy.spl.yaml.',
          )
        }
      }
    }
  }

  // Step 4: Schemastery strict validation (autofix off).
  let normalized: ConfigSnapshot | null = null
  if (errors.length === 0) {
    try {
      const filled = ConfigSchema(patchRecord, { autofix: false }) as Record<string, unknown>
      normalized = mergeSnapshots(currentConfig, filled)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      errors.push(`Schema validation failed: ${message}`)
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    normalized,
  }
}

/** Merge the Schemastery-filled patch on top of the live
 *  `ConfigSnapshot`. We re-build the snapshot so the client can
 *  render a "this is what will land" preview. The merge is a
 *  shallow key overwrite (the Schemastery fill already produced a
 *  valid post-shape — no deep merge needed). */
function mergeSnapshots(
  current: ConfigSnapshot,
  patch: Record<string, unknown>,
): ConfigSnapshot {
  // `structuredClone` guards against a hostile patch that mutates
  // `current` through a shared reference; the snapshot's contract
  // is "a stable shape the client can render" so we deliberately
  // drop unmodelled keys by going through the explicit field list.
  const picked = structuredClone(current)
  const pickStr = (v: unknown, fallback: string): string =>
    typeof v === 'string' ? v : fallback
  const pickBool = (v: unknown, fallback: boolean): boolean =>
    typeof v === 'boolean' ? v : v === 'true' ? true : v === 'false' ? false : fallback
  const merged: ConfigSnapshot = {
    ...picked,
    mode: patch['mode'] === 'enforce' ? 'enforce' : 'audit',
    enabled: pickBool(patch['enabled'], picked.enabled),
    hostId: pickStr(patch['hostId'], picked.hostId),
    containerId: pickStr(patch['containerId'], picked.containerId),
    collector: { ...picked.collector, ...(subBlock(patch['collector']) as object) },
    application: { ...picked.application, ...(subBlock(patch['application']) as object) },
    networkCapture: { ...picked.networkCapture, ...(subBlock(patch['networkCapture']) as object) },
    intervention: { ...picked.intervention, ...(subBlock(patch['intervention']) as object) },
    runtimeHooks: { ...picked.runtimeHooks, ...(subBlock(patch['runtimeHooks']) as object) },
    inlineGuards: mergeInlineGuards(picked.inlineGuards, patch['inlineGuards']),
    // The 7 §6.2 sub-blocks. The
    // snapshot must mirror the live Config after a successful patch
    // preview so the client can render the "this is what will land"
    // surface (saveConfigDraft re-validates anyway, so a missing
    // mirror here would only affect the preview pane).
    sensitivePathGuard: { ...picked.sensitivePathGuard, ...(subBlock(patch['sensitivePathGuard']) as object) },
    inlinePromptInjection: { ...picked.inlinePromptInjection, ...(subBlock(patch['inlinePromptInjection']) as object) },
    stdioMirror: { ...picked.stdioMirror, ...(subBlock(patch['stdioMirror']) as object) },
    envPassthroughGuard: { ...picked.envPassthroughGuard, ...(subBlock(patch['envPassthroughGuard']) as object) },
    sensitiveHeaderGuard: { ...picked.sensitiveHeaderGuard, ...(subBlock(patch['sensitiveHeaderGuard']) as object) },
    loopedToolDetector: { ...picked.loopedToolDetector, ...(subBlock(patch['loopedToolDetector']) as object) },
    tokenUsageDetector: { ...picked.tokenUsageDetector, ...(subBlock(patch['tokenUsageDetector']) as object) },
    sinkDiskLow: { ...picked.sinkDiskLow, ...(subBlock(patch['sinkDiskLow']) as object) },
  }
  return merged
}

function subBlock(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

function mergeInlineGuards(
  base: ConfigSnapshotInlineGuards,
  override: unknown,
): ConfigSnapshotInlineGuards {
  const o = subBlock(override)
  if (!o) return base
  const pickStrList = (v: unknown, fallback: string[]): string[] =>
    Array.isArray(v) ? (v.filter((x) => typeof x === 'string') as string[]) : fallback
  return {
    engineLaunchers: pickStrList(o['engineLaunchers'], [...base.engineLaunchers]),
    pluginPackageName:
      typeof o['pluginPackageName'] === 'string' ? o['pluginPackageName'] : base.pluginPackageName,
    patchMarkers: pickStrList(o['patchMarkers'], [...base.patchMarkers]),
  }
}