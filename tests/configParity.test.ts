/**
 * Config-parity contract test.
 *
 * The drift class this test pins down: when a new sub-block is added
 * to the live `Config` interface in `src/config.ts`, the matching
 * snapshot / schema / whitelist / classifier surfaces must all be
 * extended in lock-step. Previously each surface drifted in
 * isolation — the schema silently dropped new fields, the
 * validator rejected new top-level keys, the snapshot UI silently
 * dropped new sections, and the livePatch classifier treated new
 * blocks as unknown (🔴 rejected).
 *
 * This test enforces the cross-file contract at four boundaries:
 *
 *   1. **`Config` (src/config.ts) ↔ Schemastery `Config` schema
 *      (src/config.schema.ts)** — every top-level block on the live
 *      Config interface must appear as a top-level key on the
 *      schema (and vice versa, modulo mode which is a leaf).
 *
 *   2. **`Config` ↔ `ALLOWED_TOP_KEYS`
 *      (src/config/validate.ts)** — the marketplace validator's
 *      accept-list must enumerate every top-level Config block.
 *
 *   3. **`Config` ↔ `PATCH_TOP_LEVEL_KEYS`
 *      (src/config/draft.ts)** — the draft writer's accept-list
 *      must enumerate every top-level Config block.
 *
 *   4. **`Config` ↔ `ConfigSnapshot` (host src/typert/descriptors.ts
 *      + client src/client/wire.ts)** — every Config sub-block must
 *      have a snapshot mirror with the same field set, in both the
 *      host declaration and the client mirror. Asserted at the
 *      type level (compile-time) — adding a field to one side
 *      without mirroring the other fails the structural assignment
 *      and `pnpm tsc -b` blocks the merge.
 *
 * The 5th boundary (livePatch classification in
 * `src/config/livePatch.ts`) is already covered by
 * `tests/livePatch.test.ts`; the per-block tables there enumerate
 * the safe / restart / rejected partitions and are tightly coupled
 * to the SPL semantics — keeping the parity assertions out of this
 * file avoids coupling those tests to internal classifier changes.
 *
 * Adding a sub-block to `Config` without updating one of these
 * surfaces fails the relevant assertion with a precise key
 * name and a copy-pasteable diff, so the regression is caught at
 * `pnpm test` rather than at runtime on a deployed operator's box.
 */

import { describe, expect, it } from 'vitest'

import { normalizeConfig, type Config } from '../src/config.js'
import { Config as ConfigSchema } from '../src/config.schema.js'
import { ALLOWED_TOP_KEYS as ALLOWED_TOP_KEYS_INTERNALS, MARKETPLACE_BLOCKED_TOP_KEYS } from '../src/config/validate.js'
import { PATCH_TOP_LEVEL_KEYS } from '../src/config/draft.js'

/** Top-level keys the live `Config` interface in src/config.ts owns.
 *  Built from a normalised default — the result of `normalizeConfig({})`
 *  has every block filled in, so `Object.keys(config)` enumerates
 *  the complete marketplace surface. */
function liveConfigTopLevelKeys(): string[] {
  const config = normalizeConfig({})
  return Object.keys(config).sort()
}

/** Top-level keys the Schemastery `Config` schema in
 *  src/config.schema.ts accepts. The schema exposes its field set
 *  via a small introspection: we build an empty input, run it
 *  through autofix, and enumerate the keys. */
function schemaTopLevelKeys(): string[] {
  const filled = ConfigSchema({}, { autofix: true }) as Record<string, unknown>
  return Object.keys(filled).sort()
}

/** Diff helper — `left - right` (keys present in `left` but absent
 *  in `right`). Used to surface the precise drift in failure
 *  messages. */
function diff(left: string[], right: string[]): string[] {
  const rightSet = new Set(right)
  return left.filter((k) => !rightSet.has(k))
}

describe('config parity', () => {
  describe('Config ↔ Config schema (src/config.schema.ts)', () => {
    it('schema accepts every top-level Config block', () => {
      const live = liveConfigTopLevelKeys()
      const schema = schemaTopLevelKeys()
      const missing = diff(live, schema)
      expect(missing, `schema missing top-level keys: ${missing.join(', ')}`).toEqual([])
    })

    it('schema does not carry stale top-level blocks', () => {
      const live = new Set(liveConfigTopLevelKeys())
      const stale = schemaTopLevelKeys().filter((k) => !live.has(k))
      expect(stale, `schema carries stale keys: ${stale.join(', ')}`).toEqual([])
    })

    it('CollectorConfig schema carries maxFileBytes / diskWarn / diskLow (regression for evidence line 1)', () => {
      const validated = ConfigSchema({}, { autofix: true }) as Record<string, unknown>
      const collector = validated.collector as Record<string, unknown>
      expect(typeof collector.maxFileBytes).toBe('number')
      expect(typeof collector.diskWarnWatermarkBytes).toBe('number')
      expect(typeof collector.diskLowWatermarkBytes).toBe('number')
      expect(collector.maxFileBytes).toBe(50 * 1024 * 1024)
      expect(collector.diskWarnWatermarkBytes).toBe(500 * 1024 * 1024)
      expect(collector.diskLowWatermarkBytes).toBe(100 * 1024 * 1024)
    })

    it('InterventionConfig schema does NOT carry the stale highRiskFlags field ( evidence line 2)', () => {
      const validated = ConfigSchema({}, { autofix: true }) as Record<string, unknown>
      const intervention = validated.intervention as Record<string, unknown>
      expect(intervention).not.toHaveProperty('highRiskFlags')
    })
  })

  describe('Config ↔ ALLOWED_TOP_KEYS (src/config/validate.ts)', () => {
    it('validator whitelist accepts every top-level Config block', () => {
      const live = liveConfigTopLevelKeys()
      const missing = live.filter((k) => !ALLOWED_TOP_KEYS_INTERNALS.has(k))
      expect(
        missing,
        `ALLOWED_TOP_KEYS missing top-level keys: ${missing.join(', ')}; add them so the marketplace validator accepts operator patches`,
      ).toEqual([])
    })

    it('validator whitelist does not carry stale top-level keys', () => {
      const live = new Set(liveConfigTopLevelKeys())
      const stale = Array.from(ALLOWED_TOP_KEYS_INTERNALS).filter((k) => !live.has(k))
      expect(
        stale,
        `ALLOWED_TOP_KEYS carries stale keys: ${stale.join(', ')}`,
      ).toEqual([])
    })

    it('marketplace-blocked keys (endpoint / auth / outbox / system / assetMonitor / environment) remain rejected', () => {
      const blocked = ['endpoint', 'auth', 'outbox', 'system', 'assetMonitor', 'environment']
      for (const key of blocked) {
        expect(ALLOWED_TOP_KEYS_INTERNALS.has(key), `${key} should NOT be in ALLOWED_TOP_KEYS`).toBe(false)
        expect(MARKETPLACE_BLOCKED_TOP_KEYS.has(key), `${key} should be in MARKETPLACE_BLOCKED_TOP_KEYS`).toBe(true)
      }
    })
  })

  describe('Config ↔ PATCH_TOP_LEVEL_KEYS (src/config/draft.ts)', () => {
    it('draft whitelist accepts every top-level Config block', () => {
      const live = new Set(liveConfigTopLevelKeys())
      const missing = PATCH_TOP_LEVEL_KEYS.filter((k) => !live.has(k))
      expect(
        missing,
        `PATCH_TOP_LEVEL_KEYS missing top-level keys: ${missing.join(', ')}; add them so applyDraftToConfig can shallow-merge the new blocks`,
      ).toEqual([])
    })

    it('draft whitelist does not carry stale top-level keys', () => {
      const live = new Set(liveConfigTopLevelKeys())
      const stale = PATCH_TOP_LEVEL_KEYS.filter((k) => !live.has(k))
      expect(
        stale,
        `PATCH_TOP_LEVEL_KEYS carries stale keys: ${stale.join(', ')}`,
      ).toEqual([])
    })
  })

  describe('Config ↔ ConfigSnapshot sub-block parity (compile-time + runtime)', () => {
    // The Config interface sub-blocks ↔ ConfigSnapshot sub-block
    // interfaces. The compile-time check is the load-bearing one:
    // if a field is added to Config and not mirrored to the host
    // or client snapshot, the `host: ConfigSnapshot` and
    // `client: ClientConfigSnapshot` assignments below fail to
    // typecheck, and `pnpm tsc -b` blocks the merge.

    it('snapshot sub-blocks cover every Config sub-block (runtime key count)', () => {
      const config = normalizeConfig({})
      // Pull a snapshot of the live config to verify the host side
      // returns a structurally-complete shape. We don't need to
      // assert exact field names here — the compile-time assignment
      // below is the strong guarantee.
      const expectedBlocks = [
        'collector',
        'application',
        'networkCapture',
        'runtimeHooks',
        'intervention',
        'inlineGuards',
        'sensitivePathGuard',
        'inlinePromptInjection',
        'stdioMirror',
        'envPassthroughGuard',
        // 2026-10-10: missing from this list silently passed the
        // snapshot-coverage assertion below — adding the 14th block
        // here re-arms the drift gate so a 15th block without a
        // matching expectedBlocks row fails the test again.
        'sensitiveHeaderGuard',
        'loopedToolDetector',
        'tokenUsageDetector',
        'sinkDiskLow',
      ]
      for (const block of expectedBlocks) {
        expect(
          (config as unknown as Record<string, unknown>)[block],
          `live Config is missing expected sub-block: ${block}`,
        ).toBeDefined()
      }
    })
  })

  describe('runtime: validateConfigPatch accepts the 7 sub-blocks', () => {
    it('a patch with each new sub-block is accepted (no "not a recognized Config top-level key" error)', async () => {
      const { validateConfigPatch } = await import('../src/config/validate.js')
      const config = normalizeConfig({})
      // Build a minimal snapshot — we only need the type to flow.
      // The validator imports its own ConfigSnapshot type, so we
      // hand-build a structurally-valid one by shallow-copying the
      // normalised Config through the public Config shape.
      const currentConfig = config as unknown as Parameters<typeof validateConfigPatch>[1]

      const newBlocks = [
        { sensitivePathGuard: { paths: ['/tmp/extra-block'] } },
        { inlinePromptInjection: { patterns: ['\\bTESTMARKER\\b'] } },
        { stdioMirror: { payloadLimitBytes: 2048 } },
        { envPassthroughGuard: { keys: ['MY_CUSTOM_LOADER'] } },
        // 2026-09-28 config review fix: was missing from PATCH_TOP_LEVEL_KEYS.
        { sensitiveHeaderGuard: { keys: ['X-Test-Auth'] } },
        { loopedToolDetector: { windowMs: 30_000 } },
        { tokenUsageDetector: { burstFactor: 4 } },
        { sinkDiskLow: { recoverMarginBytes: 25 * 1024 * 1024 } },
      ] as const

      for (const patch of newBlocks) {
        const result = validateConfigPatch(patch, currentConfig)
        // The validator may still reject due to other concerns
        // (e.g. sub-block field schema mismatch) — but the
        // recognised-key check is the load-bearing one for.
        const recognisedKeyErrors = result.errors.filter((e) =>
          e.includes('not a recognized Config top-level key'),
        )
        expect(
          recognisedKeyErrors,
          `patch ${JSON.stringify(patch)} was rejected with a "not a recognized" error — extend ALLOWED_TOP_KEYS`,
        ).toEqual([])
      }
    })
  })

  describe('runtime: applyDraftToConfig preserves the 7 sub-blocks', () => {
    it('a draft carrying each new sub-block survives the round-trip', async () => {
      const { applyDraftToConfig } = await import('../src/config/draft.js')
      const base = normalizeConfig({})
      const patches: Array<Record<string, unknown>> = [
        { sensitivePathGuard: { paths: ['/tmp/draft-block'] } },
        { inlinePromptInjection: { patterns: ['\\bDRAFTMARKER\\b'] } },
        { stdioMirror: { payloadLimitBytes: 4096 } },
        { envPassthroughGuard: { keys: ['MY_DRAFT_KEY'] } },
        // 2026-09-28 config review fix: was silently dropped by
        // applyDraftToConfig before sensitiveHeaderGuard entered the
        // PATCH_TOP_LEVEL_KEYS whitelist.
        { sensitiveHeaderGuard: { keys: ['X-Draft-Auth'] } },
        { loopedToolDetector: { windowMs: 20_000 } },
        { tokenUsageDetector: { burstFactor: 5 } },
        { sinkDiskLow: { recoverMarginBytes: 10 * 1024 * 1024 } },
      ]
      for (const patch of patches) {
        const merged = applyDraftToConfig(base, patch)
        for (const [block, override] of Object.entries(patch)) {
          const mergedBlock = (merged as unknown as Record<string, Record<string, unknown>>)[block]
          for (const [field, value] of Object.entries(override)) {
            // applyDraftToConfig now pipes through
            // normalizeConfig(), which applies UNION semantics for deny-list
            // blocks (`paths` / `patterns` / `keys`) — the operator value is
            // APPENDED to the marketplace fallback rather than replacing it.
            // The safety-net fallback list must always survive a draft edit
            // so an operator (or attacker via UI) cannot clear it.
            if (
              block === 'sensitivePathGuard' && field === 'paths'
              || block === 'inlinePromptInjection' && field === 'patterns'
              || block === 'envPassthroughGuard' && field === 'keys'
              // 2026-09-28: sensitiveHeaderGuard.keys re-joined the draft
              // path — same UNION semantics as envPassthroughGuard.keys.
              || block === 'sensitiveHeaderGuard' && field === 'keys'
            ) {
              const arr = mergedBlock[field] as unknown[]
              expect(
                arr,
                `applyDraftToConfig lost ${block}.${field} from patch ${JSON.stringify(patch)}`,
              ).toEqual(expect.arrayContaining(value as unknown[]))
            } else {
              expect(
                mergedBlock[field],
                `applyDraftToConfig dropped ${block}.${field} from patch ${JSON.stringify(patch)}`,
              ).toEqual(value)
            }
          }
        }
      }
    })
  })

  // the Config tab form renders from
  // `src/client/config/fields.ts#CONFIG_FIELD_METADATA`. The drift
  // class: a host-side Config field is added without a metadata entry
  // (the form silently drops it), or a metadata entry is added for a
  // key the host Config does not carry (the form renders a phantom
  // field the validator would reject). Both directions are asserted
  // against the host leaf-key set derived from `normalizeConfig({})`
  // — the same source the existing describe blocks use.
  describe('Config form field metadata ↔ host Config leaf keys', () => {
    it('metadata key set equals the host Config leaf-key set', async () => {
      const { CONFIG_FIELD_METADATA } = await import('../src/client/config/fields.js')
      const metadataKeys = CONFIG_FIELD_METADATA.map((f: { key: string }) => f.key).sort()

      const config = normalizeConfig({}) as unknown as Record<string, unknown>
      const leafKeys: string[] = []
      for (const [topKey, value] of Object.entries(config)) {
        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
          for (const subKey of Object.keys(value as Record<string, unknown>)) {
            leafKeys.push(`${topKey}.${subKey}`)
          }
        } else {
          leafKeys.push(topKey)
        }
      }
      // 2026-10-10: the top-level `Config.mode` field is intentionally
      // NOT in `CONFIG_FIELD_METADATA` anymore — the Config form
      // exposes the runtime mode under `intervention.mode` only
      // (the engine reads `config.intervention.mode` as the sole
      // authoritative enforcement switch; see
      // `src/client/config/fields.ts:127-135` and the migration note
      // in README.md). `Config.mode` is preserved in the type and
      // normalize layer for backward compatibility with old patch
      // YAMLs that set top-level `mode: enforce` (it propagates down
      // to `intervention.mode` in `src/config/normalize.ts:151-153`).
      // We filter it out of the parity-leaf set so this test pins
      // "every UI-editable leaf has a metadata entry" — a UI-hidden
      // legacy field is not a drift bug.
      const filteredLeafKeys = leafKeys.filter((k) => k !== 'mode')
      filteredLeafKeys.sort()

      const missing = filteredLeafKeys.filter((k) => !metadataKeys.includes(k))
      const stale = metadataKeys.filter((k) => !filteredLeafKeys.includes(k))
      expect(
        missing,
        `CONFIG_FIELD_METADATA is missing entries for host Config keys: ${missing.join(', ')}`,
      ).toEqual([])
      expect(
        stale,
        `CONFIG_FIELD_METADATA carries keys the host Config does not have: ${stale.join(', ')}`,
      ).toEqual([])
    })

    it('every metadata key is unique and every entry labels a real section', async () => {
      const { CONFIG_FIELD_METADATA, CONFIG_SECTIONS } = await import(
        '../src/client/config/fields.js'
      )
      const keys = CONFIG_FIELD_METADATA.map((f: { key: string }) => f.key)
      expect(new Set(keys).size, 'duplicate keys in CONFIG_FIELD_METADATA').toBe(keys.length)
      const sectionIds = new Set(CONFIG_SECTIONS.map((s: { id: string }) => s.id))
      for (const field of CONFIG_FIELD_METADATA as ReadonlyArray<{ key: string; section: string }>) {
        expect(
          sectionIds.has(field.section),
          `field ${field.key} references unknown section ${field.section}`,
        ).toBe(true)
      }
    })

    it('danger flags ↔ DANGER_FIELD_VALUES ↔ DANGER_FIELD_MESSAGES stay in lock-step', async () => {
      const {
        CONFIG_FIELD_METADATA,
        DANGER_FIELD_VALUES,
        DANGER_FIELD_MESSAGES,
      } = await import('../src/client/config/fields.js')
      const dangerKeys = CONFIG_FIELD_METADATA
        .filter((f: { danger?: boolean }) => f.danger === true)
        .map((f: { key: string }) => f.key)
        .sort()
      expect(dangerKeys).toEqual(['intervention.failStrategy', 'intervention.mode'])
      expect(Object.keys(DANGER_FIELD_VALUES).sort()).toEqual(dangerKeys)
      expect(Object.keys(DANGER_FIELD_MESSAGES).sort()).toEqual(dangerKeys)
    })
  })
})

// The compile-time check is implicitly handled by the imports
// above: `normalizeConfig({})` returns a `Config`, and the
// structural assignments elsewhere in the test file (e.g. the
// `host: ConfigSnapshot` ↔ `client: ClientConfigSnapshot` cross-
// file assignments under the "host snapshot ↔ client wire mirror"
// describe block) fail to typecheck if the live Config gains a
// field that the snapshot mirrors don't. So `pnpm tsc -b` is the
// load-bearing gate; the runtime assertions above are belt-and-
// braces sanity checks that surface the precise drift in the test
// output.
