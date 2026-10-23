/**
 * client locales test —.
 *
 * Enforces parity between the `en` and `zh` dictionaries in
 * `src/client/locales.ts`:
 *
 *   - Every key in `en` exists in `zh` and vice versa.
 *   - The `LocaleKey` type is the union of all keys (compiled-time
 *     check, asserted at runtime via the keys of the exported
 *     `locales.en` object).
 *
 * The runtime parity check catches a missing translation immediately
 * at `pnpm test` time, before the marketplace node ever loads the
 * bundle. Without this guard, a `t('key')` call against a missing
 * `zh` entry would silently fall back to the key string, hiding the
 * drift until an operator noticed the untranslated UI in production.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import YAML from 'yaml'
import { describe, expect, it } from 'vitest'

import { locales, type LocaleKey } from '../../src/client/locales.js'
import { LITERAL_ALIASES, localizeReason, type Translate } from '../../src/client/reasons.js'

/**
 * Repo-relative path to the SPL policy the reason table is derived from.
 *
 * Resolved from `process.cwd()`, NOT `import.meta.url`: vitest.config.ts
 * routes `tests/client/**` to happy-dom via `environmentMatchGlobs`, and
 * under that environment `import.meta.url` is not a file:// URL —
 * `fileURLToPath` throws ERR_INVALID_URL_SCHEME. Vitest runs every test
 * with cwd at the config root, so this resolves the same either way.
 */
const SPL_PATH = resolve(process.cwd(), 'policies/default-policy.spl.yaml')

describe('client locales', () => {
  it('en dictionary is non-empty', () => {
    expect(Object.keys(locales.en).length).toBeGreaterThan(0)
  })

  it('zh dictionary is non-empty', () => {
    expect(Object.keys(locales.zh).length).toBeGreaterThan(0)
  })

  it('en and zh have the same key set', () => {
    const enKeys = Object.keys(locales.en).sort()
    const zhKeys = Object.keys(locales.zh).sort()
    expect(zhKeys).toEqual(enKeys)
  })

  it('every value is a non-empty string', () => {
    for (const [k, v] of Object.entries(locales.en)) {
      expect(typeof v).toBe('string')
      expect((v as string).length, `en.${k} is empty`).toBeGreaterThan(0)
    }
    for (const [k, v] of Object.entries(locales.zh)) {
      expect(typeof v).toBe('string')
      expect((v as string).length, `zh.${k} is empty`).toBeGreaterThan(0)
    }
  })

  it('LocaleKey type is exhaustive — adding a key to en without zh fails here', () => {
    // The runtime check above already catches the drift. This test
    // double-checks that the exported `LocaleKey` type resolves to
    // the right union by exercising a few representative keys.
    // sample uses the renamed tab keys (SPL rules
    // tab removed).
    const sample: LocaleKey[] = ['nav', 'tab_metrics', 'tab_event_stream', 'tab_top_blocks']
    expect(sample.length).toBe(4)
  })

  it('Metrics-tab keys are present in both en and zh', () => {
    // The Metrics page vocabulary. The tab visual
    // rework is a follow-up task; this guard pins the key set so the
    // rename cannot drift between the two dictionaries.
    const metricsKeys: LocaleKey[] = [
      'tab_metrics',
      'tab_event_stream',
      'tab_top_blocks',
      'tab_config',
      'metrics_by_layer',
      'metrics_last_24h',
      'metrics_blocked',
      'metrics_last_updated',
      'metrics_auto_refresh',
      'total_events',
      'blocks_24h',
    ]
    for (const k of metricsKeys) {
      expect(typeof locales.en[k]).toBe('string')
      expect((locales.en[k] as string).length, `en.${k} is empty`).toBeGreaterThan(0)
      expect(typeof locales.zh[k]).toBe('string')
      expect((locales.zh[k] as string).length, `zh.${k} is empty`).toBeGreaterThan(0)
    }
  })

  it('placeholder strings use the documented {param} form', () => {
    // The runtime locale bind function does a simple replacement;
    // the contract requires placeholders to be {name} so the regex
    // /\{(\w+)\}/g in the (future) bind helper matches them.
    const placeholders = [
      locales.en.uptime_seconds,
      locales.en.uptime_minutes,
      locales.en.uptime_hours,
      locales.en.policy_reload_ok,
      locales.en.policy_reload_fail,
    ]
    for (const p of placeholders) {
      expect(p, `placeholder missing {} form: ${p}`).toMatch(/\{[a-z]+\}/)
    }
  })

  it('Config-tab keys are present in both en and zh', () => {
    // The Config tab is a new section key set introduced in. If
    // a key is added to one language but not the other, the UI would
    // silently fall back to the raw key string in the missing
    // language. This guard makes the drift a test failure.
    const configKeys: LocaleKey[] = [
      'tab_config',
      'config_reload',
      'config_reloading',
      'config_load_error',
      'config_readonly_hint',
      'config_section_top',
      'config_section_collector',
      'config_section_application',
      'config_section_network',
      'config_section_runtime',
      'config_section_intervention',
      'config_section_inline',
      'config_value_true',
      'config_value_false',
      'config_value_empty',
      'config_inline_locked_tooltip',
    ]
    for (const k of configKeys) {
      expect(typeof locales.en[k]).toBe('string')
      expect((locales.en[k] as string).length, `en.${k} is empty`).toBeGreaterThan(0)
      expect(typeof locales.zh[k]).toBe('string')
      expect((locales.zh[k] as string).length, `zh.${k} is empty`).toBeGreaterThan(0)
    }
  })

  // ---------------------------------------------------------------------
  // Untranslated-copy guard.
  //
  // Key parity alone does not prove a translation happened: `zh: 'Metrics'`
  // satisfies every assertion above while rendering English to a Chinese
  // operator. That is exactly how the 4 tab labels and `⚠ danger` sat
  // untranslated until 2026-10-22. A key whose two languages are byte
  // identical is only legitimate when the string is intentionally
  // language-neutral (a product name), so those are allowlisted by name.
  // ---------------------------------------------------------------------
  it('zh entries identical to en are explicitly allowlisted', () => {
    const ALLOWLIST = new Set<string>([
      // Product name — never translated.
      'nav',
      // Engine identifiers / config literals shown verbatim in the UI.
      'config_value_true',
      'config_value_false',
    ])
    const untranslated = Object.keys(locales.en).filter(
      (k) => locales.en[k as LocaleKey] === locales.zh[k as LocaleKey] && !ALLOWLIST.has(k),
    )
    expect(
      untranslated,
      'zh value is byte-identical to en — either translate it or add it to ALLOWLIST',
    ).toEqual([])
  })

  // ---------------------------------------------------------------------
  // Reason-column coverage guard.
  //
  // `src/client/reasons.ts` maps `policy_id` → localized Reason text. The
  // zh column is generated byte-exact from the SPL rule `name`, so these
  // assertions are what keep the two from drifting: add a rule to
  // policies/default-policy.spl.yaml without its `reason_<id>` key (in BOTH
  // languages) and this fails.
  //
  // Without it the UI degrades silently — `localizeReason` falls back to the
  // raw composed string, which is the English-wrapper-around-Chinese
  // sentence this work exists to remove.
  // ---------------------------------------------------------------------
  it('every SPL rule id has a reason_<id> entry in both languages', () => {
    const doc = YAML.parse(readFileSync(SPL_PATH, 'utf8')) as {
      rules?: { id?: unknown; name?: unknown }[]
    }
    const rules = doc.rules ?? []
    expect(rules.length).toBeGreaterThan(0)

    const missing: string[] = []
    for (const rule of rules) {
      const key = `reason_${String(rule.id)}` as LocaleKey
      if (typeof locales.en[key] !== 'string' || locales.en[key].length === 0) {
        missing.push(`en.${key}`)
      }
      if (typeof locales.zh[key] !== 'string' || locales.zh[key].length === 0) {
        missing.push(`zh.${key}`)
      }
    }
    expect(missing, 'SPL rule without a localized Reason entry').toEqual([])
  })

  it('zh reason text stays byte-identical to the SPL rule name', () => {
    const doc = YAML.parse(readFileSync(SPL_PATH, 'utf8')) as {
      rules?: { id?: unknown; name?: unknown }[]
    }
    const drifted: string[] = []
    for (const rule of doc.rules ?? []) {
      const key = `reason_${String(rule.id)}` as LocaleKey
      if (locales.zh[key] !== rule.name) drifted.push(String(rule.id))
    }
    expect(
      drifted,
      'zh Reason text diverged from the SPL `name` — regenerate, do not hand-edit',
    ).toEqual([])
  })

  it('no orphan reason_<id> keys pointing at removed SPL rules', () => {
    const doc = YAML.parse(readFileSync(SPL_PATH, 'utf8')) as {
      rules?: { id?: unknown }[]
    }
    const ids = new Set((doc.rules ?? []).map((r) => String(r.id)))
    const slugs = new Set(Object.values(LITERAL_ALIASES))
    const orphans = Object.keys(locales.en)
      .filter((k) => k.startsWith('reason_'))
      .map((k) => k.slice('reason_'.length))
      // The literal slugs have no SPL rule; they resolve via LITERAL_ALIASES.
      .filter((slug) => !ids.has(slug) && !slugs.has(slug))
    expect(orphans, 'reason_* key with no matching SPL rule').toEqual([])
  })
})

describe('localizeReason', () => {
  // Mirrors the host runtime: `LocaleRuntime.translate` ends in `?? key`,
  // so an unregistered key returns the key string itself
  // (@deepseek-ai/dsh-client-locale lib/client.js:1294). The whole
  // miss-detection scheme depends on that, so the stub reproduces it.
  const hostT = (dict: Record<string, string>) =>
    ((key: string) => dict[key] ?? key) as unknown as Translate

  it('resolves a known policy_id in both languages', () => {
    const raw = 'Block reason: 阻断敏感系统文件访问 (rule: 阻断敏感系统文件访问). Aggregate risk: 0.30 from 1 matched rule.'
    expect(localizeReason('block-sensitive-system-files-warn', raw, hostT(locales.en))).toBe(
      locales.en['reason_block-sensitive-system-files-warn'],
    )
    expect(localizeReason('block-sensitive-system-files-warn', raw, hostT(locales.zh))).toBe(
      locales.zh['reason_block-sensitive-system-files-warn'],
    )
  })

  it('falls back to the raw reason for an unregistered policy_id', () => {
    // An older plugin policy, or a rule added after this build shipped.
    const raw = 'Block reason: something new (rule: 新规则).'
    expect(localizeReason('some-rule-added-in-2030', raw, hostT(locales.en))).toBe(raw)
  })

  it('falls back to the raw reason when there is no policy_id and no literal alias', () => {
    const raw = 'Some engine message we have never seen.'
    expect(localizeReason(undefined, raw, hostT(locales.zh))).toBe(raw)
    expect(localizeReason('', raw, hostT(locales.zh))).toBe(raw)
  })

  it('resolves engine literals that carry no rule id', () => {
    const raw = 'Intervention evaluation timed out; fail-closed per policy'
    expect(localizeReason(undefined, raw, hostT(locales.zh))).toBe(
      locales.zh.reason_fail_closed_timeout,
    )
    expect(localizeReason(undefined, raw, hostT(locales.en))).toBe(
      locales.en.reason_fail_closed_timeout,
    )
  })

  it('prefers policy_id over the literal table', () => {
    // A SPL rule whose message happens to equal a known engine literal
    // must still resolve through its own rule id.
    const raw = 'Intervention evaluation timed out; fail-closed per policy'
    expect(
      localizeReason('block-exec-reverse-shell', raw, hostT(locales.en)),
    ).toBe(locales.en['reason_block-exec-reverse-shell'])
  })

  it('returns an empty string when there is nothing to show', () => {
    expect(localizeReason(undefined, undefined, hostT(locales.en))).toBe('')
    expect(localizeReason('unknown-rule', undefined, hostT(locales.en))).toBe('')
  })

  it('falls back to raw when t() returns undefined for an unknown key', () => {
    // Regression: `t` is an injected parameter, not the host runtime. A
    // stub shaped like `return en[key] as string` yields undefined on a
    // miss, which a bare `out === slug` check reads as a HIT — rendering
    // an empty cell. Missing keys must degrade to the raw reason.
    const sloppyT = ((key: string) => (locales.en as Record<string, string>)[key]) as unknown as Translate
    const raw = 'Block reason: an old policy we do not know (rule: 老规则).'
    expect(localizeReason('rule-from-the-past', raw, sloppyT)).toBe(raw)
  })

  it('every LITERAL_ALIASES target has both language entries', () => {
    for (const [literal, slug] of Object.entries(LITERAL_ALIASES)) {
      const key = `reason_${slug}` as LocaleKey
      expect(typeof locales.en[key], `en.${key} (from ${literal})`).toBe('string')
      expect(typeof locales.zh[key], `zh.${key} (from ${literal})`).toBe('string')
    }
  })
})
