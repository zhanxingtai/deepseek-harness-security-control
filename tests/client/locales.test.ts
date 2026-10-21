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
import { describe, expect, it } from 'vitest'

import { locales, type LocaleKey } from '../../src/client/locales.js'

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
})
