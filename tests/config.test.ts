import { describe, expect, it } from 'vitest'
import { normalizeConfig, inheritLegacyRequestBodyBudget } from '../src/config.js'

// marketplace Config surface. The previous shape carried
// platform-deployment knobs (auth.type, system.procfs.*, assetMonitor.*,
// application.httpCapture.*, collector.endpoint, outbox.*) — all of
// which were stripped from Config in §2 of the plan. The tests below
// cover the marketplace-relevant surface: top-level mode propagation,
// networkCapture defaults/overrides, hostId/containerId fallbacks,
// collector batchSize/flushIntervalMs defaults, intervention.failStrategy.
describe('normalizeConfig ( marketplace surface)', () => {
  it('returns defaults for empty input', () => {
    const config = normalizeConfig(undefined)
    expect(config.enabled).toBe(true)
    // 2026-10-10: default flipped from 'audit' → 'enforce' (see
    // src/config.schema.ts:381 + src/config/normalize.ts:153). A
    // fresh marketplace install lands in enforce at the normalize
    // layer; the policy-file upgrade seam is now a no-op for the
    // default path.
    expect(config.mode).toBe('enforce')
    expect(config.collector.localOutputPath).toBe('~/.dsh/security-events.jsonl')
    expect(config.collector.batchSize).toBe(100)
    expect(config.collector.flushIntervalMs).toBe(1000)
    expect(config.intervention.mode).toBe('enforce')
    expect(config.intervention.failStrategy).toBe('fail_open')
    // No marketplace surface carries the deleted platform blocks:
    expect((config as unknown as { assetMonitor?: unknown }).assetMonitor).toBeUndefined()
    expect((config as unknown as { system?: unknown }).system).toBeUndefined()
    expect((config as unknown as { outbox?: unknown }).outbox).toBeUndefined()
    // NetworkHttpCollector survives — moved to top-level networkCapture.
    expect(config.networkCapture.enabled).toBe(true)
  })

  it('respects enforce mode at the top level', () => {
    const config = normalizeConfig({ mode: 'enforce' })
    expect(config.mode).toBe('enforce')
    expect(config.intervention.mode).toBe('enforce')
  })

  it('lets intervention.mode shadow the top-level mode on BOTH surfaces', () => {
    // `intervention.mode` is the authoritative switch (the Config UI
    // edits exactly that key). When the two disagree, the nested value
    // wins — and it must win COMPLETELY: the top-level `mode` used to
    // keep its own independently-derived value, so the enforcement seam
    // (src/handlers.ts reads the top level) and the audit trail (the
    // engine reads the nested one) could disagree about whether the
    // plugin was blocking. The 2026-10-27 real capture was exactly
    // that: the trail said "audit" while the tool layer hard-blocked.
    const config = normalizeConfig({ mode: 'audit', intervention: { mode: 'enforce' } })
    expect(config.mode).toBe('enforce')
    expect(config.intervention.mode).toBe('enforce')
  })

  it('mirrors the effective mode onto both surfaces (they can never disagree)', () => {
    // Every combination of the two knobs resolves to ONE value that
    // both surfaces carry.
    for (const raw of [
      {},
      { mode: 'audit' },
      { mode: 'enforce' },
      { intervention: { mode: 'audit' } },
      { intervention: { mode: 'enforce' } },
      { mode: 'audit', intervention: { mode: 'enforce' } },
      { mode: 'enforce', intervention: { mode: 'audit' } },
    ]) {
      const config = normalizeConfig(raw)
      expect(config.mode).toBe(config.intervention.mode)
    }
  })

  it('is idempotent on the mode (a second normalize pass cannot flip it)', () => {
    // The nested field is materialised from the effective value, so a
    // second pass must resolve to the SAME value — otherwise the
    // materialised copy reads as an "operator explicit" override and
    // swallows the top-level (the bug documented in src/config/draft.ts).
    const once = normalizeConfig({ mode: 'audit' })
    const twice = normalizeConfig(once)
    expect(twice.mode).toBe('audit')
    expect(twice.intervention.mode).toBe('audit')
    const thrice = normalizeConfig(twice)
    expect(thrice.mode).toBe('audit')
    expect(thrice.intervention.mode).toBe('audit')
  })

  it('merges nested collector config (marketplace fields)', () => {
    const config = normalizeConfig({
      collector: {
        localOutputPath: '/var/log/dsh/events.jsonl',
        batchSize: 50,
        flushIntervalMs: 250,
      },
    })
    expect(config.collector.localOutputPath).toBe('/var/log/dsh/events.jsonl')
    expect(config.collector.batchSize).toBe(50)
    expect(config.collector.flushIntervalMs).toBe(250)
    // Untouched fields keep their defaults.
    expect(config.collector.validateEvents).toBe(true)
    expect(config.collector.maxFileBytes).toBe(50 * 1024 * 1024)
  })

  it('ignores invalid failStrategy and falls back to fail_open', () => {
    const config = normalizeConfig({ intervention: { failStrategy: 'invalid' as never } })
    expect(config.intervention.failStrategy).toBe('fail_open')
  })

  it('defaults networkCapture to enabled with redaction and 1 MiB cap', () => {
    const config = normalizeConfig(undefined)
    expect(config.networkCapture.enabled).toBe(true)
    expect(config.networkCapture.redactBodies).toBe(true)
    expect(config.networkCapture.captureResponseBody).toBe(true)
    expect(config.networkCapture.maxBodyBytes).toBe(1024 * 1024)
    // Request/response split: request bodies persist at 64 KiB by default.
    expect(config.networkCapture.maxRequestBodyBytes).toBe(64 * 1024)
    expect(config.networkCapture.sseSummaryChunks).toBe(5)
    expect(config.networkCapture.sseSummaryLastChunks).toBe(1)
    expect(config.networkCapture.excludeHosts).toEqual([])
    expect(config.networkCapture.excludeUrls).toEqual([])
    // DNS capture stays opt-in (default false) — the in-process dns
    // monkey-patch is observable behaviour for every name resolution
    // in the harness process.
    expect(config.networkCapture.captureDns).toBe(false)
  })

  it('merges networkCapture overrides', () => {
    const config = normalizeConfig({
      networkCapture: {
        enabled: false,
        maxBodyBytes: 4096,
        sseSummaryChunks: 3,
        sseSummaryLastChunks: 2,
        excludeHosts: ['localhost'],
      },
    })
    expect(config.networkCapture.enabled).toBe(false)
    expect(config.networkCapture.maxBodyBytes).toBe(4096)
    // maxRequestBodyBytes absent → legacy inherit: request budget follows
    // the operator's maxBodyBytes (pre-split both directions shared it).
    expect(config.networkCapture.maxRequestBodyBytes).toBe(4096)
    expect(config.networkCapture.sseSummaryChunks).toBe(3)
    expect(config.networkCapture.sseSummaryLastChunks).toBe(2)
    expect(config.networkCapture.excludeHosts).toEqual(['localhost'])
    // Untouched fields keep their defaults.
    expect(config.networkCapture.redactBodies).toBe(true)
  })

  it('maxRequestBodyBytes: explicit value wins over the legacy maxBodyBytes inherit', () => {
    const config = normalizeConfig({
      networkCapture: { maxBodyBytes: 4096, maxRequestBodyBytes: 8192 },
    })
    expect(config.networkCapture.maxBodyBytes).toBe(4096)
    expect(config.networkCapture.maxRequestBodyBytes).toBe(8192)
  })

  it('maxRequestBodyBytes: no networkCapture keys at all → 64 KiB default', () => {
    const config = normalizeConfig({})
    expect(config.networkCapture.maxRequestBodyBytes).toBe(64 * 1024)
  })

  it('inheritLegacyRequestBodyBudget is idempotent and tolerant of junk input', () => {
    expect(inheritLegacyRequestBodyBudget(undefined)).toBe(undefined)
    expect(inheritLegacyRequestBodyBudget(null)).toBe(null)
    expect(inheritLegacyRequestBodyBudget('x')).toBe('x')
    const already = { networkCapture: { maxBodyBytes: 1, maxRequestBodyBytes: 2 } }
    expect(inheritLegacyRequestBodyBudget(already)).toBe(already)
    const legacy = { networkCapture: { maxBodyBytes: 12345 } }
    const inherited = inheritLegacyRequestBodyBudget(legacy) as { networkCapture: { maxRequestBodyBytes: number } }
    expect(inherited.networkCapture.maxRequestBodyBytes).toBe(12345)
    // Idempotent: a second pass does not overwrite the inherited value.
    const again = inheritLegacyRequestBodyBudget(inherited) as { networkCapture: { maxRequestBodyBytes: number } }
    expect(again.networkCapture.maxRequestBodyBytes).toBe(12345)
  })

  it('init.ts pre-seeds the legacy inherit BEFORE Schemastery validation', async () => {
    // Schema carries the 64 KiB default; without the pre-seed a legacy
    // {maxBodyBytes: 2 MiB} config would silently shrink to 64 KiB.
    const { validateConfig } = await import('../src/config.schema.js')
    const { inheritLegacyRequestBodyBudget } = await import('../src/config.js')
    const legacy = { networkCapture: { maxBodyBytes: 2 * 1024 * 1024 } }
    const validated = validateConfig(inheritLegacyRequestBodyBudget(legacy))
    expect(validated?.networkCapture?.['maxRequestBodyBytes']).toBe(2 * 1024 * 1024)
    const withoutPreseed = validateConfig(legacy)
    expect(withoutPreseed?.networkCapture?.['maxRequestBodyBytes']).toBe(64 * 1024)
  })

  it('falls back to os.hostname() when hostId is missing', () => {
    const config = normalizeConfig(undefined)
    // The literal string 'host' is the platform's bare-metal token;
    // os.hostname() returns whatever the kernel sees.
    expect(typeof config.hostId).toBe('string')
    expect(config.hostId.length).toBeGreaterThan(0)
  })

  it('preserves explicit hostId and containerId', () => {
    const config = normalizeConfig({ hostId: 'edge-42', containerId: 'pod-7' })
    expect(config.hostId).toBe('edge-42')
    expect(config.containerId).toBe('pod-7')
  })

  it('falls back to "host" when containerId is missing (platform bare-metal token)', () => {
    const config = normalizeConfig(undefined)
    expect(config.containerId).toBe('host')
  })

  it('respects runtimeHooks defaults ( pre-spawn seam stays enabled in marketplace)', () => {
    const config = normalizeConfig(undefined)
    expect(config.runtimeHooks.enabled).toBe(true)
    expect(config.runtimeHooks.enabledAtSubprocess).toBe(true)
    // Block at the runtime seam stays opt-in — same rollout posture as
    // the existing tool-layer `mode: enforce` (operators flip after
    // confirming audit-mode false positives).
    expect(config.runtimeHooks.blockAtSubprocess).toBe(false)
    expect(config.runtimeHooks.failOpenOnError).toBe(true)
  })

  // `null` / `undefined` values in input must
  // NOT override defaults. Before the fix, `withDefaults` used a plain
  // spread `{ ...defaults, ...obj }` so `{collector: {localOutputPath: null}}`
  // (which schemastery autofix can accept as "valid, type-coerced") would
  // silently nuke the path → downstream `expandHome(null)` crashes and the
  // share-config mutation already happened. The fix: filter null/undefined
  // before the spread, mirroring the policy that `undefined` means
  // "key not supplied". Empty string `''` still flows through (legitimate
  // clear of a string field — operators use `''` to mean "disable path").
  describe('null/undefined override bypass', () => {
    it('null on a primitive field falls back to the default (not the literal null)', () => {
      const config = normalizeConfig({
        collector: { localOutputPath: null as unknown as string },
      })
      expect(config.collector.localOutputPath).toBe('~/.dsh/security-events.jsonl')
    })

    it('null on a boolean field falls back to the default', () => {
      const config = normalizeConfig({
        collector: { validateEvents: null as unknown as boolean },
      })
      expect(config.collector.validateEvents).toBe(true)
    })

    it('null on a number field falls back to the default', () => {
      const config = normalizeConfig({
        collector: { batchSize: null as unknown as number },
      })
      expect(config.collector.batchSize).toBe(100)
    })

    it('null on a union (failStrategy) falls back to the default', () => {
      const config = normalizeConfig({
        intervention: { failStrategy: null as unknown as 'fail_open' },
      })
      expect(config.intervention.failStrategy).toBe('fail_open')
    })

    it('undefined on a primitive field falls back to the default', () => {
      const config = normalizeConfig({
        collector: { localOutputPath: undefined },
      })
      expect(config.collector.localOutputPath).toBe('~/.dsh/security-events.jsonl')
    })

    it('empty string "" still flows through (legitimate clear path for operators)', () => {
      const config = normalizeConfig({
        collector: { debugLogPath: '' },
      })
      expect(config.collector.debugLogPath).toBe('')
    })

    it('null in a nested sub-block (sensitivePathGuard.paths) does not nuke the deny-list', () => {
      // Even if the spread would have propagated null into the array,
      // the existing UNION fallback re-asserts the marketplace catalogue.
      // This test pins the contract so a future refactor doesn't break it.
      const config = normalizeConfig({
        sensitivePathGuard: { paths: null as unknown as string[] },
      })
      expect(Array.isArray(config.sensitivePathGuard.paths)).toBe(true)
      expect(config.sensitivePathGuard.paths.length).toBeGreaterThan(0)
      expect(config.sensitivePathGuard.paths).toContain('~/.ssh/id_rsa')
    })
  })
})