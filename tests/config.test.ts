import { describe, expect, it } from 'vitest'
import { normalizeConfig } from '../src/config.js'

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

  it('allows intervention.mode override to shadow the top-level mode', () => {
    const config = normalizeConfig({ mode: 'audit', intervention: { mode: 'enforce' } })
    expect(config.mode).toBe('audit')
    expect(config.intervention.mode).toBe('enforce')
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
    expect(config.networkCapture.sseSummaryChunks).toBe(3)
    expect(config.networkCapture.sseSummaryLastChunks).toBe(2)
    expect(config.networkCapture.excludeHosts).toEqual(['localhost'])
    // Untouched fields keep their defaults.
    expect(config.networkCapture.redactBodies).toBe(true)
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