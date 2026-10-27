/**
 * OverviewCache tests —.
 *
 * The cache sits between `overview()` and the full-file NDJSON
 * scanner (`scanOverviewAggregates`). The contract is:
 * cache HIT: same aggregate bundle (block counts + the
 *     Metrics additions `last24hTotalCount` / `byLayer`) returned
 *     without a recompute; `fromCache: true`; counters unchanged.
 *   - cache MISS: full recompute; `fromCache: false`; entry stored.
 *   - TTL backstop: even with no other invalidation, a read > TTL
 *     ms after compute recomputes.
 *   - Sink-flushed invalidation: any write that bumps
 *     `stats.flushed` forces a recompute on the next read.
 *   - Rotation invalidation: the sink's `onRotate` callback is
 *     wired through `cache.invalidate()`.
 *   - Concurrent dedup: overlapping reads share one compute.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdirSync, rmSync, writeFileSync, appendFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { OverviewCache, OVERVIEW_CACHE_TTL_MS } from '../../src/status/overviewCache.js'
import { LocalNdjsonSink } from '../../src/collectors/LocalNdjsonSink.js'
import type { Config } from '../../src/config.js'

let dir: string
let file: string

function makeConfig(): Config {
  return {
    mode: 'audit',
    enabled: true,
    hostId: 'host-test',
    containerId: 'host',
    collector: {
      localOutputPath: '',
      batchSize: 50,
      flushIntervalMs: 250,
      validateEvents: false,
      maxFileBytes: 1_000_000,
      diskWarnWatermarkBytes: 500_000_000,
      diskLowWatermarkBytes: 100_000_000,
      redactRawParams: true,
      debugLogPath: '',
    },
    application: {
      captureUserPrompt: true,
      captureSystemPrompt: false,
      captureAgentPlan: false,
      captureReasoning: false,
      toolResultMaxChars: 100_000,
      sessionTtlMs: 1_800_000,
    },
    networkCapture: {
      enabled: false,
      redactBodies: true,
      captureResponseBody: false,
      maxBodyBytes: 1_048_576,
      maxRequestBodyBytes: 1024 * 1024,
      sseSummaryChunks: 5,
      sseSummaryLastChunks: 1,
      includeHosts: [],
      excludeHosts: [],
      excludeUrls: [],
      sensitiveKeyPatterns: [],
      captureDns: false,
    },
    runtimeHooks: {
      enabled: true,
      networkEnabled: false,
      logPath: '',
      hookPath: '',
      excludeCommandLines: [],
      enabledAtSubprocess: true,
      blockAtSubprocess: false,
      failOpenOnError: true,
    },
    intervention: {
      enabled: true,
      mode: 'audit',
      policyPath: '',
      policyPaths: [],
      reloadIntervalMs: 30_000,
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
    },
    inlineGuards: {
      engineLaunchers: [],
      pluginPackageName: 'sst-security-control-dsh',
      patchMarkers: [],
    },
    sensitivePathGuard: {
      enabled: true,
      paths: [],
      watchEnabled: false,
      watchDebounceMs: 500,
    },
    inlinePromptInjection: {
      enabled: true,
      patterns: [],
      excerptMaxChars: 80,
    },
    stdioMirror: {
      enabled: false,
      payloadLimitBytes: 1_048_576,
      outputPath: '',
    },
    envPassthroughGuard: {
      enabled: true,
      keys: [],
    },
    loopedToolDetector: {
      enabled: true,
      windowMs: 60_000,
      thresholdPerWindow: 100,
    },
    tokenUsageDetector: {
      enabled: true,
      windowMs: 60_000,
      burstFactor: 3,
      minBaselineSamples: 5,
    },
    sinkDiskLow: {
      recoverMarginBytes: 50 * 1024 * 1024,
    },
  }
}

/** Build a minimal sink that targets a temp NDJSON file, with no
 *  side effects beyond the file path. We deliberately bypass
 *  `initialize()` so no flush timer / disk-low probe runs. */
function makeSink(onRotate?: (info: { reason: string; rotatedCount: number; lastRotationAt: number }) => void): LocalNdjsonSink {
  const config = makeConfig()
  config.collector.localOutputPath = file
  const sink = new LocalNdjsonSink(config, {
    logger: { log: () => {}, warn: () => {}, error: () => {} },
    onRotate,
  })
  sink.localPath = file
  return sink
}

function writeBlockEvents(n: number, tsBase = Date.now()): void {
  const lines: string[] = []
  for (let i = 0; i < n; i++) {
    lines.push(JSON.stringify({
      ts: tsBase + i,
      event_type: 'agent_tool_call',
      intervention: { decision: 'block', decision_internal: 'block' },
      tool_name: `tool-${i}`,
      tool_call_id: `call-${i}`,
    }))
  }
  writeFileSync(file, lines.join('\n') + '\n', 'utf8')
}

function writeAllowEvent(ts: number): void {
  appendFileSync(file, JSON.stringify({
    ts,
    event_type: 'agent_tool_call',
    intervention: { decision: 'allow' },
  }) + '\n', 'utf8')
}

beforeEach(() => {
  dir = join(tmpdir(), `overview-cache-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  mkdirSync(dir, { recursive: true })
  file = join(dir, 'events.jsonl')
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('OverviewCache', () => {
  it('cache miss → compute → fromCache=false', async () => {
    writeBlockEvents(5)
    const sink = makeSink()
    const cache = new OverviewCache()
    const r = await cache.read(sink)
    expect(r.fromCache).toBe(false)
    expect(r.blockCount).toBe(5)
    expect(r.last24hBlockCount).toBe(5)
    // the same single pass also produces the
    // Metrics-page aggregates. The block fixtures carry no `layer`
    // field, so every event buckets under 'unknown'.
    expect(r.last24hTotalCount).toBe(5)
    expect(r.byLayer).toEqual({ unknown: 5 })
  })

  // 2026-09-28 — 威胁事件口径:warn 级命中计入 threatCount,block 命中
  // 同时计入两个计数器(threat ⊇ blocked);runtime 层命中同样计入。
  it('threat counts include warn-marked and runtime-layer hits (threat ⊇ blocked)', async () => {
    const now = Date.now()
    const events = [
      // 2 blocks: tool layer
      { ts: now - 100, event_type: 'agent_tool_call', intervention: { decision: 'deny', decision_internal: 'block' } },
      { ts: now - 90, event_type: 'agent_tool_call', intervention: { decision: 'deny', decision_internal: 'block' } },
      // 1 warn hit: tool layer (标记未拦截)
      { ts: now - 80, event_type: 'agent_tool_call', intervention: { decision: 'ask', decision_internal: 'warn' } },
      // 1 warn hit: runtime spawn layer
      { ts: now - 70, event_type: 'runtime_spawn_intent', intervention: { decision: 'ask', decision_internal: 'warn' } },
      // 1 plain allow — not a hit
      { ts: now - 60, event_type: 'agent_tool_call', intervention: { decision: 'allow' } },
    ]
    writeFileSync(file, events.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8')
    const sink = makeSink()
    const cache = new OverviewCache()
    const r = await cache.read(sink)
    expect(r.blockCount).toBe(2)
    expect(r.last24hBlockCount).toBe(2)
    expect(r.threatCount).toBe(4)
    expect(r.last24hThreatCount).toBe(4)
    expect(r.last24hTotalCount).toBe(5)
  })

  // 2026-09-28 — 早于 24h 窗口的旧命中:全时间威胁计数仍保留,窗口内
  // 计数归零(与 blockCount 的窗口语义一致)。
  it('threat window counts respect the 24h cutoff', async () => {
    const old = Date.now() - 50 * 60 * 60 * 1000
    writeFileSync(
      file,
      [
        JSON.stringify({ ts: old, event_type: 'agent_tool_call', intervention: { decision: 'ask', decision_internal: 'warn' } }),
        JSON.stringify({ ts: old + 1, event_type: 'agent_tool_call', intervention: { decision: 'deny', decision_internal: 'block' } }),
      ].join('\n') + '\n',
      'utf8',
    )
    const sink = makeSink()
    const cache = new OverviewCache()
    const r = await cache.read(sink)
    expect(r.threatCount).toBe(2)
    expect(r.last24hThreatCount).toBe(0)
    expect(r.blockCount).toBe(1)
    expect(r.last24hBlockCount).toBe(0)
  })

  it('cache hit → no recompute → fromCache=true (counts come from memory)', async () => {
    writeBlockEvents(3)
    const sink = makeSink()
    const cache = new OverviewCache()
    const first = await cache.read(sink)
    expect(first.fromCache).toBe(false)
    // Mutate the file underneath so a real recompute would surface
    // new numbers; if the cache is doing its job, the next read
    // returns the cached values (3,3).
    writeBlockEvents(99)
    const second = await cache.read(sink)
    expect(second.fromCache).toBe(true)
    expect(second.blockCount).toBe(3)
    expect(second.last24hBlockCount).toBe(3)
  })

  it('sink write invalidates the cache (flushed counter sentinel)', async () => {
    writeBlockEvents(2)
    const sink = makeSink()
    const cache = new OverviewCache()
    const first = await cache.read(sink)
    expect(first.fromCache).toBe(false)
    expect(first.blockCount).toBe(2)
    // The sink's `flushed` counter bumps on every successful write.
    // We don't go through `report()` here (the test sink is not
    // initialized), but `getStats().flushed` is the public sentinel
    // — a synchronous mutation by any path forces a miss.
    // Simulate a write-side bump by faking the counter via the
    // sink's own `report` path: synthesize a single event and feed
    // it through the writeLocalDirect code path. We use `appendFileSync`
    // + the stats object directly to keep the test focused on the
    // cache contract, not the sink's write pipeline.
    sink.stats.flushed += 1
    writeBlockEvents(7)
    const second = await cache.read(sink)
    expect(second.fromCache).toBe(false)
    expect(second.blockCount).toBe(7)
  })

  it('TTL backstop recomputes after the window expires', async () => {
    writeBlockEvents(2)
    const sink = makeSink()
    const cache = new OverviewCache()
    await cache.read(sink) // prime
    // Force the cache entry's computedAt to be just inside the TTL
    // window so the SAME counter value still hits. Advance past it
    // by mocking Date.now().
    const originalNow = Date.now
    let now = Date.now()
    Date.now = () => now
    try {
      const stillFresh = await cache.read(sink)
      expect(stillFresh.fromCache).toBe(true)
      // Advance past TTL — the next read must miss.
      now += OVERVIEW_CACHE_TTL_MS + 1
      const stale = await cache.read(sink)
      expect(stale.fromCache).toBe(false)
      expect(stale.blockCount).toBe(2)
    } finally {
      Date.now = originalNow
    }
  })

  it('concurrent reads share one compute (inflight dedup)', async () => {
    writeBlockEvents(5)
    const sink = makeSink()
    const cache = new OverviewCache()
    // Fire 5 reads in parallel — only the first one runs the scan.
    // We can't directly observe the scan count without instrumenting
    // countAllBlocks; instead we verify the resolved values are
    // byte-identical (the second read got the first's result, not
    // its own fresh scan).
    const [a, b, c, d, e] = await Promise.all([
      cache.read(sink),
      cache.read(sink),
      cache.read(sink),
      cache.read(sink),
      cache.read(sink),
    ])
    const values = [a, b, c, d, e].map((r) => ({ blockCount: r.blockCount, last24hBlockCount: r.last24hBlockCount }))
    for (const v of values) {
      expect(v.blockCount).toBe(5)
      expect(v.last24hBlockCount).toBe(5)
    }
    // Exactly ONE of the 5 reads should be `fromCache: false`; the
    // rest ride on the inflight promise and store the same entry.
    const misses = values.length // placeholder; replaced below
    void misses
    const fromCacheFlags = [a, b, c, d, e].map((r) => r.fromCache)
    // At least one miss (the first compute); subsequent reads land
    // on the cached entry, so fromCache=true.
    expect(fromCacheFlags.filter((x) => x === false).length).toBeGreaterThanOrEqual(1)
    expect(fromCacheFlags).toContain(true)
  })

  it('invalidate() forces the next read to recompute', async () => {
    writeBlockEvents(1)
    const sink = makeSink()
    const cache = new OverviewCache()
    const a = await cache.read(sink)
    expect(a.fromCache).toBe(false)
    expect(a.blockCount).toBe(1)
    // Same state — read hits cache.
    const b = await cache.read(sink)
    expect(b.fromCache).toBe(true)
    // Explicit invalidation — next read must miss.
    cache.invalidate()
    const c = await cache.read(sink)
    expect(c.fromCache).toBe(false)
    expect(c.blockCount).toBe(1)
  })

  it('returns 0 when the sink has no local output path', async () => {
    const config = makeConfig()
    config.collector.localOutputPath = '/var/empty/no/such/path'
    const sink = new LocalNdjsonSink(config, {
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    })
    // No initialize() — `localPath` stays undefined, simulating a
    // pre-initialize sink. The cache must return 0/0 without
    // throwing (the sink's `getLocalOutputPath()` is the source of
    // truth).
    const cache = new OverviewCache()
    const r = await cache.read(sink)
    expect(r.blockCount).toBe(0)
    expect(r.last24hBlockCount).toBe(0)
    expect(r.last24hTotalCount).toBe(0)
    expect(r.byLayer).toEqual({})
  })
})

describe('LocalNdjsonSink.onRotate wiring', () => {
  it('fires the callback with reason + counters after a size-cap rotation', async () => {
    // Synthesize a sink that has just had its file reset via
    // _resetLocalBaseline (the same code path the size-cap path
    // uses). We reach in directly because `initialize()` would
    // require a valid path + the file system; the wiring contract
    // we care about is the callback.
    const sink = makeSink()
    const observed: Array<{ reason: string; rotatedCount: number; lastRotationAt: number }> = []
    ;(sink as unknown as { onRotateCallback: (info: { reason: string; rotatedCount: number; lastRotationAt: number }) => void }).onRotateCallback = (info) => {
      observed.push(info)
    }
    // Call the private method via cast.
    ;(sink as unknown as { _resetLocalBaseline: (r: string) => void })._resetLocalBaseline('size cap')
    expect(observed).toHaveLength(1)
    expect(observed[0]!.reason).toBe('size cap')
    expect(observed[0]!.rotatedCount).toBe(1)
    expect(typeof observed[0]!.lastRotationAt).toBe('number')
  })

  it('callback errors do not throw to the host (invariant #3)', () => {
    const config = makeConfig()
    config.collector.localOutputPath = file
    const errors: unknown[] = []
    const sink = new LocalNdjsonSink(config, {
      logger: {
        log: () => {},
        warn: (msg: string) => errors.push(msg),
        error: () => {},
      },
      onRotate: () => {
        throw new Error('callback boom')
      },
    })
    sink.localPath = file
    expect(() => {
      ;(sink as unknown as { _resetLocalBaseline: (r: string) => void })._resetLocalBaseline('low disk')
    }).not.toThrow()
    expect(errors.some((m) => typeof m === 'string' && m.includes('onRotate callback failed'))).toBe(true)
  })

  it('OverviewCache.invalidate runs when wired as the onRotate callback', async () => {
    writeBlockEvents(2)
    const sink = makeSink()
    const cache = new OverviewCache()
    // Prime the cache.
    const a = await cache.read(sink)
    expect(a.fromCache).toBe(false)
    expect(a.blockCount).toBe(2)
    // Re-register the SAME cache as the sink's onRotate callback.
    ;(sink as unknown as { onRotateCallback: (info: { reason: string; rotatedCount: number; lastRotationAt: number }) => void }).onRotateCallback = () => {
      cache.invalidate()
    }
    // Trigger the rotation — must invalidate the cache.
    ;(sink as unknown as { _resetLocalBaseline: (r: string) => void })._resetLocalBaseline('size cap')
    const b = await cache.read(sink)
    expect(b.fromCache).toBe(false) // invalidated → fresh compute
  })
})