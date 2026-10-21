/**
 * Tests for the per-session token-usage burst detector.
 *
 * Coverage:
 *   - learning phase: the first `minBaselineSamples` calls only learn —
 *     no alert even on a 10x burst inside the learning floor
 *   - 3x boundary: ratio === burstFactor fires (≥3x 触发), just below stays silent
 *   - 10x simulated burst fires
 *   - duplicate suppression within one burst + re-arm after a calm call
 *   - cross-session isolation (no baseline bleed between sessions)
 *   - window expiry resets state (stale samples evicted → learning restarts)
 *   - totalTokens missing → inputTokens + outputTokens fallback
 *   - non-positive / non-finite totals skipped (false-positive control)
 *   - disabled is a no-op; malformed sessionId returns null
 *   - onHit callback runs synchronously, errors are swallowed
 *   - clearSession drops samples + fired markers
 * Config normalization defaults match ticket spec
 *
 * Tee wrapper (`teeLlmStream`):
 *   - stream passes through completely (order, identity, completion)
 *   - usage chunks are consumed by the tap
 *   - tap throwing mid-stream: chunks still pass, consumer sees no error
 *   - source stream errors propagate unchanged (transparent passthrough)
 */

import { describe, expect, it, vi } from 'vitest'
import { normalizeConfig } from '../src/config.js'
import {
  TokenUsageDetector,
  normalizeTokenUsage,
  teeLlmStream,
  type TokenUsageDetectorConfig,
  type TokenUsageHit,
  type TokenUsageSampleInput,
} from '../src/utils/tokenUsage.js'
import type { StreamChunk, TokenUsage } from '../src/types/external.js'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const CFG_DEFAULT: TokenUsageDetectorConfig = {
  enabled: true,
  windowMs: 60_000,
  burstFactor: 3,
  minBaselineSamples: 5,
}

const CFG_SHORT_WINDOW: TokenUsageDetectorConfig = {
  enabled: true,
  windowMs: 1_000,
  burstFactor: 3,
  minBaselineSamples: 5,
}

const CFG_DISABLED: TokenUsageDetectorConfig = {
  enabled: false,
  windowMs: 60_000,
  burstFactor: 3,
  minBaselineSamples: 5,
}

function usage(totalTokens: number): TokenUsageSampleInput {
  return { inputTokens: Math.round(totalTokens / 2), outputTokens: totalTokens - Math.round(totalTokens / 2), totalTokens }
}

/** Record `n` baseline calls of `total` tokens, 100 ms apart from `base`. */
function learn(
  d: TokenUsageDetector,
  sessionId: string,
  base: number,
  n: number,
  total: number,
): void {
  for (let i = 0; i < n; i++) {
    d.record(sessionId, usage(total), base + i * 100)
  }
}

async function collect(stream: AsyncIterable<StreamChunk>): Promise<StreamChunk[]> {
  const out: StreamChunk[] = []
  for await (const chunk of stream) out.push(chunk)
  return out
}

// ---------------------------------------------------------------------------
// normalizeTokenUsage
// ---------------------------------------------------------------------------

describe('normalizeTokenUsage', () => {
  it('passes through a complete TokenUsage verbatim', () => {
    expect(normalizeTokenUsage({ inputTokens: 10, outputTokens: 20, totalTokens: 30 })).toEqual({
      inputTokens: 10,
      outputTokens: 20,
      totalTokens: 30,
    })
  })

  it('derives totalTokens = inputTokens + outputTokens when missing', () => {
    expect(normalizeTokenUsage({ inputTokens: 10, outputTokens: 20 })).toEqual({
      inputTokens: 10,
      outputTokens: 20,
      totalTokens: 30,
    })
  })

  it('keeps an authoritative totalTokens when only the total is reported', () => {
    expect(normalizeTokenUsage({ totalTokens: 42 })).toEqual({
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 42,
    })
  })

  it('returns null for non-positive totals (false-positive control)', () => {
    expect(normalizeTokenUsage({ inputTokens: 0, outputTokens: 0, totalTokens: 0 })).toBeNull()
    expect(normalizeTokenUsage({ inputTokens: 0, outputTokens: 0 })).toBeNull()
    expect(normalizeTokenUsage({ totalTokens: -5 })).toBeNull()
  })

  it('returns null for non-finite / non-numeric values', () => {
    expect(normalizeTokenUsage({ totalTokens: Number.NaN })).toBeNull()
    expect(normalizeTokenUsage({ totalTokens: Number.POSITIVE_INFINITY })).toBeNull()
    expect(normalizeTokenUsage({ totalTokens: '30' as unknown as number })).toBeNull()
    expect(normalizeTokenUsage({})).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Learning phase (ticket: baseline 学习期 < 5 次调用，前几次只学习不告警)
// ---------------------------------------------------------------------------

describe('TokenUsageDetector — learning phase', () => {
  it('a 10x burst INSIDE the learning floor does not fire', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    // 4 learning calls at 100 tokens, then a 10x (1000) burst as the 5th —
    // still inside minBaselineSamples=5, so it only learns.
    learn(d, 's1', 1_000_000, 4, 100)
    expect(d.record('s1', usage(1000), 1_000_400)).toBeNull()
    expect(onHit).not.toHaveBeenCalled()
    expect(d.size()).toBe(5)
  })

  it('a burst on the FIRST post-learning call fires against the learned baseline', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100) // 5 learning calls → baseline 100
    const hit = d.record('s1', usage(1000), 1_000_500) // 6th call, 10x
    expect(hit).not.toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
    expect(hit!.baseline).toBe(100)
    expect(hit!.sampleCount).toBe(6)
  })
})

// ---------------------------------------------------------------------------
// Burst factor boundary (ticket: ≥3x 触发)
// ---------------------------------------------------------------------------

describe('TokenUsageDetector — burst factor boundary', () => {
  it.each([
    ['exactly 3x fires (>= boundary)', 300, true],
    ['1 token below 3x stays silent', 299, false],
    ['2.9x stays silent', 290, false],
    ['simulated 10x burst fires', 1000, true],
  ] as const)('%s', (_label, total, expectFire) => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    const hit = d.record('s1', usage(total), 1_000_500)
    if (expectFire) {
      expect(hit).not.toBeNull()
      expect(hit!.ratio).toBeCloseTo(total / 100, 5)
      expect(onHit).toHaveBeenCalledTimes(1)
    } else {
      expect(hit).toBeNull()
      expect(onHit).not.toHaveBeenCalled()
    }
  })

  it('a baseline inflated by the burst suppresses duplicate alerts until re-arm', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    // Burst fires.
    expect(d.record('s1', usage(1000), 1_000_500)).not.toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
    // Sustained same-size bursts stay silent (marker held) — and even
    // without the marker they would: the fired 1000-token samples inflate
    // the in-window mean, so 1000 is no longer ≥3× the baseline.
    expect(d.record('s1', usage(1000), 1_000_600)).toBeNull()
    expect(d.record('s1', usage(1000), 1_000_700)).toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
    // A calm call back below the factor re-arms the marker (no fire — calm).
    expect(d.record('s1', usage(100), 1_000_800)).toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
    // The next burst fires fresh — but it must out-grow the burst-inflated
    // baseline: the window now holds three 1000-token samples (mean ≈ 400),
    // so only a proportionally larger burst crosses the factor again.
    expect(d.record('s1', usage(5000), 1_000_900)).not.toBeNull()
    expect(onHit).toHaveBeenCalledTimes(2)
  })
})

// ---------------------------------------------------------------------------
// Cross-session isolation + window expiry
// ---------------------------------------------------------------------------

describe('TokenUsageDetector — session isolation', () => {
  it('sessions do not share baselines (no bleed across sessions)', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    learn(d, 's2', 1_000_000, 5, 100)
    // s1 bursts, s2 stays calm — only s1 fires, and s2's later burst
    // still fires independently.
    expect(d.record('s1', usage(1000), 1_000_500)).not.toBeNull()
    expect(d.record('s2', usage(100), 1_000_500)).toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
    expect(d.record('s2', usage(1000), 1_000_600)).not.toBeNull()
    expect(onHit).toHaveBeenCalledTimes(2)
    const firedSessions = onHit.mock.calls.map((c) => (c[0] as TokenUsageHit).sessionId).sort()
    expect(firedSessions).toEqual(['s1', 's2'])
  })
})

describe('TokenUsageDetector — window expiry', () => {
  it('samples older than windowMs are evicted; a fully expired window restarts learning', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_SHORT_WINDOW, onHit)
    learn(d, 's1', 1_000_000, 5, 100) // t = 0..400
    // At t=2000 every sample is older than windowMs (1000) → all evicted,
    // so this call restarts the learning phase even though it is a 10x
    // burst (window 过期清零).
    expect(d.record('s1', usage(1000), 1_002_000)).toBeNull()
    expect(onHit).not.toHaveBeenCalled()
    expect(d.size()).toBe(1)
    // Re-learn 5 fresh samples, then burst — fires.
    learn(d, 's1', 1_002_100, 5, 100)
    expect(d.record('s1', usage(1000), 1_002_600)).not.toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
  })

  it('partial expiry shrinks the baseline but keeps learning-floor semantics', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_SHORT_WINDOW, onHit)
    learn(d, 's1', 1_000_000, 5, 100) // t = 0..400
    // t=900: samples at 0 is evicted (900-1000=-100 → ts 0 < -100? no:
    // cutoff = -100, sample ts 0 >= -100 stays). Only ts eviction when
    // sample.ts < ts - windowMs = -100 — none. Use a longer jump instead.
    // At t=1500 cutoff=500: samples 0..400 all evicted (same as full
    // expiry) — verified above. Here verify the boundary itself:
    learn(d, 's1', 2_000_000, 5, 100) // t = 0..400 (fresh session timeline)
    // cutoff at t=1400 → 400; sample ts 400 is NOT < 400 → stays.
    expect(d.record('s1', usage(100), 2_001_400)).toBeNull()
    // Next call at t=1500 (cutoff 500) evicts the 400-sample; still in
    // learning floor (4 left < 5), burst must not fire.
    expect(d.record('s1', usage(1000), 2_001_500)).toBeNull()
    expect(onHit).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Disabled / malformed inputs
// ---------------------------------------------------------------------------

describe('TokenUsageDetector — disabled + malformed inputs', () => {
  it('enabled=false is a no-op', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DISABLED, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    d.record('s1', usage(1000), 1_000_500)
    expect(onHit).not.toHaveBeenCalled()
    expect(d.size()).toBe(0)
  })

  it('empty sessionId returns null without creating state', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    expect(d.record('', usage(1000), 1000)).toBeNull()
    expect(d.size()).toBe(0)
    expect(onHit).not.toHaveBeenCalled()
  })

  it('zero-total usage chunks are skipped and never poison the baseline', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    // A malformed 0-total chunk must not be recorded — otherwise the
    // baseline would sag and a later normal call could false-fire.
    expect(d.record('s1', { inputTokens: 0, outputTokens: 0, totalTokens: 0 }, 1_000_500)).toBeNull()
    expect(d.size()).toBe(5)
    // Normal call stays silent (baseline intact at 100 → ratio 1).
    expect(d.record('s1', usage(100), 1_000_600)).toBeNull()
    expect(onHit).not.toHaveBeenCalled()
  })

  it('totalTokens missing falls back to inputTokens + outputTokens for the burst check', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    // Provider-style split-only chunk: 1000 total via 600+400 → 10x.
    const hit = d.record('s1', { inputTokens: 600, outputTokens: 400 }, 1_000_500)
    expect(hit).not.toBeNull()
    expect(hit!.usage.totalTokens).toBe(1000)
    expect(hit!.usage.inputTokens).toBe(600)
    expect(hit!.usage.outputTokens).toBe(400)
    expect(onHit).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// onHit callback semantics
// ---------------------------------------------------------------------------

describe('TokenUsageDetector — onHit callback', () => {
  it('callback exceptions are swallowed (detector stays healthy)', () => {
    const d = new TokenUsageDetector(CFG_DEFAULT, () => {
      throw new Error('audit emit failed')
    })
    learn(d, 's1', 1_000_000, 5, 100)
    expect(() => d.record('s1', usage(1000), 1_000_500)).not.toThrow()
    expect(d.size()).toBe(6)
  })

  it('callback runs synchronously inside the bursting call', () => {
    const order: string[] = []
    const d = new TokenUsageDetector(CFG_DEFAULT, () => {
      order.push('callback')
    })
    learn(d, 's1', 1_000_000, 5, 100)
    expect(order).toEqual([])
    order.push('before')
    const hit = d.record('s1', usage(1000), 1_000_500)
    order.push('after')
    expect(hit).not.toBeNull()
    expect(order).toEqual(['before', 'callback', 'after'])
  })

  it('hit payload carries every field an audit consumer needs', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    const hit = d.record('s1', usage(1000), 1_000_500)
    expect(hit).toMatchObject({
      sessionId: 's1',
      ts: 1_000_500,
      baseline: 100,
      ratio: 10,
      burstFactor: 3,
      sampleCount: 6,
      windowMs: 60_000,
      usage: { totalTokens: 1000 },
    })
  })
})

// ---------------------------------------------------------------------------
// clearSession
// ---------------------------------------------------------------------------

describe('TokenUsageDetector — clearSession', () => {
  it('drops samples and the fired marker; a fresh same-id session starts at zero', () => {
    const onHit = vi.fn()
    const d = new TokenUsageDetector(CFG_DEFAULT, onHit)
    learn(d, 's1', 1_000_000, 5, 100)
    expect(d.record('s1', usage(1000), 1_000_500)).not.toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
    d.clearSession('s1')
    expect(d.size()).toBe(0)
    // Post-clear: the burst lands in a learning floor again → silent.
    expect(d.record('s1', usage(1000), 2_000_000)).toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
  })

  it('only clears the targeted session', () => {
    const d = new TokenUsageDetector(CFG_DEFAULT)
    learn(d, 's1', 1_000_000, 3, 100)
    learn(d, 's2', 1_000_000, 4, 100)
    d.clearSession('s1')
    expect(d.size()).toBe(4)
  })

  it('clearSession on an unknown / empty id is a no-op', () => {
    const d = new TokenUsageDetector(CFG_DEFAULT)
    learn(d, 's1', 1_000_000, 2, 100)
    d.clearSession('nope')
    d.clearSession('')
    expect(d.size()).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// Config normalization (ticket defaults)
// ---------------------------------------------------------------------------

describe('TokenUsageDetector — config defaults via normalizeConfig', () => {
  it('omitting the block defaults to enabled=true / 60s / 3x / 5 samples (ticket spec)', () => {
    const cfg = normalizeConfig({})
    expect(cfg.tokenUsageDetector.enabled).toBe(true)
    expect(cfg.tokenUsageDetector.windowMs).toBe(60_000)
    expect(cfg.tokenUsageDetector.burstFactor).toBe(3)
    expect(cfg.tokenUsageDetector.minBaselineSamples).toBe(5)
  })

  it('honours operator overrides', () => {
    const cfg = normalizeConfig({
      tokenUsageDetector: { enabled: false, windowMs: 30_000, burstFactor: 5, minBaselineSamples: 10 },
    })
    expect(cfg.tokenUsageDetector.enabled).toBe(false)
    expect(cfg.tokenUsageDetector.windowMs).toBe(30_000)
    expect(cfg.tokenUsageDetector.burstFactor).toBe(5)
    expect(cfg.tokenUsageDetector.minBaselineSamples).toBe(10)
  })
})

// ---------------------------------------------------------------------------
// teeLlmStream — llm/stream waterfall wrapper
// ---------------------------------------------------------------------------

function textChunk(text: string): StreamChunk {
  return { type: 'text', text }
}

function usageChunk(usage: TokenUsage): StreamChunk {
  return { type: 'usage', usage }
}

describe('teeLlmStream — stream pass-through', () => {
  it('yields every chunk unchanged, in order (identity preserved)', async () => {
    const chunks: StreamChunk[] = [
      textChunk('hello'),
      usageChunk({ inputTokens: 10, outputTokens: 20, totalTokens: 30 }),
      textChunk('world'),
      usageChunk({ inputTokens: 40, outputTokens: 50 }),
    ]
    async function* source(): AsyncIterable<StreamChunk> {
      for (const c of chunks) yield c
    }
    const tapped: TokenUsage[] = []
    const out = await collect(teeLlmStream(source(), (u) => tapped.push(u)))
    // Identity + order preserved — the SAME objects come out.
    expect(out).toEqual(chunks)
    expect(out[0]).toBe(chunks[0])
    expect(out[3]).toBe(chunks[3])
    // Both usage chunks were consumed by the tap.
    expect(tapped).toEqual([
      { inputTokens: 10, outputTokens: 20, totalTokens: 30 },
      { inputTokens: 40, outputTokens: 50 },
    ])
  })

  it('non-usage chunks never touch the tap', async () => {
    async function* source(): AsyncIterable<StreamChunk> {
      yield textChunk('a')
      yield { type: 'thinking', text: 'b' }
    }
    const tapped = vi.fn()
    const out = await collect(teeLlmStream(source(), tapped))
    expect(out).toHaveLength(2)
    expect(tapped).not.toHaveBeenCalled()
  })

  it('usage chunk with a throwing tap still passes through and the consumer sees no error', async () => {
    const chunks: StreamChunk[] = [
      textChunk('before'),
      usageChunk({ inputTokens: 1, outputTokens: 1, totalTokens: 2 }),
      textChunk('after'),
    ]
    async function* source(): AsyncIterable<StreamChunk> {
      for (const c of chunks) yield c
    }
    let tapCalls = 0
    const out = await collect(
      teeLlmStream(source(), () => {
        tapCalls++
        throw new Error('detector exploded')
      }),
    )
    // Invariant : the tap failure must not break the LLM stream — all
    // chunks are delivered, in order, and the iteration itself succeeds.
    expect(out).toEqual(chunks)
    expect(tapCalls).toBe(1)
  })

  it('source stream errors propagate unchanged (transparent passthrough)', async () => {
    const boom = new Error('upstream provider failure')
    async function* source(): AsyncIterable<StreamChunk> {
      yield textChunk('partial')
      throw boom
    }
    const tapped = vi.fn()
    const iterator = teeLlmStream(source(), tapped)[Symbol.asyncIterator]()
    await expect(iterator.next()).resolves.toMatchObject({ done: false })
    await expect(iterator.next()).rejects.toBe(boom)
  })

  it('feeds the detector end-to-end: 10x usage burst in a stream fires exactly once', async () => {
    const onHit = vi.fn()
    const detector = new TokenUsageDetector(CFG_DEFAULT, onHit)
    async function* source(): AsyncIterable<StreamChunk> {
      yield textChunk('turn 1')
      for (let i = 0; i < 5; i++) {
        yield usageChunk({ inputTokens: 50, outputTokens: 50, totalTokens: 100 })
      }
      yield usageChunk({ inputTokens: 500, outputTokens: 500, totalTokens: 1000 })
      yield textChunk('done')
    }
    const out = await collect(
      teeLlmStream(source(), (u) => {
        detector.record('s1', u, 1_000_000)
      }),
    )
    expect(out).toHaveLength(8)
    expect(onHit).toHaveBeenCalledTimes(1)
    expect((onHit.mock.calls[0]![0] as TokenUsageHit).ratio).toBe(10)
  })
})
