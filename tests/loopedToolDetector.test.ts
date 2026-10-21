/**
 * Tests for the per-tool loop detector (Stage 3 §6.2 EAT-22).
 *
 * Coverage:
 *   - threshold crossing (single (session, tool) crosses threshold → fires)
 *   - suppression within the same window (one audit per crossing)
 *   - re-arm when count drops back below threshold
 *   - window eviction (timestamps older than `windowMs` are dropped)
 *   - per-(session, tool) isolation — multiple sessions / multiple tools
 *   - clearSession removes timestamps + fired markers
 *   - disabled is a no-op
 *   - malformed inputs (empty toolName / sessionId) return null
 * Config normalization defaults match ticket spec
 *   - the public hit payload shape carries everything an audit consumer
 *     needs (threshold / windowMs / windowStart / windowEnd / count)
 *   - onHit callback runs synchronously, errors are swallowed (audit
 *     failures must not break the detector)
 *   - size() introspection
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { normalizeConfig } from '../src/config.js'
import {
  LoopedToolDetector,
  type LoopedToolDetectorConfig,
  type LoopedToolHit,
} from '../src/intervention/LoopedToolDetector.js'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const CFG_DEFAULT: LoopedToolDetectorConfig = {
  enabled: true,
  windowMs: 60_000,
  thresholdPerWindow: 100,
}

const CFG_TIGHT: LoopedToolDetectorConfig = {
  // Tighter defaults so tests can drive the threshold quickly without
  // hammering the detector with 100+ records.
  enabled: true,
  windowMs: 1_000,
  thresholdPerWindow: 5,
}

const CFG_DISABLED: LoopedToolDetectorConfig = {
  enabled: false,
  windowMs: 60_000,
  thresholdPerWindow: 100,
}

function ts(base: number, ms: number): number {
  return base + ms
}

describe('LoopedToolDetector — disabled is a no-op', () => {
  it('enabled=false returns null on every call', () => {
    const d = new LoopedToolDetector(CFG_DISABLED)
    for (let i = 0; i < 200; i++) {
      expect(d.record('bash', 's1', 1_000_000 + i)).toBeNull()
    }
    expect(d.size()).toBe(0)
  })

  it('enabled=false does not call the onHit handler even when threshold would otherwise fire', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector({ ...CFG_DISABLED }, onHit)
    for (let i = 0; i < 200; i++) d.record('bash', 's1', 1_000_000 + i)
    expect(onHit).not.toHaveBeenCalled()
  })
})

describe('LoopedToolDetector — threshold crossing', () => {
  it('first N-1 calls stay silent; the threshold-th call fires the hit', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    for (let i = 0; i < CFG_TIGHT.thresholdPerWindow; i++) {
      const hit = d.record('bash', 's1', ts(1_000_000, i))
      expect(hit).toBeNull()
      expect(onHit).not.toHaveBeenCalled()
    }
    // The threshold+1st call crosses the boundary and fires.
    const crossing = d.record('bash', 's1', ts(1_000_000, CFG_TIGHT.thresholdPerWindow))
    expect(crossing).not.toBeNull()
    expect(crossing!.count).toBe(CFG_TIGHT.thresholdPerWindow + 1)
    expect(onHit).toHaveBeenCalledTimes(1)
    const hitArg = onHit.mock.calls[0]![0] as LoopedToolHit
    expect(hitArg.toolName).toBe('bash')
    expect(hitArg.sessionId).toBe('s1')
    expect(hitArg.threshold).toBe(CFG_TIGHT.thresholdPerWindow)
    expect(hitArg.windowMs).toBe(CFG_TIGHT.windowMs)
    expect(hitArg.windowStart).toBe(ts(1_000_000, 0))
    expect(hitArg.windowEnd).toBe(ts(1_000_000, CFG_TIGHT.thresholdPerWindow))
  })

  it('subsequent calls within the same window stay silent (no duplicate audit)', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    // Drive past the threshold by a wide margin.
    for (let i = 0; i < CFG_TIGHT.thresholdPerWindow * 3; i++) {
      d.record('bash', 's1', ts(1_000_000, i * 10))
    }
    expect(onHit).toHaveBeenCalledTimes(1)
  })

  it('multiple tools in the same session are isolated', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    for (let i = 0; i < CFG_TIGHT.thresholdPerWindow * 2; i++) {
      // Interleave bash + edit so each has its own counter.
      d.record('bash', 's1', ts(1_000_000, i * 10))
      d.record('edit', 's1', ts(1_000_000, i * 10 + 5))
    }
    expect(onHit).toHaveBeenCalledTimes(2)
    const firedTools = onHit.mock.calls.map((c) => (c[0] as LoopedToolHit).toolName).sort()
    expect(firedTools).toEqual(['bash', 'edit'])
  })

  it('multiple sessions with the same tool are isolated', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    for (let i = 0; i < CFG_TIGHT.thresholdPerWindow * 2; i++) {
      d.record('bash', 's1', ts(1_000_000, i * 5))
      d.record('bash', 's2', ts(1_000_000, i * 5 + 2))
    }
    expect(onHit).toHaveBeenCalledTimes(2)
    const firedSessions = onHit.mock.calls.map((c) => (c[0] as LoopedToolHit).sessionId).sort()
    expect(firedSessions).toEqual(['s1', 's2'])
  })
})

describe('LoopedToolDetector — sliding window eviction', () => {
  it('timestamps older than windowMs are evicted before the threshold check', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    // Drive 5 calls (== threshold) at t=0..400.
    for (let i = 0; i < 5; i++) d.record('bash', 's1', i * 100)
    // At t=1500 every prior timestamp is older than windowMs (1000) and
    // must be evicted; this single call starts the next loop.
    const hit = d.record('bash', 's1', 1500)
    expect(hit).toBeNull()
    expect(onHit).not.toHaveBeenCalled()
    // After eviction the (session, tool) pair starts fresh — drive 6
    // more calls (one more than threshold) so the boundary crossing
    // fires inside this second loop.
    let triggered: LoopedToolHit | null = null
    for (let i = 0; i < 6; i++) {
      const result = d.record('bash', 's1', 2000 + i * 100)
      if (result) triggered = result
    }
    expect(triggered).not.toBeNull()
    expect(onHit).toHaveBeenCalledTimes(1)
    // windowStart/windowEnd reflect the post-eviction timestamps, NOT
    // the original phase-1 timestamps (which were all evicted).
    expect(triggered!.windowStart).toBe(1500)
    expect(triggered!.windowEnd).toBe(2400)
  })

  it('windowStart is the oldest timestamp still inside the window', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    for (let i = 0; i < 5; i++) d.record('bash', 's1', i * 100)
    const hit = d.record('bash', 's1', 500)
    expect(hit).not.toBeNull()
    expect(hit!.windowStart).toBe(0) // the very first call
    expect(hit!.windowEnd).toBe(500) // the call that fired
  })
})

describe('LoopedToolDetector — re-arm policy', () => {
  it('re-arms when the count drops back to or below the threshold', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    // First loop: 6 calls (1 over threshold).
    for (let i = 0; i < 6; i++) d.record('bash', 's1', ts(1_000_000, i * 50))
    expect(onHit).toHaveBeenCalledTimes(1)
    // Wait past the window (1100 ms > windowMs 1000) so the old
    // timestamps fully evict.
    d.record('bash', 's1', ts(1_000_000, 1500))
    // Build up to 4 (below threshold 5) — marker should re-arm.
    for (let i = 0; i < 3; i++) d.record('bash', 's1', ts(1_000_000, 1600 + i * 10))
    expect(onHit).toHaveBeenCalledTimes(1)
    // Cross the threshold again — marker was re-armed, this fires fresh.
    for (let i = 0; i < 5; i++) d.record('bash', 's1', ts(1_000_000, 1700 + i * 10))
    expect(onHit).toHaveBeenCalledTimes(2)
  })

  it('a paused loop that resumes within the same window does NOT re-fire', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    // Cross the threshold.
    for (let i = 0; i < 6; i++) d.record('bash', 's1', ts(1_000_000, i * 10))
    expect(onHit).toHaveBeenCalledTimes(1)
    // Pause (no calls) but stay inside the window.
    // 100ms of silence; the previous timestamps are still inside the
    // 1000ms window. The count never drops below the threshold.
    for (let i = 0; i < 5; i++) d.record('bash', 's1', ts(1_000_000, 200 + i * 10))
    expect(onHit).toHaveBeenCalledTimes(1) // still 1 — the marker stays
  })
})

describe('LoopedToolDetector — clearSession', () => {
  it('drops all timestamps for a session', () => {
    const d = new LoopedToolDetector(CFG_TIGHT)
    for (let i = 0; i < 4; i++) d.record('bash', 's1', i * 100)
    for (let i = 0; i < 4; i++) d.record('edit', 's1', i * 100)
    expect(d.size()).toBe(8)
    d.clearSession('s1')
    expect(d.size()).toBe(0)
  })

  it('clears the fired-marker so a fresh session with the same id starts at zero', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    for (let i = 0; i < 6; i++) d.record('bash', 's1', ts(1_000_000, i * 10))
    expect(onHit).toHaveBeenCalledTimes(1)
    // Simulate session-end → fresh session with the same id (rare but
    // possible after TTL eviction).
    d.clearSession('s1')
    // Drive another loop; should fire again because the marker is gone.
    for (let i = 0; i < 6; i++) d.record('bash', 's1', ts(2_000_000, i * 10))
    expect(onHit).toHaveBeenCalledTimes(2)
  })

  it('only clears the targeted session — siblings untouched', () => {
    const d = new LoopedToolDetector(CFG_TIGHT)
    for (let i = 0; i < 3; i++) d.record('bash', 's1', i * 100)
    for (let i = 0; i < 4; i++) d.record('bash', 's2', i * 100)
    d.clearSession('s1')
    expect(d.size()).toBe(4)
  })

  it('clearSession on an unknown id is a no-op', () => {
    const d = new LoopedToolDetector(CFG_TIGHT)
    d.clearSession('does-not-exist')
    expect(d.size()).toBe(0)
  })

  it('clearSession with empty string is a no-op (matches the guard in record())', () => {
    const d = new LoopedToolDetector(CFG_TIGHT)
    d.record('bash', 's1', 0)
    d.clearSession('')
    expect(d.size()).toBe(1)
  })
})

describe('LoopedToolDetector — malformed inputs', () => {
  it('empty sessionId is a no-op (no state created, no audit)', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    expect(d.record('bash', '', 1000)).toBeNull()
    expect(onHit).not.toHaveBeenCalled()
    expect(d.size()).toBe(0)
  })

  it('empty toolName is a no-op (no state created, no audit)', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    expect(d.record('', 's1', 1000)).toBeNull()
    expect(onHit).not.toHaveBeenCalled()
    expect(d.size()).toBe(0)
  })
})

describe('LoopedToolDetector — onHit callback errors', () => {
  it('callback exceptions are swallowed (detector stays healthy)', () => {
    const d = new LoopedToolDetector(CFG_TIGHT, () => {
      throw new Error('audit emit failed')
    })
    // Drive past the threshold; the throw inside onHit must not bubble.
    expect(() => {
      for (let i = 0; i < 6; i++) d.record('bash', 's1', i * 100)
    }).not.toThrow()
    expect(d.size()).toBe(6)
  })

  it('callback runs synchronously inside the call that crosses the threshold', () => {
    const order: string[] = []
    const d = new LoopedToolDetector(CFG_TIGHT, () => {
      order.push('callback')
    })
    // The first 5 records stay below threshold → no callback yet.
    for (let i = 0; i < 5; i++) d.record('bash', 's1', i * 100)
    expect(order).toEqual([])
    // Mark the moment just before the crossing call returns.
    order.push('before-crossing')
    const result = d.record('bash', 's1', 500)
    order.push('after-crossing')
    // The callback fires DURING the crossing call (synchronously),
    // so it lands between our two markers.
    expect(result).not.toBeNull()
    expect(order).toEqual(['before-crossing', 'callback', 'after-crossing'])
  })
})

describe('LoopedToolDetector — config defaults via normalizeConfig', () => {
  it('omitting the block defaults to enabled=true / 60s / 100 (ticket spec)', () => {
    const cfg = normalizeConfig({})
    expect(cfg.loopedToolDetector.enabled).toBe(true)
    expect(cfg.loopedToolDetector.windowMs).toBe(60_000)
    expect(cfg.loopedToolDetector.thresholdPerWindow).toBe(100)
  })

  it('honours operator overrides', () => {
    const cfg = normalizeConfig({
      loopedToolDetector: { enabled: false, windowMs: 30_000, thresholdPerWindow: 50 },
    })
    expect(cfg.loopedToolDetector.enabled).toBe(false)
    expect(cfg.loopedToolDetector.windowMs).toBe(30_000)
    expect(cfg.loopedToolDetector.thresholdPerWindow).toBe(50)
  })
})

describe('LoopedToolDetector — hit payload shape', () => {
  it('hit carries every field an audit consumer needs (no follow-up lookup)', () => {
    const onHit = vi.fn()
    const d = new LoopedToolDetector(CFG_TIGHT, onHit)
    for (let i = 0; i < 5; i++) d.record('bash', 's1', ts(1_000_000, i * 50))
    const hit = d.record('bash', 's1', ts(1_000_000, 260))
    expect(hit).toMatchObject({
      toolName: 'bash',
      sessionId: 's1',
      count: 6,
      windowStart: 1_000_000,
      windowEnd: 1_000_260,
      threshold: 5,
      windowMs: 1_000,
    })
  })
})

describe('LoopedToolDetector — size() introspection', () => {
  it('counts every timestamp across every session/tool', () => {
    const d = new LoopedToolDetector(CFG_TIGHT)
    d.record('bash', 's1', 0)
    d.record('bash', 's1', 100)
    d.record('edit', 's1', 200)
    d.record('bash', 's2', 300)
    expect(d.size()).toBe(4)
  })

  it('reports zero on a fresh detector', () => {
    expect(new LoopedToolDetector(CFG_TIGHT).size()).toBe(0)
  })
})