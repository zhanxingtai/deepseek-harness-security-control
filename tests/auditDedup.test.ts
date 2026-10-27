/**
 * Sliding-window content dedup for security_audit emissions
 * (`src/utils/events/auditDedup.ts`).
 *
 * Real-data motivation: 268/326 security_audit rows in the 2026-10-27
 * sample were `policy/modify success` heartbeats for the same policy
 * file — 12 identical rows inside one 10 s window. The deduper swallows
 * same-content repeats inside the window and NEVER merges different
 * content.
 */
import { describe, expect, it, vi } from 'vitest'
import { AuditDeduper } from '../src/utils/events/auditDedup.js'

describe('AuditDeduper', () => {
  it('suppresses same-hash repeats inside the window (burst of 12 → 1 emit)', () => {
    const d = new AuditDeduper({ windowMs: () => 10_000, now: () => 1_000 })
    const results: boolean[] = []
    for (let i = 0; i < 12; i++) results.push(d.shouldEmit('policy|/p', 'hash-A'))
    expect(results.filter(Boolean)).toHaveLength(1)
    expect(results[0]).toBe(true)
    expect(d.suppressedCount('policy|/p')).toBe(11)
  })

  it('ALWAYS emits immediately when the content hash differs', () => {
    let now = 1_000
    const d = new AuditDeduper({ windowMs: () => 10_000, now: () => now })
    expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(true)
    // Same window, different content — must NOT be merged.
    expect(d.shouldEmit('policy|/p', 'hash-B')).toBe(true)
    expect(d.shouldEmit('policy|/p', 'hash-B')).toBe(false)
    expect(d.suppressedCount('policy|/p')).toBe(1)
    // Switching back to hash-A is a different-content event again → emits
    // and opens a fresh window (counters reset).
    expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(true)
    expect(d.suppressedCount('policy|/p')).toBe(0)
  })

  it('emits again once the window has expired', () => {
    let now = 1_000
    const d = new AuditDeduper({ windowMs: () => 500, now: () => now })
    expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(true)
    now += 100
    expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(false)
    now += 501 // past the 500 ms window from lastTs
    expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(true)
  })

  it('windowMs 0 disables dedup entirely', () => {
    const d = new AuditDeduper({ windowMs: () => 0, now: () => 1_000 })
    for (let i = 0; i < 5; i++) expect(d.shouldEmit('k', 'same')).toBe(true)
  })

  it('keys are independent', () => {
    const d = new AuditDeduper({ windowMs: () => 10_000, now: () => 1_000 })
    expect(d.shouldEmit('policy|/a', 'h')).toBe(true)
    expect(d.shouldEmit('policy|/b', 'h')).toBe(true)
    expect(d.shouldEmit('policy|/a', 'h')).toBe(false)
    expect(d.shouldEmit('policy|/b', 'h')).toBe(false)
  })

  it('flushes window bookkeeping (count/firstTs/lastTs) after the window goes quiet', () => {
    vi.useFakeTimers()
    try {
      const flushed: Array<{ key: string; count: number; firstTs: number; lastTs: number }> = []
      const d = new AuditDeduper({
        windowMs: () => 1_000,
        onFlush: (win) => flushed.push(win),
      })
      expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(true) // 14:00:00.000
      vi.advanceTimersByTime(200)
      expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(false) // .200
      vi.advanceTimersByTime(200)
      expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(false) // .400
      expect(flushed).toHaveLength(0) // window still open
      vi.advanceTimersByTime(1_100) // quiet past the window → flush
      expect(flushed).toHaveLength(1)
      expect(flushed[0]).toMatchObject({ key: 'policy|/p', count: 3 })
      expect(flushed[0]!.lastTs - flushed[0]!.firstTs).toBe(400)
      // A single-hit window (nothing suppressed) produces NO bookkeeping.
      vi.advanceTimersByTime(5_000)
      expect(d.shouldEmit('policy|/q', 'hash-Z')).toBe(true)
      vi.advanceTimersByTime(5_000)
      expect(flushed).toHaveLength(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('a new emission cancels the previous window bookkeeping (no stale flush)', () => {
    vi.useFakeTimers()
    try {
      const flushed: string[] = []
      const d = new AuditDeduper({
        windowMs: () => 1_000,
        onFlush: (win) => flushed.push(win.key),
      })
      expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(true)
      vi.advanceTimersByTime(100)
      expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(false)
      // New content resets the entry — the old window's timer is cleared
      // (its flush never fires), and a suppression in the NEW window
      // flushes exactly once.
      vi.advanceTimersByTime(100)
      expect(d.shouldEmit('policy|/p', 'hash-B')).toBe(true)
      vi.advanceTimersByTime(100)
      expect(d.shouldEmit('policy|/p', 'hash-B')).toBe(false)
      vi.advanceTimersByTime(5_000)
      expect(flushed).toEqual(['policy|/p']) // one flush — the B window only
    } finally {
      vi.useRealTimers()
    }
  })

  it('clear() drops windows and pending flushes', () => {
    vi.useFakeTimers()
    try {
      const flushed: string[] = []
      const d = new AuditDeduper({
        windowMs: () => 1_000,
        onFlush: (win) => flushed.push(win.key),
      })
      expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(true)
      vi.advanceTimersByTime(100)
      expect(d.shouldEmit('policy|/p', 'hash-A')).toBe(false)
      d.clear()
      vi.advanceTimersByTime(5_000)
      expect(flushed).toHaveLength(0)
    } finally {
      vi.useRealTimers()
    }
  })
})
