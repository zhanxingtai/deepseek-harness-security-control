/**
 * Unit tests for `PidBindingStore` (refactor).
 *
 * The store encapsulates the `pid → session` cross-correlation map that
 * was previously inline in `ApplicationCollector`:
 *   - get / has / set / clear / size accessors
 *   - the `MAX_SIZE = 5000` defensive cap (force-evict oldest by `ts`)
 *   - the TTL eviction (`evictStale(cutoff)`)
 *   - the cascade eviction on parent-session retirement
 *     (`evictBySessionId(sessionId)`)
 *   - the invalid-PID guard (NaN, ±Infinity, ≤ 1)
 *   - the test-only `setTs(pid, ts)` helper used by
 *     `tests/ApplicationCollector.test.ts` to artificially age entries
 *     past the TTL window without waiting 15 minutes
 *
 * The integration with `ApplicationCollector` (bind on session start,
 * TTL sweep via `evictStaleSessions`, shutdown clear) is covered by the
 * existing `tests/ApplicationCollector.test.ts > ApplicationCollector
 * PID session cache ` block — these tests focus on the data layer
 * alone.
 */

import { describe, expect, it } from 'vitest'
import { PidBindingStore, type PidSessionEntry } from '../src/collectors/pidBindingStore.js'

const SESSION = { sessionId: 's-1', runId: 'r-1' }
const SESSION_B = { sessionId: 's-2', runId: 'r-2' }

describe('PidBindingStore (refactor)', () => {
  it('set + get round-trips a pid binding', () => {
    const store = new PidBindingStore()
    store.set(100, SESSION, 1000)
    expect(store.get(100)).toEqual({ sessionId: 's-1', runId: 'r-1' })
  })

  it('get on an unknown pid returns undefined', () => {
    const store = new PidBindingStore()
    expect(store.get(999)).toBeUndefined()
  })

  it('has distinguishes known from unknown pids', () => {
    const store = new PidBindingStore()
    store.set(100, SESSION, 1000)
    expect(store.has(100)).toBe(true)
    expect(store.has(999)).toBe(false)
  })

  it('set rejects obviously-invalid PIDs (NaN, ≤ 1, ±Infinity)', () => {
    const store = new PidBindingStore()
    // The defensive guard: kernel/init sentinels and Windows spawn-failure
    // sentinels would pollute the resolver if bound.
    store.set(0, SESSION, 1000)
    store.set(1, SESSION, 1000)
    store.set(-1, SESSION, 1000)
    store.set(Number.NaN, SESSION, 1000)
    store.set(Number.POSITIVE_INFINITY, SESSION, 1000)
    store.set(Number.NEGATIVE_INFINITY, SESSION, 1000)
    expect(store.size).toBe(0)
  })

  it('set with the same pid overwrites the previous binding (most-recent wins)', () => {
    const store = new PidBindingStore()
    store.set(100, SESSION, 1000)
    store.set(100, SESSION_B, 2000)
    expect(store.size).toBe(1)
    expect(store.get(100)?.sessionId).toBe('s-2')
  })

  it('clear wipes every entry', () => {
    const store = new PidBindingStore()
    store.set(100, SESSION, 1000)
    store.set(200, SESSION, 1000)
    store.clear()
    expect(store.size).toBe(0)
    expect(store.has(100)).toBe(false)
  })

  it('evictStale drops every entry whose ts < cutoff', () => {
    const store = new PidBindingStore()
    store.set(100, SESSION, 1000)
    store.set(200, SESSION, 2000)
    store.set(300, SESSION, 3000)
    const evicted = store.evictStale(2500)
    expect(evicted).toBe(2)
    expect(store.size).toBe(1)
    expect(store.has(100)).toBe(false)
    expect(store.has(200)).toBe(false)
    expect(store.has(300)).toBe(true)
  })

  it('evictBySessionId cascades every entry belonging to the retired session', () => {
    const store = new PidBindingStore()
    store.set(100, SESSION, 1000)
    store.set(200, SESSION, 1500)
    store.set(300, SESSION_B, 2000)
    const evicted = store.evictBySessionId('s-1')
    expect(evicted).toBe(2)
    expect(store.size).toBe(1)
    expect(store.has(300)).toBe(true)
  })

  it('setTs mutates the bind time of an existing entry (test-only helper)', () => {
    const store = new PidBindingStore()
    store.set(100, SESSION, 1000)
    store.setTs(100, 5000)
    // After aging, evictStale with a cutoff of 3000 must drop the entry —
    // proves setTs actually rewrote the LRU key.
    expect(store.evictStale(3000)).toBe(0)
    store.setTs(100, 0)
    expect(store.evictStale(1)).toBe(1)
    expect(store.has(100)).toBe(false)
  })

  it('setTs on an unknown pid is a silent no-op', () => {
    const store = new PidBindingStore()
    expect(() => store.setTs(999, 1234)).not.toThrow()
    expect(store.has(999)).toBe(false)
  })

  it('enforces the MAX_SIZE cap on the next set() call', () => {
    const store = new PidBindingStore()
    const max = PidBindingStore.MAX_SIZE
    // Seed the map to exactly the cap. Each bind ages by 1 ms so the
    // earlier pids have the smallest `ts` (they will be evicted first).
    for (let i = 0; i < max; i += 1) {
      store.set(1_000_000 + i, SESSION, i)
    }
    expect(store.size).toBe(max)
    // One more bind crosses the cap and triggers force-eviction of the
    // oldest entry (pid=1_000_000, ts=0).
    store.set(2_000_000, SESSION, max + 1)
    expect(store.size).toBe(max)
    expect(store.has(2_000_000)).toBe(true)
    expect(store.has(1_000_000)).toBe(false)
    // A second bind evicts the next-oldest (pid=1_000_001, ts=1).
    store.set(2_000_001, SESSION, max + 2)
    expect(store.size).toBe(max)
    expect(store.has(2_000_001)).toBe(true)
    expect(store.has(1_000_001)).toBe(false)
  })

  it('exposes MAX_SIZE as a static for test seeding', () => {
    expect(PidBindingStore.MAX_SIZE).toBe(5000)
  })

  it('returns PidSessionEntry-shaped objects from get (no internal leakage)', () => {
    const store = new PidBindingStore()
    const entry: PidSessionEntry = {
      sessionId: 's-1',
      runId: 'r-1',
      agentId: 'a-1',
      ts: 1000,
    }
    store.set(100, entry, 1000)
    const got = store.get(100)
    expect(got).toBeDefined()
    // Public shape drops `ts` so callers cannot re-order eviction.
    expect(got).toEqual({ sessionId: 's-1', runId: 'r-1', agentId: 'a-1' })
    expect(got).not.toHaveProperty('ts')
  })
})