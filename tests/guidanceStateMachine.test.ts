import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { GuidanceStateMachine } from '../src/intervention/GuidanceStateMachine.js'

describe('GuidanceStateMachine', () => {
  let machine: GuidanceStateMachine

  beforeEach(() => {
    machine = new GuidanceStateMachine()
  })

  it('records first hit with count=1 and shouldEscalate=false', () => {
    const result = machine.record(
      { sessionId: 's1', policyId: 'p1', templateId: 't1' },
      { maxAttempts: 3 },
    )
    expect(result.state.count).toBe(1)
    expect(result.state.firstSeenTs).toBeGreaterThan(0)
    expect(result.state.lastSeenTs).toBeGreaterThanOrEqual(result.state.firstSeenTs)
    expect(result.shouldEscalate).toBe(false)
  })

  it('increments count on each subsequent hit', () => {
    const key = { sessionId: 's1', policyId: 'p1', templateId: 't1' }
    const limits = { maxAttempts: 3 }
    machine.record(key, limits)
    const r2 = machine.record(key, limits)
    const r3 = machine.record(key, limits)
    expect(r2.state.count).toBe(2)
    expect(r3.state.count).toBe(3)
    expect(r3.shouldEscalate).toBe(true)
  })

  it('flips shouldEscalate=true when count >= maxAttempts', () => {
    const key = { sessionId: 's1', policyId: 'p1', templateId: 't1' }
    machine.record(key, { maxAttempts: 3 })
    machine.record(key, { maxAttempts: 3 })
    const third = machine.record(key, { maxAttempts: 3 })
    expect(third.state.count).toBe(3)
    expect(third.shouldEscalate).toBe(true)
  })

  it('flips shouldEscalate=true when count >= escalateThreshold', () => {
    const key = { sessionId: 's1', policyId: 'p1', templateId: 't1' }
    machine.record(key, { escalateThreshold: 2 })
    const second = machine.record(key, { escalateThreshold: 2 })
    expect(second.state.count).toBe(2)
    expect(second.shouldEscalate).toBe(true)
  })

  it('never escalates when neither maxAttempts nor escalateThreshold is set', () => {
    const key = { sessionId: 's1', policyId: 'p1', templateId: 't1' }
    for (let i = 0; i < 50; i++) {
      const r = machine.record(key, {})
      expect(r.shouldEscalate).toBe(false)
    }
    const last = machine.record(key, {})
    expect(last.state.count).toBe(51)
  })

  it('separate templates do not share state', () => {
    const limits = { maxAttempts: 1 }
    const a = machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, limits)
    const b = machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't2' }, limits)
    expect(a.state.count).toBe(1)
    expect(b.state.count).toBe(1)
    expect(a.shouldEscalate).toBe(true)
    expect(b.shouldEscalate).toBe(true)
  })

  it('separate sessions do not share state', () => {
    const limits = { maxAttempts: 1 }
    const a = machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, limits)
    const b = machine.record({ sessionId: 's2', policyId: 'p1', templateId: 't1' }, limits)
    expect(a.state.count).toBe(1)
    expect(b.state.count).toBe(1)
  })

  it('separate policies do not share state', () => {
    const limits = { maxAttempts: 1 }
    const a = machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, limits)
    const b = machine.record({ sessionId: 's1', policyId: 'p2', templateId: 't1' }, limits)
    expect(a.state.count).toBe(1)
    expect(b.state.count).toBe(1)
  })

  it('gc evicts entries older than maxAgeMs', () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(1_000_000)
      machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, { maxAttempts: 5 })
      machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't2' }, { maxAttempts: 5 })
      expect(machine.size()).toBe(2)

      // Advance just past the default 1h TTL.
      vi.setSystemTime(1_000_000 + 60 * 60 * 1000 + 1000)
      const evicted = machine.gc()
      expect(evicted).toBe(2)
      expect(machine.size()).toBe(0)

      // Re-record after eviction starts fresh at count=1.
      const r = machine.record(
        { sessionId: 's1', policyId: 'p1', templateId: 't1' },
        { maxAttempts: 5 },
      )
      expect(r.state.count).toBe(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('gc keeps entries younger than maxAgeMs', () => {
    vi.useFakeTimers()
    try {
      vi.setSystemTime(1_000_000)
      machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, { maxAttempts: 5 })

      vi.setSystemTime(1_000_000 + 100) // 100ms later, well within TTL
      const evicted = machine.gc()
      expect(evicted).toBe(0)
      expect(machine.size()).toBe(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('reset clears one key', () => {
    const limits = { maxAttempts: 5 }
    machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, limits)
    machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't2' }, limits)
    expect(machine.size()).toBe(2)

    machine.reset({ sessionId: 's1', policyId: 'p1', templateId: 't1' })
    expect(machine.size()).toBe(1)

    // Re-record starts fresh.
    const r = machine.record(
      { sessionId: 's1', policyId: 'p1', templateId: 't1' },
      limits,
    )
    expect(r.state.count).toBe(1)
  })

  it('reset is a no-op for an unknown key', () => {
    machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, { maxAttempts: 5 })
    expect(machine.size()).toBe(1)
    machine.reset({ sessionId: 's-other', policyId: 'p1', templateId: 't1' })
    expect(machine.size()).toBe(1)
  })

  it('resetAll clears everything', () => {
    machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't1' }, { maxAttempts: 5 })
    machine.record({ sessionId: 's1', policyId: 'p1', templateId: 't2' }, { maxAttempts: 5 })
    machine.record({ sessionId: 's2', policyId: 'p1', templateId: 't1' }, { maxAttempts: 5 })
    expect(machine.size()).toBe(3)

    machine.resetAll()
    expect(machine.size()).toBe(0)
  })

  it('keying treats missing templateId as empty string (shares bucket)', () => {
    // Two hits without a templateId share the same bucket; this matches the
    // spec's `${sessionId}::${policyId}::${templateId ?? ''}` shape.
    const limits = { maxAttempts: 5 }
    const a = machine.record({ sessionId: 's1', policyId: 'p1' }, limits)
    const b = machine.record({ sessionId: 's1', policyId: 'p1' }, limits)
    expect(a.state.count).toBe(1)
    expect(b.state.count).toBe(2)
  })
})