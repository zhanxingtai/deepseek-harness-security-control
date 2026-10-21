/**
 * Unit tests for `EventEmitter` (A1 god-class split, 2026-09-26).
 *
 * Locks the four extracted primitives:
 *   - `makeBaseEvent(eventType, sessionContext)` — platform-standard
 *     base shape (comm / event_id / event_type / layer / source_layer /
 *     ts / pid / session_id / run_id / agent_id / host_meta / blocked:false)
 *   - `stampSource(event, collector)` — `source` string + structured
 *     `collector` metadata per the platform spec
 *   - `applyDecisionToEvent(event, decision?)` — hoist SPL decision
 *     onto the emitted event (top-level block_reason + intervention
 *     marketplace wire vocabulary + optional risk_assessment)
 *   - `emit(event)` — call `LocalNdjsonSink.report()` and bump the
 *     shared `eventsEmitted` counter
 *
 * The `eventsEmitted` counter is shared with the host via the
 * `EventEmitterStats` reference — we assert that the counter increments
 * exactly once per emit (not per makeBaseEvent / stampSource /
 * applyDecisionToEvent call, which are pure functions over their input).
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { EventEmitter } from '../src/collectors/EventEmitter.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { DEFAULT_PLATFORM_ID, type SecurityEvent, type SecurityDecision, type SessionContext, type SourceMeta } from '../src/types/index.js'
import { nowMs } from '../src/utils/time.js'

interface StubStats {
  eventsEmitted: number
}

class CapturingSink {
  public readonly reported: SecurityEvent[] = []
  report(event: SecurityEvent): void {
    this.reported.push(event)
  }
}

function makeSession(overrides: Partial<SessionContext> = {}): SessionContext {
  return {
    sessionId: 'session-1',
    runId: 'run-1',
    agentId: 'agent-1',
    previousActions: [],
    stepIndex: 0,
    messageIndex: 0,
    ...overrides,
  }
}

describe('EventEmitter', () => {
  let sink: CapturingSink
  let stats: StubStats
  let emitter: EventEmitter

  beforeEach(() => {
    sink = new CapturingSink()
    stats = { eventsEmitted: 0 }
    // The host passes the real LocalNdjsonSink in production; here we
    // exercise the bridge by duck-typing through `CapturingSink`. The
    // EventEmitter only calls `report(event)`, which our stub provides.
    emitter = new EventEmitter(sink as unknown as LocalNdjsonSink, stats)
  })

  afterEach(() => {
    sink.reported.length = 0
  })

  describe('makeBaseEvent', () => {
    it('stamps the platform-standard base shape', () => {
      const session = makeSession()
      const event = emitter.makeBaseEvent('agent_tool_call', session)
      expect(event.comm).toBe(DEFAULT_PLATFORM_ID)
      expect(typeof event.event_id).toBe('string')
      expect(event.event_id.length).toBeGreaterThan(0)
      expect(event.event_type).toBe('agent_tool_call')
      expect(event.layer).toBe('application')
      expect(event.source_layer).toBe('application')
      expect(event.ts).toBeGreaterThan(0)
      expect(event.timestamp).toBe(event.ts)
      expect(event.pid).toBe(process.pid)
      expect(event.collection_method).toBe('agent_api')
      expect(event.session_id).toBe('session-1')
      expect(event.run_id).toBe('run-1')
      expect(event.agent_id).toBe('agent-1')
      expect(event.blocked).toBe(false)
    })

    it('propagates the host_meta fields from LocalNdjsonSink.buildHostMeta()', () => {
      const event = emitter.makeBaseEvent('agent_session_start', makeSession())
      // buildHostMeta() always populates host_id / container_id
      // (possibly empty strings in test contexts where neither is set).
      // The shape is stable across hosts.
      expect('host_id' in event).toBe(true)
      expect('container_id' in event).toBe(true)
    })

    it('does NOT increment eventsEmitted (pure builder)', () => {
      emitter.makeBaseEvent('agent_tool_call', makeSession())
      emitter.makeBaseEvent('agent_tool_call', makeSession())
      emitter.makeBaseEvent('agent_tool_call', makeSession())
      expect(stats.eventsEmitted).toBe(0)
      expect(sink.reported).toHaveLength(0)
    })
  })

  describe('stampSource', () => {
    it('sets the source string to the marketplace form identifier', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      const collector: SourceMeta = {
        hook_name: 'agent_tool_call',
        middleware_name: DEFAULT_PLATFORM_ID,
        collector_name: 'application-collector',
      }
      emitter.stampSource(event, collector)
      expect(event.source).toBe('sst-security-control-dsh.application-collector.0.4.0')
      expect(event.collector).toEqual(collector)
    })

    it('does NOT increment eventsEmitted (pure mutator)', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      emitter.stampSource(event, {
        hook_name: 'x',
        middleware_name: 'y',
        collector_name: 'z',
      })
      expect(stats.eventsEmitted).toBe(0)
    })
  })

  describe('applyDecisionToEvent', () => {
    it('is a no-op when decision is undefined', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      const before = { ...event }
      emitter.applyDecisionToEvent(event, undefined)
      expect(event.blocked).toBe(before.blocked)
      expect(event.intervention).toBe(before.intervention)
    })

    it('hoists a block decision onto the event top level', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      const decision: SecurityDecision = {
        decision: 'block',
        mode: 'enforce',
        block_reason: 'credential access attempt',
        block_code: 'INLINE_SENSITIVE_PATH_001',
        appealable: false,
        intervention: {
          decision: 'deny',
          decision_internal: 'block',
          mode: 'enforce',
          block_reason: 'credential access attempt',
          block_code: 'INLINE_SENSITIVE_PATH_001',
        },
        latency_ms: 1,
      }
      emitter.applyDecisionToEvent(event, decision)
      expect(event.blocked).toBe(true)
      expect(event.block_reason).toBe('credential access attempt')
      expect(event.intervention?.decision).toBe('deny')
      expect(event.intervention?.decision_internal).toBe('block')
      expect(event.intervention?.block_code).toBe('INLINE_SENSITIVE_PATH_001')
    })

    it('drops top-level block_reason on allow decisions', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      const decision: SecurityDecision = {
        decision: 'allow',
        mode: 'audit',
        intervention: undefined,
        latency_ms: 0,
      }
      emitter.applyDecisionToEvent(event, decision)
      expect(event.blocked).toBe(false)
      expect(event.block_reason).toBeUndefined()
    })

    it('strips fail_strategy from the intervention payload (marketplace wire vocabulary)', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      const decision: SecurityDecision = {
        decision: 'block',
        mode: 'enforce',
        block_reason: 'x',
        intervention: {
          decision: 'deny',
          decision_internal: 'block',
          mode: 'enforce',
          block_reason: 'x',
          fail_strategy: 'inline_self_protection',
        },
        latency_ms: 0,
      }
      emitter.applyDecisionToEvent(event, decision)
      expect(event.intervention).toBeDefined()
      expect('fail_strategy' in event.intervention!).toBe(false)
    })

    it('does NOT increment eventsEmitted (pure mutator)', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      emitter.applyDecisionToEvent(event, {
        decision: 'allow',
        mode: 'audit',
        intervention: undefined,
        latency_ms: 0,
      })
      expect(stats.eventsEmitted).toBe(0)
    })
  })

  describe('emit', () => {
    it('forwards to LocalNdjsonSink.report() and increments eventsEmitted', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      emitter.emit(event)
      expect(sink.reported).toEqual([event])
      expect(stats.eventsEmitted).toBe(1)
    })

    it('increments eventsEmitted exactly once per emit (not per builder call)', () => {
      for (let i = 0; i < 5; i++) {
        const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
        emitter.stampSource(event, {
          hook_name: 'agent_tool_call',
          middleware_name: DEFAULT_PLATFORM_ID,
          collector_name: 'application-collector',
        })
        emitter.emit(event)
      }
      expect(sink.reported).toHaveLength(5)
      expect(stats.eventsEmitted).toBe(5)
    })

    it('shares the stats reference with the host (counter stays in sync)', () => {
      // Mimic the host wiring: host creates its own stats object and
      // passes it to the emitter. Bumping the counter from the emitter
      // side must be visible to the host (the host's `getStats()` would
      // read it).
      expect(stats.eventsEmitted).toBe(0)
      emitter.emit(emitter.makeBaseEvent('a', makeSession()))
      expect(stats.eventsEmitted).toBe(1)
      // Host could also bump via a direct read; the assertion is that
      // a single emitter emit increments by exactly one.
      expect(stats.eventsEmitted).toBe(1)
    })
  })

  describe('integration: full emission contract', () => {
    it('makeBaseEvent + stampSource + applyDecisionToEvent + emit lands the right shape on the sink', () => {
      const event = emitter.makeBaseEvent('agent_tool_call', makeSession())
      emitter.stampSource(event, {
        hook_name: 'agent_tool_call',
        middleware_name: DEFAULT_PLATFORM_ID,
        collector_name: 'application-collector',
      })
      emitter.applyDecisionToEvent(event, {
        decision: 'block',
        mode: 'enforce',
        block_reason: 'sensitive path access',
        intervention: {
          decision: 'deny',
          decision_internal: 'block',
          mode: 'enforce',
          block_reason: 'sensitive path access',
        },
        latency_ms: 2,
      })
      emitter.emit(event)

      const landed = sink.reported[0]!
      expect(landed.event_type).toBe('agent_tool_call')
      expect(landed.source).toBe('sst-security-control-dsh.application-collector.0.4.0')
      expect(landed.blocked).toBe(true)
      expect(landed.block_reason).toBe('sensitive path access')
      expect(landed.intervention?.decision).toBe('deny')
      // ts must be present and look like a wall-clock (positive integer)
      expect(landed.ts).toBeGreaterThan(0)
      expect(nowMs() - landed.ts).toBeLessThan(1000)
    })
  })
})