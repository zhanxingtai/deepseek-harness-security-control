/**
 * Unit tests for `SessionStore` (A1 god-class split, 2026-09-26).
 *
 * Locks the extracted session-lifecycle primitives:
 *   - `getOrCreateSession(sessionId, agent?)` — fresh-context creation
 *     with `sessionStartTs` lazy stamping + Map lazy initialisation
 *   - `evictStaleSessions()` — TTL sweep with cascade into the loop
 *     detector + token-usage detector + pidBindingStore
 *   - `bindPidToSession(pid, session)` — defense-in-depth PID binding
 *     (defensive cap + invalid-PID guard live in PidBindingStore)
 *   - `bindChildPidToSession(pid, sessionId)` — typed convenience
 *     that looks up the session first (no-op on miss)
 *   - `resolveSessionByPid(pid)` — pid → session lookup
 *   - `resolveHttpSessionByPid(pid)` — typed convenience for
 *     NetworkHttpCollector
 *   - `resolveMostRecentSessionForRuntime()` — RuntimeHook reads
 *     most-recent `tools/pre-execute` session
 *   - `setMostRecentSession(ctx)` — host writes on `onToolPreExecute`
 *   - `resolveActiveSessionId()` — token-usage-detector session
 *     attribution (most-recent tool-call session, else freshest
 *     user-message session, else `'__unknown__'`)
 *   - `pickRecentSession(actor)` — fs event session attribution
 *   - `clearAll()` — shutdown wipe
 *   - `getSessions()` / `getRecentUserMessages()` — read accessors
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SessionStore } from '../src/collectors/SessionStore.js'
import { PidBindingStore } from '../src/collectors/pidBindingStore.js'
import type { Agent } from '../src/types/external.js'
import type { SessionContext } from '../src/types/index.js'
import { nowMs } from '../src/utils/time.js'

interface StubStats {
  sessionsTracked: number
}

interface FakeDetector {
  cleared: string[]
  clearSession(sessionId: string): void
}

/** Stand-in for the two detectors (LoopedToolDetector + TokenUsageDetector).
 *  Records every clearSession call so the cascade prune behaviour is
 *  testable without booting the real detector (which would need a config
 *  + a callback wiring). */
function makeDetector(): FakeDetector {
  return {
    cleared: [],
    clearSession(sessionId: string): void {
      this.cleared.push(sessionId)
    },
  }
}

function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: 'agent-1',
    session: { header: { id: 'session-1' } },
    options: { provider: 'test', model: 'test-model' },
    ...overrides,
  } as unknown as Agent
}

describe('SessionStore', () => {
  let looped: FakeDetector
  let token: FakeDetector
  let pidStore: PidBindingStore
  let applicationConfig: { sessionTtlMs: number }
  let stats: StubStats
  let store: SessionStore

  beforeEach(() => {
    looped = makeDetector()
    token = makeDetector()
    pidStore = new PidBindingStore()
    applicationConfig = { sessionTtlMs: 15 * 60 * 1000 }
    stats = { sessionsTracked: 0 }
    store = new SessionStore(stats, {
      applicationConfig,
      loopedToolDetector: looped,
      tokenUsageDetector: token,
      pidBindingStore: pidStore,
    })
  })

  afterEach(() => {
    store.clearAll()
    pidStore.clear()
  })

  describe('getOrCreateSession', () => {
    it('creates a fresh SessionContext on first call', () => {
      const session = store.getOrCreateSession('s-1', makeAgent())
      expect(session.sessionId).toBe('s-1')
      expect(session.runId).toBe('s-1')
      expect(session.agentId).toBe('agent-1')
      expect(session.previousActions).toEqual([])
      expect(session.stepIndex).toBe(-1)
      expect(session.messageIndex).toBe(-1)
      expect(session.blockedCalls).toBeInstanceOf(Map)
      expect(session.pendingToolStarts).toBeInstanceOf(Map)
      expect(session.sessionStartTs).toBeGreaterThan(0)
    })

    it('returns the same reference on subsequent calls (Map identity)', () => {
      const a = store.getOrCreateSession('s-1')
      const b = store.getOrCreateSession('s-1')
      expect(a).toBe(b)
    })

    it('bumps sessionsTracked exactly once per UNIQUE session id', () => {
      expect(stats.sessionsTracked).toBe(0)
      store.getOrCreateSession('s-1')
      expect(stats.sessionsTracked).toBe(1)
      store.getOrCreateSession('s-2')
      expect(stats.sessionsTracked).toBe(2)
      // Repeat lookups: no bump
      store.getOrCreateSession('s-1')
      store.getOrCreateSession('s-2')
      expect(stats.sessionsTracked).toBe(2)
    })

    it('preserves sessionStartTs across rehydrations (whole-session duration)', () => {
      const a = store.getOrCreateSession('s-1')
      const stamp1 = a.sessionStartTs
      // Sleep a tick so wall-clock advances
      const before = nowMs()
      while (nowMs() === before) {
        // spin
      }
      const b = store.getOrCreateSession('s-1')
      expect(b.sessionStartTs).toBe(stamp1)
    })

    it('lazily populates blockedCalls + pendingToolStarts on rehydration', () => {
      // Simulate a session that was created without these maps (legacy
      // / older callers). getOrCreateSession must backfill them.
      const sessions = store.getSessions()
      sessions.set('legacy', {
        sessionId: 'legacy',
        runId: 'legacy',
        previousActions: [],
        stepIndex: 0,
        messageIndex: 0,
      } as SessionContext)
      const rehydrated = store.getOrCreateSession('legacy')
      expect(rehydrated.blockedCalls).toBeInstanceOf(Map)
      expect(rehydrated.pendingToolStarts).toBeInstanceOf(Map)
      expect(rehydrated.sessionStartTs).toBeGreaterThan(0)
    })
  })

  describe('evictStaleSessions', () => {
    it('drops sessions whose lastUserMessageAt is older than sessionTtlMs', () => {
      const session = store.getOrCreateSession('s-1')
      session.lastUserMessageAt = nowMs() - applicationConfig.sessionTtlMs - 1
      store.evictStaleSessions()
      expect(store.getSession('s-1')).toBeUndefined()
    })

    it('keeps sessions within the TTL window', () => {
      const session = store.getOrCreateSession('s-1')
      session.lastUserMessageAt = nowMs()
      store.evictStaleSessions()
      expect(store.getSession('s-1')).toBe(session)
    })

    it('drops sessions whose lastUserMessageAt is undefined (fresh session-start)', () => {
      // fix: a fresh session-start leaves
      // lastUserMessageAt undefined, and the first sweep would
      // (correctly) treat it as expired.
      store.getOrCreateSession('s-1')
      store.evictStaleSessions()
      expect(store.getSession('s-1')).toBeUndefined()
    })

    it('cascades into the loop detector (clearSession per evicted session)', () => {
      const session = store.getOrCreateSession('s-1')
      session.lastUserMessageAt = 0
      store.evictStaleSessions()
      expect(looped.cleared).toEqual(['s-1'])
    })

    it('cascades into the token-usage detector (clearSession per evicted session)', () => {
      const session = store.getOrCreateSession('s-1')
      session.lastUserMessageAt = 0
      store.evictStaleSessions()
      expect(token.cleared).toEqual(['s-1'])
    })

    it('cascades into pidBindingStore.evictBySessionId for every evicted session', () => {
      const session = store.getOrCreateSession('s-1')
      pidStore.set(process.pid, session, nowMs())
      pidStore.set(12345, session, nowMs())
      session.lastUserMessageAt = 0
      store.evictStaleSessions()
      // Both pid bindings for s-1 should be gone (cascade eviction
      // closes the orphan-pid bug fixed).
      expect(pidStore.has(process.pid)).toBe(false)
      expect(pidStore.has(12345)).toBe(false)
    })

    it('cascades into pidBindingStore.evictStale for stale individual bindings', () => {
      const session = store.getOrCreateSession('s-1')
      session.lastUserMessageAt = nowMs() // keep session alive
      // But bind a pid whose own `ts` is far in the past
      pidStore.set(process.pid, session, 0)
      expect(pidStore.has(process.pid)).toBe(true)
      store.evictStaleSessions()
      // Session stays (lastUserMessageAt is now), pid is dropped by the
      // own-`ts` prune.
      expect(store.getSession('s-1')).toBeDefined()
      expect(pidStore.has(process.pid)).toBe(false)
    })

    it('reads sessionTtlMs lazily so livePatch takes effect without re-register', () => {
      const session = store.getOrCreateSession('s-1')
      session.lastUserMessageAt = 1000
      // Tighten the TTL to 100ms — the sweep should now evict
      applicationConfig.sessionTtlMs = 100
      store.evictStaleSessions()
      expect(store.getSession('s-1')).toBeUndefined()
    })
  })

  describe('pid binding surface', () => {
    it('bindPidToSession → resolveSessionByPid round-trip', () => {
      const session = store.getOrCreateSession('s-1', makeAgent())
      store.bindPidToSession(process.pid, session)
      expect(store.resolveSessionByPid(process.pid)).toEqual({
        sessionId: 's-1',
        runId: 's-1',
        agentId: 'agent-1',
      })
    })

    it('resolveSessionByPid returns undefined for unknown pids', () => {
      expect(store.resolveSessionByPid(99999)).toBeUndefined()
    })

    it('resolveHttpSessionByPid delegates to resolveSessionByPid', () => {
      const session = store.getOrCreateSession('s-1', makeAgent())
      store.bindPidToSession(42, session)
      expect(store.resolveHttpSessionByPid(42)).toEqual({
        sessionId: 's-1',
        runId: 's-1',
        agentId: 'agent-1',
      })
    })

    it('bindChildPidToSession is a no-op when the sessionId is unknown', () => {
      store.bindChildPidToSession(process.pid, 'does-not-exist')
      expect(store.resolveSessionByPid(process.pid)).toBeUndefined()
    })

    it('bindChildPidToSession looks up the session in the cache, then binds the pid', () => {
      store.getOrCreateSession('s-1', makeAgent())
      store.bindChildPidToSession(process.pid, 's-1')
      expect(store.resolveSessionByPid(process.pid)).toEqual({
        sessionId: 's-1',
        runId: 's-1',
        agentId: 'agent-1',
      })
    })
  })

  describe('mostRecentSession pointer', () => {
    it('starts undefined', () => {
      expect(store.resolveMostRecentSessionForRuntime()).toBeUndefined()
    })

    it('setMostRecentSession + resolveMostRecentSessionForRuntime round-trip', () => {
      store.setMostRecentSession({
        sessionId: 's-1',
        runId: 'r-1',
        agentId: 'a-1',
        taskId: 't-1',
        turnId: 'r-1',
      })
      expect(store.resolveMostRecentSessionForRuntime()).toEqual({
        sessionId: 's-1',
        runId: 'r-1',
        agentId: 'a-1',
        taskId: 't-1',
        turnId: 'r-1',
      })
    })

    it('returns a defensive copy (mutating the resolved shape does not mutate the pointer)', () => {
      store.setMostRecentSession({
        sessionId: 's-1',
        runId: 'r-1',
        taskId: 't-1',
        turnId: 'r-1',
      })
      const resolved = store.resolveMostRecentSessionForRuntime()
      resolved!.sessionId = 'mutated'
      expect(store.resolveMostRecentSessionForRuntime()?.sessionId).toBe('s-1')
    })
  })

  describe('resolveActiveSessionId', () => {
    it('returns mostRecentSession.sessionId when set', () => {
      store.setMostRecentSession({
        sessionId: 's-most-recent',
        runId: 'r-most-recent',
      })
      // Even when an older session has a fresh user message, the most-
      // recent tool-call session wins.
      const old = store.getOrCreateSession('s-old')
      old.lastUserMessageAt = nowMs()
      expect(store.resolveActiveSessionId()).toBe('s-most-recent')
    })

    it('falls back to the freshest user-message session when no mostRecentSession', () => {
      const old = store.getOrCreateSession('s-old')
      old.lastUserMessageAt = nowMs() - 1000
      const fresh = store.getOrCreateSession('s-fresh')
      fresh.lastUserMessageAt = nowMs()
      expect(store.resolveActiveSessionId()).toBe('s-fresh')
    })

    it('returns "__unknown__" when no session has any signal', () => {
      expect(store.resolveActiveSessionId()).toBe('__unknown__')
    })

    it('mostRecentSession.sessionId wins even when the session is not in the map', () => {
      // The pre-spawn RuntimeHook correlation uses mostRecentSession
      // verbatim — by design, the spawned child may outlive the session
      // eviction and the pre-execute still has to attribute the spawn
      // back to the agent that issued the tool call. The map-membership
      // check is intentionally not performed here.
      store.setMostRecentSession({
        sessionId: 's-not-in-map',
        runId: 'r-not-in-map',
      })
      expect(store.resolveActiveSessionId()).toBe('s-not-in-map')
    })
  })

  describe('pickRecentSession', () => {
    it('returns the only live session when exactly one exists', () => {
      const session = store.getOrCreateSession('s-1')
      expect(store.pickRecentSession(undefined)).toBe(session)
    })

    it('returns an empty stub when multiple sessions exist and no actor is given', () => {
      store.getOrCreateSession('s-1')
      store.getOrCreateSession('s-2')
      const stub = store.pickRecentSession(undefined)
      expect(stub.sessionId).toBe('')
      expect(stub.runId).toBe('')
      expect(stub.previousActions).toEqual([])
    })

    it('returns the matching session when the actor carries its session id', () => {
      store.getOrCreateSession('s-1')
      const s2 = store.getOrCreateSession('s-2')
      const actor = { agent: { session: { header: { id: 's-2' } } } }
      expect(store.pickRecentSession(actor)).toBe(s2)
    })

    it('returns an empty stub when the actor carries an unknown session id', () => {
      store.getOrCreateSession('s-1')
      store.getOrCreateSession('s-2')
      const actor = { agent: { session: { header: { id: 's-unknown' } } } }
      expect(store.pickRecentSession(actor).sessionId).toBe('')
    })
  })

  describe('clearAll', () => {
    it('wipes sessions, recentUserMessages, and mostRecentSession', () => {
      store.getOrCreateSession('s-1')
      store.getRecentUserMessages().set('s-1', { prompt: 'hi', timestamp: 1 })
      store.setMostRecentSession({ sessionId: 's-1', runId: 'r-1' })
      store.clearAll()
      expect(store.getSessions().size).toBe(0)
      expect(store.getRecentUserMessages().size).toBe(0)
      expect(store.resolveMostRecentSessionForRuntime()).toBeUndefined()
    })
  })
})