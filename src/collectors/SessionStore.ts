/**
 * SessionStore — session-state container.
 *
 * Owns:
 *   - the `sessions` Map<sessionId, SessionContext> + lifecycle
 *   - the `recentUserMessages` Map (last user prompt per session, used
 *     by the token-usage detector's session attribution)
 *   - the `mostRecentSession` pointer (set on every `tools/pre-execute`,
 *     read by `RuntimeHook` to correlate spawns that lack the `exec`
 *     reference)
 *   - the TTL-driven `evictStaleSessions` sweep, which cascades into
 *     `PidBindingStore` (drop bindings whose owning session aged out)
 *     and into `LoopedToolDetector` / `TokenUsageDetector` (drop their
 *     per-session sliding-window state)
 *   - the public pid↔session binding surface
 *     (`bindPidToSession`, `bindChildPidToSession`, `resolveSessionByPid`,
 *     `resolveHttpSessionByPid`)
 *
 * Why extract this and not the rest of the session state:
 *   - The session lifecycle is the most-coupled-with-pure-data chunk
 *     of the god class. `getOrCreateSession` + the TTL sweep +
 *     `bindPidToSession` are three side-effect-free primitives that
 *     form a clean API. The handlers (`onToolPreExecute` /
 *     `onAgentPreStep` / `onAgentSessionStart`) read + write the
 *     session map but do not OWN its lifecycle — they call the store
 *     and continue. Splitting the data from the handlers makes the
 *     mutation contract auditable in one place.
 *   - The detectors (`LoopedToolDetector`, `TokenUsageDetector`) plug
 *     into `evictStaleSessions` via the `clearSession` callback. The
 *     dependency is one-directional (host → store → detector) which
 *     keeps the test surface small.
 *   - The remaining ApplicationCollector surface (tool pipeline, message
 *     pipeline, fs pipeline) reads `sessions` + `mostRecentSession` +
 *     `recentUserMessages` via accessor methods on the store, so the
 *     migration is mechanical (the field reads stay on the host, but
 *     they route through `this.sessionStore.getSession(...)` /
 *     `this.sessionStore.setMostRecentSession(...)`).
 *
 * Public API surface (consumed by ApplicationCollector + tests):
 *   - `getOrCreateSession(sessionId, agent?)` — build or fetch a
 *     SessionContext (stamps sessionStartTs on first creation, populates
 *     blockedCalls + pendingToolStarts maps lazily)
 *   - `evictStaleSessions()` — TTL sweep; returns when the timer fires
 *   - `bindPidToSession(pid, session)` — defense-in-depth PID binding
 *     (defensive cap + invalid-PID guard live in PidBindingStore)
 *   - `bindChildPidToSession(pid, sessionId)` — typed convenience for
 *     `RuntimeHook` after the real child PID is observed
 *   - `resolveSessionByPid(pid)` — pid → session lookup
 *   - `resolveHttpSessionByPid(pid)` — typed convenience for
 *     `NetworkHttpCollector`
 *   - `resolveMostRecentSessionForRuntime()` — `RuntimeHook` calls this
 *     inside its pre-spawn wrapper
 *   - `setMostRecentSession(ctx)` — set by `onToolPreExecute`
 *   - `resolveActiveSessionId()` — session attribution for the
 *     token-usage detector (most-recent tool-call session, else
 *     freshest user-message session, else `__unknown__`)
 *   - `pickRecentSession(sessions, actor)` — fs event session attribution
 *   - `getSessions()` / `getRecentUserMessages()` — read accessors
 *   - `sessions` — direct Map accessor for tests
 *     (`tests/ApplicationCollector.test.ts:826` mutates
 *     `lastUserMessageAt` via this path)
 *   - `clearAll()` — shutdown-time wipe
 */
import type { Agent } from '../types/external.js'
import type { RuntimeHookSessionContext } from '../intervention/InterventionEngine.js'
import type { SessionContext } from '../types/index.js'
import { nowMs } from '../utils/time.js'
import type { LoopedToolDetector } from '../intervention/LoopedToolDetector.js'
import type { TokenUsageDetector } from '../utils/tokenUsage.js'
import type { PidBindingStore } from './pidBindingStore.js'

/** Stats counter shared with the host `ApplicationCollector` so `getStats()`
 *  keeps reading one shape. The host owns the lifetime; we only mutate
 *  `sessionsTracked`. */
export interface SessionStoreStats {
  sessionsTracked: number
}

export interface SessionStoreOptions {
  /** Shared reference to the application-layer config so livePatch updates
   *  to `sessionTtlMs` take effect on the next sweep without a re-register.
   *  The store reads `config.sessionTtlMs` lazily at sweep time. */
  applicationConfig: { sessionTtlMs: number }
  /** Loop detector wired into the store so the TTL sweep can drop
   *  per-session sliding-window state. The detector is pure — the store
   *  is the only caller of `clearSession`. */
  loopedToolDetector: Pick<LoopedToolDetector, 'clearSession'>
  /** Token-usage detector wired into the store for the same reason. */
  tokenUsageDetector: Pick<TokenUsageDetector, 'clearSession'>
  /** PID binding store wired into the store so the TTL sweep can cascade
   * prune bindings whose owning session aged out (orphan-pid fix). */
  pidBindingStore: PidBindingStore
}

export class SessionStore {
  private readonly sessions = new Map<string, SessionContext>()
  /** last user prompt per session, used by the token-usage detector's
   *  session attribution (most-recent message fallback). */
  private readonly recentUserMessages = new Map<string, { prompt: string; timestamp: number }>()
  /** Session titles observed via the host `session/title` event BEFORE the
   *  session context exists in the store. Applied once on
   *  `getOrCreateSession`; entries carry the observation timestamp so the
   *  TTL sweep can prune titles for sessions that never materialize. */
  private readonly pendingSessionTitles = new Map<string, { title: string; ts: number }>()
  /** Most-recent `tools/pre-execute` session. The RuntimeHook wrapper at the
   * subprocess seam doesn't see the `exec` object, so it correlates spawns
   * to sessions via "the pre-execute that just fired". Safe under the
   * harness's single-threaded turn loop. */
  private mostRecentSession: RuntimeHookSessionContext | undefined
  private readonly stats: SessionStoreStats
  private readonly options: SessionStoreOptions

  constructor(stats: SessionStoreStats, options: SessionStoreOptions) {
    this.stats = stats
    this.options = options
  }

  /** Build a fresh `SessionContext` or return the cached one. Stamps
   *  `sessionStartTs` on first creation (preserved across rehydrations
   *  so `agent_stop.duration` reflects the whole session, not just the
   *  most recent re-entry). Populates `blockedCalls` + `pendingToolStarts`
   *  lazily so older callers that pre-date these maps don't crash. */
  getOrCreateSession(sessionId: string, agent?: Agent): SessionContext {
    let session = this.sessions.get(sessionId)
    if (!session) {
      session = {
        sessionId,
        runId: sessionId,
        agentId: agent?.id,
        previousActions: [],
        stepIndex: -1,
        messageIndex: -1,
        blockedCalls: new Map(),
      }
      this.sessions.set(sessionId, session)
      this.stats.sessionsTracked++
    }
    const pendingTitle = this.pendingSessionTitles.get(sessionId)
    if (pendingTitle !== undefined && !session.sessionTitle) {
      session.sessionTitle = pendingTitle.title
      this.pendingSessionTitles.delete(sessionId)
    }
    if (!session.blockedCalls) session.blockedCalls = new Map()
    if (!session.pendingToolStarts) session.pendingToolStarts = new Map()
    // Stamp the first-seen wall-clock once. Subsequent
    // rehydrations keep the original so `agent_stop.duration` reflects the
    // whole session, not just the most recent re-entry.
    if (session.sessionStartTs === undefined) session.sessionStartTs = nowMs()
    return session
  }

  /** TTL sweep. Drops sessions whose `lastUserMessageAt` is older than
   *  `config.sessionTtlMs`. Cascades into:
   *    - `PidBindingStore.evictBySessionId` for every evicted session
   * (closes the orphan-pid bug fixed)
   *    - `PidBindingStore.evictStale` for bindings whose own `ts` aged out
   *    - `LoopedToolDetector.clearSession` for every evicted session
   *    - `TokenUsageDetector.clearSession` for every evicted session
   *
   *  Reads `config.sessionTtlMs` lazily so livePatch updates to the TTL
   *  take effect on the next sweep (no re-register needed).
   *
   *  Public method because `tests/ApplicationCollector.test.ts:827,835,1043`
   *  drives it directly via `(collector as unknown as { evictStaleSessions: () => void }).evictStaleSessions()`.
   *  The store doesn't own the interval timer — the host does — so
   *  `evictStaleSessions` is the public primitive and the host wraps it
   *  in `setInterval`. */
  evictStaleSessions(): void {
    const cutoff = nowMs() - this.options.applicationConfig.sessionTtlMs
    // collect evicted sessionIds in this pass
    // so the second pass can prune their pid bindings without waiting for
    // each PID's own ts to age out (see below).
    const evictedSessionIds = new Set<string>()
    for (const [sessionId, context] of this.sessions.entries()) {
      if ((context.lastUserMessageAt ?? 0) < cutoff) {
        this.sessions.delete(sessionId)
        this.recentUserMessages.delete(sessionId)
        evictedSessionIds.add(sessionId)
        // Drop the per-session sliding-window state so the timestamp arrays +
        // fired-marker set don't grow unbounded as sessions come and go.
        this.options.loopedToolDetector.clearSession(sessionId)
        // Drop the token-usage sliding-window state alongside the loop
        // detector so sample arrays don't grow unbounded as sessions come
        // and go.
        this.options.tokenUsageDetector.clearSession(sessionId)
      }
    }
    // Prune queued titles whose session never materialized (or was evicted
    // above) — same TTL window as sessions so a title observed just before
    // its session's `agent/created` survives the sweep.
    for (const [sessionId, pending] of this.pendingSessionTitles.entries()) {
      if (pending.ts < cutoff) this.pendingSessionTitles.delete(sessionId)
    }
    // Prune pid bindings whose owning session was just evicted OR whose
    // own ts is past the cutoff. Without the evictedSessionIds branch a
    // session that bound many PIDs at start would leave orphan entries
    // until each PID's ts ages out individually — the pidSessionMap grows
    // with the cross-product of (session count × PIDs per session) instead
    // of just (session count × TTL window). Reverse lookup is O(n) over
    // the (typically small) pidSessionMap; acceptable for the ttlTimer
    // firing cadence.
    for (const sessionId of evictedSessionIds) {
      this.options.pidBindingStore.evictBySessionId(sessionId)
    }
    this.options.pidBindingStore.evictStale(cutoff)
  }

  /** Record a session title observed from the host `session/title` event
   *  (fallback / LLM / user rename — caller passes each emission through;
   *  the store keeps last-wins semantics because the harness only appends
   *  the event when the title actually changed). Applies to the live
   *  session context when one exists; otherwise queues in
   *  `pendingSessionTitles` for the session's first `getOrCreateSession`.
   *  No-ops on empty / non-string titles. */
  recordSessionTitle(sessionId: string, title: unknown): void {
    if (typeof title !== 'string' || title.length === 0) return
    const session = this.sessions.get(sessionId)
    if (session) {
      session.sessionTitle = title
      return
    }
    this.pendingSessionTitles.set(sessionId, { title, ts: nowMs() })
  }

  /** Record the most-recent `tools/pre-execute` session so RuntimeHook can
   *  correlate spawns that lack the `exec` reference. Captured BEFORE
   *  stepIndex++ in the host so the first pre-execute in a session is
   *  recorded. */
  setMostRecentSession(ctx: RuntimeHookSessionContext): void {
    this.mostRecentSession = ctx
  }

  /** `RuntimeHook` calls this inside its pre-spawn wrapper. The spawn seam
   *  doesn't carry the `exec` object, so the wrapper uses "the last
   *  pre-execute that fired" as the implicit correlation. The harness's
   *  tool dispatch is single-threaded within an agent turn, so this is
   *  safe — the spawn always follows its own pre-execute without another
   *  tool's pre-execute interleaving.
   *
   *  Returns `undefined` outside any active agent frame (e.g. harness
   *  bootstrap helpers). The wrapper treats `undefined` as "untracked
   *  spawn" and still emits the audit event without session metadata.
   *
   * forward taskId / turnId through to RuntimeHook so
   *  they end up stamped on every runtime_*_intent event. The shape
   *  already lives on `mostRecentSession` (set in onToolPreExecute). */
  resolveMostRecentSessionForRuntime(): RuntimeHookSessionContext | undefined {
    return this.mostRecentSession
      ? {
          sessionId: this.mostRecentSession.sessionId,
          runId: this.mostRecentSession.runId,
          agentId: this.mostRecentSession.agentId,
          taskId: this.mostRecentSession.taskId,
          turnId: this.mostRecentSession.turnId,
        }
      : undefined
  }

  /** Session key for the token-usage detector (see `onLlmStream` doc).
   *  Most-recent tool-call session first, else freshest user-message
   *  session, else `'__unknown__'`. */
  resolveActiveSessionId(): string {
    if (this.mostRecentSession?.sessionId) return this.mostRecentSession.sessionId
    let bestId: string | undefined
    let bestTs = -1
    for (const [sessionId, context] of this.sessions.entries()) {
      const ts = context.lastUserMessageAt ?? 0
      if (ts > bestTs) {
        bestTs = ts
        bestId = sessionId
      }
    }
    return bestId ?? '__unknown__'
  }

  /** Bind a pid to a session. Defensive guards (NaN / ≤ 1) and the
   *  LRU-by-`ts` cap enforcement live in `PidBindingStore.set`; the
   *  store is pure so the host-side call site is a one-liner. */
  bindPidToSession(pid: number, session: SessionContext): void {
    this.options.pidBindingStore.set(pid, session, nowMs())
  }

  /** Public binding entry used by `RuntimeHook` after it has observed
   *  the real child PID returned by `ctx.subprocess.spawn`. Looks the
   *  session up from the in-memory cache; no-op when the session has
   *  already been evicted. */
  bindChildPidToSession(pid: number, sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (!session) return
    this.bindPidToSession(pid, session)
  }

  /** pid → session lookup. Used by the system layer (and indirectly by
   *  `NetworkHttpCollector` via `resolveHttpSessionByPid`) to enrich
   *  events that were not stamped by the active Python binding. Returns
   *  `undefined` when the pid is not known to belong to any active
   *  agent session. */
  resolveSessionByPid(pid: number):
    | { sessionId: string; runId: string; agentId?: string }
    | undefined {
    const ctx = this.options.pidBindingStore.get(pid)
    if (!ctx) return undefined
    return { sessionId: ctx.sessionId, runId: ctx.runId, agentId: ctx.agentId }
  }

  /** Typed convenience for `NetworkHttpCollector`. Falls back to
   *  `resolveSessionByPid(process.pid)` when an outbound HTTP request
   *  is not running inside an AsyncLocalStorage context. */
  resolveHttpSessionByPid(pid: number):
    | { sessionId: string; runId: string; agentId?: string }
    | undefined {
    return this.resolveSessionByPid(pid)
  }

  /** Read accessor for `recentUserMessages`. Used by `onAgentPreStep`
   *  to record the most recent user prompt. Also exposed so the host
   *  can iterate for test fixtures; production callers go through the
   *  typed helpers. */
  getRecentUserMessages(): Map<string, { prompt: string; timestamp: number }> {
    return this.recentUserMessages
  }

  /** Read accessor for the sessions Map. Tests poke at this directly via
   *  `(collector as unknown as { sessions: Map<string, …> }).sessions`
   *  (see `tests/ApplicationCollector.test.ts:826,855,878,1039`). */
  getSessions(): Map<string, SessionContext> {
    return this.sessions
  }

  /** Read accessor for a single session. */
  getSession(sessionId: string): SessionContext | undefined {
    return this.sessions.get(sessionId)
  }

  /** Pick the session to attribute an fs/* event to when the harness does
   *  not provide one. fs/observed and fs/write-intent are emitted by
   *  tool-fs / tool-str-replace-editor outside any agent session frame,
   *  so we have to infer.
   *
   *  Rules (in order):
   *   1. If exactly one session is live, return it.
   *   2. If multiple sessions are live and exactly one matches the
   *      actor's `agent.session.header.id` (when the actor looks like
   *      a ToolExecution), return that one.
   *   3. Otherwise, return an empty stub so the event is still emitted
   *      (session_id will be undefined). Auditors can correlate via
   *      `target_key` + `tool_name`. */
  pickRecentSession(actor: object | undefined): SessionContext {
    if (this.sessions.size === 1) {
      return this.sessions.values().next().value as SessionContext
    }
    if (this.sessions.size > 1 && actor) {
      const candidate = (actor as { agent?: { session?: { header?: { id?: string } } } })?.agent?.session?.header?.id
      if (candidate && this.sessions.has(candidate)) {
        return this.sessions.get(candidate)!
      }
    }
    return { sessionId: '', runId: '', previousActions: [], stepIndex: -1, messageIndex: -1 }
  }

  /** Wipe all session state — called from `ApplicationCollector.shutdown`. */
  clearAll(): void {
    this.sessions.clear()
    this.recentUserMessages.clear()
    this.pendingSessionTitles.clear()
    this.mostRecentSession = undefined
  }
}