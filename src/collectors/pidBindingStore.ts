/**
 * PidBindingStore — pure data layer for `pid → session` cross-correlation.
 *
 * The store encapsulates:
 *   - the `pidSessionMap` (Map<number, PidSessionEntry>)
 *   - the `PID_SESSION_MAP_MAX_SIZE = 5000` defensive cap
 *   - TTL-driven stale eviction (called by `ApplicationCollector.evictStaleSessions`)
 *   - session-eviction cascade (called by `ApplicationCollector.evictStaleSessions`
 *     when a parent session has aged out)
 *
 * Why extract this and not the rest of the session state:
 *   - PidBindingStore is PURE: no Cordis events, no event-emission, no logger
 *     reads, no detector callbacks. The store only mutates its own map.
 *   - The TTL eviction + cap-enforcement logic was previously scattered
 *     across three private methods on ApplicationCollector
 *     (`evictStaleSessions`, `enforcePidSessionMapCap`, `bindPidToSession`).
 *     Co-locating the data + the accessors in one file makes the contract
 *     easier to reason about (defensive PID validation, LRU-by-`ts`
 *     eviction order, the cap-vs-TTL interaction).
 *   - The remaining session-state members (`sessions`,
 *     `recentUserMessages`, `pendingIntents`, `mostRecentSession`) are
 *     too intertwined with the handler-method emit logic to extract
 *     cleanly today — moving them into SessionStore would force every
 *     `onToolPreExecute` / `onAgentPreStep` / `onFsObserved` body to
 *     swap its field reads, with no behavior change beyond indirection.
 *     They stay on ApplicationCollector.
 *
 * The class is intentionally framework-free: no Cordis, no fs I/O,
 * no network. All it owns is `Map<number, PidSessionEntry>` + the
 * eviction primitives.
 *
 * Public API surface (consumed by ApplicationCollector):
 *   - `get(pid)` — read accessor used by `resolveSessionByPid` /
 *     `resolveHttpSessionByPid`
 *   - `set(pid, session, ts)` — bind a pid → session; rejected for
 *     obviously-invalid PIDs (NaN, ≤ 1 — kernel/init sentinels)
 *   - `evictStale(cutoff)` — TTL prune; called once per session-eviction sweep
 *   - `evictBySessionId(sessionId)` — cascade prune; called when the
 *     owning session has aged out (so its descendant bindings do not
 *     linger waiting for their own `ts` to age out)
 *   - `clear()` — shutdown-time wipe
 *   - `size` — read-only stat for tests + observability
 *
 * The defensive cap (5 000 entries) is enforced lazily inside `set()`:
 * every new binding triggers `enforceCap()` which sorts the map by `ts`
 * and force-evicts the oldest entries — the burst-defence against binding
 * storms that outpace the TTL sweep.
 */

/**
 * Per-pid cross-correlation record. `ts` is the bind wall-clock and is
 * the sort key for the LRU cap eviction.
 */
export interface PidSessionEntry {
  sessionId: string
  runId: string
  agentId?: string
  ts: number
}

/** Public read shape — drops `ts` so callers cannot mutate the eviction key. */
export interface PidSessionBinding {
  sessionId: string
  runId: string
  agentId?: string
}

export class PidBindingStore {
  private readonly entries = new Map<number, PidSessionEntry>()
  /** Defensive cap. Exposed statically so the test suite can seed
   *  the map to exactly `MAX_SIZE` and exercise the force-evict path. */
  static readonly MAX_SIZE = 5000

  /** Look up a pid's session binding. `undefined` when the pid is unknown. */
  get(pid: number): PidSessionBinding | undefined {
    const entry = this.entries.get(pid)
    if (!entry) return undefined
    return {
      sessionId: entry.sessionId,
      runId: entry.runId,
      agentId: entry.agentId,
    }
  }

  /** Presence check — exposed for tests + callers that want to distinguish
   *  "unknown pid" from "known pid bound to an empty session". */
  has(pid: number): boolean {
    return this.entries.has(pid)
  }

  /**
   * Test-only helper — overwrite the bind time of an existing entry. Used
   * by `tests/ApplicationCollector.test.ts > evicts stale pid bindings` to
   * artificially age a binding past the TTL window without waiting the
   * real `sessionTtlMs` (default 15 min). Documented as `@internal` so
   * production callers do not mutate `ts` directly.
   */
  setTs(pid: number, ts: number): void {
    const entry = this.entries.get(pid)
    if (!entry) return
    entry.ts = ts
  }

  /** Read-only size for tests + observability. */
  get size(): number {
    return this.entries.size
  }

  /**
   * Bind a pid to a session. Rejects obviously-invalid PIDs (NaN, ≤ 1)
   * — kernel/init sentinels and Windows spawn-failure sentinels would
   * otherwise pollute the resolver with cache hits that always return
   * an unrelated session. The most-recent assignment wins (unconditional
   * `set` — a forked-at-T process cannot have moved sessions between
   * the fork and the resolve).
   */
  set(pid: number, session: { sessionId: string; runId: string; agentId?: string }, ts: number): void {
    if (!Number.isFinite(pid) || pid <= 1) return
    this.enforceCap()
    this.entries.set(pid, {
      sessionId: session.sessionId,
      runId: session.runId,
      agentId: session.agentId,
      ts,
    })
  }

  /**
   * TTL prune: drop entries whose `ts` is older than `cutoff`. Returns
   * the count of evicted entries (mostly for tests).
   */
  evictStale(cutoff: number): number {
    let evicted = 0
    for (const [pid, entry] of this.entries) {
      if (entry.ts < cutoff) {
        this.entries.delete(pid)
        evicted += 1
      }
    }
    return evicted
  }

  /**
   * Cascade prune: drop every entry belonging to `sessionId`. Called when
   * a parent session has aged out so its descendant bindings do not
   * linger waiting for their own `ts` to age out individually.
   */
  evictBySessionId(sessionId: string): number {
    let evicted = 0
    for (const [pid, entry] of this.entries) {
      if (entry.sessionId === sessionId) {
        this.entries.delete(pid)
        evicted += 1
      }
    }
    return evicted
  }

  /**
   * Defensive cap: when the map crosses `MAX_SIZE`, evict the
   * oldest-by-`ts` entries until back at the cap. Runs on every `set()`
   * call but is a no-op in steady state (the cap is generous — 5 000
   * entries covers a dsh session that forks thousands of child tools
   * over its lifetime while keeping memory well under 1 MiB).
   *
   * Sorting is O(n log n) but only runs when the cap is exceeded —
   * a once-per-many-binds event. We collect the eviction list first,
   * then delete, so the order stays deterministic (oldest first) and
   * we don't rely on insertion-order tie-break.
   */
  private enforceCap(): void {
    if (this.entries.size < PidBindingStore.MAX_SIZE) return
    const sorted = Array.from(this.entries.entries()).sort((a, b) => a[1].ts - b[1].ts)
    const toEvict = sorted.length - PidBindingStore.MAX_SIZE + 1
    for (let i = 0; i < toEvict; i += 1) {
      this.entries.delete(sorted[i]![0])
    }
  }

  /** Wipe all entries — called from `ApplicationCollector.shutdown`. */
  clear(): void {
    this.entries.clear()
  }
}