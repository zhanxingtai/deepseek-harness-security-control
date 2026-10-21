/**
 * GuidanceStateMachine — per-(session, policy, template) counter for
 * `context_adjust` decisions.
 *
 * The SPL `action.guidance` block carries `max_attempts` /
 * `escalate_threshold`; the engine consults this machine on every
 * `context_adjust` hit and, once the counter crosses the limit, flips
 * the decision to `escalate` so the platform surfaces a human-approval
 * request instead of looping on the same guidance.
 *
 * Why per-engine (not per-session, not per-process):
 *   - The state lives on the engine because the engine is the single
 *     owner of the policy lifecycle. A new session that triggers the
 *     same policy/template under a new `sessionId` is correctly
 *     counted separately (different key), so cross-session bleed is
 *     impossible.
 *   - Tests construct fresh engines, which keeps unit tests isolated
 *     without needing a global reset hook.
 *   - Per-process would mean a module-level singleton that survives
 *     `engine.shutdown()` and bleeds state across the test suite.
 *
 * TTL: each entry carries `firstSeenTs` / `lastSeenTs`; the caller can
 * `gc(maxAgeMs)` to evict stale entries (a per-engine `setInterval` is
 * not wired by design — the caller already owns an interval for policy
 * reload and can piggy-back).
 */

export interface GuidanceKey {
  sessionId: string
  policyId: string
  templateId?: string
}

export interface GuidanceState {
  count: number
  firstSeenTs: number
  lastSeenTs: number
}

export interface GuidanceStateMachineOptions {
  /** Default TTL applied to `gc()` when called without arguments. 1 hour. */
  ttlMs?: number
}

export interface GuidanceRecordLimits {
  maxAttempts?: number
  escalateThreshold?: number
}

export interface GuidanceRecordResult {
  state: GuidanceState
  shouldEscalate: boolean
}

export class GuidanceStateMachine {
  private readonly ttlMs: number
  private state = new Map<string, GuidanceState>()

  constructor(options: GuidanceStateMachineOptions = {}) {
    this.ttlMs = options.ttlMs ?? 60 * 60 * 1000
  }

  /**
   * Record a guidance hit. Increments the counter for the key (creating
   * it on first hit) and returns the new state plus a `shouldEscalate`
   * flag. `shouldEscalate` is true when the post-increment count has
   * reached `maxAttempts ?? escalateThreshold`; if neither limit is
   * set, escalation is never triggered.
   */
  record(key: GuidanceKey, limits: GuidanceRecordLimits): GuidanceRecordResult {
    const composite = this.keyOf(key)
    const now = Date.now()
    const existing = this.state.get(composite)
    const updated: GuidanceState = existing
      ? { count: existing.count + 1, firstSeenTs: existing.firstSeenTs, lastSeenTs: now }
      : { count: 1, firstSeenTs: now, lastSeenTs: now }
    this.state.set(composite, updated)

    const limit = limits.maxAttempts ?? limits.escalateThreshold
    const shouldEscalate = limit !== undefined ? updated.count >= limit : false

    return { state: updated, shouldEscalate }
  }

  /** Reset a single key (e.g., when a session ends). No-op if missing. */
  reset(key: GuidanceKey): void {
    this.state.delete(this.keyOf(key))
  }

  /** Reset everything (called on policy reload or engine shutdown). */
  resetAll(): void {
    this.state.clear()
  }

  /**
   * Evict entries whose `lastSeenTs` is older than `maxAgeMs`. Defaults
   * to the constructor-supplied TTL. Returns the number of entries
   * evicted (useful for tests / metrics).
   */
  gc(maxAgeMs: number = this.ttlMs): number {
    const cutoff = Date.now() - maxAgeMs
    let evicted = 0
    for (const [composite, s] of this.state) {
      if (s.lastSeenTs < cutoff) {
        this.state.delete(composite)
        evicted += 1
      }
    }
    return evicted
  }

  /** Inspection helper (tests only). */
  size(): number {
    return this.state.size
  }

  private keyOf(key: GuidanceKey): string {
    return `${key.sessionId}::${key.policyId}::${key.templateId ?? ''}`
  }
}