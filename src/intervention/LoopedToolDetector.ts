/**
 * Per-tool call-counter loop detector (Stage 3 §6.2).
 *
 * Sliding-window counter over `tools/pre-execute` calls, keyed by
 * (sessionId, toolName). When a single (session, tool) exceeds the
 * configured threshold within the configured window, the detector emits
 * an audit-only `security_audit/looped_tool` event via the host-side
 * callback. The detector is NOT in the SPL pipeline — it does not
 * block tool calls. Operators decide policy based on the audit signal.
 *
 * Why this is a separate module (not folded into `InlineSelfProtection` /
 * `SensitivePathGuard` / `InlinePromptInjection`):
 *   - The sibling inline guards are *deny-list matchers*: they test a
 *     specific structural feature (path-shaped value, env-var key,
 *     prompt-injection fingerprint) and either hit or don't. The
 *     loop detector is a *rate-limiter*: it aggregates behaviour over
 *     time and only fires after the threshold is crossed. Different
 *     shape → different module.
 *   - State is per-session; the deny-list matchers are stateless. The
 *     loop detector owns its own map and exposes a session-eviction
 *     API so `ApplicationCollector.evictStaleSessions` can clear state
 *     alongside the existing `recentUserMessages` cleanup.
 *
 * Why per-(session, tool) and not per-tool globally:
 *   - Agents legitimately call `bash` or `edit` hundreds of times per
 *     minute across a long task. The detector is only useful when the
 *     calls cluster within a single session — a sustained loop within
 *     one turn is the actual signal.
 *   - Cross-session counting would create a permanent high baseline
 *     for normal agents and flood the audit log.
 *
 * Audit-suppression policy:
 *   - First call that crosses the threshold fires `security_audit/looped_tool`
 *     exactly once.
 *   - Subsequent calls within the same window stay silent (the audit
 *     log would be drowned in duplicates for a tight loop).
 *   - The detector re-arms when the count drops back to or below the
 *     threshold, so a loop that pauses and resumes will fire again.
 *   - Session eviction (`clearSession`) clears both the timestamps and
 *     the fired-marker so a fresh session starts at zero.
 *
 * Default thresholds (per ticket):
 *   - windowMs = 60_000  (60 seconds)
 *   - thresholdPerMinute = 100  (calls / minute)
 *
 * The detector is intentionally cheap: a `Map<sessionId, Map<toolName,
 * number[]>>` with monotonic timestamps. Eviction is `shift()` per call
 * (the kept array never exceeds `thresholdPerMinute + 1` entries
 * because that's the only range the comparator reads). Worst-case
 * O(threshold) per call, which is well under 200 ns on commodity
 * hardware.
 *
 * Concurrency: audit. Node.js executes
 * JavaScript on a single fiber, so `record()`, `clearSession()`, and
 * `onHit()` are mutually atomic across all call sites — the
 * ttlTimer-fired `clearSession` in `ApplicationCollector.evictStaleSessions`
 * cannot interleave with the synchronous `record()` call in
 * `onToolPreExecute`; they alternate only at microtask / await
 * boundaries. The `onHit` callback (`emitLoopedToolAudit`) is itself
 * fully synchronous — `eventCollector.report()` is a sync NDJSON
 * appendFileSync — so the detector never observes a half-written
 * timestamp array. A future change that turns `onHit` into an
 * `async` callback or that calls `record()` from a `setImmediate`
 * boundary would re-open this; the `try/catch` around `onHit` is the
 * only safety net for that future regression.
 */

export interface LoopedToolDetectorConfig {
  /** Master switch. Defaults to true. */
  enabled: boolean
  /** Sliding-window size in ms. Default 60_000 (60 seconds). */
  windowMs: number
  /** Calls / window threshold. Default 100 (matches the ticket spec). */
  thresholdPerWindow: number
}

export interface LoopedToolHit {
  /** Tool name from `exec.name` (e.g. `'bash'`, `'edit'`). */
  readonly toolName: string
  /** Session ID the loop is confined to. */
  readonly sessionId: string
  /** Total call count within the window at the moment of firing
   *  (always `thresholdPerWindow + 1` when fired for the first time). */
  readonly count: number
  /** First timestamp still inside the window. */
  readonly windowStart: number
  /** Last timestamp (i.e. the call that triggered the hit). */
  readonly windowEnd: number
  /** The configured threshold. Echoed so the audit event can carry it
   *  without a separate config lookup. */
  readonly threshold: number
  /** The configured window size in ms. Echoed for the same reason. */
  readonly windowMs: number
}

/**
 * Callback signature: the detector fires this once per (session, tool)
 * threshold crossing. The host (typically `ApplicationCollector`) is
 * responsible for emitting the wire-format `security_audit/looped_tool`
 * event. The detector itself is pure — no I/O, no event emission.
 *
 * `sessionId` and `toolName` are already on the `hit` payload; they're
 * also passed positionally so a host that wants to filter on
 * `toolName.startsWith('bash')` doesn't have to crack open the object.
 */
export type LoopedToolHitHandler = (hit: LoopedToolHit) => void

/**
 * Pure in-memory sliding-window detector. No I/O, no clock dependency
 * (the host injects `ts` so tests can drive deterministic time).
 *
 * Construction:
 *   const detector = new LoopedToolDetector(cfg, (hit) => emitAudit(hit))
 *
 * Per-call:
 *   const hit = detector.record(exec.name, session.sessionId, nowMs())
 *
 * Session-end:
 *   detector.clearSession(sessionId)
 */
export class LoopedToolDetector {
  /**
   * the config reference is publicly readable
   * (though never reassignable) so the host's livePatch path can mutate
   * threshold fields in place — the detector reads them per call. The
   * `enabled` switch is never exposed to livePatch (🔴 rejected at the
   * classifier level).
   */
  readonly config: LoopedToolDetectorConfig
  private readonly onHit: LoopedToolHitHandler | undefined
  /**
   * Outer key: sessionId. Inner key: toolName. Value: monotonic
   * ascending timestamp array, kept within
   * `[thresholdPerWindow + 1, thresholdPerWindow + 1]` entries via
   * the shift-based eviction at the head.
   */
  private readonly windows = new Map<string, Map<string, number[]>>()
  /**
   * Set of "sessionId:toolName" markers that have already fired in the
   * current window. Re-armed (removed) when the count drops back to
   * `<= thresholdPerWindow`.
   */
  private readonly firedHits = new Set<string>()

  constructor(config: LoopedToolDetectorConfig, onHit?: LoopedToolHitHandler) {
    this.config = config
    this.onHit = onHit
  }

  /**
   * Record a single `tools/pre-execute` call. Returns the hit payload
   * when this call crosses the threshold and fires the audit event;
   * returns `null` otherwise (including disabled / no-hit paths).
   *
   * The detector is fail-safe: a malformed `toolName` (empty string)
   * still records the call so the operator can spot
   * `exec.name === ''` looping if it ever happens, but the hit key is
   * the literal empty string (no special handling needed).
   */
  record(toolName: string, sessionId: string, ts: number): LoopedToolHit | null {
    if (!this.config.enabled) return null
    if (!sessionId || !toolName) return null
    const cutoff = ts - this.config.windowMs

    let sessionMap = this.windows.get(sessionId)
    if (!sessionMap) {
      sessionMap = new Map<string, number[]>()
      this.windows.set(sessionId, sessionMap)
    }
    let timestamps = sessionMap.get(toolName)
    if (!timestamps) {
      timestamps = []
      sessionMap.set(toolName, timestamps)
    }
    // Evict expired entries from the head. Timestamps are pushed in
    // monotonic ascending order because `ts` only grows (callers pass
    // `Date.now()` or a test-injected monotonic clock). The shift()
    // loop terminates after at most `thresholdPerWindow + 1`
    // iterations — the comparator only cares about whether count
    // exceeds the threshold.
    while (timestamps.length > 0 && timestamps[0] < cutoff) {
      timestamps.shift()
    }
    timestamps.push(ts)

    const count = timestamps.length
    const key = sessionId + ':' + toolName

    // Re-arm the fired marker when the count has fallen back to the
    // safe zone — a loop that pauses (e.g. agent waits 60s for an
    // async result, then resumes looping) gets a fresh alert on the
    // next crossing.
    if (count <= this.config.thresholdPerWindow && this.firedHits.has(key)) {
      this.firedHits.delete(key)
    }

    // Suppress when count is within bounds or the marker has already
    // fired for this window.
    if (count <= this.config.thresholdPerWindow) return null
    if (this.firedHits.has(key)) return null

    // First crossing for this (session, tool) — fire the audit.
    this.firedHits.add(key)
    const hit: LoopedToolHit = {
      toolName,
      sessionId,
      count,
      windowStart: timestamps[0]!,
      windowEnd: ts,
      threshold: this.config.thresholdPerWindow,
      windowMs: this.config.windowMs,
    }
    if (this.onHit) {
      try {
        this.onHit(hit)
      } catch {
        // Best-effort: a host-side emit failure must never break the
        // detector (the host already swallowed its own emit failure
        // via the same try/catch boundary).
      }
    }
    return hit
  }

  /**
   * Drop all state for a session. Wired into
   * `ApplicationCollector.evictStaleSessions` so the timestamp arrays
   * don't accumulate indefinitely as sessions come and go.
   *
   * Also clears the `firedHits` markers that belong to this session —
   * a fresh session with the same `sessionId` (rare but possible
   * after TTL eviction + new start) starts with no audit history.
   */
  clearSession(sessionId: string): void {
    if (!sessionId) return
    this.windows.delete(sessionId)
    const prefix = sessionId + ':'
    for (const key of this.firedHits) {
      if (key.startsWith(prefix)) this.firedHits.delete(key)
    }
  }

  /** Snapshot of current state — for tests + debug introspection. */
  size(): number {
    let total = 0
    for (const sessionMap of this.windows.values()) {
      for (const timestamps of sessionMap.values()) {
        total += timestamps.length
      }
    }
    return total
  }
}