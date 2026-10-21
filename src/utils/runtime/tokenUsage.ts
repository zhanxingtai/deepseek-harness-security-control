/**
 * Per-session token-usage burst detector.
 *
 * Sliding-window baseline over `llm/stream` usage chunks, keyed by sessionId.
 * When a single call's token total exceeds `burstFactor` × the in-window
 * baseline, the detector emits an audit-only
 * `security_audit/anomalous_token_usage` event via the host-side callback.
 * The detector is NOT in the SPL pipeline — it does not block, throttle, or
 * modify the LLM stream. Operators decide policy based on the audit signal.
 *
 * Data source: the harness `llm/stream` Cordis waterfall
 * (the host LLM adapter) yields `StreamChunk`s; chunks with
 * `type === 'usage'` carry a `TokenUsage`
 * (`{ inputTokens, outputTokens, totalTokens? }`). `teeLlmStream()` below
 * wraps the downstream `AsyncIterable` so every chunk passes through
 * untouched while usage chunks are synchronously fed to `record()`.
 *
 * Baseline statistic — MEAN (not median), deliberately:
 *   - The learning floor is `minBaselineSamples` (default 5), so the window
 *     holds 5-10 samples at decision time. The median of 5 samples is the
 *     3rd order statistic — quantized to an actual sample value, so it
 *     over-fires when the middle sample happens to be small and under-fires
 *     once a large sample enters the median position.
 *   - Mean is smooth, O(n) without a sort, and for a ≥3× burst factor the
 *     classic outlier-sensitivity objection is bounded by the audit
 *     suppression policy below: a fired burst inflates the baseline, which
 *     suppresses duplicate alerts rather than causing them.
 *
 * Audit-suppression policy (mirrors `LoopedToolDetector`):
 *   - First call that crosses `burstFactor` fires exactly once.
 *   - Subsequent bursting calls stay silent until a call lands back below
 *     the factor (re-arm), so a sustained burst does not drown the audit
 *     log and a fresh burst after a calm call fires again.
 *   - Session eviction (`clearSession`) drops both samples and the
 *     fired-marker.
 *
 * Learning phase:
 *   - The first `minBaselineSamples` calls per session only populate the
 *     window — no ratio is computed, so a cold session cannot fire on its
 *     own early calls (ticket acceptance: 前几次调用只学习不告警).
 *
 * Default thresholds (per ticket):
 *   - windowMs = 60_000  (60 seconds)
 *   - burstFactor = 3    (≥3× baseline triggers)
 *   - minBaselineSamples = 5
 *
 * Fail-safety: non-positive / non-finite totals are skipped (a 0-token
 * usage chunk would drag the mean to zero and guarantee false bursts);
 * `totalTokens` missing falls back to `inputTokens + outputTokens`.
 */

import type { StreamChunk, TokenUsage } from '../../types/external.js'

export interface TokenUsageDetectorConfig {
  /** Master switch. Defaults to true. */
  enabled: boolean
  /** Sliding-window size in ms. Default 60_000 (60 seconds). */
  windowMs: number
  /** Baseline multiplier that constitutes a burst. Default 3 (≥3×). */
  burstFactor: number
  /** Calls that only learn (no ratio computed) before the first decision.
   *  Default 5 — ticket acceptance ("baseline 学习期 < 5 次调用"). */
  minBaselineSamples: number
}

/** Raw usage shape accepted by `record()` — matches harness `TokenUsage`. */
export interface TokenUsageSampleInput {
  inputTokens?: number
  outputTokens?: number
  totalTokens?: number
}

/** Normalized usage carried on the hit payload. */
export interface NormalizedTokenUsage {
  inputTokens: number
  outputTokens: number
  totalTokens: number
}

export interface TokenUsageHit {
  /** Session the burst is confined to. */
  readonly sessionId: string
  /** Timestamp of the bursting call. */
  readonly ts: number
  /** Normalized usage of the bursting call. */
  readonly usage: NormalizedTokenUsage
  /** In-window mean token total computed BEFORE this call was appended. */
  readonly baseline: number
  /** usage.totalTokens / baseline at fire time. */
  readonly ratio: number
  /** Configured burst factor. Echoed for the audit event. */
  readonly burstFactor: number
  /** In-window sample count at fire time (baseline size + 1). */
  readonly sampleCount: number
  /** Configured window size in ms. Echoed for the same reason. */
  readonly windowMs: number
}

export type TokenUsageHitHandler = (hit: TokenUsageHit) => void

/** Normalize a raw usage payload. Returns null when no meaningful total can
 *  be derived (non-numeric inputs, negative values, or an all-zero chunk).
 *  `totalTokens` falling back to `inputTokens + outputTokens` covers
 *  providers that only report the split counts. */
export function normalizeTokenUsage(
  usage: TokenUsageSampleInput,
): NormalizedTokenUsage | null {
  if (!usage || typeof usage !== 'object') return null
  let input = usage.inputTokens
  let output = usage.outputTokens
  let total = usage.totalTokens
  if (!isUsableCount(input)) input = undefined
  if (!isUsableCount(output)) output = undefined
  if (!isUsableCount(total)) total = undefined
  if (total === undefined && input !== undefined && output !== undefined) {
    total = input + output
  }
  // A zero-token chunk carries no burst signal and would poison the mean
  // baseline; skip it entirely.
  if (total === undefined || total <= 0) return null
  return {
    inputTokens: input ?? 0,
    outputTokens: output ?? 0,
    totalTokens: total,
  }
}

function isUsableCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

interface WindowSample {
  ts: number
  total: number
}

/**
 * Pure in-memory sliding-window detector. No I/O, no clock dependency
 * (the host injects `ts` so tests can drive deterministic time).
 *
 * Construction:
 *   const detector = new TokenUsageDetector(cfg, (hit) => emitAudit(hit))
 *
 * Per usage chunk:
 *   const hit = detector.record(sessionId, usage, nowMs())
 *
 * Session-end:
 *   detector.clearSession(sessionId)
 */
export class TokenUsageDetector {
  /**
   * the config reference is publicly readable
   * (though never reassignable) so the host's livePatch path can mutate
   * threshold fields in place — the detector reads them per sample. The
   * `enabled` switch is never exposed to livePatch (🔴 rejected at the
   * classifier level).
   */
  readonly config: TokenUsageDetectorConfig
  private readonly onHit: TokenUsageHitHandler | undefined
  /** sessionId → monotonic ascending (ts, total) samples inside the window. */
  private readonly windows = new Map<string, WindowSample[]>()
  /** sessionIds that have already fired in the current burst. Re-armed
   *  (removed) when a call lands back below the burst factor. */
  private readonly firedHits = new Set<string>()

  constructor(config: TokenUsageDetectorConfig, onHit?: TokenUsageHitHandler) {
    this.config = config
    this.onHit = onHit
  }

  /**
   * Record a single usage chunk for a session. Returns the hit payload when
   * this call crosses the burst factor; returns null otherwise (disabled,
   * learning phase, below factor, duplicate suppression, malformed input).
   */
  record(
    sessionId: string,
    usage: TokenUsageSampleInput,
    ts: number,
  ): TokenUsageHit | null {
    if (!this.config.enabled) return null
    if (!sessionId) return null
    const normalized = normalizeTokenUsage(usage)
    if (!normalized) return null
    const cutoff = ts - this.config.windowMs

    let samples = this.windows.get(sessionId)
    if (!samples) {
      samples = []
      this.windows.set(sessionId, samples)
    }
    // Evict expired entries from the head. Timestamps are pushed in
    // monotonic ascending order (callers pass `Date.now()` or a
    // test-injected monotonic clock).
    while (samples.length > 0 && samples[0]!.ts < cutoff) {
      samples.shift()
    }

    // Learning phase: the first `minBaselineSamples` calls only populate
    // the window so a cold session cannot fire on its own early calls.
    if (samples.length < this.config.minBaselineSamples) {
      samples.push({ ts, total: normalized.totalTokens })
      return null
    }

    // Baseline = in-window MEAN computed BEFORE the current call is
    // appended (the current call is the suspect, not part of its own
    // baseline). See the module header for the mean-vs-median rationale.
    let sum = 0
    for (const sample of samples) sum += sample.total
    const baseline = sum / samples.length
    samples.push({ ts, total: normalized.totalTokens })

    // A zero/empty baseline carries no ratio information — skip rather than
    // divide by zero (this can only happen if zero-total samples got in
    // before the positivity guard existed).
    if (baseline <= 0) return null

    const ratio = normalized.totalTokens / baseline

    // Re-arm when the burst subsides: a call back below the factor clears
    // the fired marker so the next burst fires fresh.
    if (ratio < this.config.burstFactor) {
      if (this.firedHits.has(sessionId)) this.firedHits.delete(sessionId)
      return null
    }
    if (this.firedHits.has(sessionId)) return null

    this.firedHits.add(sessionId)
    const hit: TokenUsageHit = {
      sessionId,
      ts,
      usage: normalized,
      baseline,
      ratio,
      burstFactor: this.config.burstFactor,
      sampleCount: samples.length,
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
   * `ApplicationCollector.evictStaleSessions` so sample arrays don't
   * accumulate indefinitely as sessions come and go.
   */
  clearSession(sessionId: string): void {
    if (!sessionId) return
    this.windows.delete(sessionId)
    this.firedHits.delete(sessionId)
  }

  /** Snapshot of current state — for tests + debug introspection. */
  size(): number {
    let total = 0
    for (const samples of this.windows.values()) total += samples.length
    return total
  }
}

/**
 * Tee wrapper for the `llm/stream` Cordis waterfall (ticket).
 *
 * Wraps the downstream `AsyncIterable<StreamChunk>` in an async generator
 * that yields every chunk unchanged (order, identity, completion) while
 * synchronously feeding `onUsage` for each `type === 'usage'` chunk. This
 * is the whole data tap — the LLM stream itself is never paused, buffered,
 * or modified.
 *
 * Fail-safety (invariant: never throw to the host):
 *   - An `onUsage` throw (e.g. a detector bug) is swallowed INSIDE the loop
 *     so the chunk is still yielded and the consumer never sees the error.
 *   - Errors thrown by the SOURCE stream propagate unchanged to the
 *     consumer — transparent passthrough; the harness sees exactly what it
 *     would have seen without the plugin.
 */
export async function* teeLlmStream(
  source: AsyncIterable<StreamChunk>,
  onUsage: (usage: TokenUsage) => void,
): AsyncIterable<StreamChunk> {
  for await (const chunk of source) {
    if (chunk && chunk.type === 'usage' && chunk.usage) {
      try {
        onUsage(chunk.usage)
      } catch {
        // Never break the LLM stream because the detector hiccuped.
      }
    }
    yield chunk
  }
}
