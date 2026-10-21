/**
 * OverviewCache —.
 *
 * `overview()` is the highest-traffic read in the security monitor UI:
 * the DSH Web settings page auto-refreshes it on a 5 s interval
 * (see `src/client/usePolling.ts`), and a cold render on a 50 MiB
 * NDJSON log takes 200–400 ms because the aggregate scan
 * (`scanOverviewAggregates`) is a full-file pass (`streamNdjson`).
 *
 * Without a cache, the operator sees the Overview numbers stutter
 * every 5 s; with a cache, the second and subsequent renders are
 * O(1). The cache sits BETWEEN the typert handler and the sink:
 *
 *     [client bridge] → overviewHandler(sink, engine, config)
 *                          └── OverviewCache.read(sink)
 *                                ├── cache HIT  → cached aggregates
 *                                └── cache MISS → scanOverviewAggregates (single pass)
 *
 * Cache key
 * ---------
 * Two-tier invalidation:
 *   1. **Freshness** — `(Date.now() - computedAt) < TTL_MS`; the TTL
 *      is the safety net. Even if every other invalidation path fails,
 *      counts are at most TTL_MS old.
 *   2. **Sink version** — `stats.flushed` from the sink. The sink
 *      increments `flushed` on every successful write (see
 *      `LocalNdjsonSink.writeLocalDirect`), so any new event that
 *      landed since the cache entry was built invalidates the cache
 *      on the very next read. This is the cheap, synchronous path.
 *
 * On rotation (`onRotate` callback from the sink) we also
 * invalidate explicitly — the size-cap rotation (or any other
 * file-deleting event) makes `stats.flushed` reset, and the TTL
 * alone would otherwise keep stale counts for up to TTL_MS.
 *
 * Concurrency
 * -----------
 * `inflight` promise dedupes concurrent misses. If two `overview()`
 * calls land back-to-back before the first one's `countAllBlocks`
 * scan finishes, the second waits on the same promise instead of
 * running a second full-file scan. The dedup is process-local
 * (no shared state); cross-process cache freshness is bounded by
 * the TTL.
 *
 * Why TTL = 5 s?
 * --------------
 * Matches the client's auto-refresh interval. Worst case: a new
 * block lands JUST AFTER a cache write; the client sees the old
 * count for one polling cycle (≤ 5 s) before the next read
 * recomputes. That's acceptable for an operator-visible aggregate.
 */
import type { LocalNdjsonSink } from '../collectors/LocalNdjsonSink.js'
import { scanOverviewAggregates, type OverviewAggregates } from './overview.js'

/** Cache freshness window — see module header. */
export const OVERVIEW_CACHE_TTL_MS = 5_000

export interface OverviewCacheEntry {
  /** When this entry was computed (ms since epoch). */
  computedAt: number
  /** `sink.getStats().flushed` at compute time. Bumped on every
   *  successful NDJSON write — the cheap invalidation sentinel. */
  flushedAtCompute: number
  /** Aggregates from `scanOverviewAggregates` at compute time. */
  aggregates: OverviewAggregates
}

export interface OverviewCacheRead {
  /** ALL parsed events in the file (metrics-page total). */
  totalCount: number
  blockCount: number
  last24hBlockCount: number
  /** 威胁事件计数(规则命中含 warn),与 block 计数同缓存。 */
  threatCount: number
  last24hThreatCount: number
  /** Metrics-page additions, cached alongside the
   *  block counts so a cache hit stays O(1) for the whole snapshot. */
  last24hTotalCount: number
  byLayer: Record<string, number>
  /** True when the read returned a cached entry; false on miss. */
  fromCache: boolean
}

export class OverviewCache {
  private entry: OverviewCacheEntry | null = null
  private inflight: Promise<OverviewCacheRead> | null = null

  /**
   * Read the cached block counts, computing on miss.
   *
   * Cache hit conditions (ALL must hold):
   *   - `entry !== null`
   *   - `Date.now() - entry.computedAt < TTL_MS`
   *   - `entry.flushedAtCompute === sink.getStats().flushed`
   *
   * On miss: synchronously start a single compute; concurrent
   * callers share the same `inflight` promise.
   */
  async read(sink: LocalNdjsonSink): Promise<OverviewCacheRead> {
    const now = Date.now()
    const currentFlushed = sink.getStats().flushed

    if (this.entry) {
      const fresh =
        now - this.entry.computedAt < OVERVIEW_CACHE_TTL_MS &&
        this.entry.flushedAtCompute === currentFlushed
      if (fresh) {
        return {
          ...this.entry.aggregates,
          fromCache: true,
        }
      }
    }

    if (this.inflight) {
      // Dedup hit on the inflight promise. Surface
      // `fromCache: true` so callers see the same semantics as a TTL
      // hit (a parallel caller did not actually pay for the scan;
      // it rode the first caller's inflight). The first caller (who
      // triggered the compute) still sees `fromCache: false` via the
      // `this.compute(sink)` path below.
      const inflight = this.inflight
      return inflight.then((result) => ({ ...result, fromCache: true }))
    }

    this.inflight = this.compute(sink).finally(() => {
      this.inflight = null
    })
    return this.inflight
  }

  /**
   * Force the next read to recompute. Wired to the sink's
   * `onRotate` callback so a file truncation (size cap, disk-low,
   * manual operator action) does not surface stale counts for up
   * to TTL_MS.
   */
  invalidate(): void {
    this.entry = null
  }

  private async compute(sink: LocalNdjsonSink): Promise<OverviewCacheRead> {
    const path = sink.getLocalOutputPath()
    const aggregates: OverviewAggregates = path
      ? await scanOverviewAggregates(sink)
      : { totalCount: 0, blockCount: 0, last24hBlockCount: 0, threatCount: 0, last24hThreatCount: 0, last24hTotalCount: 0, byLayer: {} }
    this.entry = {
      computedAt: Date.now(),
      flushedAtCompute: sink.getStats().flushed,
      aggregates,
    }
    return {
      ...aggregates,
      fromCache: false,
    }
  }
}