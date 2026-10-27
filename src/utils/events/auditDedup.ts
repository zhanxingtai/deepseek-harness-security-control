/**
 * Sliding-window content dedup for `security_audit` emissions.
 *
 * Motivation (2026-10-27, real-data analysis of security-events.jsonl):
 * 268 of 326 security_audit rows were `policy/modify success` heartbeats
 * for the same policy file — the PolicyWatcher re-fires on every fs.watch
 * event and the 30 s reload poll, and the bootstrap `onReloaded` emitter
 * wrote one audit row per reload even when the rule-set fingerprint was
 * unchanged. A 10 s window held 12 identical rows.
 *
 * Contract:
 *   - Keyed by caller-supplied `key` (e.g. `policy|${policyPath}`).
 *   - Within the window, an emission whose `contentHash` EQUALS the last
 *     emitted hash for the key is SUPPRESSED and merged into bookkeeping
 *     (count / firstTs / lastTs). A different hash ALWAYS emits
 *     immediately and resets the window — dedup never merges distinct
 *     content.
 *   - Window expiry alone does NOT flush an aggregate row: a suppressed
 *     burst contributes zero audit rows. Bookkeeping lands in the debug
 *     log (`audit_dedup` phase) at window end so operators can still see
 *     how many rows were coalesced. Single-hit windows (nothing
 *     suppressed) produce no bookkeeping at all.
 *   - `windowMs` is read through an accessor so livePatch hot-updates are
 *     picked up on the next emission. A windowMs of 0 disables dedup
 *     (everything emits).
 *
 * Timers are `unref`'d so a pending flush never holds the host process
 * open.
 */

export interface AuditDedupWindow {
  readonly key: string
  readonly count: number
  readonly firstTs: number
  readonly lastTs: number
}

export interface AuditDedupDeps {
  /** Hot accessor for the configured window (ms). 0 = disabled. */
  windowMs: () => number
  /** Sink for window-end bookkeeping. Defaults to silent. */
  onFlush?: (window: AuditDedupWindow, suppressed: number) => void
  /** Clock injection (tests). Defaults to Date.now. */
  now?: () => number
}

interface DedupEntry {
  hash: string
  firstTs: number
  lastTs: number
  /** Rows suppressed since the last EMIT (not since window start). */
  suppressed: number
  timer?: NodeJS.Timeout
}

export class AuditDeduper {
  private readonly deps: AuditDedupDeps
  private readonly entries = new Map<string, DedupEntry>()

  constructor(deps: AuditDedupDeps) {
    this.deps = deps
  }

  /**
   * Decide whether an emission with `contentHash` under `key` should be
   * written to the audit stream. Returns true = emit, false = suppressed
   * (merged into the open window's bookkeeping).
   */
  shouldEmit(key: string, contentHash: string): boolean {
    const windowMs = this.deps.windowMs()
    if (windowMs <= 0) return true
    const now = this.deps.now?.() ?? Date.now()
    const entry = this.entries.get(key)
    if (entry && entry.hash === contentHash && now - entry.lastTs <= windowMs) {
      // Same content inside the window — swallow the duplicate.
      entry.suppressed += 1
      entry.lastTs = now
      this.armTimer(key, entry, windowMs)
      return false
    }
    // New content (or window expired / first sighting): emit. A
    // previously-open window with suppressed duplicates leaves its
    // bookkeeping to its own timer — nothing is lost.
    if (entry?.timer) clearTimeout(entry.timer)
    this.entries.set(key, { hash: contentHash, firstTs: now, lastTs: now, suppressed: 0 })
    return true
  }

  /**
   * Number of rows currently suppressed in the open window for `key`
   * (test surface).
   */
  suppressedCount(key: string): number {
    return this.entries.get(key)?.suppressed ?? 0
  }

  /** Drop all windows and cancel pending flushes (shutdown / tests). */
  clear(): void {
    for (const entry of this.entries.values()) {
      if (entry.timer) clearTimeout(entry.timer)
    }
    this.entries.clear()
  }

  private armTimer(key: string, entry: DedupEntry, windowMs: number): void {
    if (!this.deps.onFlush) return
    if (entry.timer) clearTimeout(entry.timer)
    entry.timer = setTimeout(() => {
      entry.timer = undefined
      // The timer is re-armed on every suppression, so firing means the
      // window has been quiet for windowMs. A firing timer always belongs
      // to the current entry (emission resets clearTimeout the old one).
      if (entry.suppressed > 0) {
        const window: AuditDedupWindow = {
          key,
          count: entry.suppressed + 1,
          firstTs: entry.firstTs,
          lastTs: entry.lastTs,
        }
        const suppressed = entry.suppressed
        // Reset the counters so a continued burst in a fresh window starts
        // a new bookkeeping span instead of double-counting.
        entry.suppressed = 0
        entry.firstTs = entry.lastTs
        this.deps.onFlush!(window, suppressed)
      }
    }, windowMs)
    entry.timer.unref?.()
  }
}
