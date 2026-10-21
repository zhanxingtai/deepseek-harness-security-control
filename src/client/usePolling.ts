/**
 * Shared polling context for the DSH Web settings page.
 *
 * Background
 * ----------
 * The four data tabs (Metrics / Event Stream / Policy Hits / Config)
 * all need periodic background refresh against the host's Typert
 * Remote namespace. The shared context owns ONE timer and ONE
 * registry; tabs register a refresh callback and a per-tab interval
 * via `polling.register(id, fn, intervalMs)` and the central tick
 * fan-outs callbacks based on the registered interval and the
 * currently-active tab.
 *
 * Design contract
 * ---------------
 *  - `activeTab` is the SOLE gate for whether a callback fires.
 *    Each registered `id` is namespaced `'<tab>:<purpose>'`; the
 *    tab prefix matches `activeTab` and the callback only fires
 *    when the operator is actually viewing that tab. The Config
 *    tab is the exception (auto-refresh OFF by default — the data
 *    is policy-scoped, not event-scoped), so its registrations use
 *    `whileActive: false` and never fire from polling; it relies on
 *    its own reload button + draft-save flow.
 *  - Concurrent overlapping ticks for the SAME id are deduped via
 *    an inflight-promise map. If a 3 s interval fires while the
 *    last fetch is still in flight, the new tick is dropped (not
 *    re-queued) — back-pressure rather than burst. The cancelled
 *    flag pattern at the tab layer still protects against late
 *    resolutions after unmount.
 *  - `trigger(id)` allows synchronous manual fire (used by the
 *    "Reload policy" button on Overview to refresh counts after
 *    a `bridge.reload()` success).
 *
 * Why a single timer and not one timer per registration?
 * ------------------------------------------------------
 * React effect cleanup hygiene: `clearInterval` must be called from
 * every `useEffect` that owns a timer. A single timer owned by the
 * section component, with a registry of callbacks, lets tabs add
 * and remove callbacks without owning timers. Tab switch unmounts
 * the tab component but the polling context lives on the section —
 * no remount churn, no missed tick during a fast back-and-forth
 * switch.
 */
import { useEffect } from 'react'

export interface PollingEntry {
  fn: () => void | Promise<void>
  /** Per-entry interval. The central tick decides eligibility based
   *  on `Date.now() - lastFire`; if the entry was never fired (lastFire
   *  is 0) it is considered eligible immediately on the first tick. */
  intervalMs: number
  /** When true (default), the entry only fires while `activeTab`
   *  matches the id's `'<tab>:<purpose>'` prefix. The Config tab
   *  uses `whileActive: false` to opt out of auto-refresh. */
  whileActive: boolean
  /** Last fire timestamp (ms). 0 means never fired. */
  lastFire: number
}

export interface PollingContext {
  /** Currently-active tab id (the section's `active` state). The
   *  section component owns this — it sets it whenever the operator
   *  switches tabs. Reads happen on every tick; the getter returns
   *  the latest value. */
  readonly activeTab: string
  setActiveTab(tab: string): void
  /**
   * Register a refresh callback under `id`. Returns a deregister
   * function the caller invokes on unmount.
   *
   * Re-registering under the same id REPLACES the previous entry
   * (used by RecentBlocks when the operator picks a new limit and
   * the registered fetch args change).
   */
  register(
    id: string,
    fn: () => void | Promise<void>,
    intervalMs: number,
    whileActive?: boolean,
  ): () => void
  /**
   * Synchronously fire the registered callback for `id`. Used by
   * manual reload actions (Reload policy button). The callback's
   * promise is returned so callers can `await` it; concurrent
   * overlap is deduped via the inflight map just like a tick fire.
   */
  trigger(id: string): Promise<void> | undefined
  /** Test-only escape hatch — number of entries currently registered. */
  size(): number
  /**
   * Fire every eligible entry as of `now` (ms) and return the fired
   * promises. This is the central-tick primitive: `usePolling` calls it
   * from its interval with `Date.now()`; unit tests call it with
   * synthetic timestamps. Eligibility = `whileActive` tab match +
   * interval boundary + not already inflight.
   */
  _tickForTest(now: number): Promise<void>[]
}

/** Build a fresh `PollingContext`. The section component owns ONE
 *  instance for its entire mount lifecycle. The instance is mutable
 *  (activeTab changes on every tab click) but its identity is stable
 *  across renders so registered callbacks survive. */
export function createPollingContext(): PollingContext {
  const registry = new Map<string, PollingEntry>()
  const inflight = new Map<string, Promise<void>>()
  let active = ''

  async function runEntry(id: string, entry: PollingEntry): Promise<void> {
    if (inflight.has(id)) return inflight.get(id)
    const p = Promise.resolve()
      .then(() => entry.fn())
      .finally(() => inflight.delete(id))
    inflight.set(id, p)
    return p
  }

  return {
    get activeTab(): string {
      return active
    },
    setActiveTab(tab: string): void {
      active = tab
    },
    register(id, fn, intervalMs, whileActive = true): () => void {
      const existing = registry.get(id)
      registry.set(id, {
        fn,
        intervalMs,
        whileActive,
        // Preserve previous fire timestamp on re-register so a fresh
        // interval boundary is not "now" if the user is just changing
        // a child arg (e.g. limit). Tests that want a fresh fire must
        // explicitly `trigger(id)`.
        lastFire: existing ? existing.lastFire : 0,
      })
      return () => {
        // Only delete if the entry is still ours — guards against a
        // re-register race during fast unmount.
        if (registry.get(id)?.fn === fn) registry.delete(id)
        inflight.delete(id)
      }
    },
    trigger(id): Promise<void> | undefined {
      const entry = registry.get(id)
      if (!entry) return undefined
      const p = runEntry(id, entry)
      // Update lastFire so the periodic tick does not immediately
      // re-fire after a manual trigger.
      registry.set(id, { ...entry, lastFire: Date.now() })
      return p
    },
    size(): number {
      return registry.size
    },
    // Exposed for the central tick loop below.
    _tickForTest(now: number): Promise<void>[] {
      const fired: Promise<void>[] = []
      for (const [id, entry] of registry) {
        if (entry.whileActive && !id.startsWith(`${active}:`)) continue
        if (entry.lastFire !== 0 && now - entry.lastFire < entry.intervalMs) continue
        if (inflight.has(id)) continue
        registry.set(id, { ...entry, lastFire: now })
        fired.push(runEntry(id, entry))
      }
      return fired
    },
  }
}

/** Hook the section component mounts once. Owns the central timer
 *  and the inflight dedup loop. `tickMs` defaults to 1000 ms (1 s
 *  granularity) — each registered entry's own `intervalMs` decides
 *  when its callback actually fires. The hook's effect cleanup
 *  clears the timer; the registry itself is owned by the context
 *  passed in (the section keeps it). */
export function usePolling(ctx: PollingContext, tickMs = 1000): void {
  useEffect(() => {
    const handle = setInterval(() => {
      const promises = ctx._tickForTest(Date.now())
      // Fire-and-forget; the inflight map inside the context dedupes.
      // Errors are absorbed by the registered callback's own try/catch
      // — the section component never wants the polling timer to
      // throw. (Invariant: never throw to the host.)
      void Promise.allSettled(promises)
    }, tickMs)
    return () => clearInterval(handle)
  }, [ctx, tickMs])
}

/** Helper: split a registered id into its tab prefix and purpose
 *  tail. Returns `[tab, purpose]` where `tab` is the portion before
 *  the first `:` and `purpose` is the remainder (or the whole id
 *  if there is no colon). Useful for tests and ad-hoc callers. */
export function splitPollingId(id: string): readonly [string, string] {
  const idx = id.indexOf(':')
  if (idx < 0) return [id, ''] as const
  return [id.slice(0, idx), id.slice(idx + 1)] as const
}