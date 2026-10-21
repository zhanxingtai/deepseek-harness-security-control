/**
 * usePolling tests —.
 *
 * The shared polling context replaces the per-tab setInterval pattern
 * with one central timer + registry. Tests below cover:
 *
 *   1. basic tick fan-out (registered callback fires per interval)
 *   2. tab gating (entries only fire while their tab is active)
 *   3. inflight dedup (overlapping ticks for same id are dropped)
 *   4. manual trigger (single fire + lastFire update so next tick
 *      does not immediately re-fire)
 *   5. unregister (return-from-register call removes the entry)
 *   6. concurrent calls: register-twice on same id replaces (no dup
 *      callbacks) — RecentBlocks re-registers on limit change
 *
 * The hook owns a `setInterval` that tests drive with vi fake
 * timers so the suite is fast and deterministic.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, act } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'

import {
  createPollingContext,
  splitPollingId,
  usePolling,
  type PollingContext,
} from '../../src/client/usePolling.js'

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  cleanup()
})

/** Tiny harness that owns a PollingContext and mounts usePolling.
 *  Re-rendering with a different activeTab flips the context. */
function TestHost({
  tab,
  ctx,
}: {
  tab: string
  ctx: PollingContext
}): ReactNode {
  usePolling(ctx)
  ctx.setActiveTab(tab)
  return null
}

describe('createPollingContext', () => {
  it('returns a context with activeTab getter / setter', () => {
    const ctx = createPollingContext()
    expect(ctx.activeTab).toBe('')
    ctx.setActiveTab('overview')
    expect(ctx.activeTab).toBe('overview')
  })

  it('register returns a deregister function that removes the entry', () => {
    const ctx = createPollingContext()
    const unregister = ctx.register('overview:tick', () => {}, 1000)
    expect(ctx.size()).toBe(1)
    unregister()
    expect(ctx.size()).toBe(0)
  })

  it('re-registering the same id replaces the entry (no duplicate callbacks)', () => {
    const ctx = createPollingContext()
    const a = vi.fn()
    const c = vi.fn()
    ctx.register('overview:tick', a, 1000)
    ctx.register('overview:tick', c, 1000)
    // Only one entry; the second `c` won.
    expect(ctx.size()).toBe(1)
    // Force a tick while the active tab matches; the latest fn fires.
    ctx.setActiveTab('overview')
    const fired = ctx._tickForTest(Date.now())
    expect(fired).toHaveLength(1)
    // The promise resolves asynchronously; microtask flush.
    return Promise.allSettled(fired).then(() => {
      expect(a).not.toHaveBeenCalled()
      expect(c).toHaveBeenCalledTimes(1)
    })
  })

  it('_tickForTest returns zero entries when no registrations', () => {
    const ctx = createPollingContext()
    expect(ctx._tickForTest(Date.now())).toEqual([])
  })

  it('trigger returns undefined when the id is not registered', () => {
    const ctx = createPollingContext()
    expect(ctx.trigger('overview:missing')).toBeUndefined()
  })

  it('trigger fires the registered callback and updates lastFire', async () => {
    const ctx = createPollingContext()
    const fn = vi.fn(async () => {})
    ctx.register('overview:tick', fn, 1000)
    ctx.setActiveTab('overview')
    const before = Date.now()
    const p = ctx.trigger('overview:tick')
    expect(p).toBeInstanceOf(Promise)
    await p
    expect(fn).toHaveBeenCalledTimes(1)
    // The next tick should NOT immediately re-fire because the
    // interval is 1000 ms and the trigger just bumped lastFire to
    // ~before (effectively now).
    const fired = ctx._tickForTest(before + 100) // 100 ms later
    expect(fired).toEqual([])
  })
})

describe('usePolling tick fan-out', () => {
  it('fires registered callbacks at the registered interval', async () => {
    const ctx = createPollingContext()
    const fn = vi.fn(async () => {})
    ctx.setActiveTab('overview')
    ctx.register('overview:tick', fn, 3000)

    render(createElement(TestHost, { tab: 'overview', ctx }))

    // Tick 1 — fires immediately (lastFire is 0).
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fn).toHaveBeenCalledTimes(1)

    // 2 s later — too soon (interval = 3000 ms).
    await act(async () => {
      vi.advanceTimersByTime(2000)
    })
    expect(fn).toHaveBeenCalledTimes(1)

    // Another 2 s — cumulative 5 s, second fire allowed.
    await act(async () => {
      vi.advanceTimersByTime(2000)
    })
    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('skips callbacks whose tab is not active (tab gating)', async () => {
    const ctx = createPollingContext()
    const overview = vi.fn(async () => {})
    const recent = vi.fn(async () => {})
    ctx.register('overview:tick', overview, 1000)
    ctx.register('recent:tick', recent, 1000)

    render(createElement(TestHost, { tab: 'overview', ctx }))

    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(overview).toHaveBeenCalledTimes(1)
    expect(recent).not.toHaveBeenCalled()

    // Switch to recent; recent now fires, overview stops.
    await act(async () => {
      vi.advanceTimersByTime(0)
    })
    render(createElement(TestHost, { tab: 'recent', ctx }))

    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(overview).toHaveBeenCalledTimes(1)
    expect(recent).toHaveBeenCalledTimes(1)
  })

  it('whileActive=false fires regardless of activeTab (Config tab uses this)', async () => {
    const ctx = createPollingContext()
    const fn = vi.fn(async () => {})
    ctx.register('config:anywhere', fn, 1000, false)

    // activeTab is empty (config never goes through polling).
    render(createElement(TestHost, { tab: '', ctx }))

    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('dedups overlapping ticks (inflight guard)', async () => {
    const ctx = createPollingContext()
    let inflight = false
    const fn = vi.fn(async () => {
      expect(inflight).toBe(false)
      inflight = true
      // Keep the promise pending until we manually resolve.
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 500)
      })
      inflight = false
    })
    ctx.setActiveTab('overview')
    ctx.register('overview:tick', fn, 1000)

    render(createElement(TestHost, { tab: 'overview', ctx }))

    // Tick 1 — fires the callback; promise is pending.
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fn).toHaveBeenCalledTimes(1)

    // Tick 2 before the first resolves — must be deduped.
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fn).toHaveBeenCalledTimes(1)

    // Let the first resolve; subsequent ticks fire.
    await act(async () => {
      vi.advanceTimersByTime(500)
    })
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fn).toHaveBeenCalledTimes(2)
  })

  it('clearInterval is called on unmount (no orphan timers)', async () => {
    const ctx = createPollingContext()
    const fn = vi.fn(async () => {})
    ctx.setActiveTab('overview')
    ctx.register('overview:tick', fn, 1000)

    const { unmount } = render(createElement(TestHost, { tab: 'overview', ctx }))
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fn).toHaveBeenCalledTimes(1)

    unmount()
    await act(async () => {
      vi.advanceTimersByTime(5000)
    })
    // No further fires after unmount.
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('unregister stops further ticks (per-entry cleanup)', async () => {
    const ctx = createPollingContext()
    const fn = vi.fn(async () => {})
    ctx.setActiveTab('overview')
    const unregister = ctx.register('overview:tick', fn, 1000)

    render(createElement(TestHost, { tab: 'overview', ctx }))
    await act(async () => {
      vi.advanceTimersByTime(1000)
    })
    expect(fn).toHaveBeenCalledTimes(1)

    unregister()
    await act(async () => {
      vi.advanceTimersByTime(5000)
    })
    expect(fn).toHaveBeenCalledTimes(1)
  })
})

describe('splitPollingId', () => {
  it('splits tab:purpose into a tuple', () => {
    expect(splitPollingId('overview:overview')).toEqual(['overview', 'overview'])
    expect(splitPollingId('recent:recentBlocks')).toEqual(['recent', 'recentBlocks'])
  })

  it('returns the whole id as the tab when there is no colon', () => {
    expect(splitPollingId('overview')).toEqual(['overview', ''])
  })

  it('preserves internal colons in the purpose tail', () => {
    expect(splitPollingId('overview:a:b:c')).toEqual(['overview', 'a:b:c'])
  })
})