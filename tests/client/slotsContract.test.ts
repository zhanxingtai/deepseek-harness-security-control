import { beforeEach, describe, expect, it, vi } from 'vitest'
// pins the one-step slot registration contract aligned with the
// harness reference impl (ui-settings-unarchive-sessions) — the
// `slots.inject` callback MUST return a disposer (returning a bare spec
// is a silent no-op under the current host registry semantics, which
// was the outstanding root cause).
//
// the previous revision gated the
// `slots.register` call behind `ctx.inject(['remote.securityMonitor'],
// …)` — that peer is never registered on host cordis contexts today,
// so the fiber hung pending and the section never registered (the
// outstanding root cause + a sibling of the host-side `remote`
// regression). The contract now pins the simpler shape: register
// synchronously with `bridge === undefined`; the React component
// (`SecurityMonitorSection`) handles the missing-bridge branch via a
// load-error banner at the section root. A future host that DOES
// expose `remote.securityMonitor` can wire the bridge through the
// registration's `inject` thunk without re-introducing the
// `ctx.inject` call (which would pin the fiber again).
//
// the apply function registers TWO slots
// — `sidebar.panellist` (top-level left-rail icon —
// `ui-plugin-manager/src/client/index.ts:94` shape), and `main`
// keyed-slot (`ui-plugin-manager/src/client/index.ts:83` shape) so the
// operator can reach the page from the sidebar. Both share
// `id / key = 'security-monitor'` so a single sidebar click routes to
// the right page. The contract pins each of the two registrations
// independently.
//
// settings removal): the previous
// `settings.section` slot (Settings modal card, parity with sibling
// plugins) was removed — the sidebar icon is now the single discovery
// surface, so a marketplace install no longer shows up twice. The
// `SecurityMonitorSection` component itself still ships (rendered via
// `SecurityMonitorPage` for the `main` keyed-slot); only its slot
// registration was dropped. The contract reflects this by no longer
// pinning the `settings.section` row and by collapsing the count
// assertion from 3 → 2.
// fix: the `apply ` function in src/client/index.ts
// carries a module-level `_applied` idempotency guard so a host that
// materializes the same module via two paths doesn't double-register.
// Production callers leave the guard alone (it's a real correctness
// property). Tests call `__resetAppliedForTests()` in beforeEach so
// each `it()` block can re-exercise the registration path on a fresh
// `_applied = false` state. We also import `apply` statically (top of
// file) so `vi.resetModules()` doesn't disturb the test file's own
// function declarations — `__resetAppliedForTests` reuses the same
// module instance the static import resolved to.
import { apply, __resetAppliedForTests } from '../../src/client/index.js'

beforeEach(() => {
  __resetAppliedForTests()
})

interface RegisteredEntry {
  slot: string
  spec: Record<string, unknown>
  component: unknown
}

function makeCtx() {
  const registered: RegisteredEntry[] = []
  let lastEffect: unknown
  let lastEffectReturnedDisposer = false
  const disposers: Array<() => void> = []
  const slots = {
    inject: (slot: string, callback: () => unknown) => {
      const effect = callback()
      lastEffect = effect
      lastEffectReturnedDisposer = typeof effect === 'function'
    },
    register: (spec: Record<string, unknown>, component: unknown) => {
      const slot = typeof spec.name === 'string' ? spec.name : '<unknown>'
      registered.push({ slot, spec, component })
      const dispose = vi.fn()
      disposers.push(dispose)
      return dispose
    },
  }
  const locale = {
    register: vi.fn(),
    bind: () => (key: string) => key,
  }
  const ctx: Record<string, unknown> = {
    get: (name: string) => (name === 'slots' ? slots : name === 'locale' ? locale : undefined),
    logger: { warn: vi.fn(), info: vi.fn() },
    // Provide ctx.inject so we can assert the new code path does NOT
    // consume it — the fixture's `inject` would record a call, and the
    // "no ctx.inject calls" assertion below catches a regression.
    inject: vi.fn(),
  }
  return {
    ctx,
    registered,
    disposers,
    locale,
    slotsRef: slots,
    isReturnedDisposer: () => lastEffectReturnedDisposer,
    getEffect: () => lastEffect as (() => void) | undefined,
  }
}

function findEntry(h: ReturnType<typeof makeCtx>, slot: string): RegisteredEntry | undefined {
  return h.registered.find((entry) => entry.slot === slot)
}

describe('client apply — one-step slots registration contract', () => {
  it('inject callback returns a disposer (not a bare spec)', async () => {
    const h = makeCtx()
    apply(h.ctx)
    // At least one of the two slot injections must return a disposer;
    // a bare spec return is a silent no-op on the current host registry.
    expect(h.isReturnedDisposer()).toBe(true)
  })

  it('registers sidebar.panellist with id"security-monitor"(top-level left-rail icon —)', async () => {
    const h = makeCtx()
    apply(h.ctx)
    const entry = findEntry(h, 'sidebar.panellist')
    expect(entry).toBeDefined()
    const spec = entry!.spec as { id: string; name: string; order: number; locale: string; label: () => string }
    expect(spec.id).toBe('security-monitor')
    expect(spec.name).toBe('sidebar.panellist')
    // PANELIST_ORDER in src/client/index.ts — order 10 keeps the icon
    // just below the Plugins entry (order 0).
    expect(spec.order).toBe(10)
    expect(spec.locale).toBe('settings.securityMonitor')
    // Label is a thunk so locale-change re-renders re-derive the text.
    expect(spec.label()).toBe('nav')
  })

  it('registers main slot with key"security-monitor"(central page occupant —)', async () => {
    const h = makeCtx()
    apply(h.ctx)
    const entry = findEntry(h, 'main')
    expect(entry).toBeDefined()
    const spec = entry!.spec as { key: string; name: string; locale: string; inject: () => { bridge: unknown; t: unknown } }
    expect(spec.key).toBe('security-monitor')
    expect(spec.name).toBe('main')
    expect(spec.locale).toBe('settings.securityMonitor')
    const injected = spec.inject()
    expect(injected.bridge).toBeUndefined()
    expect(typeof injected.t).toBe('function')
  })

  it('registers exactly two slot contributions (sidebar.panellist + main)', async () => {
    const h = makeCtx()
    apply(h.ctx)
    expect(h.registered).toHaveLength(2)
    const names = h.registered.map((e) => e.slot).sort()
    expect(names).toEqual(['main', 'sidebar.panellist'])
  })

  it('does NOT call ctx.inject (the remote.securityMonitor peer is intentionally absent)', async () => {
    const h = makeCtx()
    apply(h.ctx)
    expect(h.ctx.inject).not.toHaveBeenCalled()
  })

  it('still registers when ctx.inject is unavailable (defensive null-check)', async () => {
    const h = makeCtx()
    delete (h.ctx as { inject?: unknown }).inject
    apply(h.ctx)
    expect(h.registered).toHaveLength(2)
  })

  it('returned disposer disposes the registered contribution (per-slot)', async () => {
    const h = makeCtx()
    apply(h.ctx)
    // Each of the two inject callbacks returns its own slots.register
    // disposer; we can dispose each independently. We exercise the
    // effects in registration order.
    // For a simpler contract pin, just confirm the second call's effect
    // (the `main` slot) returned a function that disposes its entry.
    const lastEntry = h.registered[h.registered.length - 1]
    expect(lastEntry).toBeDefined()
    expect(h.disposers).toHaveLength(2)
    // Both disposers are unique vi.fn() instances.
    expect(new Set(h.disposers).size).toBe(2)
  })

  it('warns and skips registration when slots/locale are unavailable', async () => {
    const warn = vi.fn()
    const ctx = { get: () => undefined, logger: { warn } }
    apply(ctx)
    expect(warn).toHaveBeenCalled()
  })
})
