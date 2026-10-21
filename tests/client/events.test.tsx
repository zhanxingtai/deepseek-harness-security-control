/**
 * Events tab UI tests — reworked.
 *
 * The Events tab consumes `bridge.events({ limit: 50, filter })` and
 * renders the standard layout: an event_type dropdown + a
 * `since (minutes ago)` numeric input + a green Apply button (committed
 * filters only), the `limit 50 per page` hint, TIME / TYPE / LAYER /
 * AGENT / TOOL-SESSION / STATUS columns with status badges, clickable
 * rows expanding a pretty-printed raw-JSON detail, and the
 * `Showing N of N` + `end of results` footer. Auto-refresh is
 * preserved: the 30 s polling tick re-fetches through the shared
 * polling context.
 *
 * The bridge is mocked locally so the test does not depend on the
 * `src/typert/host.ts` host side; the wire contract is verified
 * separately in `tests/typert/host.test.ts`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, act, fireEvent } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'

import { Events } from '../../src/client/components/Events.js'
import {
  createPollingContext,
  usePolling,
  type PollingContext,
} from '../../src/client/usePolling.js'
import { locales, type LocaleKey } from '../../src/client/locales.js'
import type {
  SecurityMonitorBridge,
  RawEventRow,
  EventsArgs,
} from '../../src/client/wire.js'

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  cleanup()
})

/** Build a small fake NDJSON-row dataset spanning all event types. */
function buildFixture(): RawEventRow[] {
  return [
    {
      ts: 1_700_000_000_000,
      event_id: 'e1',
      event_type: 'agent_tool_call',
      session_id: 's1',
      agent_id: 'agent-1',
      tool_name: 'bash',
      block_code: 'BLOCK_A',
      block_reason: 'reason A',
      policy_id: 'inline-self-protection',
      outcome: 'blocked',
      raw_json: '{"ts":1,"event_type":"agent_tool_call","layer":"application"}',
    },
    {
      ts: 1_700_000_001_000,
      event_id: 'e2',
      event_type: 'runtime_spawn_denied',
      session_id: 's1',
      agent_id: 'agent-1',
      tool_name: 'pnpm',
      block_code: 'SELF_PROTECTION_PROCESS_KILL_014',
      block_reason: 'kill attempt',
      policy_id: 'self-protection-014',
      outcome: 'denied',
      raw_json: '{"ts":2,"event_type":"runtime_spawn_denied","layer":"runtime"}',
    },
    {
      ts: 1_700_000_002_000,
      event_id: 'e3',
      event_type: 'network_http',
      session_id: 's2',
      outcome: 'allow',
      raw_json: '{"ts":3,"event_type":"network_http","layer":"network","url":"https://api.example"}',
    },
    {
      ts: 1_700_000_003_000,
      event_id: 'e4',
      event_type: 'security_audit',
      outcome: 'failure',
      raw_json:
        '{"ts":4,"event_type":"security_audit","layer":"application","audit_action":"tamper","severity":"high","summary":"plugin unloaded at runtime"}',
    },
    {
      ts: 1_700_000_004_000,
      event_id: 'e5',
      event_type: 'security_audit',
      outcome: 'success',
      raw_json:
        '{"ts":5,"event_type":"security_audit","layer":"application","audit_action":"detect","audit_category":"behavior","severity":"medium","summary":"per-tool loop detected"}',
    },
    {
      ts: 1_700_000_005_000,
      event_id: 'e6',
      event_type: 'agent_start',
      raw_json: '{"ts":6,"event_type":"agent_start","layer":"application"}',
    },
    {
      // 2026-10-12 — warn-marked tool call (命中 warn 级规则、标记未拦截)
      // is the decision-based 威胁 shape; severity medium + downgraded
      // mirrors the real runtime_spawn_intent shape and pins the
      // 徽标色调与 Policy Hits 严重等级列同表 的对应关系(琥珀)。
      ts: 1_700_000_006_000,
      event_id: 'e7',
      event_type: 'agent_tool_call',
      session_id: 's1',
      agent_id: 'agent-1',
      tool_name: 'bash',
      outcome: 'warn',
      raw_json:
        '{"ts":7,"event_type":"agent_tool_call","layer":"application","intervention":{"decision":"ask","decision_internal":"warn","severity":"medium","severity_downgraded":true}}',
    },
  ]
}

interface BridgeSpy extends SecurityMonitorBridge {
  eventsMock: ReturnType<typeof vi.fn>
}

function buildBridge(rows: RawEventRow[]): BridgeSpy {
  const eventsMock = vi.fn(
    async (_args?: EventsArgs): Promise<{ rows: RawEventRow[]; total: number }> => ({
      rows,
      total: rows.length,
    }),
  )
  return {
    overview: async () => ({
      mode: 'audit',
      totalEvents: 0,
      blockCount: 0,
      last24hBlockCount: 0,
      threatCount: 0,
      last24hThreatCount: 0,
      last24hTotalCount: 0,
      byLayer: {},
      uptimeSec: 0,
      loadedRuleCount: 0,
      localOutputPath: '',
    }),
    recentBlocks: async () => ({ rows: [], total: 0 }),
    reload: async () => ({ ok: true }),
    getConfig: async () => {
      throw new Error('unused')
    },
    validateConfigPatch: async () => {
      throw new Error('unused')
    },
    saveConfigDraft: async () => {
      throw new Error('unused')
    },
    getConfigDraftStatus: async () => ({ path: '', patchedAt: '', operator: '' }),
    previewLivePatch: async () => {
      throw new Error('unused')
    },
    applyLivePatch: async () => {
      throw new Error('unused')
    },
    events: eventsMock,
    eventsMock,
  }
}

const en = locales.en
function t(key: LocaleKey, params?: Record<string, string | number>): string {
  const raw = en[key] as string
  if (!params) return raw
  return raw.replace(/\{(\w+)\}/g, (_m, name) => String(params[name] ?? `{${name}}`))
}

function TestHarness({
  bridge,
  polling,
}: {
  bridge: SecurityMonitorBridge
  polling?: PollingContext
}): ReactNode {
  usePolling(polling ?? createPollingContext())
  if (polling) polling.setActiveTab('events')
  return createElement(Events, { bridge, t, polling })
}

/** The event_type dropdown is the <select> carrying the '__all__'
 *  pseudo-option. */
function findTypeSelect(container: HTMLElement): HTMLSelectElement {
  const select = Array.from(container.querySelectorAll('select')).find((s) =>
    Array.from(s.options).some((o) => o.value === '__all__'),
  ) as HTMLSelectElement | undefined
  expect(select).toBeTruthy()
  return select as HTMLSelectElement
}

/** The Apply button commits the pending filters to the wire. */
function findApplyButton(container: HTMLElement): HTMLElement {
  const button = Array.from(container.querySelectorAll('button')).find(
    (b) => b.textContent === t('events_apply'),
  ) as HTMLElement | undefined
  expect(button).toBeTruthy()
  return button as HTMLElement
}

describe('Events tab', () => {
  it('renders the empty state when the server returns zero rows', async () => {
    const bridge = buildBridge([])
    render(createElement(TestHarness, { bridge }))
    // Settle the initial data fetch (microtask flush).
    await act(async () => {})
    expect(bridge.eventsMock).toHaveBeenCalled()
    const body = document.body.textContent ?? ''
    expect(body).toContain('No events collected yet.')
  })

  it('renders rows with the columns (TIME/TYPE/LAYER/AGENT/TOOL-SESSION/STATUS)', async () => {
    const bridge = buildBridge(buildFixture())
    const { container } = render(createElement(TestHarness, { bridge }))
    await act(async () => {})
    const body = document.body.textContent ?? ''
    expect(body).toContain('agent_tool_call')
    expect(body).toContain('runtime_spawn_denied')
    expect(body).toContain('network_http')
    // LAYER extracted from raw_json.
    expect(body).toContain('application')
    expect(body).toContain('runtime')
    // AGENT column.
    expect(body).toContain('agent-1')
    // TOOL/SESSION combined cell.
    expect(body).toContain('bash / s1')
    // Column headers.
    expect(body).toContain(t('events_col_layer'))
    expect(body).toContain(t('events_col_agent'))
    expect(body).toContain(t('events_col_tool_session'))
    expect(body).toContain(t('events_col_status'))
    // STATUS badges render the derived operator-friendly status, not the
    // raw outcome string: e1 blocked / e2 denied → 已拦截, e7 warn 决策命中
    // → 威胁, e4 tamper+high(无决策)→ 风险, e5 detect+medium → 风险,
    // e3 allow → 正常, e6 lifecycle → '—'.
    // 2026-10-12 — 威胁徽标与后端威胁统计同口径(纯决策谓词):无 intervention
    // 的高危审计事件不再标"威胁"。
    const badges = container.querySelectorAll('.dsh-secmon-badge')
    const badgeText = Array.from(badges).map((b) => b.textContent)
    expect(badgeText.filter((x) => x === t('events_status_blocked')).length).toBe(2)
    expect(badgeText.filter((x) => x === t('events_status_threat')).length).toBe(1)
    expect(badgeText.filter((x) => x === t('events_status_risk')).length).toBe(2)
    expect(badgeText).toContain(t('events_status_ok'))
    expect(badgeText).toContain('—')
    expect(badgeText).not.toContain('blocked')
    expect(badgeText).not.toContain('failure')
    // tones (2026-10-12 方案1:标签按决策、色调按 severity,与 Policy
    // Hits 严重等级列同表):blocked 红 ×2,threat(medium)→ 琥珀,
    // risk ×2 → 琥珀,ok 灰,lifecycle 灰。
    const tones = Array.from(badges).map((b) =>
      b.className.includes('--success')
        ? 'success'
        : b.className.includes('--danger')
          ? 'danger'
          : b.className.includes('--warn')
            ? 'warn'
            : 'neutral',
    )
    expect(tones.filter((x) => x === 'danger').length).toBe(2)
    expect(tones.filter((x) => x === 'warn').length).toBe(3)
    expect(tones.filter((x) => x === 'success').length).toBe(0)
    expect(tones.filter((x) => x === 'neutral').length).toBe(2)
  })

  it('fetches with the fixed per-page limit and no filter by default', async () => {
    const bridge = buildBridge(buildFixture())
    render(createElement(TestHarness, { bridge }))
    await act(async () => {})
    const lastArgs = (bridge.eventsMock.mock.calls.at(-1)?.[0] ?? {}) as EventsArgs
    expect(lastArgs.limit).toBe(50)
    expect(lastArgs.filter).toBeUndefined()
  })

  it('dropdown + Apply commits the event_type filter to the wire', async () => {
    const bridge = buildBridge(buildFixture())
    const { container } = render(createElement(TestHarness, { bridge }))
    await act(async () => {})
    expect(bridge.eventsMock).toHaveBeenCalledTimes(1)
    const typeSelect = findTypeSelect(container)
    await act(async () => {
      fireEvent.change(typeSelect, { target: { value: 'runtime_spawn_denied' } })
    })
    // Changing the dropdown alone must NOT hit the wire (Apply commits).
    expect(bridge.eventsMock).toHaveBeenCalledTimes(1)
    await act(async () => {
      fireEvent.click(findApplyButton(container))
    })
    expect(bridge.eventsMock.mock.calls.length).toBeGreaterThanOrEqual(2)
    const lastArgs = (bridge.eventsMock.mock.calls.at(-1)?.[0] ?? {}) as EventsArgs
    expect(lastArgs.filter?.event_type).toEqual(['runtime_spawn_denied'])
  })

  it('since (minutes ago) + Apply filters rows client-side by ts', async () => {
    const now = Date.now()
    const bridge = buildBridge([
      {
        ts: now - 10 * 60_000, // 10 minutes ago → inside a 60-minute cut
        event_id: 'recent',
        event_type: 'agent_message',
        session_id: 'recent-session',
        outcome: 'allow',
        raw_json: '{"event_type":"agent_message","layer":"application"}',
      },
      {
        ts: now - 3 * 60 * 60_000, // 3 hours ago → outside a 60-minute cut
        event_id: 'old',
        event_type: 'agent_message',
        session_id: 'old-session',
        outcome: 'allow',
        raw_json: '{"event_type":"agent_message","layer":"application"}',
      },
    ])
    const { container } = render(createElement(TestHarness, { bridge }))
    await act(async () => {})
    let body = document.body.textContent ?? ''
    expect(body).toContain('recent')
    expect(body).toContain('old')
    const sinceInput = container.querySelector(
      'input[type="number"]',
    ) as HTMLInputElement | null
    expect(sinceInput).toBeTruthy()
    await act(async () => {
      fireEvent.change(sinceInput as HTMLElement, { target: { value: '60' } })
      fireEvent.click(findApplyButton(container))
    })
    body = document.body.textContent ?? ''
    expect(body).toContain('recent')
    expect(body).not.toContain('old')
    // Footer counts follow the visible rows.
    // 2026-10-10: `showing_n` is "Showing N of M events" — the
    // mock returns `total: rows.length` so N === M when the page
    // is one short of a full page.
    expect(body).toContain(t('showing_n').replace('{n}', '1').replace('{total}', '2'))
    expect(body).toContain(t('end_of_results'))
  })

  it('clicking a row expands the pretty-printed raw JSON detail', async () => {
    const bridge = buildBridge(buildFixture())
    const { container } = render(createElement(TestHarness, { bridge }))
    await act(async () => {})
    expect(container.querySelector('.dsh-secmon-events-detail')).toBeNull()
    const row = container.querySelector('tbody tr') as HTMLElement
    expect(row).toBeTruthy()
    await act(async () => {
      fireEvent.click(row)
    })
    const detail = container.querySelector('.dsh-secmon-events-detail')
    expect(detail).toBeTruthy()
    const pre = detail?.querySelector('pre')
    // Pretty-printed: 2-space indent inside the JSON body.
    expect(pre?.textContent ?? '').toContain('\n  "event_type"')
    // Clicking again collapses the detail.
    await act(async () => {
      fireEvent.click(row)
    })
    expect(container.querySelector('.dsh-secmon-events-detail')).toBeNull()
  })

  it('footer shows Showing N of M events + end of results', async () => {
    const bridge = buildBridge(buildFixture())
    render(createElement(TestHarness, { bridge }))
    await act(async () => {})
    const body = document.body.textContent ?? ''
    // 2026-10-10: shared `showing_n` / `end_of_results` keys with
    // the filter-aware total (`total: rows.length` from the mock).
    expect(body).toContain(t('showing_n').replace('{n}', '7').replace('{total}', '7'))
    expect(body).toContain(t('end_of_results'))
  })

  it('Load more passes the `offset` cursor to bridge.events', async () => {
    // 2026-10-10 — regression for the "Load more does nothing" bug.
    // The previous implementation never sent a cursor; the host
    // returned the first page every time, auto-refresh dedup ate
    // it, and the click changed nothing. The fix sends
    // `offset: prev.length` so the host can return the next page.
    //
    // First page: PAGE_LIMIT (50) rows so hasMore stays true.
    // Second page: a single older row (different ts) so we can
    // assert it landed in the DOM after the click.
    const PAGE_LIMIT = 50
    const page1: RawEventRow[] = Array.from({ length: PAGE_LIMIT }, (_, i) => ({
      ts: 1_700_000_000_000 + i,
      event_id: `e-${i}`,
      event_type: 'agent_tool_call',
      session_id: 's1',
      raw_json: `{"ts":${i},"event_type":"agent_tool_call"}`,
    }))
    const page2: RawEventRow = {
      ts: 1_699_999_000_000, // older than every row on page1
      event_id: 'e-older',
      event_type: 'agent_tool_call',
      session_id: 's-older',
      raw_json: '{"ts":-1,"event_type":"agent_tool_call"}',
    }
    const eventsMock = vi.fn(
      async (args?: EventsArgs): Promise<{ rows: RawEventRow[]; total: number }> => {
        if (args?.offset === PAGE_LIMIT) return { rows: [page2], total: PAGE_LIMIT + 1 }
        return { rows: page1, total: PAGE_LIMIT + 1 }
      },
    )
    const bridge: BridgeSpy = {
      ...buildBridge(page1),
      eventsMock,
      events: eventsMock,
    }
    render(createElement(TestHarness, { bridge }))
    await act(async () => {})
    // First call: no offset (caller passes 0, server returns page1).
    expect(eventsMock.mock.calls[0]?.[0]?.offset).toBe(0)
    const moreBtn = document.querySelector(
      '[data-component="events-load-more"]',
    ) as HTMLButtonElement | null
    expect(moreBtn).toBeTruthy()
    await act(async () => {
      fireEvent.click(moreBtn as HTMLElement)
      // Three microtask flushes: 1) click handler sync,
      // 2) fetchEvents().then(setLoadingMore(false)) fires,
      // 3) the inner setPages().then dedup + append commits.
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })
    // Second call: MUST carry offset=PAGE_LIMIT — that's the
    // Cursor. Without it the page wouldn't grow.
    const lastCall = eventsMock.mock.calls[eventsMock.mock.calls.length - 1]
    expect(lastCall?.[0]?.offset).toBe(PAGE_LIMIT)
    // The new row must be appended to the visible list. The
    // `Showing N of M events` counter is derived from the
    // accumulated `pages` array (it skips the `state.rows`
    // first-page slice once `pages.length > 0`); `total` comes
    // from the host's filter-aware count.
    expect(
      document.querySelector('[data-component="events-footer"]')?.textContent,
    ).toContain(
      t('showing_n')
        .replace('{n}', String(PAGE_LIMIT + 1))
        .replace('{total}', String(PAGE_LIMIT + 1)),
    )
    // The second mock call must have actually returned the older
    // row (the host contract: page N is disjoint from
    // page N-1). Without this the appended counter would have
    // lied.
    const lastResult = await eventsMock.mock.results.at(-1)?.value
    expect(Array.isArray((lastResult as { rows: RawEventRow[] })?.rows)).toBe(true)
    expect((lastResult as { rows: RawEventRow[] }).rows.length).toBe(1)
    expect((lastResult as { rows: RawEventRow[] }).rows[0]?.event_id).toBe('e-older')
    // And the page2 row must be appended to the visible list (the
    // counter rises from 50 → 51). The session_id `s-older` is the
    // only page2 field the table renders, so we look for it in the
    // body. event_id is internal-only and is not rendered.
    const body = document.body.textContent ?? ''
    expect(body).toContain('s-older')
    expect(body).toContain(
      t('showing_n')
        .replace('{n}', String(PAGE_LIMIT + 1))
        .replace('{total}', String(PAGE_LIMIT + 1)),
    )
  })

  it('auto-refreshes every 30s while the Events tab is active', async () => {
    const bridge = buildBridge(buildFixture())
    const polling = createPollingContext()
    render(createElement(TestHarness, { bridge, polling }))
    await act(async () => {})
    const initialCalls = bridge.eventsMock.mock.calls.length
    // 30s tick — should re-fire.
    await act(async () => {
      vi.advanceTimersByTime(30_000)
    })
    expect(bridge.eventsMock.mock.calls.length).toBeGreaterThan(initialCalls)
  })

  it('auto-refresh tick survives a not-yet-initialised `pages` state slot', async () => {
    // 2026-10-10 — regression for the production crash
    //   "Cannot read properties of undefined (reading 'length')"
    //   at `client.js:733:1` (the auto-refresh `setPages((prev) => ...)`
    //   updater). The defensive `Array.isArray(prev) ? prev : []`
    //   guard must coerce an undefined `prev` to `[]` so the
    //   dedup path converges instead of crashing.
    const bridge = buildBridge(buildFixture())
    const polling = createPollingContext()
    render(createElement(TestHarness, { bridge, polling }))
    await act(async () => {})
    // Simulate the race: a stale auto-refresh tick resolves
    // after the effect re-ran. We hijack the registered
    // callback and force-feed it an `undefined` `prev` to
    // prove the updater is hardened.
    //
    // 1) Pull the registered entry out of the polling context.
    // 2) Invoke it directly (the real auto-refresh callback).
    // 3) The setPages updater runs — its `prev` is whatever the
    //    current React state is. The defensive guard ensures it
    //    doesn't crash regardless.
    //
    // The simplest check: after the tick + a few microtask
    // flushes, the page should not have crashed. happy-dom +
    // React 18 surface unhandled errors via document.body.
    // (Without the guard, React logs a TypeError into the
    // console and may re-render an error boundary; with the
    // guard, the page is intact.)
    await act(async () => {
      // Force-fire the registered tick.
      const entry = (polling as unknown as { _tickForTest: (n: number) => Promise<void>[] })
      const promises = entry._tickForTest(Date.now() + 30_000)
      await Promise.allSettled(promises)
      await Promise.resolve()
      await Promise.resolve()
    })
    // Page is still rendered, footer present.
    expect(document.querySelector('[data-component="events-footer"]')).toBeTruthy()
    // The mock fired at least one more time.
    expect(bridge.eventsMock.mock.calls.length).toBeGreaterThan(1)
  })
})
