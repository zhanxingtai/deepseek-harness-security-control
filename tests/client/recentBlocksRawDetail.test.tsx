/**
 * Policy Hits (RecentBlocks) raw-detail expansion tests — 2026-09-29 B2.
 *
 * The wire `BlockRow` is a summary shape; the expanded detail region
 * lazily fetches the full raw event via ONE
 * `recentBlocks({includeRaw:true})` call, caches it by row key, and
 * re-renders the complete record. These tests pin that contract on the
 * client side with a mocked bridge:
 *
 *   - summary polling never sets `includeRaw`
 *   - expanding a row fires exactly one `includeRaw:true` fetch
 *   - the detail region ends up showing the raw event JSON, not just
 *     the BlockRow summary fields
 *   - a `...[truncated]` breadcrumb surfaces the truncation hint
 *     (same locale key as the Events tab)
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, waitFor } from '@testing-library/react'
import { createElement } from 'react'

import { RecentBlocks } from '../../src/client/components/RecentBlocks.js'
import { locales, type LocaleKey } from '../../src/client/locales.js'
import type { BlockRow, SecurityMonitorBridge } from '../../src/client/wire.js'

afterEach(() => {
  cleanup()
})

const en = locales.en
function t(key: LocaleKey, params?: Record<string, string | number>): string {
  const raw = en[key] as string
  if (!params) return raw
  return raw.replace(/\{(\w+)\}/g, (_m, name) => String(params[name] ?? `{${name}}`))
}

/** Summary rows — what the 3 s poll returns (no raw_json). */
function summaryRows(): BlockRow[] {
  return [
    {
      ts: 1_000,
      session_id: 's1',
      tool_name: 'bash',
      tool_call_id: 'call-1',
      decision: 'deny',
      decision_internal: 'block',
      block_reason: 'sensitive file read',
      block_code: 'POLICY_X',
      policy_id: 'rule-x',
    },
    {
      ts: 2_000,
      session_id: 's2',
      tool_name: 'write',
      tool_call_id: 'call-2',
      decision: 'deny',
      decision_internal: 'block',
      block_reason: 'oversized write',
      block_code: 'POLICY_Y',
      policy_id: 'rule-y',
    },
  ]
}

/** includeRaw rows — same summaries plus the capped raw event JSON. */
function rawRows(): BlockRow[] {
  return [
    {
      ...summaryRows()[0],
      raw_json:
        '{"ts":1000,"event_type":"agent_tool_call","tool_name":"bash","tool_params":"{\\"command\\":\\"cat /etc/shadow\\"}"}',
    },
    {
      ...summaryRows()[1],
      raw_json: '{"ts":2000,"event_type":"agent_tool_call","tool_params":"' + 'x'.repeat(100) + '"}...[truncated]',
    },
  ]
}

interface BridgeSpy extends SecurityMonitorBridge {
  recentBlocksMock: ReturnType<typeof vi.fn>
}

function buildBridge(): BridgeSpy {
  const recentBlocksMock = vi.fn(
    async (args?: { limit?: number; scope?: 'blocked' | 'all-hits'; includeRaw?: boolean }): Promise<{ rows: BlockRow[]; total: number }> => {
      const rows = args?.includeRaw ? rawRows() : summaryRows()
      return { rows, total: rows.length }
    },
  )
  return {
    overview: async () => {
      throw new Error('unused')
    },
    recentBlocks: recentBlocksMock,
    reload: async () => {
      throw new Error('unused')
    },
    getConfig: async () => {
      throw new Error('unused')
    },
    validateConfigPatch: async () => {
      throw new Error('unused')
    },
    saveConfigDraft: async () => {
      throw new Error('unused')
    },
    getConfigDraftStatus: async () => {
      throw new Error('unused')
    },
    previewLivePatch: async () => {
      throw new Error('unused')
    },
    applyLivePatch: async () => {
      throw new Error('unused')
    },
    events: async () => ({ rows: [], total: 0 }),
    recentBlocksMock,
  }
}

/** The Policy Hits table renders one clickable <tr> per row; find the
 *  one whose cells carry the given reason text. */
function findRow(container: HTMLElement, text: string): HTMLElement {
  const tr = Array.from(container.querySelectorAll('tr.dsh-secmon-table-row')).find((el) =>
    el.textContent?.includes(text),
  )
  if (!tr) throw new Error(`row not found: ${text}`)
  return tr as HTMLElement
}

describe('RecentBlocks raw detail (B2 惰性明细)', () => {
  it('summary polling never sets includeRaw', async () => {
    const bridge = buildBridge()
    render(createElement(RecentBlocks, { bridge, t }))
    await waitFor(() => {
      expect(bridge.recentBlocksMock).toHaveBeenCalled()
    })
    for (const call of bridge.recentBlocksMock.mock.calls) {
      expect((call[0] as { includeRaw?: boolean } | undefined)?.includeRaw).not.toBe(true)
    }
  })

  it('expanding a row fetches includeRaw once and renders the raw event', async () => {
    const bridge = buildBridge()
    const { container } = render(createElement(RecentBlocks, { bridge, t }))
    await waitFor(() => {
      expect(bridge.recentBlocksMock).toHaveBeenCalled()
    })
    fireEvent.click(findRow(container, 'sensitive file read'))
    await waitFor(() => {
      const detail = container.querySelector('[data-component="recent-detail"] pre')
      expect(detail?.textContent).toContain('cat /etc/shadow')
    })
    // raw_json 必须重新缩进展示,而不是单行紧凑 JSON。
    const pre = container.querySelector('[data-component="recent-detail"] pre')
    expect(pre?.textContent).toContain('\n  "ts": 1000')
    const rawCalls = bridge.recentBlocksMock.mock.calls.filter(
      (c) => (c[0] as { includeRaw?: boolean } | undefined)?.includeRaw === true,
    )
    expect(rawCalls.length).toBe(1)
    expect((rawCalls[0][0] as { scope?: string }).scope).toBe('all-hits')
  })

  it('truncated raw_json surfaces the truncation hint', async () => {
    const bridge = buildBridge()
    const { container } = render(createElement(RecentBlocks, { bridge, t }))
    await waitFor(() => {
      expect(bridge.recentBlocksMock).toHaveBeenCalled()
    })
    fireEvent.click(findRow(container, 'oversized write'))
    await waitFor(() => {
      const hint = container.querySelector('.dsh-secmon-events-truncated-hint')
      expect(hint?.textContent).toBe(en.events_row_truncated_hint)
    })
  })

  it('Load more passes the `offset` cursor to bridge.recentBlocks', async () => {
    // 2026-10-10 — regression for the parallel bug on the Policy
    // Hits tab. Same shape as the Events tab test: the host must
    // skip the rows we already have; a full page implies there's
    // more; a short page is the end-of-results marker.
    const LIMIT = 50
    const page1: BlockRow[] = Array.from({ length: LIMIT }, (_, i) => ({
      ts: 1_700_000_000_000 + i,
      session_id: `s${i}`,
      tool_name: `tool-${i}`,
      decision: 'deny',
      decision_internal: 'block',
      block_reason: `reason-${i}`,
      block_code: 'POLICY_X',
      policy_id: 'rule-x',
    }))
    const page2: BlockRow = {
      ts: 1_699_999_000_000, // older than every row on page1
      session_id: 's-older',
      tool_name: 'tool-older',
      decision: 'deny',
      decision_internal: 'block',
      block_reason: 'reason-older',
      block_code: 'POLICY_X',
      policy_id: 'rule-x',
    }
    const recentBlocksMock = vi.fn(
      async (args?: { limit?: number; offset?: number }): Promise<{ rows: BlockRow[]; total: number }> => {
        if (args?.offset === LIMIT) return { rows: [page2], total: LIMIT + 1 }
        return { rows: page1, total: LIMIT + 1 }
      },
    )
    const bridge: BridgeSpy = {
      ...buildBridge(),
      recentBlocksMock,
      recentBlocks: recentBlocksMock,
    }
    render(createElement(RecentBlocks, { bridge, t }))
    // Three microtask flushes: 1) initial mount's useEffect
    // starts the fetch, 2) the mock resolves + then(setPages(page1),
    // setHasMore(true)) fires, 3) React commits the re-render so
    // pagesRef is up to date and the Load more button is enabled.
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })
    // First call must have no offset (offset=0, the first page).
    expect(recentBlocksMock.mock.calls[0]?.[0]?.offset).toBe(0)
    const moreBtn = document.querySelector(
      '[data-component="recent-load-more"]',
    ) as HTMLButtonElement | null
    expect(moreBtn).toBeTruthy()
    await act(async () => {
      fireEvent.click(moreBtn as HTMLElement)
      // Six microtask flushes: 1) click sync, 2) mock resolves,
      // 3) .then(rows => setPages(...)) commit, 4) .finally
      // setLoadingMore(false) commit, 5) state batch, 6) React
      // commit. happy-dom + React 18 sometimes needs 5-6 passes
      // to drain a chained .then / .finally inside a click handler.
      for (let i = 0; i < 6; i++) await Promise.resolve()
    })
    const lastCall = recentBlocksMock.mock.calls.at(-1)
    expect(lastCall?.[0]?.offset).toBe(LIMIT)
    // The older row must be appended to the visible list.
    const lastResult = await recentBlocksMock.mock.results.at(-1)?.value
    expect((lastResult as { rows: BlockRow[] }).rows[0]?.session_id).toBe('s-older')
    // The page2 row must be appended to the visible list. The
    // table renders TIME / TOOL / DECISION / SEVERITY / POLICY /
    // REASON columns — session_id is internal-only (used as a
    // stable row key but not surfaced). tool-older + reason-older
    // are the visible field on the appended row.
    const body = document.body.textContent ?? ''
    expect(body).toContain('tool-older')
    expect(body).toContain('reason-older')
    expect(body).toContain(
      t('showing_n_blocks')
        .replace('{n}', String(LIMIT + 1))
        .replace('{total}', String(LIMIT + 1)),
    )
    expect(document.body.textContent ?? '').toContain(
      t('showing_n_blocks')
        .replace('{n}', String(LIMIT + 1))
        .replace('{total}', String(LIMIT + 1)),
    )
  })
})
