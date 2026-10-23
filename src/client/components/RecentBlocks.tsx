/**
 * Top Blocks tab — visual + column rework.
 *
 * The wire `BlockRow` is a summary shape — the expanded region
 * first renders the row's own fields as an immediate fallback,
 * then fires ONE `recentBlocks({includeRaw:true})` fetch, caches
 * the matching row's `raw_json` by row key, and re-renders the
 * complete raw event once it lands (same truncation semantics as
 * the Events tab: `...[truncated]` breadcrumb + hint). The 3 s
 * auto-refresh stays in summary mode, so the polling payload is
 * unchanged; `pollingPausedRef` already halts refresh while any
 * row is expanded, which naturally rate-limits the raw fetch.
 */
import { createElement, useEffect, useRef, useState, type ReactNode } from 'react'
import type { SecurityMonitorBridge, BlockRow } from '../wire.js'
import type { LocaleKey } from '../locales.js'
import type { PollingContext } from '../usePolling.js'
import { prettyRawJson } from './Events.js'
import { Card, Table, Banner, Badge, IconButton, type IconButtonIcon, type BadgeTone, type TableColumn } from './primitives.js'
import { formatTime } from '../formatTime.js'
import { localizeReason } from '../reasons.js'

const LIMIT_OPTIONS = [20, 50, 100] as const
type Limit = (typeof LIMIT_OPTIONS)[number]

export interface RecentBlocksProps {
  bridge: SecurityMonitorBridge
  t: (key: LocaleKey, params?: Record<string, string | number>) => string
  /** Auto-refresh every 10 s while the Top Blocks tab is active.
   *  Optional for back-compat with isolated tests. */
  polling?: PollingContext | undefined
  /** Pause auto-refresh while any detail row is expanded (user is reading data). */
  pollingPausedRef?: React.MutableRefObject<boolean>
}

type State =
  | { kind: 'loading' }
  | { kind: 'ready'; rows: BlockRow[] }
  | { kind: 'error'; message: string }

/** DECISION badge tone by the INTERNAL decision: block / blocked /
 *  denied → red; warn (命中 warn 级规则、标记未拦截) → amber;
 *  escalate (人工审核) → 靛蓝(紫色); anything else → neutral gray.
 *  `escalate` distinguishes "needs human review" from "hard blocked". */
function decisionTone(internal: string | undefined): BadgeTone {
  switch ((internal ?? '').toLowerCase()) {
    case 'block':
    case 'blocked':
    case 'deny':
      return 'danger'
    case 'warn':
      return 'warn'
    case 'escalate':
      return 'escalate'
    default:
      return 'neutral'
  }
}

/** Severity badge tone. critical / high map to danger (red),
 *  medium to warn (amber), low to neutral (gray). The downgrade
 *  marker `↓warn` is appended inline by the cell renderer when
 *  `severity_downgraded` is true. */
function severityTone(severity: string | undefined): BadgeTone {
  switch ((severity ?? '').toLowerCase()) {
    case 'critical':
      return 'danger'
    case 'high':
      return 'warn'
    case 'medium':
      return 'warn'
    case 'low':
      return 'neutral'
    default:
      return 'neutral'
  }
}

function severityLabel(row: BlockRow): string {
  if (!row.severity) return '—'
  return row.severity_downgraded ? `${row.severity} ↓warn` : row.severity
}

function decisionLabel(internal: string | undefined): string {
  return internal && internal.length > 0 ? internal : '—'
}

export function RecentBlocks({ bridge, t, polling, pollingPausedRef }: RecentBlocksProps): ReactNode {
  const [limit, setLimit] = useState<Limit>(50)
  const [state, setState] = useState<State>({ kind: 'loading' })
  // Pagination: Load more accumulates additional pages on top of
  // the initial first page. `pages` is the rendered source;
  // `state.rows` stays as the first page for parity with the
  // auto-refresh path (the polled slice replaces it whole).
  //
  // Cursor: `offset` is the count of
  // rows already shown to the operator; the next `bridge.recentBlocks
  // ({ limit, offset })` call skips the newest `offset` matches and
  // returns the next `limit` older rows. The wire clamps the offset
  // to `[0, ∞)`; an out-of-range offset returns `[]` and the button
  // disappears on the next render.
  const [pages, setPages] = useState<BlockRow[]>([])
  const [offset, setOffset] = useState<number>(0)
  // The host returns a filter-aware total
  // alongside each page, used by the "Showing N of M blocks" footer
  // The total is stable for a given scope /
  // limit, but we refresh it on every page fetch so the footer
  // never lies if the file rotated between clicks.
  const [totalCount, setTotalCount] = useState<number>(0)
  // hasMore is heuristic: a page that returned a full `limit` rows
  // may have more; a short page means we've hit the file head.
  // This mirrors the `blocks-more` button and is
  // sufficient for the marketplace UI (the audit log is a flat
  // NDJSON tail).
  const [hasMore, setHasMore] = useState<boolean>(false)
  const [loadingMore, setLoadingMore] = useState<boolean>(false)
  const [expandedKeys, setExpandedKeys] = useState<ReadonlySet<string>>(new Set())
  // Raw detail cache keyed by rowKey. Populated lazily on first
  // expand via one `includeRaw` fetch; the summary-mode 3 s poll
  // never pays for these bytes.
  const [rawDetails, setRawDetails] = useState<ReadonlyMap<string, string>>(new Map())
  // Per-row copy-feedback: 'idle' = button shows the default
  // label; 'ok' / 'fail' show the translated toast line so the
  // operator gets immediate confirmation that the JSON landed in
  // the clipboard (or didn't, with the failure reason). Per-row
  // state is required because a page may have multiple rows
  // expanded simultaneously. The optional `error` field carries
  // the clipboard failure detail so the button label can render
  // the exact reason without an extra side-channel ref.
  interface CopyState {
    status: 'idle' | 'ok' | 'fail'
    error?: string
  }
  const [copyState, setCopyState] = useState<ReadonlyMap<string, CopyState>>(new Map())

  useEffect(() => {
    let cancelled = false
    setState({ kind: 'loading' })
    setPages([])
    setOffset(0)
    setTotalCount(0)
    setHasMore(false)
    setLoadingMore(false)
    bridge
      // Policy Hits scope covers all rule hits (including warn-level
      // markings and runtime subprocess layer), not only blocked
      // tool calls. Load more cursor: offset=0 → first page. The
      // host returns `{ rows, total }`; `total` is the filter-aware
      // count for the footer.
      .recentBlocks({ limit, offset: 0, scope: 'all-hits' })
      .then((page) => {
        if (cancelled) return
        const rows = page.rows
        setPages(rows)
        setOffset(rows.length)
        setTotalCount(page.total)
        setHasMore(rows.length === limit)
        setState({ kind: 'ready', rows })
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            kind: 'error',
            message: t('load_error') + ` [${err instanceof Error ? err.message : String(err)}]`,
          })
        }
      })
    return () => {
      cancelled = true
    }
  }, [bridge, limit, t])

  // Memory hygiene: when the expanded set shrinks (row closed or
  // rotated out of the tail window) drop the per-row caches and
  // any pending copy-reset timer. Unmount also clears everything.
  // The raw payload for one row can be tens of KB; without this a
  // long session that expands and closes dozens of rows would
  // accumulate unbounded state until tab switch.
  useEffect(() => {
    setRawDetails((prev) => {
      if (prev.size === 0) return prev
      const next = new Map<string, string>()
      for (const key of prev.keys()) {
        if (expandedKeys.has(key)) next.set(key, prev.get(key) as string)
      }
      return next.size === prev.size ? prev : next
    })
    setCopyState((prev) => {
      if (prev.size === 0) return prev
      const next = new Map<string, CopyState>()
      for (const key of prev.keys()) {
        if (expandedKeys.has(key)) next.set(key, prev.get(key) as CopyState)
      }
      return next.size === prev.size ? prev : next
    })
    // Cancel any pending copy-reset timer whose key is no longer
    // expanded; otherwise a stale reset would setState after the row
    // is closed (warning + wasted render).
    const timers = copyTimersRef.current
    for (const key of Array.from(timers.keys())) {
      if (!expandedKeys.has(key)) {
        clearTimeout(timers.get(key) as ReturnType<typeof setTimeout>)
        timers.delete(key)
      }
    }
  }, [expandedKeys])
  useEffect(() => {
    const timers = copyTimersRef.current
    return () => {
      for (const tmr of timers.values()) clearTimeout(tmr)
      timers.clear()
    }
  }, [])

  // Auto-refresh while Top Blocks is active. The limit is captured
  // at register time (closure); a limit change re-runs the above
  // effect and re-registers the callback with the new limit (the
  // polling context replaces by id). Pagination: auto-refresh
  // re-fetches only the first page and merges any new rows onto
  // the head of the accumulated tail (preserves the user's Load
  // more progress).
  useEffect(() => {
    if (!polling) return
    let cancelled = false
    const unregister = polling.register(
      'recent:recentBlocks',
      async () => {
        if (pollingPausedRef?.current) return
        try {
          // Always poll the FIRST page (offset=0) — auto-refresh
          // only adds new rows at the head. The accumulated tail
          // (Load more pages) is untouched: same row keys stay
          // anchored at their original positions.
          const fresh = await bridge.recentBlocks({ limit, offset: 0, scope: 'all-hits' })
          if (cancelled) return
          setPages((prev) => {
            // Defensive: auto-refresh tick can run against a
            // not-yet-initialised state slot in some React 18
            // batches; coerce to [] to keep the dedup path sane.
            // (Same guard as Events.tsx.)
            const safe = Array.isArray(prev) ? prev : []
            if (safe.length === 0) {
              setOffset(fresh.rows.length)
              setTotalCount(fresh.total)
              setHasMore(fresh.rows.length === limit)
              return fresh.rows
            }
            const seen = new Set(safe.map((r) => rowKeyOf(r)))
            const head = fresh.rows.filter((r) => !seen.has(rowKeyOf(r)))
            // Refresh the total on every poll so the footer stays
            // accurate if the file rotated between ticks.
            setTotalCount(fresh.total)
            return head.length > 0 ? [...head, ...safe] : safe
          })
          setState({ kind: 'ready', rows: fresh.rows })
        } catch {
          // Auto-refresh errors are swallowed; last good rows stay
          // visible. The manual limit selector triggers an explicit
          // re-fetch via the data effect above.
        }
      },
      // 与 Metrics 页统一为 10 s(产品决策):两个统计型
      // 页面刷新节奏一致,页头「自动刷新 Ns」提示与 section.tsx 的
      // TAB_REFRESH_SECONDS 同步维护。
      10_000,
    )
    return () => {
      cancelled = true
      unregister()
    }
  }, [bridge, limit, polling])

  // Load more: append another page (limit-sized) onto the tail of
  // the accumulated window. Bails early if the previous fetch
  // returned fewer than `limit` rows (nothing left to read) or
  // the user is already paginating (loadingMore guard).
  //
  // Cursor: pass `offset: prev.length`
  // to the host so it skips the rows we already have. We read the
  // offset from `pagesRef` (kept in lockstep with `pages`) so the
  // click handler sees the latest value synchronously — the React
  // `setState` updater approach raced the test environment's
  // microtask flushes.
  const pagesRef = useRef<BlockRow[]>([])
  useEffect(() => {
    pagesRef.current = pages
  }, [pages])
  const loadMore = (): void => {
    if (loadingMore || !hasMore) return
    setLoadingMore(true)
    const snapOffset = pagesRef.current.length
    bridge
      .recentBlocks({ limit, offset: snapOffset, scope: 'all-hits' })
      .then((page) => {
        setPages((prev) => {
          const rows = page.rows
          // Defensive: coerce to [] if a stale Load-more
          // click lands on a not-yet-initialised state slot
          // (same guard as Events.tsx).
          const safe = Array.isArray(prev) ? prev : []
          // Refresh the total on every page fetch so the footer
          // never lies if the file rotated between clicks.
          setTotalCount(page.total)
          if (rows.length === 0) {
            setHasMore(false)
            return safe
          }
          // The wire guarantees disjoint pages for a given (offset,
          // limit) pair; we still dedup defensively in case the
          // audit log rotated between clicks.
          const seen = new Set(safe.map((r) => rowKeyOf(r)))
          const tail = rows.filter((r) => !seen.has(rowKeyOf(r)))
          if (tail.length === 0) {
            setHasMore(false)
            return safe
          }
          setOffset(safe.length + tail.length)
          setHasMore(tail.length === limit)
          return [...safe, ...tail]
        })
      })
      .catch(() => {
        // Swallow — Load more failure leaves the current page
        // intact. The user can retry the button.
      })
      .finally(() => setLoadingMore(false))
  }

  const rowKeyOf = (row: BlockRow): string =>
    `${row.ts}-${row.tool_call_id ?? row.session_id ?? ''}`

  /** 惰性明细:fetch the full raw event for one expanded row. Fired
   *  once per row key — the result lands in `rawDetails` and the
   *  detail region re-renders with the complete record. Failures
   *  (fetch error, row rotated out of the tail window) leave the
   *  summary fallback in place. */
  const loadRawDetail = (row: BlockRow): void => {
    const key = rowKeyOf(row)
    setRawDetails((prev) => {
      if (prev.has(key)) return prev
      bridge
        .recentBlocks({ limit, scope: 'all-hits', includeRaw: true })
        .then((page) => {
          // `recentBlocks` returns
          // `{ rows, total }`; the page rows are the lookup target.
          const match = page.rows.find((r) => rowKeyOf(r) === key)
          if (match?.raw_json) {
            setRawDetails((cur) => new Map(cur).set(key, match.raw_json as string))
          }
        })
        .catch(() => {
          // Detail stays on the summary fallback — never surface a
          // fetch error inside the expand region.
        })
      return prev
    })
  }

  // Track auto-reset timeouts per row so a stale reset never clobbers
  // a newer copy action (the closure-vs-Map race) and so unmount can
  // clear pending timers (no setState-after-unmount warnings).
  const copyTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  const toggleRow = (row: BlockRow): void => {
    const key = rowKeyOf(row)
    setExpandedKeys((prev) => {
      const next = new Set(prev)
      if (next.has(key)) {
        next.delete(key)
        if (pollingPausedRef) pollingPausedRef.current = false
      } else {
        next.add(key)
        if (pollingPausedRef) pollingPausedRef.current = true
        loadRawDetail(row)
      }
      return next
    })
  }

  // Copy the current row's expanded JSON to the clipboard. The
  // copied text is exactly what's rendered in the <pre> below —
  // prettyRawJson of the raw_json once the lazy `includeRaw`
  // fetch has landed. While the fetch is still in flight we block
  // the copy button rather than serialise the full row (which
  // would include internal fields not shown in the summary view);
  // the original fallback was a clipboard-content drift between
  // what the operator saw and what they pasted.
  const copyRowJson = (row: BlockRow): void => {
    const key = rowKeyOf(row)
    const raw = rawDetails.get(key)
    // Render-blocking when the raw payload isn't ready — the rendered
    // <pre> is the summary fallback, and copying the full row would
    // silently include internal fields the operator never saw.
    if (raw === undefined) {
      setCopyState((prev) => {
        const next = new Map(prev)
        next.set(key, { status: 'fail', error: 'raw detail not loaded' })
        return next
      })
      return
    }
    const text = prettyRawJson(raw)
    const clipboard = (
      globalThis as { navigator?: { clipboard?: { writeText(s: string): Promise<void> } } }
    ).navigator?.clipboard
    const applyStatus = (status: CopyState['status'], error?: string): void => {
      setCopyState((prev) => {
        const next = new Map(prev)
        next.set(key, { status, error })
        return next
      })
      // Auto-reset the badge after 2 s. We track the timer in a ref
      // so a fresh copy on the same key cancels the previous timer
      // (no stale reset clobbering the new state) and so unmount /
      // row-close can clear pending timers without setState-after-
      // unmount warnings.
      const delayMs = 2000
      const timers = copyTimersRef.current
      const prev = timers.get(key)
      if (prev) clearTimeout(prev)
      const tmr = setTimeout(() => {
        timers.delete(key)
        setCopyState((cur) => {
          if (cur.get(key)?.status !== status) return cur
          const next = new Map(cur)
          next.set(key, { status: 'idle' })
          return next
        })
      }, delayMs)
      timers.set(key, tmr)
    }
    if (clipboard && typeof clipboard.writeText === 'function') {
      clipboard
        .writeText(text)
        .then(() => applyStatus('ok'))
        .catch((err: unknown) => {
          // Surface the error inline so the operator doesn't have to
          // open devtools to see WHY the copy failed.
          const detail = err instanceof Error ? err.message : String(err)
          applyStatus('fail', detail)
        })
    } else {
      applyStatus('fail', t('copy_clipboard_unavailable'))
    }
  }

  if (state.kind === 'loading') {
    return createElement(
      'div',
      { className: 'dsh-secmon-recent' },
      createElement(Banner, { level: 'info', message: t('loading') }),
    )
  }
  if (state.kind === 'error') {
    return createElement(
      'div',
      { className: 'dsh-secmon-recent' },
      createElement(Banner, { level: 'error', message: state.message }),
    )
  }

  const columns: ReadonlyArray<TableColumn<BlockRow>> = [
    {
      key: 'time',
      header: t('recent_row_time'),
      render: (row) => formatTime((row as BlockRow).ts),
    },
    {
      key: 'tool',
      header: t('recent_row_tool'),
      // Runtime-layer hit rows lack tool_name; fall back to `spawn: <exe>`.
      render: (row) => {
        const r = row as BlockRow
        return r.tool_name ?? (r.exe ? `spawn: ${r.exe}` : '—')
      },
    },
    {
      key: 'decision',
      header: t('recent_col_decision'),
      cellClassName: 'dsh-secmon-recent-cell-decision',
      // Badge tone by internal decision: block/deny red, warn amber,
      // everything else neutral; label uses the internal decision
      // (warn level shows "warn" rather than "ask").
      render: (row) => {
        const r = row as BlockRow
        // 审计发现档行(security_audit)无 intervention 决策,
        // 决策列回退显示 audit_action(tamper / detect / …),否则这类行只有
        // 灰色的 "unknown",与事件页的"风险"徽标对不上。
        const internal = r.decision_internal ?? r.decision
        const label = internal !== 'unknown' ? internal : (r.audit_action ?? internal)
        return createElement(Badge, { tone: decisionTone(internal) }, decisionLabel(label))
      },
    },
    {
      // 规则严重等级列。critical/high 在 SEVERITY 列染成
      // 红/紫(与 DECISION 块的 danger/escalate tone 共用一调),
      // medium 琥珀,low 中性灰。`severity_downgraded:true` 时附加
      // `↓warn` 提示读者"该行由 block 降级而来"。
      key: 'severity',
      header: t('recent_col_severity'),
      cellClassName: 'dsh-secmon-recent-cell-severity',
      render: (row) => {
        const r = row as BlockRow
        if (!r.severity) return '—'
        return createElement(Badge, { tone: severityTone(r.severity) }, severityLabel(r))
      },
    },
    {
      key: 'policy',
      header: t('recent_col_policy'),
      cellClassName: 'dsh-secmon-recent-cell-policy',
      // Policy id in monospace emphasis colour.
      render: (row) =>
        createElement(
          'code',
          { className: 'dsh-secmon-policy-id' },
          (row as BlockRow).policy_id ?? '—',
        ),
    },
    {
      key: 'reason',
      header: t('recent_row_reason'),
      render: (row) => {
        const b = row as BlockRow
        // block_reason is a runtime-composed English sentence wrapped around
        // Chinese rule text (DecisionComposer.buildReason), so it reads wrong
        // in both languages. Prefer the per-policy_id copy; fall back to the
        // raw chain when nothing is registered (older policy, unseen engine
        // literal) so the column never goes blank.
        const localized = localizeReason(b.policy_id, b.block_reason, t)
        return localized !== ''
          ? localized
          : (b.block_reason ?? b.decision_internal ?? b.decision)
      },
    },
  ]

  const rows: BlockRow[] = pages.length > 0 ? pages : state.rows

  return createElement(
    'div',
    { className: 'dsh-secmon-recent' },
    createElement(
      Card,
      { title: t('tab_top_blocks') },
      createElement(
        'div',
        { className: 'dsh-secmon-recent-controls' },
        createElement('label', null, t('recent_limit_label'), ' '),
        createElement(
          'select',
          {
            value: String(limit),
            onChange: (ev: { target: { value: string } }) => {
              const next = Number.parseInt(ev.target.value, 10)
              if (LIMIT_OPTIONS.includes(next as Limit)) {
                setLimit(next as Limit)
              }
            },
          },
          ...LIMIT_OPTIONS.map((n) =>
            createElement('option', { key: n, value: String(n) }, String(n)),
          ),
        ),
        createElement('span', null, ' ', t('recent_limit_suffix')),
      ),
      createElement(Table, {
        columns: columns as ReadonlyArray<TableColumn<unknown>>,
        rows: rows as ReadonlyArray<unknown>,
        emptyText: t('recent_empty'),
        rowKey: (row) => rowKeyOf(row as BlockRow),
        onRowClick: (row) => toggleRow(row as BlockRow),
        isRowExpanded: (row) => expandedKeys.has(rowKeyOf(row as BlockRow)),
        // 惰性明细:the row's own summary fields render immediately
        // as the fallback; once the one-shot `includeRaw` fetch lands,
        // the region re-renders with the complete raw event. The
        // truncation hint mirrors the Events tab contract.
        renderExpanded: (row) => {
          const r = row as BlockRow
          const raw = rawDetails.get(rowKeyOf(r))
          const truncated = raw !== undefined && raw.endsWith('...[truncated]')
          // Copy affordance at the right end of the detail header. The
          // icon and aria-label both swap with the row's copy state
          // (idle / ok / fail). Mirrors the Events tab contract.
          const copy = copyState.get(rowKeyOf(r)) ?? { status: 'idle' }
          const iconSlot: IconButtonIcon =
            copy.status === 'ok'
              ? 'check'
              : copy.status === 'fail'
                ? 'alert'
                : 'copy'
          const iconLabel =
            copy.status === 'ok'
              ? t('copy_ok')
              : copy.status === 'fail'
                ? t('copy_fail', { error: copy.error ?? 'unknown' })
                : t('copy')
          return createElement(
            'div',
            {
              className: 'dsh-secmon-recent-detail',
              'data-component': 'recent-detail',
            },
            // Header row: title on the left, Copy icon-button on the right.
            // `align-items: center` keeps the icon and the title
            // text vertically aligned.
            createElement(
              'div',
              {
                className: 'dsh-secmon-recent-detail-header',
                'data-component': 'recent-detail-header',
              },
              createElement(
                'div',
                { className: 'dsh-secmon-recent-detail-title' },
                t('recent_detail'),
              ),
              createElement(IconButton, {
                onClick: () => copyRowJson(r),
                icon: iconSlot,
                label: iconLabel,
              }),
            ),
            createElement(
              'pre',
              { className: 'dsh-secmon-events-raw' },
              // raw_json 是紧凑序列化,过 prettyRawJson 重新缩进;
              // 截断行解析失败时按原样展示(与 Events tab 一致)。
              raw !== undefined ? prettyRawJson(raw) : JSON.stringify(r, null, 2),
            ),
            truncated
              ? createElement(
                  'div',
                  { className: 'dsh-secmon-events-truncated-hint' },
                  t('events_row_truncated_hint'),
                )
              : null,
          )
        },
      }),
      // Footer: counts + Load more + end marker. The Load more button
      // widens the visible window by one page at a time; the end
      // marker replaces it once the server runs out of rows. The
      // footer uses the shared
      // `load_more` / `loading_more` / `end_of_results` keys (no
      // per-tab duplicates — same as the Events tab).
      createElement(
        'div',
        { className: 'dsh-secmon-recent-footer', 'data-component': 'recent-footer' },
        createElement('span', null, t('showing_n_blocks', { n: rows.length, total: totalCount })),
        hasMore
          ? createElement(
              'button',
              {
                type: 'button',
                className: 'dsh-secmon-button dsh-secmon-button--secondary',
                onClick: loadMore,
                disabled: loadingMore,
                'data-component': 'recent-load-more',
              },
              loadingMore ? t('loading_more') : t('load_more'),
            )
          : createElement(
              'span',
              { className: 'dsh-secmon-recent-footer-end' },
              t('end_of_results'),
            ),
      ),
    ),
  )
}
