/**
 * Events tab — visual + column rework.
 *
 * Wire contract: `bridge.events({ limit: 50, filter })` — the
 * server-side filter carries only the committed event_type; the
 * `since` cut is applied client-side on `ts` (the wire EventsFilter
 * has no time predicate, and a client cut is exact because the rows
 * already carry their timestamps).
 *
 * Auto-refresh is preserved untouched: the tab re-fetches every
 * 30 s while active through the shared polling context.
 */
import {
  createElement,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type ReactNode,
} from 'react'
import type {
  SecurityMonitorBridge,
  RawEventRow,
  EventsFilter,
} from '../wire.js'
import type { LocaleKey } from '../locales.js'
import type { PollingContext } from '../usePolling.js'
import { Card, Table, Banner, Badge, IconButton, type IconButtonIcon, type BadgeTone, type TableColumn } from './primitives.js'

// Fixed per-page cap. The wire clamps to
// [1, 1000]; 50 matches the "limit 50 per page" hint.
const PAGE_LIMIT = 50

// mirrors the host allow-list
// (`src/typert/descriptors.ts#ALLOWED_EVENT_TYPES`). Keeping the
// client list in lockstep with the server list is mandatory — the
// server silently drops unknowns, so a stale client list would render
// dropdown entries that filter to zero rows on the wire (defensive UX
// is fine since the table shows the empty state instead of an error).
const EVENT_TYPE_OPTIONS = [
  'agent_tool_call',
  'agent_tool_result',
  'agent_message',
  'agent_session_start',
  'agent_stop',
  'agent_start',
  'network_http',
  'security_audit',
  'runtime_spawn_intent',
  'runtime_spawn_denied',
  'runtime_terminal_intent',
  'runtime_resolve_intent',
  'runtime_resolve_denied',
  'file_read',
  'file_write',
  'runtime_stdio_mirror',
  'runtime_stdio_mirror_exit',
  'runtime_stdio_mirror_error',
] as const

export interface EventsProps {
  bridge: SecurityMonitorBridge
  t: (key: LocaleKey, params?: Record<string, string | number>) => string
  /** Auto-refresh every 10 s while the Events tab is active.
   *  Optional for back-compat with isolated tests. */
  polling?: PollingContext | undefined
  /** Pause auto-refresh while any detail row is expanded (user is reading data). */
  pollingPausedRef?: React.MutableRefObject<boolean>
}

type State =
  | { kind: 'loading' }
  | { kind: 'ready'; rows: RawEventRow[] }
  | { kind: 'error'; message: string }

/** Parse the layer out of a raw event JSON without throwing — a
 *  malformed / truncated `raw_json` yields null (rendered as '—'). */
function extractLayer(row: RawEventRow): string | null {
  try {
    const parsed = JSON.parse(row.raw_json) as Record<string, unknown>
    return typeof parsed['layer'] === 'string' && parsed['layer'].length > 0
      ? parsed['layer']
      : null
  } catch {
    return null
  }
}

/** STATUS column: the raw `outcome` string (success/failure) is an
 *  operator-hostile vocabulary ("detector ran cleanly" reads as
 *  success even when it DETECTED something). The column renders
 *  a derived, display-only status parsed out of `raw_json`
 *  (`blocked` / `intervention.decision` / `audit_action` /
 *  `severity`) plus the wire `outcome`, by priority:
 *
 *    1. blocked    — blocked:true or outcome blocked/denied/block
 *                    → red 已拦截
 *    2. threat     — intervention decision warn/block/deny that was
 *                    NOT already caught by tier 1. 威胁
 *                    徽标与后端威胁统计同口径(纯决策谓词 isRuleHit)
 *                    ——severity 级审计事件不标"威胁",避免列表徽
 *                    标与 Metrics/Policy Hits 数字对不上。
 *    3. risk       — audit findings without an intervention decision:
 *                    tamper, outcome failure, severity ≥ high, or
 *                    detect/warn at medium (behavioural findings)
 *    4. ok         — outcome allow/success or severity info/low
 *    5. none       — anything else (lifecycle events) → '—'
 *
 *  徽标色调与 Policy Hits「严重等级」列同表(severityTone,
 *  RecentBlocks.tsx):标签按决策、颜色按 `intervention.severity`。
 *  critical → 红;high / medium → 琥珀;low / 缺省 → 灰。因此同一条
 *  warn+medium 事件在两个页面读出一致(琥珀),不出现事件页红、
 *  Policy Hits 黄的分裂。blocked 始终红色(处置结果,不随等级变化)。 */
type DerivedStatus = 'blocked' | 'threat' | 'risk' | 'ok' | 'none'

/** Severity ranks for the tier comparisons below. */
const SEVERITY_RANK: Readonly<Record<string, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** Pull the status-relevant fields out of the row's raw event JSON
 *  without throwing — malformed / truncated JSON yields empties. The
 *  wire row does not flatten severity/blocked/audit_action/intervention. */
function extractStatusFields(row: RawEventRow): {
  blocked: boolean
  decision: string
  auditAction: string
  severity: string
} {
  try {
    const parsed = JSON.parse(row.raw_json) as Record<string, unknown>
    const intervention = parsed['intervention'] as
      | { decision?: string; decision_internal?: string; severity?: string }
      | undefined
    const topSeverity = parsed['severity']
    return {
      blocked: parsed['blocked'] === true,
      decision: String(
        intervention?.decision_internal ?? intervention?.decision ?? '',
      ).toLowerCase(),
      auditAction:
        typeof parsed['audit_action'] === 'string' ? parsed['audit_action'].toLowerCase() : '',
      // severity lives on the intervention block for rule hits and at
      // the top level for security_audit events — same resolution order
      // as toBlockRow / the Policy Hits severity column.
      severity:
        typeof intervention?.severity === 'string'
          ? intervention.severity.toLowerCase()
          : typeof topSeverity === 'string'
            ? topSeverity.toLowerCase()
            : '',
    }
  } catch {
    return { blocked: false, decision: '', auditAction: '', severity: '' }
  }
}

function deriveStatus(row: RawEventRow): DerivedStatus {
  const outcome = (row.outcome ?? '').toLowerCase()
  const { blocked, decision, auditAction, severity } = extractStatusFields(row)
  if (blocked || outcome === 'blocked' || outcome === 'denied' || outcome === 'block') {
    return 'blocked'
  }
  // 威胁徽标与后端威胁统计同口径:仅 intervention 决策
  // 命中(warn 标记未拦截;block/deny 未被上层拦截口径捕获时兜底)。
  if (decision === 'warn' || decision === 'block' || decision === 'deny') {
    return 'threat'
  }
  // 无决策的审计发现(tamper / 高危 / 检测命中)降为「风险」琥珀档。
  if (
    auditAction === 'tamper' ||
    outcome === 'failure' ||
    (SEVERITY_RANK[severity] ?? -1) >= SEVERITY_RANK['high']! ||
    ((auditAction === 'detect' || auditAction === 'warn') && severity === 'medium')
  ) {
    return 'risk'
  }
  if (outcome === 'allow' || outcome === 'success' || severity === 'info' || severity === 'low') {
    return 'ok'
  }
  return 'none'
}

/** Tone for the 威胁 tier — same lookup table as the Policy Hits
 *  severity column (severityTone in RecentBlocks.tsx): label follows
 *  the DECISION, the color follows the SEVERITY. A warn-marked hit
 *  downgraded to medium therefore reads amber on BOTH pages. */
function threatTone(severity: string): BadgeTone {
  // Identical lookup to the Policy Hits severity column (severityTone,
  // RecentBlocks.tsx): critical → red, high/medium → amber, low or
  // missing → neutral gray.
  switch (severity) {
    case 'critical':
      return 'danger'
    case 'high':
    case 'medium':
      return 'warn'
    default:
      return 'neutral'
  }
}

function statusTone(status: DerivedStatus, severity: string): BadgeTone {
  switch (status) {
    case 'blocked':
      // 处置结果,不随等级变化——拦截始终红色。
      return 'danger'
    case 'threat':
      return threatTone(severity)
    case 'risk':
      return 'warn'
    default:
      // ok + none both render neutral gray — see block comment above.
      return 'neutral'
  }
}

function statusLabel(status: DerivedStatus): LocaleKey | null {
  switch (status) {
    case 'blocked':
      return 'events_status_blocked'
    case 'threat':
      return 'events_status_threat'
    case 'risk':
      return 'events_status_risk'
    case 'ok':
      return 'events_status_ok'
    default:
      return null
  }
}

/** Pretty-print a raw event JSON for the expanded detail region:
 *  re-indent when the string parses, fall back to the verbatim string
 *  when parsing fails (truncated rows end mid-string and are NOT
 *  valid JSON). Shared by the Events tab and Policy Hits detail. */
export function prettyRawJson(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

export function Events({ bridge, t, polling, pollingPausedRef }: EventsProps): ReactNode {
  // Pending filter inputs — only the Apply button commits them into
  // `applied`, which is what the wire fetch + client-side since-cut
  // actually read.
  const [pendingType, setPendingType] = useState<string>('__all__')
  const [pendingSinceMin, setPendingSinceMin] = useState<string>('')
  const [applied, setApplied] = useState<{ type: string; sinceMin: number }>({
    type: '__all__',
    sinceMin: 0,
  })
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [expandedKeys, setExpandedKeys] = useState<ReadonlySet<string>>(new Set())
  // Per-row copy-feedback: 'idle' = default label; 'ok' / 'fail'
  // show the translated toast line so the operator gets immediate
  // confirmation that the JSON landed in the clipboard (or didn't,
  // with the failure reason). Per-row state is required because a
  // page may have multiple rows expanded simultaneously.
  interface CopyState {
    status: 'idle' | 'ok' | 'fail'
    error?: string
  }
  const [copyState, setCopyState] = useState<ReadonlyMap<string, CopyState>>(new Map())

  // Stable wire payload: rebuilt only when the committed filter
  // changes. `JSON.stringify` keeps the referential identity stable so
  // the effect below doesn't re-fetch on every render.
  const filter: EventsFilter = useMemo(() => {
    const f: EventsFilter = {}
    if (applied.type !== '__all__') {
      f.event_type = [applied.type]
    }
    return f
  }, [applied])

  // Fetch one page from the wire. The optional `offset` skips the
  // newest `offset` matches before returning the next `limit`
  // (Load more cursor). Caller is the data effect (first page) and
  // `loadMore` (subsequent pages). The host returns `{ rows, total }`
  // — `total` is the filter-aware count of all matching events in
  // the file, used by the "Showing N of M events" footer.
  const fetchEvents = (
    offset?: number,
  ): Promise<{ rows: RawEventRow[]; total: number }> =>
    bridge.events({
      limit: PAGE_LIMIT,
      ...(offset !== undefined ? { offset } : {}),
      filter: filter.event_type === undefined ? undefined : filter,
    })

  // Pagination state. The Events tab fetches the latest `limit`
  // rows per call; a Load more button widens the visible window
  // by another page until the server returns fewer than a full
  // page. The cursor is the count of rows already shown; the next
  // call passes it as `offset` so the host skips them.
  //
  // Offset-based cursor pagination.
  // (`offset` is honoured by the host; a client-side-only cursor
  // would make every Load more click re-fetch the first page and
  // dedup would eat the lot).
  const [pages, setPages] = useState<RawEventRow[]>([])
  const [offset, setOffset] = useState<number>(0)
  // Filter-aware total returned by the host on every page call —
  // drives the "Showing N of M events" footer. Stable across
  // Load more clicks (the same filter yields the same total).
  const [totalCount, setTotalCount] = useState<number>(0)
  // hasMore is heuristic: a page that returned a full `limit` rows
  // may have more; a short page means we've hit the file head.
  const [hasMore, setHasMore] = useState<boolean>(false)
  const [loadingMore, setLoadingMore] = useState<boolean>(false)
  // Track per-row copy-reset timers so a fresh copy cancels the
  // previous timer and row-close / unmount can clear pending ones
  // (no stale setState or setState-after-unmount warnings).
  const copyTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  // Reset paging + cache whenever the committed filter changes (Apply
  // or initial mount). The auto-refresh effect below keeps the first
  // page fresh without touching the rest of the accumulated tail.
  useEffect(() => {
    let cancelled = false
    setState({ kind: 'loading' })
    setPages([])
    setOffset(0)
    setTotalCount(0)
    setHasMore(false)
    setLoadingMore(false)
    fetchEvents(0)
      .then((page) => {
        if (cancelled) return
        const rows = page.rows
        setPages(rows)
        setOffset(rows.length)
        setTotalCount(page.total)
        // A full page implies there's likely more; the next
        // `loadMore` call will discover otherwise.
        setHasMore(rows.length === PAGE_LIMIT)
        setState({ kind: 'ready', rows })
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setState({
            kind: 'error',
            message:
              t('load_error') +
              ` [${err instanceof Error ? err.message : String(err)}]`,
          })
        }
      })
    return () => {
      cancelled = true
    }
    // We intentionally exclude `filter` (memoised) from the dep array —
    // `fetchEvents` recreates whenever one changes, and re-running on
    // every render would cause an infinite loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bridge, applied, t])

  // Auto-refresh while the Events tab is active. 30s interval: raw
  // events accumulate slowly (1 per tool call at most) so a tighter
  // interval would burn cycles without operator value. Tab gating
  // is handled by the polling context.
  useEffect(() => {
    if (!polling) return
    let cancelled = false
    const unregister = polling.register(
      'events:events',
      async () => {
        if (pollingPausedRef?.current) return
        try {
          // Always poll the FIRST page (offset=0) — auto-refresh
          // only adds new rows at the head. The accumulated tail
          // (Load more pages) is untouched: same row keys stay
          // anchored at their original positions.
          const fresh = await fetchEvents(0)
          if (cancelled) return
          setPages((prev) => {
            // Defensive: if the auto-refresh tick
            // fires against a state slot React hasn't yet
            // initialised (filter-change effect just called
            // `setPages([])` in the same batch, the updater can see
            // `undefined` on the next render in some React 18
            // edge cases). Coerce to [] so the dedup path still
            // converges.
            const safe = Array.isArray(prev) ? prev : []
            if (safe.length === 0) {
              setOffset(fresh.rows.length)
              setTotalCount(fresh.total)
              setHasMore(fresh.rows.length === PAGE_LIMIT)
              return fresh.rows
            }
            // New rows are at the head (newest-first). Skip duplicates
            // by rowKey so the tail that the user paginated into
            // stays anchored to the same records.
            const seen = new Set(safe.map((r) => rowKeyOf(r)))
            const head = fresh.rows.filter((r) => !seen.has(rowKeyOf(r)))
            // The total is filter-stable, so refresh it too (the
            // file may have grown or events rotated).
            setTotalCount(fresh.total)
            return head.length > 0 ? [...head, ...safe] : safe
          })
          setState({ kind: 'ready', rows: pages })
        } catch {
          // Auto-refresh errors are swallowed; last good rows stay
          // visible. The Apply button triggers an explicit re-fetch
          // via the data effect above.
        }
      },
      30_000,
    )
    return () => {
      cancelled = true
      unregister()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bridge, applied, polling])

  // Client-side `since` cut on the committed value. Applied at render
  // time so both the initial fetch and every auto-refresh tick honour
  // it without extra wire round-trips. Pagination: render from the
  // accumulated `pages` array (Load more widens this), not from
  // `state.rows` (always the latest first page only).
  const visibleRows: RawEventRow[] = useMemo(() => {
    if (state.kind !== 'ready') return []
    const source = pages.length > 0 ? pages : state.rows
    if (applied.sinceMin <= 0) return source
    const cutoff = Date.now() - applied.sinceMin * 60_000
    return source.filter((row) => Number.isFinite(row.ts) && row.ts >= cutoff)
  }, [state, pages, applied.sinceMin])

  // Load more — appends the next page (one limit-sized chunk) to
  // `pages`. Bails early if the previous fetch returned fewer than
  // `limit` rows (nothing left to read) or the user is already
  // paginating (loadingMore guard).
  //
  // Cursor: pass `offset: prev.length`
  // to the host so it skips the rows we already have. We read the
  // offset from `pagesRef` (a ref kept in
  // lockstep with the `pages` state) so the click handler sees the
  // latest value synchronously — the React `setState` updater
  // approach raced the test environment's microtask flushes.
  const pagesRef = useRef<RawEventRow[]>([])
  useEffect(() => {
    pagesRef.current = pages
  }, [pages])
  const loadMore = (): void => {
    if (loadingMore || !hasMore) return
    setLoadingMore(true)
    const snapOffset = pagesRef.current.length
    fetchEvents(snapOffset)
      .then((page) => {
        setPages((prev) => {
          const rows = page.rows
          // Defensive: a stale Load-more click
          // against a state slot React hasn't initialised
          // would crash on `prev.length`. Coerce to [].
          const safe = Array.isArray(prev) ? prev : []
          // Refresh the total on every page fetch so the footer
          // never lies even if events rotated between clicks.
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
          setHasMore(tail.length === PAGE_LIMIT)
          return [...safe, ...tail]
        })
      })
      .catch(() => {
        // Swallow — Load more failure leaves the current page intact.
        // The user can retry the button.
      })
      .finally(() => setLoadingMore(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }

  const rowKeyOf = (row: RawEventRow): string =>
    `${row.ts}-${row.event_id ?? ''}-${row.event_type}`

  const toggleRow = (row: RawEventRow): void => {
    const key = rowKeyOf(row)
    setExpandedKeys((prev) => {
      const next = new Set(prev)
      if (next.has(key)) {
        next.delete(key)
        if (pollingPausedRef) pollingPausedRef.current = false
      } else {
        next.add(key)
        if (pollingPausedRef) pollingPausedRef.current = true
      }
      return next
    })
  }

  // Copy the current row's expanded JSON to the clipboard. Mirrors
  // the Recent Blocks tab: the copied text is exactly what is
  // rendered in the <pre> below (prettyRawJson), so pasting it back
  // into a JSON viewer / bug report reproduces what the operator
  // is looking at. Auto-resets the per-row badge to 'idle' after
  // 2 s; a fresh click in that window overrides the pending reset
  // so a fast double-click doesn't get its label clobbered.
  const copyRowJson = (row: RawEventRow): void => {
    const key = rowKeyOf(row)
    // Capture the raw_json string at click time so a bridge-side
    // mutation of `row.raw_json` between click and the clipboard
    // write cannot change what we copy. The captured value is
    // also what the operator visually confirmed in the <pre>.
    const text = prettyRawJson(row.raw_json)
    const clipboard = (
      globalThis as { navigator?: { clipboard?: { writeText(s: string): Promise<void> } } }
    ).navigator?.clipboard
    const applyStatus = (status: CopyState['status'], error?: string): void => {
      setCopyState((prev) => {
        const next = new Map(prev)
        next.set(key, { status, error })
        return next
      })
      const delayMs = 2000
      const timers = copyTimersRef.current
      const prev = timers.get(key)
      if (prev) clearTimeout(prev)
      const tmr = setTimeout(() => {
        timers.delete(key)
        setCopyState((cur) => {
          // Only auto-reset if the badge hasn't been re-set by a
          // newer copy action; otherwise the new "ok" would be
          // overwritten by a stale "idle".
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
          const detail = err instanceof Error ? err.message : String(err)
          applyStatus('fail', detail)
        })
    } else {
      applyStatus('fail', 'clipboard unavailable')
    }
  }

  // Memory hygiene: when the expanded set shrinks (row closed),
  // drop the per-row copyState entry. Without this a long session
  // that opens and closes dozens of detail rows would accumulate
  // the map indefinitely. The filter-change effect also resets
  // pages (which closes all rows via re-render).
  useEffect(() => {
    setCopyState((prev) => {
      if (prev.size === 0) return prev
      const next = new Map<string, CopyState>()
      for (const key of prev.keys()) {
        if (expandedKeys.has(key)) next.set(key, prev.get(key) as CopyState)
      }
      return next.size === prev.size ? prev : next
    })
    // Cancel any pending copy-reset timer whose row is no longer
    // expanded; otherwise a stale reset fires setState on a row the
    // operator has already closed.
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

  if (state.kind === 'loading') {
    return createElement(
      'div',
      { className: 'dsh-secmon-events' },
      createElement(Banner, { level: 'info', message: t('loading') }),
    )
  }
  if (state.kind === 'error') {
    return createElement(
      'div',
      { className: 'dsh-secmon-events' },
      createElement(Banner, { level: 'error', message: state.message }),
    )
  }

  const columns: ReadonlyArray<TableColumn<RawEventRow>> = [
    {
      key: 'time',
      header: t('events_col_time'),
      render: (row) => formatTime(row.ts),
    },
    {
      key: 'type',
      header: t('events_col_type'),
      cellClassName: 'dsh-secmon-events-cell-type',
      render: (row) => row.event_type,
    },
    {
      key: 'layer',
      header: t('events_col_layer'),
      cellClassName: 'dsh-secmon-events-cell-layer',
      render: (row) => extractLayer(row) ?? '—',
    },
    {
      key: 'agent',
      header: t('events_col_agent'),
      render: (row) => row.agent_id ?? '—',
    },
    {
      key: 'tool_session',
      header: t('events_col_tool_session'),
      render: (row) =>
        row.tool_name
          ? `${row.tool_name}${row.session_id ? ` / ${row.session_id}` : ''}`
          : (row.session_id ?? '—'),
    },
    {
      key: 'status',
      header: t('events_col_status'),
      cellClassName: 'dsh-secmon-events-cell-status',
      render: (row) => {
        const status = deriveStatus(row)
        const labelKey = statusLabel(status)
        const severity = extractStatusFields(row).severity
        return createElement(
          Badge,
          { tone: statusTone(status, severity) },
          labelKey === null ? '—' : t(labelKey),
        )
      },
    },
  ]

  return createElement(
    'div',
    { className: 'dsh-secmon-events' },
    createElement(
      Card,
      { title: t('tab_event_stream') },
      // Filter bar: event_type dropdown + since (minutes ago)
      // + green Apply; right side the per-page hint.
      createElement(
        'div',
        { className: 'dsh-secmon-events-controls', 'data-component': 'events-controls' },
        createElement(
          'div',
          { className: 'dsh-secmon-events-filter-bar' },
          createElement(
            'label',
            { className: 'dsh-secmon-events-filter' },
            createElement('span', null, t('events_filter_type')),
            createElement(
              'select',
              {
                value: pendingType,
                onChange: (ev: ChangeEvent<HTMLSelectElement>) => setPendingType(ev.target.value),
              },
              createElement('option', { value: '__all__' }, t('events_no_filter')),
              ...EVENT_TYPE_OPTIONS.map((type) =>
                createElement('option', { key: type, value: type }, type),
              ),
            ),
          ),
          createElement(
            'label',
            { className: 'dsh-secmon-events-filter' },
            createElement('span', null, t('events_filter_since')),
            createElement('input', {
              type: 'number',
              min: 0,
              value: pendingSinceMin,
              placeholder: '0',
              onChange: (ev: ChangeEvent<HTMLInputElement>) => setPendingSinceMin(ev.target.value),
            }),
          ),
          createElement(
            'span',
            { 'data-component': 'events-apply' },
            createElement(
              'button',
              {
                type: 'button',
                className: 'dsh-secmon-button dsh-secmon-button--success',
                onClick: () => {
                  const since = Number.parseInt(pendingSinceMin, 10)
                  setApplied({
                    type: pendingType,
                    sinceMin: Number.isFinite(since) && since > 0 ? since : 0,
                  })
                },
              },
              t('events_apply'),
            ),
          ),
        ),
        createElement(
          'div',
          { className: 'dsh-secmon-events-controls-right' },
          createElement('span', { className: 'dsh-secmon-events-per-page' }, t('events_per_page')),
        ),
      ),
      createElement(Table, {
        columns: columns as ReadonlyArray<TableColumn<unknown>>,
        rows: visibleRows as ReadonlyArray<unknown>,
        emptyText: t('events_empty'),
        rowKey: (row) => rowKeyOf(row as RawEventRow),
        onRowClick: (row) => toggleRow(row as RawEventRow),
        isRowExpanded: (row) => expandedKeys.has(rowKeyOf(row as RawEventRow)),
        renderExpanded: (row) => {
          const r = row as RawEventRow
          // Copy affordance at the right end of the detail header.
          // The visual icon and the screen-reader label both swap
          // with the row's copy state (idle / ok / fail). Click
          // feedback is purely the icon swap — there's no text
          // rendering inside the button, so the common
          // `<pre>`-next-to-button layout never shifts.
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
              className: 'dsh-secmon-events-detail',
              'data-component': 'events-detail',
            },
            // Header row: title on the left, Copy icon-button on the right.
            // `align-items: center` keeps the icon and the title
            // text vertically aligned.
            createElement(
              'div',
              {
                className: 'dsh-secmon-events-detail-header',
                'data-component': 'events-detail-header',
              },
              createElement(
                'div',
                { className: 'dsh-secmon-events-detail-title' },
                t('events_detail'),
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
              prettyRawJson(r.raw_json),
            ),
            r.raw_json.endsWith('...[truncated]')
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
      // `load_more` / `loading_more` / `end_of_results` / `showing_n`
      // keys (no per-tab duplicates — same as the Policy Hits tab).
      createElement(
        'div',
        { className: 'dsh-secmon-events-footer', 'data-component': 'events-footer' },
        createElement(
          'span',
          null,
          t('showing_n', { n: visibleRows.length, total: totalCount }),
        ),
        hasMore
          ? createElement(
              'button',
              {
                type: 'button',
                className: 'dsh-secmon-button dsh-secmon-button--secondary',
                onClick: loadMore,
                disabled: loadingMore,
                'data-component': 'events-load-more',
              },
              loadingMore ? t('loading_more') : t('load_more'),
            )
          : createElement(
              'span',
              { className: 'dsh-secmon-events-footer-end' },
              t('end_of_results'),
            ),
      ),
    ),
  )
}

function formatTime(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '—'
  try {
    return new Date(ms).toISOString().replace('T', ' ').slice(0, 19)
  } catch {
    return String(ms)
  }
}
