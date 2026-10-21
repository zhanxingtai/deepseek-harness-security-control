/**
 * Metrics tab — visual rework.
 *
 * Design baseline: the approved design screenshot for this tab is
 * mandatory. Layout:
 *
 *   - Stat card row (gray rounded cards, horizontal ×3): Total events
 *     (`totalEvents`) / Last 24h (`last24hTotalCount`) / Blocked
 *     (`blockCount`, number in red).
 *   - "BY LAYER" panel (gray background, small bold title): one row per
 *     `<layer>: <count>`; counts render in the brown-orange emphasis
 *     tone; data comes from the wire `byLayer` record; empty → the
 *     "no data yet" placeholder.
 *   - Meta line under the BY LAYER panel: mode · SPL
 *     rules loaded · uptime (the layout folds the former
 *     full stat cards into one small line).
 *   - Bottom-right `Last updated: HH:MM:SS` — stamped on every
 *     successful snapshot load (manual, initial, or polling tick).
 *
 * Data is read from `bridge.overview()`; auto-refresh stays on the
 * shared polling context (5 s). The policy Reload action is kept —
 * the operator still needs a manual re-check of `loadedRuleCount` after
 * editing policy files on disk.
 */
import { createElement, useEffect, useState, type ReactNode } from 'react'
import type { SecurityMonitorBridge, OverviewSnapshot } from '../wire.js'
import type { LocaleKey } from '../locales.js'
import type { PollingContext } from '../usePolling.js'
import { Card, Stat, Button, Banner } from './primitives.js'
import { QrModal } from './QrModal.js'

export interface OverviewProps {
  bridge: SecurityMonitorBridge
  t: (key: LocaleKey, params?: Record<string, string | number>) => string
  /** Optional pre-loaded snapshot. When undefined, the component fetches
   *  on mount; when provided, the component uses it directly. The
   *  parent uses the prop form to pre-warm the first paint with data
   *  fetched outside the section's mount cycle. */
  initial?: OverviewSnapshot | undefined
  /** Auto-refresh every 5 s while the Metrics tab
   *  is active. Optional for back-compat with the existing tests; when
   *  absent (e.g. in isolation), the component falls back to the
   *  manual "Reload policy" button only. */
  polling?: PollingContext | undefined
}

type State =
  | { kind: 'loading' }
  | { kind: 'ready'; snapshot: OverviewSnapshot }
  | { kind: 'error'; message: string }

export function Overview({ bridge, t, initial, polling }: OverviewProps): ReactNode {
  const [state, setState] = useState<State>(
    initial ? { kind: 'ready', snapshot: initial } : { kind: 'loading' },
  )
  const [reloading, setReloading] = useState(false)
  const [reloadMessage, setReloadMessage] = useState<string | null>(null)
  // "Last updated: HH:MM:SS" stamps on every
  // successful snapshot resolution so the operator can tell a live
  // page from a stalled bridge.
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  // Metrics 页脚「关注公众号」触发二维码模态。
  // 模态层通过 React portal 挂到 document.body 末，避开 Metrics 自动
  // 刷新（每 5s 重写 panel DOM）销毁打开中的预览。
  const [showQr, setShowQr] = useState(false)

  useEffect(() => {
    if (initial) return
    let cancelled = false
    bridge
      .overview()
      .then((snapshot) => {
        if (!cancelled) {
          setState({ kind: 'ready', snapshot })
          setLastUpdated(Date.now())
        }
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
  }, [bridge, initial, t])

  // Auto-refresh while Metrics is active. The
  // shared polling context owns the central timer; we register a
  // refresh callback that re-fetches the snapshot and ignores the
  // result if the component has unmounted. We deliberately do NOT
  // touch the `state` setter from outside the effect — the `cancelled`
  // flag prevents late resolutions from clobbering an error state.
  useEffect(() => {
    if (!polling) return
    let cancelled = false
    const unregister = polling.register(
      'overview:overview',
      async () => {
        try {
          const snapshot = await bridge.overview()
          if (!cancelled) {
            setState({ kind: 'ready', snapshot })
            setLastUpdated(Date.now())
          }
        } catch {
          // Auto-refresh errors are swallowed silently — the existing
          // `state` already holds the last good snapshot, and the
          // next tick will retry. The manual Reload button surfaces
          // explicit failures.
        }
      },
      // 与 Policy Hits 页统一为 10 s,与 section.tsx 的
      // TAB_REFRESH_SECONDS.overview 同步维护。
      10_000,
    )
    return () => {
      cancelled = true
      unregister()
    }
  }, [bridge, polling])

  if (state.kind === 'loading') {
    return createElement(
      'div',
      { className: 'dsh-secmon-overview' },
      createElement(Banner, { level: 'info', message: t('loading') }),
    )
  }
  if (state.kind === 'error') {
    return createElement(
      'div',
      { className: 'dsh-secmon-overview' },
      createElement(Banner, { level: 'error', message: state.message }),
    )
  }

  const s = state.snapshot
  const modeLabel = s.mode === 'enforce' ? t('mode_enforce') : t('mode_audit')
  const uptimeLabel = formatUptime(s.uptimeSec, t)
  const layerEntries = Object.entries(s.byLayer).sort((a, b) => b[1] - a[1])

  return createElement(
    'div',
    { className: 'dsh-secmon-overview' },
    createElement(
      Card,
      { title: t('tab_metrics') },
      // Stat card row: Total / Last 24h / Blocked
      // (Blocked number in red via the danger tone).
      // 第 4 张「威胁事件」卡片:规则命中(含 warn 级
      // 标记未拦截,拦截是其子集)。顺序按 总 / 24h / 拦截 / 威胁事件;
      // 数字颜色使用 accent 琥珀强调色(与 BY LAYER 计数同款,
      // 见 styles.ts --accent),区别于拦截的 danger 红。
      createElement(
        'div',
        { className: 'dsh-secmon-stats' },
        createElement(Stat, { label: t('total_events'), value: s.totalEvents }),
        createElement(Stat, { label: t('metrics_last_24h'), value: s.last24hTotalCount }),
        createElement(Stat, {
          label: t('metrics_blocked'),
          value: s.blockCount,
          tone: 'danger',
        }),
        createElement(Stat, {
          label: t('metrics_threat_events'),
          value: s.threatCount,
          tone: 'accent',
        }),
      ),
      // BY LAYER panel — one `<layer>: <count>` row per bucket; the
      // count renders in the emphasis tone. Empty record → placeholder.
      createElement(
        'div',
        { className: 'dsh-secmon-metrics-by-layer', 'data-component': 'metrics-by-layer' },
        createElement('h4', { className: 'dsh-secmon-metrics-by-layer-title' }, t('metrics_by_layer')),
        layerEntries.length === 0
          ? createElement(
              'div',
              { className: 'dsh-secmon-metrics-by-layer-empty' },
              t('metrics_no_data'),
            )
          : createElement(
              'dl',
              { className: 'dsh-secmon-metrics-by-layer-list' },
              layerEntries.map(([layer, count]) =>
                createElement(
                  'div',
                  { key: layer, className: 'dsh-secmon-metrics-by-layer-row' },
                  createElement('dt', null, layer),
                  createElement('dd', { className: 'dsh-secmon-stat-value--accent' }, String(count)),
                ),
              ),
            ),
      ),
      // Meta line — mode / rules / uptime folded into one
      // small line under the BY LAYER panel.
      createElement(
        'div',
        { className: 'dsh-secmon-metrics-meta', 'data-component': 'metrics-meta' },
        t('metrics_meta_line', { mode: modeLabel, rules: s.loadedRuleCount, uptime: uptimeLabel }),
      ),
      createElement(
        'div',
        { className: 'dsh-secmon-metrics-footer' },
        createElement(
          'div',
          { className: 'dsh-secmon-actions' },
          createElement(Button, {
            onClick: async () => {
              setReloading(true)
              setReloadMessage(null)
              try {
                const result = await bridge.reload()
                if (result.ok) {
                  setReloadMessage(
                    t('policy_reload_ok', { n: result.ruleCount ?? 0 }),
                  )
                  // Go through the shared polling
                  // context's `trigger` so the post-reload refresh is
                  // rate-limited the same way as a periodic tick. If no
                  // polling context is wired, fall back to a direct call.
                  if (polling) {
                    await polling.trigger('overview:overview')
                  } else {
                    const next = await bridge.overview()
                    setState({ kind: 'ready', snapshot: next })
                    setLastUpdated(Date.now())
                  }
                } else {
                  setReloadMessage(
                    t('policy_reload_fail', { err: result.error ?? 'unknown' }),
                  )
                }
              } catch (err: unknown) {
                setReloadMessage(
                  t('policy_reload_fail', {
                    err: err instanceof Error ? err.message : String(err),
                  }),
                )
              } finally {
                setReloading(false)
              }
            },
            disabled: reloading,
            children: reloading ? t('reloading') : t('reload'),
          }),
        ),
        // Metrics 页脚右对齐「访问官网」入口
        // `metrics-footer` 形态（见 the marketplace presentation
        // spec §2)。`margin-left:auto` 让链接右对齐，与 Reload 按钮
        // 共存。
        createElement(
          'div',
          { className: 'dsh-secmon-metrics-footer-links', 'data-component': 'metrics-footer-links' },
          createElement(
            'a',
            {
              href: 'https://www.zhihuizhanxing.com',
              target: '_blank',
              rel: 'noopener noreferrer',
              'data-component': 'metrics-footer-website',
            },
            t('metrics_footer_website'),
          ),
          createElement(
            'button',
            {
              type: 'button',
              onClick: () => setShowQr(true),
              'data-component': 'metrics-footer-wechat',
            },
            t('metrics_footer_wechat'),
          ),
        ),
      ),
      reloadMessage
        ? createElement(Banner, {
            level: 'info',
            message: reloadMessage,
          })
        : null,
    ),
    // Last updated — bottom-right of the tab page, stamped on every
    // successful fetch.
    lastUpdated === null
      ? null
      : createElement(
          'div',
          {
            className: 'dsh-secmon-metrics-last-updated',
            'data-component': 'metrics-last-updated',
          },
          `${t('metrics_last_updated')}: ${formatClock(lastUpdated)}`,
        ),
    // 公众号二维码模态层（portal 到 body 末
    // 避开 Metrics 自动刷新销毁）。放在 return 的尾部（与 last-updated
    // 平级），不进任何 footer 容器，确保 portal 不被 innerHTML 重写。
    createElement(QrModal, {
      open: showQr,
      onClose: () => setShowQr(false),
      t,
    }),
  )
}

/** Format uptime seconds into a locale-aware string. The placeholder
 *  `t('uptime_*')` keys accept positional `{n}` / `{h}` / `{m}`
 *  placeholders. Below 60s → seconds; below 60m → minutes; otherwise
 *  hours + minutes. */
function formatUptime(
  seconds: number,
  t: (key: LocaleKey, params?: Record<string, string | number>) => string,
): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—'
  if (seconds < 60) return t('uptime_seconds', { n: Math.floor(seconds) })
  if (seconds < 60 * 60) return t('uptime_minutes', { n: Math.floor(seconds / 60) })
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return t('uptime_hours', { h: hours, m: minutes })
}

/** `HH:MM:SS` local-time rendering for the Last-updated stamp. Manual
 *  zero-padding keeps the output identical across locales. */
function formatClock(ms: number): string {
  const d = new Date(ms)
  const p = (n: number): string => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
