/**
 * SecurityMonitorSection.
 *
 * The inner React component rendered by `SecurityMonitorPage` for
 * the `main` slot registration. Receives `{ bridge, t }` from the
 * slot registration's `inject: () => ({ bridge, t })` clause, where:
 *
 *   - `bridge` is the host's Remote namespace
 *     (`ctx.remote.securityMonitor`) obtained via
 *     `ctx.inject(['remote.securityMonitor'], ...)`.
 *   - `t` is the locale bind function for the
 *     `settings.securityMonitor` namespace.
 *
 * Renders the 4 tabs — Metrics / Event Stream / Top Blocks / Config —
 * and delegates the body of each tab to the dedicated component in
 * `./components/`. The internal tab ids keep their historical keys
 * (`overview` / `events` / `recent` / `config`) so tab-scoped polling
 * registrations survive the rename. The active tab lives in component
 * state.
 *
 * The Config tab is a read-only mirror of the host's
 * current `Config` (via `bridge.getConfig()`); the client layers a
 * draft edit on top, then live-patch after signoff. This
 * file only knows the tab exists; the read-only render lives in
 * `./components/Config.js`.
 *
 * The component ships rendered through `SecurityMonitorPage` for the
 * `main` keyed-slot so all tab content / bridge fallback / load-error
 * semantics stay in one place.
 */
import { createElement, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import type { SecurityMonitorBridge } from './wire.js'
import type { LocaleKey } from './locales.js'
import { PACKAGE_VERSION } from './buildInfo.js'
import { hardReload } from './hardReload.js'
import { Tabs, Banner, PageHeader } from './components/primitives.js'
import { SecurityMonitorIcon } from './components/SecurityMonitorIcon.js'
import { Overview } from './components/Overview.js'
import { RecentBlocks } from './components/RecentBlocks.js'
import { Config } from './components/Config.js'
import { Events } from './components/Events.js'
import {
  createPollingContext,
  usePolling,
  type PollingContext,
} from './usePolling.js'

export interface SecurityMonitorSectionProps {
  /**
   * The host's `remote.securityMonitor` namespace. Undefined on
   * marketplace hosts that do not register that peer — the section
   * still mounts, but every tab renders its load-error banner. The
   * card must mount before any tabs read from it.
   */
  bridge?: SecurityMonitorBridge
  /**
   * Re-resolver for the mount-vs-render race. `ctx.remote.$mount` is
   * async (`src/client/remote.ts`); when
   * the slot renders before the mount settles, `bridge` arrives as
   * undefined. The section polls this thunk briefly and swaps the
   * fallback banner for live tabs once the namespace appears.
   */
  resolveBridge?: () => SecurityMonitorBridge | undefined
  t: (key: LocaleKey, params?: Record<string, string | number>) => string
}

// Tab strip. The four ids keep their historical keys so the
// tab-scoped polling registrations ('overview:overview',
// 'events:events', 'recent:recent') and the default-active Metrics
// tab survive the rename. Display order is Metrics / Event Stream /
// Top Blocks / Config.
const TAB_IDS = ['overview', 'events', 'recent', 'config'] as const
type TabId = (typeof TAB_IDS)[number]

/** The auto-refresh interval each tab registers in
 *  `usePolling`, in seconds. Shown in the global header's right side
 *  (`<version> · auto-refresh <N>s`). The Config tab opts out of
 *  auto-refresh (policy-scoped data, not event-scoped), so its entry is
 *  null → the header renders the manual-refresh hint instead. Keep in
 *  sync with the interval each tab component passes to
 *  `polling.register(...)`. */
const TAB_REFRESH_SECONDS: Record<TabId, number | null> = {
  // Metrics 与 Policy Hits 统一 10 s(产品决策)。
  overview: 10,
  events: 30,
  recent: 10,
  config: null,
}

export function SecurityMonitorSection({
  bridge,
  resolveBridge,
  t,
}: SecurityMonitorSectionProps): ReactNode {
  const [active, setActive] = useState<TabId>('overview')
  // The bridge may arrive AFTER first render (async $mount). Track
  // it in state and retry the resolver for a short window before
  // settling on the fallback banner.
  const [liveBridge, setLiveBridge] = useState<SecurityMonitorBridge | undefined>(bridge)
  useEffect(() => {
    if (liveBridge || !resolveBridge) return
    let attempts = 0
    const timer = setInterval(() => {
      attempts += 1
      const resolved = resolveBridge()
      if (resolved) {
        setLiveBridge(resolved)
        clearInterval(timer)
      } else if (attempts >= 20) {
        // 10 s cap — the host genuinely lacks the gateway client;
        // stay on the fallback banner.
        clearInterval(timer)
      }
    }, 500)
    return () => clearInterval(timer)
  }, [liveBridge, resolveBridge])

  // Shared pause flag: expanding a detail row in Events or
  // RecentBlocks sets this true; collapsing sets it false. The polling
  // callbacks in those components read it before fetching.
  const pollingPausedRef = useRef(false)

  // Single polling context for the section's lifetime. `useMemo` keeps
  // the instance stable across re-renders so registered callbacks
  // survive tab switches. The hook below owns the central timer.
  const polling: PollingContext = useMemo(() => createPollingContext(), [])
  polling.setActiveTab(active)
  usePolling(polling)

  const tabs: Array<{ id: TabId; label: string }> = [
    { id: 'overview', label: t('tab_metrics') },
    { id: 'events', label: t('tab_event_stream') },
    { id: 'recent', label: t('tab_top_blocks') },
    { id: 'config', label: t('tab_config') },
  ]

  // Global title row above every tab page: plugin icon
  // + locale short label on the left; raw package version + the ACTIVE
  // tab's real polling interval on the right. The "↗ full
  // panel" button is intentionally not ported — the marketplace page
  // is already the full surface.
  //
  // The page header title is driven by the `nav` locale key — same
  // key the sidebar panellist uses — so a single source of truth
  // (`locales.ts`) governs the visible short label across both
  // surfaces. The raw version stays in
  // `headerRight` below so the build identity is still surfaced.
  // See the marketplace presentation spec §2.
  const refreshSec = TAB_REFRESH_SECONDS[active]
  // Page-level hard reload (Ctrl+Shift+R equivalent):
  // re-fetches the page bundle so a reinstalled plugin's new client JS
  // actually lands in the webview without restarting the DSH client.
  // Host-side code is reloaded separately by the plugin manager's HMR
  // on reinstall. A data-only "soft refresh" button was considered and
  // rejected — the hard reload strictly supersedes it (a page reload
  // re-fetches the data anyway), and two adjacent refresh buttons read
  // as "which one do I click".
  const [hardBusy, setHardBusy] = useState(false)
  const onHardReload = (): void => {
    if (hardBusy) return
    setHardBusy(true)
    hardReload()
  }
  const headerRight = createElement(
    'span',
    { className: 'dsh-secmon-header-refresh', 'data-component': 'header-refresh' },
    createElement(
      'button',
      {
        type: 'button',
        className: 'dsh-secmon-header-refresh-btn',
        'data-component': 'header-hard-reload-btn',
        onClick: onHardReload,
        disabled: hardBusy,
        title: hardBusy ? t('header_hard_reload_busy') : t('header_hard_reload'),
        'aria-label': t('header_hard_reload'),
      },
      hardBusy ? '⏳' : '↻',
    ),
    createElement(
      'span',
      null,
      `${PACKAGE_VERSION} · ${
        refreshSec === null ? t('header_manual_refresh') : t('header_auto_refresh', { n: refreshSec })
      }`,
    ),
  )
  const header = createElement(PageHeader, {
    icon: createElement(SecurityMonitorIcon, { size: 20, active: false }),
    title: 'SST Security Control',
    right: headerRight,
  })

  // When the host has not provided the bridge, the
  // chrome still mounts but every tab's body is short-circuited to
  // a single load-error banner. Keeps the card present in the nav
  // and tells the operator why no data is shown.
  if (!liveBridge) {
    return createElement(
      'div',
      { className: 'dsh-secmon-section', 'data-component': 'security-monitor-section' },
      header,
      createElement(Tabs, { tabs, active, onChange: (id) => setActive(id as TabId) }),
      createElement(Banner, { level: 'error', message: t('load_error') }),
    )
  }

  return createElement(
    'div',
    { className: 'dsh-secmon-section', 'data-component': 'security-monitor-section' },
    header,
    createElement(Tabs, { tabs, active, onChange: (id) => setActive(id as TabId) }),
    active === 'overview'
      ? createElement(Overview, { bridge: liveBridge, t, polling })
      : null,
    active === 'events'
      ? createElement(Events, { bridge: liveBridge, t, polling, pollingPausedRef })
      : null,
    active === 'recent'
      ? createElement(RecentBlocks, { bridge: liveBridge, t, polling, pollingPausedRef })
      : null,
    active === 'config'
      ? createElement(Config, { bridge: liveBridge, t })
      : null,
    // Hidden bridge-debug line: only rendered when the page first mounts
    // and the bridge errors out. The banner inside each tab already
    // surfaces the error inline; this outer banner keeps the chrome
    // consistent if the entire bridge goes away.
    TAB_IDS.includes(active)
      ? null
      : createElement(Banner, { level: 'error', message: t('load_error') }),
  )
}
