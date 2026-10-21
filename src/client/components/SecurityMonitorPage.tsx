/**
 * SecurityMonitorPage — top-level main-slot occupant for the
 * `security-monitor` panel.
 *
 * Registered under `key: 'security-monitor'` in the
 * `main` keyed-slot so the sidebar panellist click
 * (`ctx.layout.selectPanel('security-monitor')`) routes here
 * ((host source)x:42` —
 * `renderSlot('main', {}, { entryKey: panelId ?? 'conversation' })`).
 *
 * The page is a thin wrapper over `SecurityMonitorSection` so the
 * tabs / bridge-fallback / load-error semantics stay in one place.
 * The shell owns the surrounding frame chrome (top bar, page
 * header, breadcrumb); this component only owns the inner
 * `security-monitor-section` content.
 *
 * The optional `bridge` reaches the page through the slot
 * registration's `inject: () => ({ bridge, t })` thunk at render
 * time (see `src/client/index.ts`). When the host has not registered
 * the typert gateway namespace, `bridge` is `undefined` and the
 * inner section renders its load-error banner per tab.
 */
import { createElement, type ReactNode } from 'react'
import { SecurityMonitorSection } from '../section.js'
import type { SecurityMonitorBridge } from '../wire.js'
import type { LocaleKey } from '../locales.js'

export interface SecurityMonitorPageProps {
  /**
   * The host's `remote.securityMonitor` namespace. Undefined when the
   * gateway client is absent or the async `$mount` has not settled
   * yet — the inner section renders its load-error banner in that
   * case (and retries via `resolveBridge` when provided).
   */
  bridge?: SecurityMonitorBridge
  /** Re-resolver for the async mount race. */
  resolveBridge?: () => SecurityMonitorBridge | undefined
  t: (key: LocaleKey, params?: Record<string, string | number>) => string
}

export function SecurityMonitorPage({
  bridge,
  resolveBridge,
  t,
}: SecurityMonitorPageProps): ReactNode {
  return createElement(
    'div',
    {
      className: 'dsh-secmon-page',
      'data-component': 'security-monitor-page',
    },
    createElement(SecurityMonitorSection, { bridge, resolveBridge, t }),
  )
}
