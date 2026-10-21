/**
 * SecurityMonitorIcon — the sidebar panellist entry's glyph.
 *
 * Registered under id `security-monitor` in the
 * `sidebar.panellist` list-slot so the operator can reach the page
 * from the top-level left rail instead of opening Settings →
 * Plugin → Security Monitor through a modal.
 *
 * The shell ((host source)x`)
 * owns the surrounding button / label / selected-state and only
 * forwards `{ size, active }` to this component via
 * `PropsRuntime<'sidebar.panellist'>` — see
 * the host sidebar.
 *
 * The icon is hand-rolled as a small inline SVG so the marketplace
 * bundle has **zero runtime peer dependencies** (no
 * `@deepseek-ai/dsh-client-ui-primitives` import) — the build script
 * (`scripts/build-client.mjs:94`) keeps that package external, but a
 * runtime peer resolution failure on a host that does not preload
 * the primitives seed would silently break the icon. The outline
 * here matches the visual weight of `IconShieldOutline16` from the
 * primitives library so it slots in cleanly beside sibling icons.
 */
import { createElement, type ReactNode } from 'react'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
// esbuild asset import — `loader: { '.ico': 'dataurl' }` rewrites this
// to a base64 data URL string at bundle time. Kept as a separate import
// so the loader applies and the type stays clean.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — esbuild asset import, no .d.ts at compile time.
import logoIcoDataUrl from '../../../assets/logo.ico'

/**
 * Render the shield glyph at the size the sidebar asks for.
 * @param props - the sidebar's icon share: requested edge length +
 *   whether the panel is currently selected (kept for parity with
 *   sibling icons even though this icon does not recolor by
 *   selected state today — see the host's `SidebarPanelMetadata`
 *   convention for future theming hooks).
 * @returns the icon element.
 */
export function SecurityMonitorIcon({
  size,
  active: _active,
}: PropsRuntime<'sidebar.panellist'>): ReactNode {
  return createElement('img', {
    src: logoIcoDataUrl,
    alt: 'SST Security Control',
    width: size,
    height: size,
    style: { display: 'block', flexShrink: '0' },
  })
}
