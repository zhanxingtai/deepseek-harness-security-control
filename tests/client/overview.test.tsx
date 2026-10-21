/**
 * Overview (Metrics) tab tests —.
 *
 * Covers:
 * the existing surface: 3-up stat row, BY LAYER list, meta line
 *     Last updated footer, Reload action with banner result
 * the surface: Metrics 页脚「访问官网 / 关注公众号」入口
 *     (a) website anchor targets the homepage + rel=noopener
 *     (b) wechat button toggles the QR modal (portal to document.body)
 *     (c) QR modal close button hides the modal
 *     (d) QR modal closes when clicking the overlay
 *
 * Mock bridge keeps the test independent from src/typert/host.ts; the
 * wire contract is verified separately in tests/typert/host.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, fireEvent } from '@testing-library/react'
import { createElement } from 'react'

import { Overview } from '../../src/client/components/Overview.js'
import { QrModal } from '../../src/client/components/QrModal.js'
import { locales, type LocaleKey } from '../../src/client/locales.js'
import type {
  SecurityMonitorBridge,
  OverviewSnapshot,
  ReloadResult,
} from '../../src/client/wire.js'

function tFactory(): (key: LocaleKey, params?: Record<string, string | number>) => string {
  return (key, params) => {
    const raw = locales.en[key as keyof typeof locales.en]
    if (typeof raw !== 'string') return String(key)
    if (!params) return raw
    return raw.replace(/\{(\w+)\}/g, (_m, name: string) =>
      params[name] !== undefined ? String(params[name]) : `{${name}}`,
    )
  }
}

function buildSnapshot(): OverviewSnapshot {
  return {
    totalEvents: 100,
    last24hTotalCount: 25,
    blockCount: 3,
    last24hBlockCount: 1,
    threatCount: 9,
    last24hThreatCount: 4,
    byLayer: { application: 90, system: 10 },
    loadedRuleCount: 12,
    uptimeSeconds: 3600,
    mode: 'audit',
  }
}

function buildBridge(reload: ReloadResult = { ok: true, ruleCount: 12 }): SecurityMonitorBridge {
  return {
    overview: vi.fn(async () => buildSnapshot()),
    events: vi.fn(async () => []),
    topBlocks: vi.fn(async () => []),
    getConfig: vi.fn(async () => ({})),
    reload: vi.fn(async () => reload),
  } as unknown as SecurityMonitorBridge
}

beforeEach(() => {
  // jsdom default; happy-dom environmentMatchGlobs in vitest.config.ts
  // routes tests/client/** here.
})

afterEach(() => {
  cleanup()
  // Clean up any portals that survived the test.
  document.body.innerHTML = ''
})

describe('Metrics footer website / WeChat entries', () => {
  it('renders the metrics footer links container', () => {
    const bridge = buildBridge()
    render(createElement(Overview, { bridge, t: tFactory(), initial: buildSnapshot() }))
    const links = document.querySelector('[data-component="metrics-footer-links"]')
    expect(links).toBeTruthy()
    expect(links?.querySelector('[data-component="metrics-footer-website"]')).toBeTruthy()
    expect(links?.querySelector('[data-component="metrics-footer-wechat"]')).toBeTruthy()
  })

  it('website link points at the operator site and uses rel=noopener', () => {
    const bridge = buildBridge()
    render(createElement(Overview, { bridge, t: tFactory(), initial: buildSnapshot() }))
    const a = document.querySelector(
      '[data-component="metrics-footer-website"]',
    ) as HTMLAnchorElement | null
    expect(a).toBeTruthy()
    expect(a?.getAttribute('href')).toBe('https://www.zhihuizhanxing.com')
    expect(a?.getAttribute('target')).toBe('_blank')
    expect(a?.getAttribute('rel')).toBe('noopener noreferrer')
  })

  it('WeChat button label comes from the locale key', () => {
    const bridge = buildBridge()
    render(createElement(Overview, { bridge, t: tFactory(), initial: buildSnapshot() }))
    const btn = document.querySelector(
      '[data-component="metrics-footer-wechat"]',
    ) as HTMLButtonElement | null
    expect(btn).toBeTruthy()
    expect(btn?.textContent).toBe(locales.en.metrics_footer_wechat)
  })

  it('WeChat button opens the QR modal (portal to document.body)', () => {
    const bridge = buildBridge()
    render(createElement(Overview, { bridge, t: tFactory(), initial: buildSnapshot() }))
    const btn = document.querySelector(
      '[data-component="metrics-footer-wechat"]',
    ) as HTMLButtonElement | null
    expect(document.querySelector('[data-component="qr-modal"]')).toBeNull()
    fireEvent.click(btn!)
    const modal = document.querySelector('[data-component="qr-modal"]')
    expect(modal).toBeTruthy()
    expect(modal?.getAttribute('role')).toBe('dialog')
    expect(modal?.getAttribute('aria-modal')).toBe('true')
  })

  it('QR modal close button hides the modal', () => {
    const bridge = buildBridge()
    render(createElement(Overview, { bridge, t: tFactory(), initial: buildSnapshot() }))
    fireEvent.click(
      document.querySelector('[data-component="metrics-footer-wechat"]') as HTMLButtonElement,
    )
    expect(document.querySelector('[data-component="qr-modal"]')).toBeTruthy()
    const closeBtn = document.querySelector('.dsh-secmon-qr-close') as HTMLButtonElement | null
    fireEvent.click(closeBtn!)
    expect(document.querySelector('[data-component="qr-modal"]')).toBeNull()
  })

  it('QR modal closes when clicking the overlay (not the card)', () => {
    const bridge = buildBridge()
    render(createElement(Overview, { bridge, t: tFactory(), initial: buildSnapshot() }))
    fireEvent.click(
      document.querySelector('[data-component="metrics-footer-wechat"]') as HTMLButtonElement,
    )
    const modal = document.querySelector('[data-component="qr-modal"]') as HTMLElement
    // Click on the modal element directly (overlay-style event bubbles).
    fireEvent.click(modal)
    expect(document.querySelector('[data-component="qr-modal"]')).toBeNull()
  })

  it('QR modal does not render when open=false (no portal leakage)', () => {
    render(createElement(QrModal, { open: false, onClose: () => undefined, t: tFactory() }))
    expect(document.querySelector('[data-component="qr-modal"]')).toBeNull()
  })

  it('QrModal renders the QR image and note text when open=true', () => {
    render(createElement(QrModal, { open: true, onClose: () => undefined, t: tFactory() }))
    const card = document.querySelector('.dsh-secmon-qr-card')
    expect(card).toBeTruthy()
    const img = card?.querySelector('img')
    expect(img).toBeTruthy()
    expect(img?.getAttribute('alt')).toBe(locales.en.qr_modal_note)
    const note = card?.querySelector('.dsh-secmon-qr-note')
    expect(note?.textContent).toBe(locales.en.qr_modal_note)
  })

  it('zh locale renders the matching keys for parity', () => {
    expect(locales.zh.metrics_footer_website).toBeTruthy()
    expect(locales.zh.metrics_footer_wechat).toBeTruthy()
    expect(locales.zh.qr_modal_note).toBeTruthy()
    expect(locales.zh.qr_modal_close).toBeTruthy()
    // en ↔ zh keys parity (sanity).
    expect(typeof locales.en.metrics_footer_website).toBe(typeof locales.zh.metrics_footer_website)
  })
})