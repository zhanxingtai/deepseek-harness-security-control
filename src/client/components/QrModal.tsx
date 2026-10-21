/**
 * QrModal — 公众号二维码预览模态层.
 *
 * 形态遵循 the marketplace presentation spec §2 的 `qr-modal` 静态
 * HTML 约定。DSH 侧有两处强制差异：
 *
 *   - QR 不能走 HTTP 路由：marketplace sandbox 禁止新开路由
 *     (`network:none`)，所以改由 esbuild `dataurl` loader 在 bundle 期
 *     inline 成 base64 data URL，详见 `scripts/build-client.mjs` 的 loader 配置。
 *   - 模态层必须挂在 `#panel` 之外：Metrics 页每 5s 自动刷新会重写
 *     `#panel.innerHTML`，挂在 panel 内的模态会被销毁。因此走 React
 *     portal 挂到 `document.body` 末。
 *
 * QR 数据 URL 由 esbuild 在 build-client 阶段通过 `loader: { '.jpg':
 * 'dataurl' }` 内联注入；vitest 直接 import .tsx 时 Vite 默认把图片转成
 * URL 字符串，jsdom 不 fetch 但 `<img>` 元素照样渲染（带 alt 文本）。
 */
// esbuild asset import — `loader: { '.jpg': 'dataurl' }` rewrites this
// import to a base64 data URL string at bundle time (≈38 KiB).
// In vitest without the loader configured, Vite emits a URL string;
// happy-dom doesn't fetch it but the element still renders with the alt
// text, which is enough for the structural tests.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — esbuild asset import, no .d.ts at compile time.
import qrDataUrl from '../../../assets/wechat-mp-qr.jpg'

import { createElement, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import type { LocaleKey } from '../locales.js'

export interface QrModalProps {
  open: boolean
  onClose: () => void
  t: (key: LocaleKey, params?: Record<string, string | number>) => string
}

export function QrModal({ open, onClose, t }: QrModalProps): ReactNode | null {
  if (!open) return null
  if (typeof document === 'undefined') return null
  return createPortal(
    createElement(
      'div',
      {
        className: 'dsh-secmon-qr-modal',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-label': t('metrics_footer_wechat'),
        'data-component': 'qr-modal',
        onClick: (e: MouseEvent) => {
          // Click on overlay (not card) → close.
          if (e.target === e.currentTarget) onClose()
        },
      },
      createElement('div', { className: 'dsh-secmon-qr-overlay', 'aria-hidden': 'true' }),
      createElement(
        'div',
        { className: 'dsh-secmon-qr-card' },
        createElement(
          'button',
          {
            type: 'button',
            className: 'dsh-secmon-qr-close',
            'aria-label': t('qr_modal_close'),
            onClick: onClose,
          },
          '×',
        ),
        createElement('img', {
          src: qrDataUrl,
          alt: t('qr_modal_note'),
          width: 258,
          height: 258,
        }),
        createElement('div', { className: 'dsh-secmon-qr-note' }, t('qr_modal_note')),
      ),
    ),
    document.body,
  )
}