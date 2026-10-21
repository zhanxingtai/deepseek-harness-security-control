/**
 * Shared primitives for the settings page.
 *
 * Elements use semantic CSS classes (`.dsh-secmon-*`) styled by the
 * plugin's own stylesheet (`src/client/styles.ts`, injected into
 * `document.head` at apply time). Colours consume the host design
 * tokens (`--dsw-alias-*`) so the page follows the host theme; the
 * marketplace "no companion files" rule is honoured because the CSS
 * ships as an in-bundle string (the same runtime-injection mechanism
 * first-party DSH UI plugins use, minus the CSS-modules hashing).
 *
 * The primitives are deliberately small (Card / Stat / Table / Tabs)
 * to mirror the dsh-permission-rules reference impl's style and to
 * keep the client bundle tight — every shipped byte is one the
 * marketplace node's browser must parse.
 */
import { createElement, type ReactNode, type Key } from 'react'

/* ---------------------------------------------------------------- *
 * Card — section wrapper with title + body.                        *
 * ---------------------------------------------------------------- */

export interface CardProps {
  title: string
  children?: ReactNode
}

export function Card({ title, children }: CardProps): ReactNode {
  return createElement(
    'section',
    { className: 'dsh-secmon-card', 'data-component': 'card' },
    createElement('h3', { className: 'dsh-secmon-card-title' }, title),
    createElement('div', { className: 'dsh-secmon-card-body' }, children),
  )
}

/* ---------------------------------------------------------------- *
 * Stat — single label / value pair used in the Overview tab.       *
 * ---------------------------------------------------------------- */

export interface StatProps {
  label: string
  value: string | number
  hint?: string
  /** Value tone. 'danger' renders the number in the
   *  theme's red (the Metrics page's Blocked counter); 'accent' uses
   *  the brown-orange emphasis colour (BY LAYER counts). Default is
   *  the neutral foreground. */
  tone?: 'default' | 'danger' | 'accent'
}

export function Stat({ label, value, hint, tone }: StatProps): ReactNode {
  const toneClass =
    tone === 'danger'
      ? ' dsh-secmon-stat-value--danger'
      : tone === 'accent'
        ? ' dsh-secmon-stat-value--accent'
        : ''
  return createElement(
    'div',
    { className: 'dsh-secmon-stat', 'data-component': 'stat' },
    createElement('div', { className: 'dsh-secmon-stat-label' }, label),
    createElement('div', { className: 'dsh-secmon-stat-value' + toneClass }, String(value)),
    hint ? createElement('div', { className: 'dsh-secmon-stat-hint' }, hint) : null,
  )
}

/* ---------------------------------------------------------------- *
 * Badge — small status pill (allow / block / neutral).             *
 * STATUS / DECISION columns.                      *
 * ---------------------------------------------------------------- */

/** 'warn' 琥珀色:warn 级规则命中(标记未拦截)在 Policy
 *  Hits 列表里与 block(红)/allow(绿)/neutral 区分。
 *'escalate'靛蓝(紫色)用于 人工审核 决策,与 danger
 *  (已拦截)和 warn (标记未拦截)区分;同样用于 SEVERITY 列渲染
 *  critical/high 等级(severityTone)以视觉凸显高严重等级。 */
export type BadgeTone = 'success' | 'danger' | 'neutral' | 'warn' | 'escalate'

export interface BadgeProps {
  tone: BadgeTone
  children?: ReactNode
}

export function Badge({ tone, children }: BadgeProps): ReactNode {
  return createElement(
    'span',
    { className: `dsh-secmon-badge dsh-secmon-badge--${tone}`, 'data-component': 'badge' },
    children,
  )
}

/* ---------------------------------------------------------------- *
 * PageHeader — global title row shown above every tab page         *
 * Left: plugin icon + formal name; right:                      *
 * version · auto-refresh hint. The shell owns the outer page       *
 * frame; this row is the plugin's own identity strip.              *
 * ---------------------------------------------------------------- */

export interface PageHeaderProps {
  icon?: ReactNode
  title: string
  right?: ReactNode
}

export function PageHeader({ icon, title, right }: PageHeaderProps): ReactNode {
  return createElement(
    'div',
    { className: 'dsh-secmon-page-header', 'data-component': 'page-header' },
    createElement(
      'div',
      { className: 'dsh-secmon-page-header-left' },
      icon ? createElement('span', { className: 'dsh-secmon-page-header-icon' }, icon) : null,
      createElement('span', { className: 'dsh-secmon-page-header-title' }, title),
    ),
    right
      ? createElement(
          'div',
          { className: 'dsh-secmon-page-header-right' },
          right,
        )
      : null,
  )
}

/* ---------------------------------------------------------------- *
 * Table — generic <table> with column headers. Renders an empty    *
 * placeholder cell when `rows` is empty.                           *
 *                                                                    *
 * The generic `Row` type is not part of the public React component  *
 * signature (React's createElement does not propagate generics      *
 * through the JSX runtime), so consumers cast `rows` to             *
 * `ReadonlyArray<unknown>` and the column `render` callback receives *
 * the original `Row` via the column declaration. This is the same   *
 * pattern dsh-permission-rules uses for its settings table.          *
 * ---------------------------------------------------------------- */

export interface TableColumn<Row> {
  key: string
  header: string
  /** Optional className applied to each <td> in the column. */
  cellClassName?: string
  render: (row: Row) => ReactNode
}

export interface TableProps {
  columns: ReadonlyArray<TableColumn<unknown>>
  rows: ReadonlyArray<unknown>
  emptyText: string
  /** Optional stable key extractor. Defaults to index. */
  rowKey?: (row: unknown, index: number) => Key
  /** Row expansion. When `onRowClick` is set the body
   *  rows become clickable; `isRowExpanded` decides which row carries the
   *  expanded class, and `renderExpanded` paints a full-width detail
   *  cell (pretty-printed event JSON) under the
   *  clicked row. */
  onRowClick?: (row: unknown) => void
  isRowExpanded?: (row: unknown) => boolean
  renderExpanded?: (row: unknown) => ReactNode
}

export function Table({
  columns,
  rows,
  emptyText,
  rowKey,
  onRowClick,
  isRowExpanded,
  renderExpanded,
}: TableProps): ReactNode {
  if (rows.length === 0) {
    return createElement(
      'div',
      { className: 'dsh-secmon-table-empty', 'data-component': 'table-empty' },
      emptyText,
    )
  }
  const colCount = columns.length
  return createElement(
    'table',
    { className: 'dsh-secmon-table', 'data-component': 'table' },
    createElement(
      'thead',
      null,
      createElement(
        'tr',
        null,
        columns.map((c) =>
          createElement('th', { key: c.key, scope: 'col' }, c.header),
        ),
      ),
    ),
    createElement(
      'tbody',
      null,
      rows.flatMap((row, i) => {
        const key = rowKey ? rowKey(row, i) : String(i)
        const expanded = isRowExpanded?.(row) === true
        const tr = createElement(
          'tr',
          {
            key,
            onClick: onRowClick ? () => onRowClick(row) : undefined,
            className:
              'dsh-secmon-table-row' +
              (onRowClick ? ' dsh-secmon-table-row--clickable' : '') +
              (expanded ? ' dsh-secmon-table-row--expanded' : ''),
          },
          columns.map((c) =>
            createElement(
              'td',
              { key: c.key, className: c.cellClassName },
              c.render(row),
            ),
          ),
        )
        if (!expanded || !renderExpanded) return [tr]
        return [
          tr,
          createElement(
            'tr',
            { key: `${key}:detail`, className: 'dsh-secmon-table-detail-row' },
            createElement(
              'td',
              { colSpan: colCount, className: 'dsh-secmon-table-detail-cell' },
              renderExpanded(row),
            ),
          ),
        ]
      }),
    ),
  )
}

/* ---------------------------------------------------------------- *
 * Tabs — minimal tab list with active highlight. State is lifted   *
 * to the parent (the section component) so deep links /            *
 * window.location hash sync can be added later without rewiring.    *
 * ---------------------------------------------------------------- */

export interface TabSpec {
  id: string
  label: string
}

export interface TabsProps {
  tabs: ReadonlyArray<TabSpec>
  active: string
  onChange: (id: string) => void
}

export function Tabs({ tabs, active, onChange }: TabsProps): ReactNode {
  return createElement(
    'div',
    { className: 'dsh-secmon-tabs', role: 'tablist', 'data-component': 'tabs' },
    tabs.map((t) =>
      createElement(
        'button',
        {
          key: t.id,
          type: 'button',
          role: 'tab',
          'aria-selected': t.id === active,
          className:
            'dsh-secmon-tab' + (t.id === active ? ' dsh-secmon-tab--active' : ''),
          onClick: () => onChange(t.id),
        },
        t.label,
      ),
    ),
  )
}

/* ---------------------------------------------------------------- *
 * Banner — error / status banner. Colours live in `styles.ts`       *
 * (host theme tokens); no inline `style` overrides here.            *
 * ---------------------------------------------------------------- */

export interface BannerProps {
  level: 'error' | 'info' | 'success'
  message: string
}

export function Banner({ level, message }: BannerProps): ReactNode {
  return createElement(
    'div',
    {
      className: `dsh-secmon-banner dsh-secmon-banner--${level}`,
      role: level === 'error' ? 'alert' : 'status',
    },
    message,
  )
}

/* ---------------------------------------------------------------- *
 * Button — minimal primary button used for the policy reload       *
 * action. Disabled state is exposed via the `disabled` prop.       *
 * ---------------------------------------------------------------- */

export interface ButtonProps {
  onClick: () => void
  disabled?: boolean
  children: ReactNode
  title?: string
  /** Visual variant. 'primary' = blue main action
   *  (Save); 'success' = green supporting action (Apply / Undo).
   *  Default is the neutral button. Per-row copy affordances live in
   *  the `IconButton` primitive below — they don't use `Button` so
   *  the icon-only ↔ text-button semantic stays clean. */
  variant?: 'default' | 'primary' | 'success'
}

export function Button({
  onClick,
  disabled,
  children,
  title,
  variant,
}: ButtonProps): ReactNode {
  const variantClass =
    variant === 'primary'
      ? ' dsh-secmon-button--primary'
      : variant === 'success'
        ? ' dsh-secmon-button--success'
        : ''
  return createElement(
    'button',
    {
      type: 'button',
      className: 'dsh-secmon-button' + variantClass,
      onClick,
      disabled: disabled === true,
      title,
    },
    children,
  )
}

/* ---------------------------------------------------------------- *
 * IconButton — square 26×26 ghost button rendering a single SVG     *
 * icon. Used by the inline Copy affordances in the Events /         *
 * Recent Blocks expanded-detail panels, where a text button would  *
 * visually compete with the monospace JSON beneath it.              *
 *                                                                    *
 * Three icon slots are predefined (`copy` / `check` / `alert`) so   *
 * the success and failure states of an action swap the SVG path     *
 * for the same button — no separate success/fail component          *
 * instances needed by callers. The accessible name (`label`) is     *
 * the element's `aria-label` and also drives the `title=` tooltip   *
 * (operators who want hover hints AND screen-reader users get       *
 * identical wording).                                               *
 *                                                                    *
 * SVG paths are GitHub Octicons (`viewBox=0 0 16 16`) chosen for    *
 * recognisability at 14 px: the clipboard outline pairs with the   *
 * JSON-copy semantics; the check / alert triangles mirror common    *
 * dev-tool feedback (e.g. VS Code's "modified in editor" indicator).*
 * ---------------------------------------------------------------- */

/** Visual icon slot. `copy` is the idle / default; `check` and `alert`
 *  are short-lived success / failure states after a copy click. */
export type IconButtonIcon = 'copy' | 'check' | 'alert'

/** SVG path data for each `IconButtonIcon` slot. Path strings live as
 *  module-level constants (NOT inline `<path>` JSX) so the React tree
 *  stays small and the path data can be unit-tested or shared with a
 *  future "icons registry" without rewriting call sites. */
export const ICON_BUTTON_PATHS: Readonly<Record<IconButtonIcon, string>> = {
  // clipboard outline (the "copy this" affordance)
  copy: 'M8 2a2 2 0 0 0-2 2v.5H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-2V4a2 2 0 0 0-2-2Zm0 1.5a.5.5 0 0 1 .5.5v1.5h-1V4a.5.5 0 0 1 .5-.5Z',
  // check mark (successful copy)
  check: 'M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z',
  // exclamation triangle (copy failure — same yellow-tinted shape used
  // by the warning state tokens)
  alert: 'M6.457 1.047c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0 1 14.082 15H1.918a1.75 1.75 0 0 1-1.543-2.575Zm1.076.827a.25.25 0 0 0-.353 0L1.468 12.857a.25.25 0 0 0 .176.393h12.712a.25.25 0 0 0 .176-.393L8.357 1.874ZM8 5a.75.75 0 0 1 .75.75v2.5a.75.75 0 0 1-1.5 0v-2.5A.75.75 0 0 1 8 5Zm0 6a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z',
}

export interface IconButtonProps {
  onClick: () => void
  disabled?: boolean
  /** Accessible name (announced to screen readers; mirrored to the
   *  `title=` attribute for hover hints). Callers should swap this
   *  alongside the visual icon so the SR experience tracks the
   *  visual state (`copy` → `check` / `alert`). */
  label: string
  /** Visual icon to render. Defaults to `copy`. */
  icon?: IconButtonIcon
}

export function IconButton({
  onClick,
  disabled,
  label,
  icon,
}: IconButtonProps): ReactNode {
  const slot: IconButtonIcon = icon ?? 'copy'
  const path = ICON_BUTTON_PATHS[slot]
  return createElement(
    'button',
    {
      type: 'button',
      className: 'dsh-secmon-icon-button',
      onClick,
      disabled: disabled === true,
      'aria-label': label,
      // title tracks aria-label so mouse hover shows the same text the
      // screen reader announces; especially useful for the `alert`
      // state where the failure reason belongs right next to the icon.
      title: label,
      // `data-icon` lets test code target a button by visual state
      // (e.g. `screen.getByRole('button', { name: 'Copied…' })`)
      // without coupling to the SVG path string.
      'data-icon': slot,
    },
    createElement(
      'svg',
      {
        viewBox: '0 0 16 16',
        width: 14,
        height: 14,
        'aria-hidden': 'true',
        focusable: false,
      },
      createElement('path', { d: path, fill: 'currentColor' }),
    ),
  )
}
