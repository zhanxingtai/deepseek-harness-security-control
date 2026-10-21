/**
 * Plugin stylesheet — shared surface styling for the plugin's
 * Control UI tabs. Every rule uses the host theme tokens first and
 * falls back to literal values when the host omits them, so the
 * plugin renders correctly against both the operator-supplied
 * reference theme and minimal / missing host tokens.
 *
 * Why this file exists: the components emit semantic
 * `.dsh-secmon-*` classes under the assumption
 * that "the host DSH Web stylesheet styles them" — but the host theme
 * knows nothing about plugin classes, so without this file everything
 * falls back to browser defaults.
 *
 * The mechanism mirrors the first-party DSH UI plugins byte-for-byte
 * in spirit:
 *   - First-party: tsdown + lightningcss compile `*.module.css` into
 *     the bundle and inject a tagged `<style>` element at factory
 *     execution (the host client build
 *     `styleInjectionModule`). No companion .css file is shipped.
 *   - Marketplace (us): this `.ts` module carries the CSS as a string
 *     (esbuild bundles it with zero loader config), and
 *     `injectSecurityMonitorStyles()` performs the same idempotent
 *     `<style data-plugin-css>` injection. The marketplace "no
 *     companion files" constraint is about disk files — a bundle-
 *     internal style string is exactly what first-party does.
 *
 * Theming rule: EVERY colour comes from the host design tokens
 * (`--dsw-alias-*`, defined by `@deepseek-ai/dsh-client-ui-theme`
 * `styles/design-platform.css`) with a light-theme fallback value, so
 * the page follows the host's light/dark theme automatically and
 * still renders sanely if a token is renamed in a future harness
 * release. Never introduce a bare hex/rgb colour for a themed surface.
 */

/** Stylesheet text. Kept as a template string; no build-step CSS loader. */
export const SECURITY_MONITOR_CSS = `
/* ---- page skeleton (mirrors ui-plugin-manager .page) ------------------ */
.dsh-secmon-page {
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
  height: 100%;
  overflow: auto;
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  background: var(--dsw-alias-bg-base, rgb(255, 255, 255));
}
.dsh-secmon-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
  box-sizing: border-box;
  width: 100%;
  padding: 24px clamp(24px, 4vw, 48px) 48px;
  font-size: 13px;
  line-height: 20px;
}

/* ---- page header ------------------------------------------------------- */
.dsh-secmon-page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.dsh-secmon-page-header-left {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.dsh-secmon-page-header-icon {
  display: inline-flex;
  align-items: center;
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
}
.dsh-secmon-page-header-title {
  font-size: 16px;
  font-weight: 600;
  line-height: 24px;
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.dsh-secmon-page-header-right {
  flex: none;
  font-size: 12px;
  line-height: 18px;
  color: var(--dsw-alias-label-tertiary, rgb(129, 133, 140));
}
/* Global manual-refresh button (page header). Icon-only
 * button hugging the version/refresh hint; hover surfaces the accent
 * colour, disabled state dims (Config tab has no polling entry). */
.dsh-secmon-header-refresh {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.dsh-secmon-header-refresh-btn {
  border: none;
  background: transparent;
  padding: 2px 4px;
  margin: 0;
  font-size: 13px;
  line-height: 1;
  cursor: pointer;
  border-radius: 4px;
  opacity: 0.75;
}
.dsh-secmon-header-refresh-btn:hover:not(:disabled) {
  opacity: 1;
  background: var(--dsw-alias-fill-secondary, rgba(15, 17, 21, 0.06));
}
.dsh-secmon-header-refresh-btn:disabled {
  cursor: default;
  opacity: 0.35;
}

/* ---- tabs --------------------------------------------------------------- */
.dsh-secmon-tabs {
  display: flex;
  align-items: center;
  gap: 4px;
  border-bottom: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
}
.dsh-secmon-tab {
  appearance: none;
  border: none;
  background: transparent;
  padding: 8px 14px;
  margin-bottom: -1px;
  font-size: 13px;
  line-height: 20px;
  color: var(--dsw-alias-label-tertiary, rgb(129, 133, 140));
  border-bottom: 2px solid transparent;
  cursor: pointer;
}
.dsh-secmon-tab:hover {
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
}
.dsh-secmon-tab--active {
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  font-weight: 500;
  border-bottom-color: var(--dsw-alias-brand-primary, rgb(15, 17, 21));
}

/* ---- card / stat -------------------------------------------------------- */
.dsh-secmon-card {
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
  padding: 16px 20px;
}
.dsh-secmon-card-title {
  margin: 0 0 8px;
  font-size: 13px;
  font-weight: 600;
  line-height: 20px;
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
}
.dsh-secmon-card-body { min-width: 0; }

.dsh-secmon-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
}
.dsh-secmon-stat {
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
  padding: 14px 16px;
}
.dsh-secmon-stat-label {
  font-size: 12px;
  line-height: 18px;
  color: var(--dsw-alias-label-secondary, rgb(97, 102, 107));
}
.dsh-secmon-stat-value {
  margin-top: 4px;
  font-size: 24px;
  font-weight: 600;
  line-height: 32px;
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  font-variant-numeric: tabular-nums;
}
.dsh-secmon-stat-value--danger {
  color: var(--dsw-alias-state-error-primary, rgb(236, 19, 19));
}
.dsh-secmon-stat-value--accent {
  /* BY-LAYER counts use the brown-orange emphasis tone rather than the
   * business-primary alias; the business-primary mapping rendered
   * them essentially black. */
  color: var(--dsw-alias-state-warn-primary, var(--dsw-alias-state-warning-primary, rgb(217, 119, 6)));
}
.dsh-secmon-stat-hint {
  margin-top: 2px;
  font-size: 12px;
  line-height: 18px;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}

/* ---- overview meta / by-layer ------------------------------------------- */
.dsh-secmon-overview {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.dsh-secmon-metrics-by-layer {
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
  padding: 16px 20px;
}
.dsh-secmon-metrics-by-layer-title {
  margin: 0 0 8px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}
.dsh-secmon-metrics-by-layer-empty {
  font-size: 13px;
  color: var(--dsw-alias-label-tertiary, rgb(129, 133, 140));
}
.dsh-secmon-metrics-by-layer-list {
  display: flex;
  flex-direction: column;
}
.dsh-secmon-metrics-by-layer-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 6px 0;
  border-top: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  font-variant-numeric: tabular-nums;
}
.dsh-secmon-metrics-by-layer-row:first-child { border-top: none; }
.dsh-secmon-metrics-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 12px;
  color: var(--dsw-alias-label-tertiary, rgb(129, 133, 140));
}
.dsh-secmon-metrics-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.dsh-secmon-metrics-last-updated {
  /* Right-align under the card (column flex — margin auto pushes
   * the stamp to the cross-axis end), matching the design
   * comment at Overview.tsx ("bottom-right Last updated"). */
  margin-left: auto;
  font-size: 12px;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}

/* Metrics 页脚右对齐链接，采用 metrics-footer 形态（见
   the marketplace presentation spec §2 ）：
   Reload 按钮保留在左侧,「访问官网 / 关注公众号」链接右对齐。
   公众号按钮触发本地模态层(QR base64-inline, marketplace sandbox 禁
   止 HTTP 路由)。 */
.dsh-secmon-metrics-footer-links {
  margin-left: auto;
  display: flex;
  gap: 16px;
  align-items: center;
}
.dsh-secmon-metrics-footer-links a,
.dsh-secmon-metrics-footer-links button {
  background: transparent;
  border: 0;
  padding: 0;
  color: var(--dsw-alias-link-fg, rgb(9, 105, 218));
  font-size: 12px;
  text-decoration: none;
  cursor: pointer;
}
.dsh-secmon-metrics-footer-links a:hover,
.dsh-secmon-metrics-footer-links button:hover { text-decoration: underline; }
.dsh-secmon-metrics-footer-links a:focus-visible,
.dsh-secmon-metrics-footer-links button:focus-visible {
  outline: 2px solid var(--dsw-alias-link-fg, rgb(9, 105, 218));
  outline-offset: 2px;
  border-radius: 4px;
}

.dsh-secmon-qr-modal {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
}
.dsh-secmon-qr-overlay {
  position: absolute;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
}
.dsh-secmon-qr-card {
  position: relative;
  background: var(--dsw-alias-surface-bg, rgb(255, 255, 255));
  color: var(--dsw-alias-label-fg, rgb(31, 35, 40));
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 8px;
  padding: 20px;
  text-align: center;
  max-width: 320px;
  z-index: 1;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
}
.dsh-secmon-qr-card img {
  width: 258px;
  height: 258px;
  display: block;
  border-radius: 4px;
  margin: 0 auto;
}
.dsh-secmon-qr-note {
  font-size: 12px;
  color: var(--dsw-alias-label-tertiary, rgb(101, 109, 118));
  margin-top: 10px;
}
.dsh-secmon-qr-close {
  position: absolute;
  top: 6px;
  right: 6px;
  background: var(--dsw-alias-surface-bg, rgb(255, 255, 255));
  color: var(--dsw-alias-label-tertiary, rgb(101, 109, 118));
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  padding: 2px 8px;
  line-height: 1.2;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
}
.dsh-secmon-qr-close:hover {
  color: var(--dsw-alias-label-fg, rgb(31, 35, 40));
  background: var(--dsw-alias-surface-hover, rgb(216, 222, 228));
}

/* ---- table --------------------------------------------------------------- */
.dsh-secmon-table {
  width: 100%;
  /* border-collapse: collapse clips the 12px radius corners; the
   * separate-borders model + border-spacing 0 keeps the rounded
   * outline intact. Cell row separators stay single 1px lines
   * (border-bottom per row, suppressed on the last row). */
  border-collapse: separate;
  border-spacing: 0;
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 12px;
  overflow: hidden;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
  font-size: 13px;
  line-height: 20px;
}
.dsh-secmon-table th {
  text-align: left;
  padding: 10px 14px;
  font-size: 12px;
  font-weight: 500;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
  border-bottom: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  white-space: nowrap;
}
.dsh-secmon-table td {
  padding: 8px 14px;
  border-bottom: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  vertical-align: top;
  word-break: break-all;
}
.dsh-secmon-table-row:last-child td,
.dsh-secmon-table-detail-row:last-child td { border-bottom: none; }
.dsh-secmon-table-row--clickable { cursor: pointer; }
.dsh-secmon-table-row--clickable:hover td {
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
}
.dsh-secmon-table-row--expanded td {
  background: var(--dsw-alias-interactive-bg-active, rgba(38, 49, 72, 0.1));
}
.dsh-secmon-table-detail-row td {
  background: var(--dsw-alias-bg-base, rgb(255, 255, 255));
}
.dsh-secmon-table-detail-cell { padding: 12px 16px; }
.dsh-secmon-table-empty {
  /* Match the surrounding table chrome (solid border, same
   * radius/padding, muted centered text) instead of the old
   * dashed box that read as a different component. */
  padding: 32px 16px;
  text-align: center;
  font-size: 13px;
  line-height: 20px;
  color: var(--dsw-alias-label-tertiary, rgb(129, 133, 140));
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
}

/* ---- badge / banner ------------------------------------------------------ */
.dsh-secmon-badge {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  border-radius: 999px;
  font-size: 12px;
  line-height: 18px;
  font-weight: 500;
  white-space: nowrap;
}
.dsh-secmon-badge--success {
  color: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  background: color-mix(in srgb, var(--dsw-alias-state-success-primary, rgb(34, 197, 94)) 12%, transparent);
}
.dsh-secmon-badge--danger {
  color: var(--dsw-alias-state-error-primary, rgb(236, 19, 19));
  background: color-mix(in srgb, var(--dsw-alias-state-error-primary, rgb(236, 19, 19)) 12%, transparent);
}
/* Warn 级规则命中(标记未拦截)的琥珀徽标,与 danger 红、success 绿并列。 */
.dsh-secmon-badge--warn {
  color: var(--dsw-alias-state-warn-primary, var(--dsw-alias-state-warning-primary, rgb(217, 119, 6)));
  background: color-mix(in srgb, var(--dsw-alias-state-warn-primary, var(--dsw-alias-state-warning-primary, rgb(217, 119, 6))) 12%, transparent);
}
.dsh-secmon-badge--neutral {
  color: var(--dsw-alias-label-secondary, rgb(97, 102, 107));
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
}
/* issue 167 — escalate (人工审核) 决策与高严重等级(critical/high)
   共用的靛蓝/紫色调,介于 danger 红和 warn 琥珀之间,凸显"需要人工
   关注但已自动放行"。使用 indigo-500 兜底以兼容未定义主题 token 的
   marketplace 形态。 */
.dsh-secmon-badge--escalate {
  color: var(--dsw-alias-brand-accent, rgb(99, 102, 241));
  background: color-mix(in srgb, var(--dsw-alias-brand-accent, rgb(99, 102, 241)) 14%, transparent);
}

.dsh-secmon-banner {
  padding: 10px 14px;
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 10px;
  font-size: 13px;
  line-height: 20px;
  color: var(--dsw-alias-label-secondary, rgb(97, 102, 107));
}
.dsh-secmon-banner--error {
  border-color: var(--dsw-alias-state-error-primary, rgb(236, 19, 19));
  color: var(--dsw-alias-state-error-primary, rgb(236, 19, 19));
  background: color-mix(in srgb, var(--dsw-alias-state-error-primary, rgb(236, 19, 19)) 8%, transparent);
}
.dsh-secmon-banner--info {
  border-color: var(--dsw-alias-border-l, rgb(225, 229, 238));
}
.dsh-secmon-banner--success {
  border-color: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  color: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  background: color-mix(in srgb, var(--dsw-alias-state-success-primary, rgb(34, 197, 94)) 8%, transparent);
}

/* Save UX — strong, persistent save confirmation.
   Bigger padding + icon + dismiss button so the operator can see at a glance
   that the save landed and where to find the draft file. Replaces the
   previous thin green banner whose visual weight was easy to miss. */
.dsh-secmon-config-saved-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 10px;
  border: 1px solid var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  background: color-mix(in srgb, var(--dsw-alias-state-success-primary, rgb(34, 197, 94)) 14%, transparent);
  color: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  font-size: 13px;
  line-height: 20px;
  font-weight: 500;
}
.dsh-secmon-config-saved-banner-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
  width: 22px;
  height: 22px;
  border-radius: 999px;
  font-size: 14px;
  font-weight: 700;
  background: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  color: var(--dsw-alias-label-primary-inverted, rgb(255, 255, 255));
}
.dsh-secmon-config-saved-banner-text {
  flex: 1 1 auto;
  min-width: 0;
  word-break: break-all;
}
.dsh-secmon-config-saved-banner-dismiss {
  appearance: none;
  flex: none;
  border: 1px solid transparent;
  background: transparent;
  color: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  width: 26px;
  height: 26px;
  border-radius: 6px;
  font-size: 18px;
  line-height: 1;
  cursor: pointer;
}
.dsh-secmon-config-saved-banner-dismiss:hover {
  background: color-mix(in srgb, var(--dsw-alias-state-success-primary, rgb(34, 197, 94)) 22%, transparent);
}
.dsh-secmon-config-saved-banner-dismiss:focus-visible {
  outline: 2px solid var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  outline-offset: 2px;
}

/* ---- button --------------------------------------------------------------- */
.dsh-secmon-button {
  appearance: none;
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 8px;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  padding: 5px 14px;
  font-size: 13px;
  line-height: 20px;
  cursor: pointer;
}
.dsh-secmon-button:hover:not(:disabled) {
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
}
.dsh-secmon-button:disabled {
  cursor: not-allowed;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
}
.dsh-secmon-button--primary {
  border-color: transparent;
  /* Visual baseline — the Save
   * action is the only blue surface in the toolbar. Default to a
   * saturated blue (Tailwind blue-600) so the fallback matches
   * the operator-supplied reference when the host theme omits
   * --dsw-alias-button-primary-fill. */
  background: var(--dsw-alias-button-primary-fill, rgb(37, 99, 235));
  color: var(--dsw-alias-label-primary-inverted, rgb(255, 255, 255));
}
.dsh-secmon-button--primary:hover:not(:disabled) {
  /* Hover is the EXACT operator-specified value (Tailwind blue-700,
   * rgb(29, 78, 216)); the host may still set the dedicated hover
   * token explicitly (theme override), otherwise the literal
   * keeps the "filled → darker filled" feedback without the
   * approximation drift of the old color-mix(...) 85% chain. */
  background: var(--dsw-alias-button-primary-hover, rgb(29, 78, 216));
}
.dsh-secmon-button--success {
  border-color: transparent;
  background: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
  color: var(--dsw-alias-label-primary-inverted, rgb(255, 255, 255));
}
/* Every filled variant needs its OWN :hover rule — the default
 * .dsh-secmon-button:hover:not(:disabled) (a 6% blue-gray overlay)
 * silently bleeds through onto the success variant and turns the
 * white text against a near-transparent background, so the button
 * reads as "white on white" to the operator. Hover uses the
 * EXACT operator-specified value (rgb(28, 168, 80)); the host may
 * override --dsw-alias-button-success-hover, otherwise the literal
 * keeps the hover clearly green. All hover rules are scoped with
 * :not(:disabled) so a disabled button never picks up the hover
 * background. */
.dsh-secmon-button--success:hover:not(:disabled) {
  background: var(--dsw-alias-button-success-hover, rgb(28, 168, 80));
}
/* Secondary (outline) button variant used by the Load more
 * affordances on the Event Stream and Policy Hits tabs. Outlined
 * so the affordance stays visually lighter than the primary
 * Apply / Save actions and never out-competes them. */
.dsh-secmon-button--secondary {
  border-color: var(--dsw-alias-line-border, rgb(217, 219, 224));
  background: var(--dsw-alias-surface-bg, rgb(255, 255, 255));
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
}
.dsh-secmon-button--secondary:hover:not(:disabled) {
  background: var(--dsw-alias-surface-hover, rgb(244, 246, 250));
  border-color: var(--dsw-alias-state-primary, rgb(37, 99, 235));
}

/* Icon-only square button used by the inline Copy affordances
 * in the Events / Recent Blocks expanded-detail headers. 26×26
 * keeps the icon vertically aligned with the 18-px-tall title
 * in the same flex row; transparent border so the button never
 * reads as a "secondary action" surfaced against the JSON pre block.
 * Hover lifts a 6% blue-gray overlay (same token the default
 * dsh-secmon-button uses) so the affordance stays visible without
 * competing for attention. Keyboard focus keeps the browser default
 * focus ring — that styling is intentionally omitted here so the
 * stylesheet doesn't introduce a brand focus token (see styles.test.ts
 * snapshot for the canonical token list). */
.dsh-secmon-icon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  padding: 0;
  appearance: none;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 6px;
  color: var(--dsw-alias-label-secondary, rgb(97, 102, 107));
  cursor: pointer;
  transition: background-color 0.12s ease, color 0.12s ease;
}
.dsh-secmon-icon-button:hover:not(:disabled) {
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
}
.dsh-secmon-icon-button:focus-visible {
  outline: 2px solid var(--dsw-alias-state-primary, rgb(37, 99, 235));
  outline-offset: 2px;
}
.dsh-secmon-icon-button:disabled {
  cursor: not-allowed;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}
.dsh-secmon-icon-button svg { fill: currentColor; }
/* Success slot swaps the colour to the success-token primary so the
 * check icon visibly responds to the "Copied" state for ~2 s before
 * resetting — no DOM swap needed, just a class add by the consumer. */
.dsh-secmon-icon-button[data-icon="check"] {
  color: var(--dsw-alias-state-success-primary, rgb(34, 197, 94));
}
.dsh-secmon-icon-button[data-icon="alert"] {
  color: var(--dsw-alias-state-warn-primary, var(--dsw-alias-state-warning-primary, rgb(217, 119, 6)));
}

/* ---- events tab ------------------------------------------------------------ */
.dsh-secmon-events { display: flex; flex-direction: column; gap: 12px; }
.dsh-secmon-events-controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.dsh-secmon-events-filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.dsh-secmon-events-filter {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--dsw-alias-label-secondary, rgb(97, 102, 107));
}
.dsh-secmon-events-controls-right { display: flex; align-items: center; gap: 8px; }
.dsh-secmon-events-per-page { font-size: 12px; color: var(--dsw-alias-label-caption, rgb(173, 178, 184)); }
.dsh-secmon-events-cell-type {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.dsh-secmon-events-cell-layer { color: var(--dsw-alias-label-secondary, rgb(97, 102, 107)); }
.dsh-secmon-events-cell-status { white-space: nowrap; }
.dsh-secmon-events-detail {
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 10px;
  padding: 12px 14px;
  background: var(--dsw-alias-bg-base, rgb(255, 255, 255));
}
/* Header row inside the Events / Recent Blocks expanded detail
 * panels. Hosts the uppercase title on the left and the per-row
 * Copy JSON action on the right (see Events.tsx /
 * RecentBlocks.tsx). The header is a flex row centred on its
 * baseline; gap enforces a minimum horizontal separation when
 * the title wraps on narrow viewports. */
.dsh-secmon-events-detail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 6px;
}
.dsh-secmon-events-detail-title {
  margin-bottom: 6px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}
/* Once the title is wrapped in a flex header, the title's own
 * bottom margin is folded into the header's margin-bottom so the
 * header still leaves 6 px between the title row and the JSON
 * pre block underneath. */
.dsh-secmon-events-detail-header .dsh-secmon-events-detail-title { margin-bottom: 0; }
.dsh-secmon-events-raw {
  margin: 0;
  max-height: 320px;
  overflow: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 18px;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--dsw-alias-label-secondary, rgb(97, 102, 107));
}
.dsh-secmon-events-truncated-hint {
  margin-top: 6px;
  font-size: 12px;
  color: var(--dsw-alias-state-warn-primary, var(--dsw-alias-state-warning-primary, rgb(217, 119, 6)));
}
.dsh-secmon-events-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 12px;
  color: var(--dsw-alias-label-tertiary, rgb(129, 133, 140));
}
.dsh-secmon-events-footer-end { display: flex; align-items: center; gap: 8px; }

/* ---- recent (top blocks) tab ------------------------------------------------ */
.dsh-secmon-recent { display: flex; flex-direction: column; gap: 12px; }
.dsh-secmon-recent-controls { display: flex; align-items: center; gap: 8px; }
.dsh-secmon-recent-cell-decision { white-space: nowrap; }
.dsh-secmon-recent-cell-severity { white-space: nowrap; }
.dsh-secmon-recent-cell-policy {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  color: var(--dsw-alias-label-secondary, rgb(97, 102, 107));
}
.dsh-secmon-recent-detail {
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 10px;
  padding: 12px 14px;
  background: var(--dsw-alias-bg-base, rgb(255, 255, 255));
}
.dsh-secmon-recent-detail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 6px;
}
.dsh-secmon-recent-detail-title {
  margin-bottom: 6px;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}
.dsh-secmon-recent-detail-header .dsh-secmon-recent-detail-title { margin-bottom: 0; }
.dsh-secmon-recent-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 12px;
  color: var(--dsw-alias-label-tertiary, rgb(129, 133, 140));
}
.dsh-secmon-recent-footer-end { display: flex; align-items: center; gap: 8px; }
.dsh-secmon-policy-id {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.dsh-secmon-actions { display: flex; align-items: center; gap: 8px; }

/* ---- config tab -------------------------------------------------------------- */
.dsh-secmon-config { display: flex; flex-direction: column; gap: 12px; }
.dsh-secmon-config-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.dsh-secmon-config-toolbar-left { display: flex; align-items: center; gap: 8px; }
.dsh-secmon-config-toolbar-right { display: flex; align-items: center; gap: 8px; }
.dsh-secmon-config-form { display: flex; flex-direction: column; gap: 12px; }
.dsh-secmon-config-section {
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
}
.dsh-secmon-config-section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 12px 16px;
  border: none;
  background: transparent;
  cursor: pointer;
  text-align: left;
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
}
.dsh-secmon-config-section-header:hover {
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
}
.dsh-secmon-config-section-chevron {
  flex: none;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
  transition: transform 0.15s ease;
}
.dsh-secmon-config-section-name {
  font-size: 13px;
  font-weight: 600;
}
.dsh-secmon-config-section-count {
  margin-left: auto;
  font-size: 12px;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}
.dsh-secmon-config-section-body {
  display: flex;
  flex-direction: column;
  padding: 4px 16px 12px;
  border-top: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
}
.dsh-secmon-config-field-row {
  display: grid;
  grid-template-columns: minmax(180px, 280px) 1fr;
  gap: 8px 16px;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
}
/* Narrow screens: collapse the label/control two-column grid so
 * the label sits above the control; help/warning stay full-width
 * below the control via the flex-wrap rule. */
@media (max-width: 720px) {
  .dsh-secmon-config-field-row { grid-template-columns: 1fr; }
}
.dsh-secmon-config-field-row:last-child { border-bottom: none; }
.dsh-secmon-config-field-row--danger {
  border-left: 3px solid var(--dsw-alias-state-error-primary, rgb(236, 19, 19));
  padding-left: 12px;
}
.dsh-secmon-config-field-label { min-width: 0; }
.dsh-secmon-config-field-label-text {
  font-size: 13px;
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
}
.dsh-secmon-config-field-key {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
  word-break: break-all;
}
.dsh-secmon-config-field-control {
  /* flex-wrap lets help/warning (flex-basis: 100%) drop BELOW the
   * control instead of squeezing in to its right; the boolean
   * on/off caption stays inline next to the checkbox. */
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
/* Shared text/select control chrome — ONE source of truth for the
 * config form inputs AND the bare select/input controls in the events
 * and recent tabs (focus/disabled states included, not just the idle
 * selectors). */
.dsh-secmon-config-input,
.dsh-secmon-events select,
.dsh-secmon-events input,
.dsh-secmon-recent select,
.dsh-secmon-recent input,
.dsh-secmon-config select {
  box-sizing: border-box;
  padding: 5px 10px;
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 8px;
  background: var(--dsw-alias-bg-base, rgb(255, 255, 255));
  color: var(--dsw-alias-label-primary, rgb(15, 17, 21));
  font-size: 13px;
  line-height: 20px;
}
.dsh-secmon-config-input { width: 100%; }
.dsh-secmon-config-input:focus,
.dsh-secmon-events select:focus,
.dsh-secmon-events input:focus,
.dsh-secmon-recent select:focus,
.dsh-secmon-recent input:focus,
.dsh-secmon-config select:focus {
  outline: none;
  border-color: var(--dsw-alias-brand-primary, rgb(15, 17, 21));
}
.dsh-secmon-config-input:disabled,
.dsh-secmon-events select:disabled,
.dsh-secmon-events input:disabled,
.dsh-secmon-recent select:disabled,
.dsh-secmon-recent input:disabled,
.dsh-secmon-config select:disabled {
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
  background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
  cursor: not-allowed;
}
.dsh-secmon-config-help {
  /* Full-width flex child of .config-field-control, so it wraps
   * BELOW the control (the old grid-column: 2 was dead — the help
   * div is not a grid item). */
  flex-basis: 100%;
  font-size: 12px;
  line-height: 18px;
  color: var(--dsw-alias-label-caption, rgb(173, 178, 184));
}
.dsh-secmon-config-bool-state { font-size: 12px; color: var(--dsw-alias-label-secondary, rgb(97, 102, 107)); }
.dsh-secmon-config-bool-state--on { color: var(--dsw-alias-state-success-primary, rgb(34, 197, 94)); }
.dsh-secmon-config-lock { color: var(--dsw-alias-label-caption, rgb(173, 178, 184)); }
.dsh-secmon-config-locked-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  color: var(--dsw-alias-label-dimmed, rgb(173, 178, 184));
}
.dsh-secmon-config-inline-locked { font-size: 12px; color: var(--dsw-alias-label-caption, rgb(173, 178, 184)); }
.dsh-secmon-config-readonly-hint { font-size: 12px; color: var(--dsw-alias-label-caption, rgb(173, 178, 184)); }
.dsh-secmon-config-danger-badge {
  flex: none;
  font-size: 11px;
  line-height: 16px;
  padding: 0 6px;
  border-radius: 999px;
  color: var(--dsw-alias-state-error-primary, rgb(236, 19, 19));
  background: color-mix(in srgb, var(--dsw-alias-state-error-primary, rgb(236, 19, 19)) 12%, transparent);
}
.dsh-secmon-config-warning {
  /* Full-width flex child of .config-field-control, so the danger
   * warning wraps BELOW the control like the help text. */
  flex-basis: 100%;
  font-size: 12px;
  color: var(--dsw-alias-state-warn-primary, var(--dsw-alias-state-warning-primary, rgb(217, 119, 6)));
}
.dsh-secmon-config-validation { display: flex; flex-direction: column; gap: 6px; }
.dsh-secmon-config-validation-errors {
  font-size: 12px;
  color: var(--dsw-alias-state-error-primary, rgb(236, 19, 19));
}
.dsh-secmon-config-validation-warnings {
  font-size: 12px;
  color: var(--dsw-alias-state-warn-primary, var(--dsw-alias-state-warning-primary, rgb(217, 119, 6)));
}

/* ---- confirm dialog (modal) ------------------------------------------------ */
/* Portal-mounted modal (QrModal pattern) — fixed-position flex
 * wrapper + semi-transparent backdrop, card centered above page
 * content. The dialog itself keeps its original class so existing
 * tests/selectors keep working. */
.dsh-secmon-confirm-modal {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
}
.dsh-secmon-confirm-overlay {
  position: absolute;
  inset: 0;
  background: rgba(15, 17, 21, 0.45);
}
.dsh-secmon-confirm-dialog {
  position: relative;
  z-index: 1;
  box-sizing: border-box;
  width: calc(100% - 48px);
  max-width: 440px;
  max-height: calc(100% - 48px);
  overflow: auto;
  border: 1px solid var(--dsw-alias-border-l, rgb(225, 229, 238));
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-1, rgb(255, 255, 255));
  padding: 16px 20px;
  box-shadow: 0 8px 24px rgba(15, 17, 21, 0.12);
}
.dsh-secmon-confirm-dialog-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 12px;
}

/* ---- misc shared ---------------------------------------------------------------- */
.dsh-secmon-field { display: flex; align-items: center; gap: 8px; }
.dsh-secmon-field-bool { display: inline-flex; align-items: center; gap: 6px; }
`

/** Style tag identity — mirrors the first-party `data-plugin-css` convention. */
const STYLE_TAG_ID = 'sst-security-control-dsh/styles'

/**
 * Idempotently inject the stylesheet into `document.head`. Safe to call
 * on every `apply()` — a second call (HMR re-apply, double load) finds
 * the existing tag and no-ops. No-op outside a DOM (unit tests, SSR).
 */
export function injectSecurityMonitorStyles(): void {
  if (typeof document === 'undefined') return
  if (document.querySelector(`style[data-plugin-css="${STYLE_TAG_ID}"]`) !== null) return
  const tag = document.createElement('style')
  tag.dataset.plugin = 'sst-security-control-dsh'
  tag.dataset.pluginCss = STYLE_TAG_ID
  tag.textContent = SECURITY_MONITOR_CSS
  document.head.appendChild(tag)
}
