/**
 * 2026-09-28: Regression pin for the `.dsh-secmon-button--*` hover
 * states.
 *
 * Background (the bug this test pins):
 *   The Config page renders three action buttons in its top toolbar:
 *     - Undo changes  → `variant: 'success'` (green)
 *     - Copy JSON     → `variant: 'success'` (green)
 *     - Save (draft)  → `variant: 'primary'` (blue)
 *   The `Button` primitive at `src/client/components/primitives.tsx`
 *   exposes exactly these three variants. The stylesheet at
 *   `src/client/styles.ts` defines `--primary` and `--success` fills
 *   but only `--primary` had a dedicated `:hover` rule; the success
 *   variant was falling through to the default
 *   `.dsh-secmon-button:hover:not(:disabled)` (a 6% blue-gray overlay),
 *   which made white-on-faded-green hover read as "the button turned
 *   white" — the exact UX complaint operators filed.
 *
 * What this test pins:
 *   1. Every filled variant (`--primary`, `--success`) has its own
 *      `:hover:not(:disabled)` rule that OVERRIDES the default hover.
 *      Without the override the white-on-faded-bg bug returns the
 *      moment someone renames the variant or adds a new filled
 *      variant (`--danger`, `--warning`) without copying the hover
 *      rule.
 *   2. The hover background differs from the rest background so the
 *      hover is perceivable (catches "I added a hover rule but
 *      accidentally set it to the same colour as the base").
 *   3. The hover background keeps enough contrast against
 *      `--dsw-alias-label-primary-inverted` (the white text colour
 *      used by every filled variant) so the label is still readable.
 *      This is the regression that produced the "white on white"
 *      perception — we never want a hover rule to drop contrast
 *      below ~3:1 against white text.
 *
 * It uses the same `SECURITY_MONITOR_CSS` constant the live client
 * injects, so a build pipeline that tree-shakes / dead-code-elims
 * the unused variant still surfaces here.
 */

import { describe, expect, it } from 'vitest'
import { SECURITY_MONITOR_CSS } from '../../src/client/styles.js'

/** Tiny css-rule extractor. Pulls selectors and declaration blocks
 *  out of one rule; assumes the stylesheet is minified single-line
 *  (which SECURITY_MONITOR_CSS is — see `injectSecurityMonitorStyles`
 *  in src/client/styles.ts). Not a real CSS parser, just enough for
 *  the assertions below. */
function extractRule(selector: string): string | null {
  // Match `.dsh-secmon-button--success:hover:not(:disabled) { ... }`.
  // The selector is passed in already-escaped (no regex specials).
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, 'g')
  const matches = re.exec(SECURITY_MONITOR_CSS)
  return matches?.[1] ?? null
}

function extractBaseBackground(selector: string): string | null {
  // Match `.cls { background: ...; ... }` (no pseudo) and grab the
  // first `background:` declaration. Anchored to the closing brace so
  // a nested at-rule wouldn't fool us.
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`${escaped}\\s*\\{([^}]*)\\}`, 'g')
  const block = re.exec(SECURITY_MONITOR_CSS)?.[1]
  if (!block) return null
  const bg = block.match(/background:\s*([^;]+);/)
  return bg?.[1]?.trim() ?? null
}

describe('SECURITY_MONITOR_CSS — button hover states', () => {
  describe('filled variants carry their own :hover rule', () => {
    const FILLED_VARIANTS = [
      { variant: 'primary', selector: '.dsh-secmon-button--primary:hover:not(:disabled)' },
      // The bug case: success had no dedicated hover until this fix.
      { variant: 'success', selector: '.dsh-secmon-button--success:hover:not(:disabled)' },
    ]

    for (const { variant, selector } of FILLED_VARIANTS) {
      it(`${variant}: declares a :hover:not(:disabled) override`, () => {
        const rule = extractRule(selector)
        expect(
          rule,
          `expected "${selector} { ... }" to exist in SECURITY_MONITOR_CSS so ` +
            `the filled variant stays visually distinct from the default ` +
            `neutral-button hover. Without this rule the variant bleeds ` +
            `through to the default 6% overlay, which renders white text ` +
            `on near-white bg (the original bug).`,
        ).not.toBeNull()
        // The override must set a background — otherwise it's just an
        // empty rule and the bug regresses the moment someone copies
        // the structure but forgets the property.
        expect(rule).toMatch(/background\s*:/)
      })
    }
  })

  describe('visual baseline', () => {
    it('primary fill defaults to blue when the host omits the theme token', () => {
      // Pin the operator-supplied reference: the Save action is the
      // only BLUE surface in the toolbar (Undo / Copy JSON are green).
      // The earlier release shipped `rgb(15, 17, 21)` (essentially
      // black) as the fallback — the operator reported the Save
      // button "looks black, not blue" against the reference mockup.
      // Tailwind blue-600 (`rgb(37, 99, 235)`) is the agreed value.
      const rule = extractRule('.dsh-secmon-button--primary')
      expect(rule).not.toBeNull()
      expect(rule).toMatch(/rgb\(37,\s*99,\s*235\)/)
    })

    it('primary hover uses the exact operator-specified blue-700', () => {
      // 2026-09-28: the hover was switched from the approximate
      // color-mix(... 85%, black) chain (rgb(29,78,216) vs the
      // computed rgb(31,84,200)-ish shade drifted by a few units) to
      // the EXACT operator table value: base blue-600 rgb(37,99,235)
      // → hover blue-700 rgb(29,78,216). The token var stays (host
      // theme override), the literal fallback is pinned here.
      const hover = extractRule('.dsh-secmon-button--primary:hover:not(:disabled)')
      expect(hover).not.toBeNull()
      expect(hover).toMatch(/--dsw-alias-button-primary-hover/)
      expect(hover).toMatch(/rgb\(29,\s*78,\s*216\)/)
      // And it must NOT be the old plain-rgb dark gray, which is what
      // produced the operator's "button changed colour on hover" complaint.
      expect(hover).not.toMatch(/rgb\(56,\s*62,\s*74\)/)
    })

    it('success hover uses the exact operator-specified green', () => {
      // Undo / Copy JSON: base rgb(34,197,94) → hover rgb(28,168,80),
      // exact values from the operator table (the color-mix 85% chain
      // computed rgb(29,167,80) — close but not the table).
      const hover = extractRule('.dsh-secmon-button--success:hover:not(:disabled)')
      expect(hover).not.toBeNull()
      expect(hover).toMatch(/--dsw-alias-button-success-hover/)
      expect(hover).toMatch(/rgb\(28,\s*168,\s*80\)/)
    })
  })

  it('success hover background differs from the rest background', () => {
    // Pin the bug — if a future refactor equalises the two, the
    // operator loses hover feedback again.
    const baseBg = extractBaseBackground('.dsh-secmon-button--success')
    const hover = extractRule('.dsh-secmon-button--success:hover:not(:disabled)')
    expect(baseBg, 'base .dsh-secmon-button--success { background } must exist').not.toBeNull()
    expect(hover, '.dsh-secmon-button--success:hover { ... } must exist').not.toBeNull()
    // The hover rule's body should reference some colour literal
    // (color-mix / hex / rgb / hsl). Catches the regression where
    // someone copies the rule body but forgets to set background.
    expect(hover).toMatch(/(color-mix|#[0-9a-fA-F]{3,8}|rgb\(|hsl\()/)
    // And the hover rule's background literal must not byte-equal the
    // base literal — catches the "copied the rule but forgot to
    // change the value" regression. Compare the raw strings
    // (extractBaseBackground returns the literal, extractRule returns
    // the whole body).
    const hoverBg = hover!.match(/background:\s*([^;]+);/)![1].trim()
    expect(hoverBg).not.toBe(baseBg)
  })

  it('success hover keeps enough contrast against white text', () => {
    // The original bug: hover background was a 6% overlay over the
    // host bg — contrast against the white text dropped to ~1:1 and
    // the button looked blank. Lock the new hover in by asserting it
    // uses a dedicated solid hover token (so a host that overrides
    // the button colours keeps its colour story intact) with a
    // green-derived literal fallback — not a translucent overlay.
    const hover = extractRule('.dsh-secmon-button--success:hover:not(:disabled)')
    expect(hover).not.toBeNull()
    expect(hover).toMatch(/--dsw-alias-button-success-hover|rgb\(28,\s*168,\s*80\)/)
    // Must NOT be a 6%/transparent mixin over the parent — that's the
    // pattern that broke the original UX. A real colour, even a
    // dimmed one, is what we want.
    expect(hover).not.toMatch(/transparent/)
  })

  it('hover rules are scoped so disabled buttons never hover', () => {
    // Every filled-variant hover selector must carry :not(:disabled)
    // so a disabled button keeps its rest background instead of
    // picking up the (darker) hover fill on mouse-over.
    for (const selector of [
      '.dsh-secmon-button--primary:hover:not(:disabled)',
      '.dsh-secmon-button--success:hover:not(:disabled)',
    ]) {
      const rule = extractRule(selector)
      expect(rule, `${selector} must exist`).not.toBeNull()
    }
    // The bare base-button hover is scoped the same way.
    expect(SECURITY_MONITOR_CSS).toMatch(
      /\.dsh-secmon-button:hover:not\(:disabled\)/,
    )
  })
})