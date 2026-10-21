/**
 * Tests for the plugin stylesheet (`src/client/styles.ts`) —
 * 2026-09-23 styling unification.
 *
 * Drift guards:
 *  - every `.dsh-secmon-*` class emitted by the client components has a
 *    rule in the stylesheet (a component/class rename without a style
 *    update fails here, and vice versa);
 *  - colours are host theme tokens (`var(--dsw-alias-*)`) — no bare
 *    hardcoded colours on themed surfaces;
 *  - `injectSecurityMonitorStyles` is idempotent and DOM-guarded.
 */
import { readFileSync } from 'node:fs'
import { globSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { SECURITY_MONITOR_CSS, injectSecurityMonitorStyles } from '../../src/client/styles.js'

const CLIENT_SRC = resolve(__dirname, '..', '..', 'src', 'client')

/** Collect every `.dsh-secmon-*` class name referenced by components. */
function componentClasses(): Set<string> {
  const files = globSync('**/*.{ts,tsx}', { cwd: CLIENT_SRC })
  const classes = new Set<string>()
  const re = /dsh-secmon-[a-z0-9-]+/g
  for (const file of files) {
    if (file === 'styles.ts') continue
    const text = readFileSync(join(CLIENT_SRC, file), 'utf8')
    for (const m of text.matchAll(re)) {
      // Skip modifier fragments captured mid-concatenation
      // (`'dsh-secmon-tab--active'` is a full class; `'dsh-secmon-'`
      // prefixes from string concatenation are not).
      if (m[0].endsWith('-')) continue
      classes.add(m[0])
    }
  }
  return classes
}

/** Class names actually defined by the stylesheet. */
function styledClasses(): Set<string> {
  const classes = new Set<string>()
  const re = /\.(dsh-secmon-[a-z0-9-]+)/g
  for (const m of SECURITY_MONITOR_CSS.matchAll(re)) classes.add(m[1])
  return classes
}

describe('SECURITY_MONITOR_CSS', () => {
  it('covers every dsh-secmon-* class the components emit', () => {
    const missing: string[] = []
    const styled = styledClasses()
    for (const cls of componentClasses()) {
      // Modifier classes are styled via their base + modifier selector;
      // `--`-suffixed classes must exist verbatim (e.g. `--active`).
      if (!styled.has(cls)) missing.push(cls)
    }
    expect(missing).toEqual([])
  })

  it('sources every colour from host theme tokens with fallbacks', () => {
    // No bare hex colours (fallbacks ride inside var() calls).
    const bareHex = SECURITY_MONITOR_CSS.match(/(?<!var\([^)]*)#[0-9a-fA-F]{3,8}\b/g) ?? []
    expect(bareHex).toEqual([])
    // Every var() reference carries a fallback.
    const noFallback =
      SECURITY_MONITOR_CSS.match(/var\(--dsw-alias-[a-z-]+\)/g) ?? []
    expect(noFallback).toEqual([])
  })

  it('references only tokens that exist in the harness theme (snapshot)', () => {
    // Snapshot of the tokens this stylesheet consumes. When the harness
    // renames a token, this list is the diff surface — verify against
    // packages/client/ui-theme/src/styles/design-platform.css.
    const tokens = [
      ...SECURITY_MONITOR_CSS.matchAll(/var\(--dsw-alias-([a-z-]+)/g),
    ].map((m) => m[1])
    const unique = [...new Set(tokens)].sort()
    expect(unique).toMatchSnapshot()
  })
})

describe('injectSecurityMonitorStyles', () => {
  it('is a no-op outside a DOM', () => {
    expect(() => injectSecurityMonitorStyles()).not.toThrow()
  })

  it('injects once and skips duplicates', () => {
    const tag = { textContent: '', dataset: {} as Record<string, string> }
    const appended: unknown[] = []
    let queryHits = 0
    const fakeDocument = {
      querySelector: () => (queryHits > 0 ? tag : null),
      createElement: () => {
        queryHits += 1
        return tag
      },
      head: { appendChild: (t: unknown) => appended.push(t) },
    }
    globalThis.document = fakeDocument as unknown as Document
    try {
      injectSecurityMonitorStyles()
      injectSecurityMonitorStyles()
      expect(appended.length).toBe(1)
      expect(tag.textContent).toBe(SECURITY_MONITOR_CSS)
    } finally {
      delete (globalThis as Record<string, unknown>).document
    }
  })
})
