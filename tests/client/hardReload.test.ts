/**
 * hardReload — page-level hard refresh (Ctrl+Shift+R equivalent).
 *
 * The operator's real need (2026-10-12): after reinstalling the plugin
 * the webview keeps serving the stale client bundle; a data-only
 * refresh cannot help. hardReload navigates to the current URL with a
 * cache-busting query param so every asset re-fetches.
 */
import { describe, expect, it } from 'vitest'
import { hardReload } from '../../src/client/hardReload.js'

/** Minimal Location stand-in — jsdom navigation is a no-op, so the
 *  test observes the href assignment instead. */
function fakeLocation(href: string): Location {
  const loc = { href } as Location
  Object.defineProperty(loc, 'reload', {
    value: () => undefined,
    enumerable: false,
  })
  return loc
}

describe('hardReload', () => {
  it('appends a cache-busting _hr param to the current URL', () => {
    const loc = fakeLocation('http://localhost:5173/?page=security-monitor')
    hardReload(loc)
    const url = new URL(loc.href)
    expect(url.origin + url.pathname).toBe('http://localhost:5173/')
    expect(url.searchParams.get('page')).toBe('security-monitor')
    expect(url.searchParams.get('_hr')).toBeTruthy()
  })

  it('overwrites a stale _hr param instead of accumulating params', () => {
    const loc = fakeLocation('http://localhost:5173/?_hr=123')
    hardReload(loc)
    const params = new URL(loc.href).searchParams.getAll('_hr')
    expect(params.length).toBe(1)
    expect(params[0]).not.toBe('123')
  })

  it('falls back to location.reload() when the URL is unparseable', () => {
    let reloaded = 0
    // Empty href → `new URL('')` throws → reload fallback.
    const loc = { href: '' } as Location
    Object.defineProperty(loc, 'reload', { value: () => reloaded++ })
    hardReload(loc)
    expect(reloaded).toBe(1)
  })
})
