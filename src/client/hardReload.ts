/**
 * hardReload — page-level hard refresh for the settings webview.
 *
 * The operator's real need: after reinstalling the plugin
 * (`dev:reinstall` reloads the HOST side via cordis HMR), the webview
 * keeps serving the stale `lib/client.js` bundle until the whole DSH
 * client restarts. A data-only refresh (polling.trigger) does not help
 * — the client code itself is cached. This performs the closest
 * JS-equivalent of Ctrl+Shift+R: navigate to the current URL with a
 * cache-busting query param, forcing the webview to re-fetch every
 * asset. The host-side plugin code is NOT affected (it lives in the
 * DSH host process and is reloaded by the plugin manager's HMR on
 * reinstall, not by page navigation).
 *
 * Injectable `loc` keeps the unit test off the real Location object
 * (jsdom navigation is a no-op / throws).
 */
export function hardReload(loc: Location = window.location): void {
  try {
    const url = new URL(loc.href)
    url.searchParams.set('_hr', String(Date.now()))
    loc.href = url.toString()
  } catch {
    // about:blank / opaque origin — fall back to a plain reload, which
    // at least re-runs bundle resolution in most webviews.
    loc.reload();
  }
}
