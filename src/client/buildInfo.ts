/**
 * buildInfo — compile-time identity constants.
 *
 * `scripts/build-client.mjs` injects the `__SECURITY_MONITOR_VERSION__`
 * identifier as plain text via esbuild `define`:
 *
 *   - `__SECURITY_MONITOR_VERSION__` — the raw `version` field, prerelease
 *     suffix included (`0.5.3-rc1` stays verbatim).
 *
 * Under unit tests (vitest imports the TypeScript sources directly) the
 * defines are absent, so the `typeof` guard falls back to a stable literal.
 * Never hand-maintain the fallback string — the bundle path always
 * carries the injected value.
 */
declare const __SECURITY_MONITOR_VERSION__: string | undefined

/** Raw package.json version, prerelease included. */
export const PACKAGE_VERSION: string =
  typeof __SECURITY_MONITOR_VERSION__ === 'string'
    ? __SECURITY_MONITOR_VERSION__
    : '0.0.0-dev'
