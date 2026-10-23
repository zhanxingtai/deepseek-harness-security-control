/**
 * Local-time formatter for the table `time` columns.
 *
 * Both the Event Stream (`Events.tsx`) and Policy Hits
 * (`RecentBlocks.tsx`) tabs render the same `YYYY-MM-DD HH:mm:ss`
 * shape, and both used to build it with `toISOString()`. Per the ECMA-262
 * spec `toISOString()` **always** returns UTC, so on any non-UTC host
 * the whole column read eight hours (or any other offset) behind the
 * operator's own clock — and before 08:00 local the *date* component
 * rolled back a day, which reads as stale or bogus data rather than as
 * a formatting choice. The stored `ts` is epoch milliseconds and was
 * always correct; only the render was wrong.
 *
 * This reads the calendar fields off the `Date` directly (local zone,
 * per ECMAScript local time) instead of round-tripping through UTC.
 * Deliberately not `toLocaleString()`: that is ICU/host-locale
 * dependent (field order, separators, `24:00` vs `00:00`) and would
 * make the column shape drift with the browser locale, and the
 * template preserves the exact prior glyph count so column widths and
 * the en/zh copy that references the format stay valid.
 *
 * Lives under `src/client/` (not `src/utils/`) on purpose:
 * `tsconfig.client.json` pins `rootDir` to `./src/client`, so a client
 * import reaching outside that subtree would fail the build.
 */

/**
 * Format epoch milliseconds as local `YYYY-MM-DD HH:mm:ss`.
 *
 * Returns `—` for the same invalid inputs the previous implementation
 * rejected (non-finite, non-positive) so a row with a missing or
 * sentinel timestamp keeps rendering the em-dash placeholder instead
 * of `1970-01-01`. Falls back to the raw value when the number is
 * outside the representable `Date` range (`getFullYear()` yields `NaN`
 * there, where `toISOString()` used to throw a `RangeError`).
 */
export function formatTime(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '—'
  const d = new Date(ms)
  if (!Number.isFinite(d.getTime())) return String(ms)
  const p = (n: number): string => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  )
}
