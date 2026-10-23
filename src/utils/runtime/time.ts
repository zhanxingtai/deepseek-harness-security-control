export function nowMs(): number {
  return Date.now()
}

/**
 * Render a signed UTC offset as `±HH:MM`.
 *
 * `offsetMinutes` is minutes **east** of UTC — i.e. the negation of
 * `Date.prototype.getTimezoneOffset()`: `330` → `+05:30`, `-270` →
 * `-04:30`, `0` → `+00:00`.
 *
 * Split out of {@link formatLocalIso} so the sign flip and the
 * half/quarter-hour remainder are unit-testable on hosts that happen to
 * sit on a whole-hour zone; the live formatter can only ever exercise
 * whatever offset its own machine has.
 */
export function formatUtcOffset(offsetMinutes: number): string {
  const sign = offsetMinutes < 0 ? '-' : '+'
  const abs = Math.abs(offsetMinutes)
  const p = (n: number): string => String(n).padStart(2, '0')
  return `${sign}${p(Math.floor(abs / 60))}:${p(abs % 60)}`
}

/**
 * Format epoch milliseconds as a local-time ISO-8601 string with an
 * explicit UTC offset, e.g. `2026-10-22T15:35:45+08:00`.
 *
 * Used by the operator-facing CLI surfaces (see `renderBlocks` in
 * `src/commands/security.ts`). Those previously rendered timestamps with
 * `Date.prototype.toISOString()`, which the spec pins to **UTC**, so the
 * printed audit trail read hours away from the operator's own clock with
 * no way to tell an offset apart from stale data.
 *
 * Unlike the client's `formatTime`, this keeps the offset instead of
 * dropping it: this is audit output, where the exact instant has to stay
 * recoverable, so a bare wall-clock time would be lossy.
 *
 * Returns the raw input when it is not a usable `Date` (non-finite or
 * outside the representable range), so one malformed row degrades to a
 * readable value instead of throwing out of the command.
 */
export function formatLocalIso(ms: number): string {
  if (!Number.isFinite(ms)) return String(ms)
  const d = new Date(ms)
  if (!Number.isFinite(d.getTime())) return String(ms)
  const p = (n: number): string => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}` +
    `T${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}` +
    // getTimezoneOffset() is minutes *west* of UTC; invert to east.
    formatUtcOffset(-d.getTimezoneOffset())
  )
}
