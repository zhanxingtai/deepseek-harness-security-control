/**
 * Tests for the timestamp formatters.
 *
 * Regression cover for the "Event Stream / Policy Hits times are 8 hours
 * behind the system clock" report: both tables rendered `ts` with
 * `Date.prototype.toISOString()`, which the spec pins to UTC, so the
 * whole column disagreed with the operator's own clock — and before 08:00
 * local the *date* rolled back a day, which reads as stale or bogus data
 * rather than as a formatting choice. The stored `ts` was always correct
 * epoch milliseconds; only the render was wrong.
 *
 * These assertions are host-timezone-independent by construction.
 * Pinning `process.env.TZ` per test is **not** an option: V8 honours that
 * in a plain `node` process, but the Vitest environment ignores it (it
 * did — the formatter kept rendering the host zone regardless), so a
 * test written that way would pass or fail for reasons unrelated to the
 * code. Instead:
 *  - local wall-clock fields are checked against `Intl.DateTimeFormat`
 *    (`en-CA` + `hourCycle: 'h23'`), an independent ICU code path;
 *  - the offset rendering is checked through the pure
 *    `formatUtcOffset`, so half/quarter-hour zones are covered even on a
 *    whole-hour host;
 *  - the "is it actually local, not UTC" property is asserted directly
 *    and self-skips when the host happens to sit on UTC.
 *
 * Coverage targets:
 *  - local wall-clock fields, not UTC
 *  - the pre-08:00 date-rollback case that made it look like stale data
 *  - signed half-hour and quarter-hour UTC offsets
 *  - degenerate inputs keep the `—` placeholder / degrade to raw value
 *  - `formatLocalIso` round-trips to the same instant (offset not lossy)
 */
import { describe, expect, it } from 'vitest'
import { formatTime } from '../../src/client/formatTime.js'
import { formatLocalIso, formatUtcOffset } from '../../src/utils/time.js'

const EM_DASH = '—'

/**
 * Independent (ICU) rendering of the local wall clock, as
 * `YYYY-MM-DD HH:mm:ss`. Assembled from `formatToParts` rather than the
 * formatted string because the literal separator is ICU/version
 * dependent (`, ` vs `T` vs space varies with the runtime's data), and
 * this must hold on whatever host runs the suite. `h23` forces 00–23 so
 * a midnight hour cannot come back as `24`.
 */
function iccLocalRef(ms: number): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(ms))
  const field = (type: Intl.DateTimeFormatPartTypes): string =>
    parts.find((p) => p.type === type)?.value ?? ''
  return `${field('year')}-${field('month')}-${field('day')} ` +
    `${field('hour')}:${field('minute')}:${field('second')}`
}

/** The UTC wall clock — what the buggy `toISOString()` render produced. */
function iccUtcRef(ms: number): string {
  return `${new Date(ms).toISOString().replace('T', ' ').slice(0, 19)}`
}

describe('formatTime (client table `time` column)', () => {
  // 2026-10-22T07:35:45Z — the exact shape of the reported bad rows.
  const MS = Date.UTC(2026, 9, 22, 7, 35, 45)

  it('renders local wall-clock fields, not UTC', () => {
    expect(formatTime(MS)).toBe(iccLocalRef(MS))
  })

  it('is not the UTC rendering when the host is not on UTC', () => {
    // The core regression. `getTimezoneOffset() === 0` means local *is*
    // UTC, where the old and new renderings are identical by definition
    // and there is nothing to distinguish — so the check cannot say
    // anything on such a host and says so rather than pretending.
    if (new Date(MS).getTimezoneOffset() === 0) return
    expect(formatTime(MS)).not.toBe(iccUtcRef(MS))
  })

  it('keeps the date component on the local day for pre-dawn events', () => {
    // The case that made this read as stale/bogus data rather than as a
    // formatting choice: local 03:00 is still the previous day in UTC,
    // so the old renderer printed the wrong calendar day. Only assertable
    // where the host is east of ~UTC-3; otherwise local 03:00 may be the
    // same UTC day and the assertion would be meaningless.
    if (new Date(MS).getTimezoneOffset() > 180) return
    const localThreeAm = new Date(MS)
    localThreeAm.setHours(3, 0, 0, 0)
    const formatted = formatTime(localThreeAm.getTime())
    expect(formatted.slice(0, 10)).toBe(iccLocalRef(localThreeAm.getTime()).slice(0, 10))
    expect(formatted.slice(11)).toBe('03:00:00')
  })

  it('always emits the fixed-width YYYY-MM-DD HH:mm:ss shape', () => {
    // Single-digit month/day/hour must be zero-padded, so column widths
    // and the locale copy that references this shape stay valid.
    for (const ms of [Date.UTC(2026, 0, 2, 1, 5, 9), MS, Date.UTC(1999, 11, 31, 23, 59, 59)]) {
      expect(formatTime(ms)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/)
    }
  })

  it('round-trips back to the same instant', () => {
    // Sub-second precision is intentionally dropped, so the parsed value
    // lands within the same second.
    expect(Math.abs(Date.parse(formatTime(MS).replace(' ', 'T')) - MS)).toBeLessThan(1000)
  })

  it('keeps the em-dash placeholder for missing / degenerate timestamps', () => {
    expect(formatTime(0)).toBe(EM_DASH)
    expect(formatTime(-1)).toBe(EM_DASH)
    expect(formatTime(Number.NaN)).toBe(EM_DASH)
    expect(formatTime(Number.POSITIVE_INFINITY)).toBe(EM_DASH)
  })

  it('degrades to the raw value instead of throwing on out-of-range input', () => {
    // `toISOString()` used to throw RangeError here; the catch returned
    // the raw number, and that fallback is preserved.
    const outOfRange = 8.7e15 + 1
    expect(formatTime(outOfRange)).toBe(String(outOfRange))
  })
})

describe('formatUtcOffset (pure offset rendering)', () => {
  it('renders signed whole-hour offsets', () => {
    expect(formatUtcOffset(0)).toBe('+00:00')
    expect(formatUtcOffset(480)).toBe('+08:00')
    expect(formatUtcOffset(-480)).toBe('-08:00')
    expect(formatUtcOffset(-210)).toBe('-03:30')
  })

  it('renders half- and quarter-hour offsets', () => {
    // The reason the offset is derived rather than assumed whole — but
    // only reachable on a host whose own zone has such an offset.
    expect(formatUtcOffset(330)).toBe('+05:30') // Asia/Kolkata
    expect(formatUtcOffset(-270)).toBe('-04:30') // Newfoundland
    expect(formatUtcOffset(345)).toBe('+05:45') // Asia/Kathmandu
    expect(formatUtcOffset(-570)).toBe('-09:30') // Pacific/Marquesas
  })

  it('zero-pads single-digit offset hours', () => {
    expect(formatUtcOffset(60)).toBe('+01:00')
    expect(formatUtcOffset(-60)).toBe('-01:00')
  })
})

describe('formatLocalIso (CLI `recent blocks` audit lines)', () => {
  const MS = Date.UTC(2026, 9, 22, 7, 35, 45)

  it('renders local wall-clock fields followed by the signed offset', () => {
    const d = new Date(MS)
    const expectedOffset = formatUtcOffset(-d.getTimezoneOffset())
    const rendered = formatLocalIso(MS)
    expect(rendered).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/)
    expect(rendered).toBe(iccLocalRef(MS).replace(' ', 'T') + expectedOffset)
    expect(rendered.endsWith(expectedOffset)).toBe(true)
  })

  it('round-trips to the same instant', () => {
    // Unlike the client helper, this one keeps the offset, so an audit
    // reader can recover the exact instant. Milliseconds are truncated,
    // hence the second-bound comparison.
    expect(Date.parse(formatLocalIso(MS))).toBe(Math.floor(MS / 1000) * 1000)
  })

  it('denotes the same UTC instant the legacy toISOString() did', () => {
    // The instant is unchanged; only the rendering moved into local time.
    expect(new Date(formatLocalIso(MS)).toISOString()).toBe(new Date(MS).toISOString())
  })

  it('prints +00:00 rather than Z when the host is on UTC', () => {
    // Only meaningful on a UTC host, but stable everywhere else.
    const offset = formatUtcOffset(-new Date(MS).getTimezoneOffset())
    expect(formatLocalIso(MS).slice(-6)).toBe(offset)
  })

  it('degrades to the raw value on degenerate input', () => {
    expect(formatLocalIso(Number.NaN)).toBe('NaN')
    expect(formatLocalIso(Number.POSITIVE_INFINITY)).toBe('Infinity')
    expect(formatLocalIso(8.7e15 + 1)).toBe(String(8.7e15 + 1))
  })
})
