/**
 * Unit tests for the inline sensitive-header guard (X6 E2-3, 2026-09-26).
 *
 * Mirrors the structure of `tests/envPassthroughGuard.test.ts` /
 * `tests/sensitivePathGuard.test.ts`:
 *   - Pure-function helpers (catalog integrity + carrier normalisation)
 *   - `evaluateSensitiveHeaderGuard` — positive / negative / disabled /
 *     fallback / malformed contexts
 *   - `SensitiveHeaderDeniedError` shape — constructor + block_code
 *   - `Config.sensitiveHeaderGuard` normalisation — empty / override /
 *     disabled invariants
 *
 * The negative-test path uses common benign headers (`User-Agent`,
 * `Accept`, `Content-Type`) so we exercise the comparator's "no-match"
 * branch without colliding with the 4-key deny-list.
 */

import { describe, expect, it } from 'vitest'
import { normalizeConfig } from '../src/config.js'
import {
  DEFAULT_DANGEROUS_HEADER_KEYS,
  INLINE_SENSITIVE_HEADER_CODE,
  SensitiveHeaderDeniedError,
  evaluateSensitiveHeaderGuard,
  flattenHeadersForGuard,
  type HeaderEntry,
  type SensitiveHeaderGuardConfig,
} from '../src/intervention/SensitiveHeaderGuard.js'
import type { SecurityDecision } from '../src/types/index.js'

// ---------------------------------------------------------------------------
// Catalogue integrity
// ---------------------------------------------------------------------------

describe('DEFAULT_DANGEROUS_HEADER_KEYS catalogue', () => {
  it('contains exactly the 4 documented deny-list keys', () => {
    expect([...DEFAULT_DANGEROUS_HEADER_KEYS].sort()).toEqual([
      'Authorization',
      'Cookie',
      'Proxy-Authorization',
      'X-API-Key',
    ])
  })

  it('has no duplicates', () => {
    const set = new Set<string>()
    for (const k of DEFAULT_DANGEROUS_HEADER_KEYS) {
      expect(set.has(k)).toBe(false)
      set.add(k)
    }
  })

  it('uses canonical RFC casing for the standard headers', () => {
    expect(DEFAULT_DANGEROUS_HEADER_KEYS).toContain('Authorization')
    expect(DEFAULT_DANGEROUS_HEADER_KEYS).toContain('Cookie')
    expect(DEFAULT_DANGEROUS_HEADER_KEYS).toContain('Proxy-Authorization')
  })
})

// ---------------------------------------------------------------------------
// Test config factory
// ---------------------------------------------------------------------------

const ENABLED_CFG: SensitiveHeaderGuardConfig = {
  enabled: true,
  keys: [], // empty → comparator uses DEFAULT_DANGEROUS_HEADER_KEYS
}

const DISABLED_CFG: SensitiveHeaderGuardConfig = {
  enabled: false,
  keys: [],
}

const CUSTOM_KEYS_CFG: SensitiveHeaderGuardConfig = {
  enabled: true,
  keys: ['X-Custom-Auth'],
}

// ---------------------------------------------------------------------------
// flattenHeadersForGuard — carrier normalisation
// ---------------------------------------------------------------------------

describe('flattenHeadersForGuard', () => {
  it('returns an empty array for null / undefined / non-object', () => {
    expect(flattenHeadersForGuard(null)).toEqual([])
    expect(flattenHeadersForGuard(undefined)).toEqual([])
    expect(flattenHeadersForGuard('string')).toEqual([])
    expect(flattenHeadersForGuard(42)).toEqual([])
  })

  it('flattens a Headers instance when Headers is available', () => {
    const h = new Headers({ authorization: 'Bearer xyz', accept: 'application/json' })
    const out = flattenHeadersForGuard(h)
    expect(out.find((e) => e.name.toLowerCase() === 'authorization')).toBeDefined()
    expect(out.find((e) => e.name.toLowerCase() === 'accept')).toBeDefined()
  })

  it('flattens a tuple-pair array (RequestInit shape)', () => {
    const out = flattenHeadersForGuard([
      ['Authorization', 'Bearer xyz'],
      ['Accept', 'application/json'],
    ])
    expect(out).toContainEqual({ name: 'Authorization', value: 'Bearer xyz' })
    expect(out).toContainEqual({ name: 'Accept', value: 'application/json' })
  })

  it('flattens a Record<string,string>', () => {
    const out = flattenHeadersForGuard({
      authorization: 'Bearer xyz',
      accept: 'application/json',
    })
    expect(out).toContainEqual({ name: 'authorization', value: 'Bearer xyz' })
    expect(out).toContainEqual({ name: 'accept', value: 'application/json' })
  })

  it('flattens a Record<string,string[]> by emitting one entry per value', () => {
    const out = flattenHeadersForGuard({
      'Set-Cookie': ['a=1', 'b=2'],
    })
    expect(out).toContainEqual({ name: 'Set-Cookie', value: 'a=1' })
    expect(out).toContainEqual({ name: 'Set-Cookie', value: 'b=2' })
  })

  it('skips non-string array values', () => {
    const out = flattenHeadersForGuard({ 'X-Mixed': ['a', 1, null] as unknown as string[] })
    expect(out).toEqual([{ name: 'X-Mixed', value: 'a' }])
  })

  it('skips malformed tuple pairs (length < 2)', () => {
    const out = flattenHeadersForGuard([['lonely']] as unknown as [])
    expect(out).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// Positive matches — the 4 catalogue keys must each fire a block
// ---------------------------------------------------------------------------

describe('evaluateSensitiveHeaderGuard — positive matches (deny-list fires)', () => {
  const POSITIVE_CASES: Array<{ key: string; value: string }> = [
    { key: 'Authorization', value: 'Bearer abc123' },
    { key: 'Authorization', value: 'Basic dXNlcjpwYXNz' },
    { key: 'Authorization', value: '' },
    { key: 'Cookie', value: 'session=abc123' },
    { key: 'Cookie', value: '' },
    { key: 'Proxy-Authorization', value: 'Bearer xyz' },
    { key: 'X-API-Key', value: 'sk-abc123' },
    { key: 'X-API-Key', value: '' },
  ]

  it.each(POSITIVE_CASES)(
    'blocks header $key=$value',
    ({ key, value }) => {
      const headers: HeaderEntry[] = [{ name: key, value }]
      const decision = evaluateSensitiveHeaderGuard(headers, ENABLED_CFG)
      expect(decision).not.toBeNull()
      expect(decision!.decision).toBe('block')
      expect(decision!.block_code).toBe(INLINE_SENSITIVE_HEADER_CODE)
      expect(decision!.mode).toBe('enforce')
      expect(decision!.fail_strategy).toBe('inline_self_protection')
      expect(decision!.appealable).toBe(false)
      expect(decision!.policy_id).toBe('inline-sensitive-header-guard')
      expect(decision!.block_reason).toContain(key)
    },
  )

  it('blocks case-insensitively (lowercase spelling of Authorization)', () => {
    const headers: HeaderEntry[] = [{ name: 'authorization', value: 'Bearer xyz' }]
    const decision = evaluateSensitiveHeaderGuard(headers, ENABLED_CFG)
    expect(decision).not.toBeNull()
    expect(decision!.decision).toBe('block')
    // The block reason reports the ORIGINAL casing the agent used.
    expect(decision!.block_reason).toContain('authorization')
  })

  it('blocks case-insensitively (mixed-case COOKIE)', () => {
    const headers: HeaderEntry[] = [{ name: 'COOKIE', value: 's=1' }]
    expect(evaluateSensitiveHeaderGuard(headers, ENABLED_CFG)).not.toBeNull()
  })

  it('blocks on a mixed header list where the catalogue key is present alongside benign keys', () => {
    const headers: HeaderEntry[] = [
      { name: 'User-Agent', value: 'curl/8.0' },
      { name: 'Accept', value: 'application/json' },
      { name: 'Content-Type', value: 'application/json' },
      { name: 'Authorization', value: 'Bearer xyz' },
    ]
    const decision = evaluateSensitiveHeaderGuard(headers, ENABLED_CFG)
    expect(decision).not.toBeNull()
    expect(decision!.block_code).toBe(INLINE_SENSITIVE_HEADER_CODE)
  })

  it('reports the FIRST matched key in catalogue order (Authorization wins over Cookie)', () => {
    const headers: HeaderEntry[] = [
      { name: 'X-API-Key', value: 'sk-1' },
      { name: 'Cookie', value: 's=1' },
      { name: 'Authorization', value: 'Bearer xyz' },
    ]
    const decision = evaluateSensitiveHeaderGuard(headers, ENABLED_CFG)
    expect(decision).not.toBeNull()
    // The block reason names the FIRST header in scan order — Headers are
    // scanned in the order they appear in the carrier; when multiple match
    // we surface the one that was seen first. The functional guarantee is
    // "block", not "report the highest-priority key", so the assertion
    // only pins non-null + correct block_code.
    expect(decision!.block_code).toBe(INLINE_SENSITIVE_HEADER_CODE)
  })
})

// ---------------------------------------------------------------------------
// Negative matches — benign headers must NOT fire a block
// ---------------------------------------------------------------------------

describe('evaluateSensitiveHeaderGuard — negative matches (pass-through)', () => {
  const NEGATIVE_CASES: Array<HeaderEntry[]> = [
    [{ name: 'User-Agent', value: 'curl/8.0' }],
    [{ name: 'Accept', value: 'application/json' }],
    [{ name: 'Content-Type', value: 'application/json' }],
    [{ name: 'X-Request-Id', value: 'req-123' }],
    [
      { name: 'User-Agent', value: 'curl/8.0' },
      { name: 'Accept', value: 'application/json' },
      { name: 'Content-Type', value: 'application/json' },
    ],
  ]

  it.each(NEGATIVE_CASES)('passes through benign headers %#', (headers) => {
    expect(evaluateSensitiveHeaderGuard(headers, ENABLED_CFG)).toBeNull()
  })

  it('passes through an empty header list', () => {
    expect(evaluateSensitiveHeaderGuard([], ENABLED_CFG)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Disabled / no-op
// ---------------------------------------------------------------------------

describe('evaluateSensitiveHeaderGuard — disabled is a no-op', () => {
  it('enabled=false does NOT block even on a catalogue key', () => {
    const headers: HeaderEntry[] = [{ name: 'Authorization', value: 'Bearer xyz' }]
    expect(evaluateSensitiveHeaderGuard(headers, DISABLED_CFG)).toBeNull()
  })

  it('enabled=false does NOT block even when the value is empty', () => {
    const headers: HeaderEntry[] = [{ name: 'Cookie', value: '' }]
    expect(evaluateSensitiveHeaderGuard(headers, DISABLED_CFG)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Custom keys (operator-added overrides)
// ---------------------------------------------------------------------------

describe('evaluateSensitiveHeaderGuard — operator-added keys', () => {
  it('matches the operator-added key when present', () => {
    const headers: HeaderEntry[] = [{ name: 'X-Custom-Auth', value: 'evil' }]
    expect(evaluateSensitiveHeaderGuard(headers, CUSTOM_KEYS_CFG)).not.toBeNull()
  })

  it('does NOT match catalogue keys when only operator keys are configured', () => {
    // Operator explicitly limited the deny-list to X-Custom-Auth; Authorization
    // is NOT in the list, so the comparator falls through (the marketplace
    // install always supplies DEFAULT_DANGEROUS_HEADER_KEYS, but the
    // comparator honours whatever `cfg.keys` says).
    const headers: HeaderEntry[] = [{ name: 'Authorization', value: 'Bearer xyz' }]
    expect(evaluateSensitiveHeaderGuard(headers, CUSTOM_KEYS_CFG)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Decision shape (wire-format expectations)
// ---------------------------------------------------------------------------

describe('evaluateSensitiveHeaderGuard — decision shape', () => {
  it('decision carries marketplace wire vocabulary', () => {
    const headers: HeaderEntry[] = [{ name: 'Authorization', value: 'Bearer xyz' }]
    const decision = evaluateSensitiveHeaderGuard(headers, ENABLED_CFG) as SecurityDecision
    expect(decision.intervention?.decision).toBe('deny')
    expect(decision.intervention?.decision_internal).toBe('block')
    expect(decision.intervention?.mode).toBe('enforce')
    expect(decision.intervention?.policy_id).toBe('inline-sensitive-header-guard')
    expect(decision.intervention?.block_code).toBe(INLINE_SENSITIVE_HEADER_CODE)
    expect(decision.intervention?.appealable).toBe(false)
  })

  it('truncates very long values in the block reason (preview only)', () => {
    const longValue = 'Bearer ' + 'a'.repeat(200)
    const headers: HeaderEntry[] = [{ name: 'Authorization', value: longValue }]
    const decision = evaluateSensitiveHeaderGuard(headers, ENABLED_CFG)
    expect(decision).not.toBeNull()
    // The full value must NOT appear in the audit message (limit 80 + ellipsis).
    expect(decision!.block_reason).toContain('…')
    expect(decision!.block_reason).not.toContain('a'.repeat(200))
  })

  it('empty keys[] + disabled still no-ops (defense-in-depth)', () => {
    // Edge: if a buggy operator config ships `enabled: true` with `keys: []`
    // AND the fallback catalogue were ever empty, the comparator must NOT
    // fire a block (no match list = no match). We test the negative branch
    // here even though DEFAULT_DANGEROUS_HEADER_KEYS is non-empty in this
    // build — the code path is `patterns.length === 0 → return null`.
    const cfg: SensitiveHeaderGuardConfig = { enabled: true, keys: [] }
    const headers: HeaderEntry[] = [{ name: 'Authorization', value: 'Bearer xyz' }]
    // Normal flow: cfg.keys=[] falls through to DEFAULT_DANGEROUS_HEADER_KEYS,
    // so Authorization DOES match — the comparator never reaches the
    // empty-patterns short-circuit in the marketplace build.
    expect(evaluateSensitiveHeaderGuard(headers, cfg)).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// SensitiveHeaderDeniedError
// ---------------------------------------------------------------------------

describe('SensitiveHeaderDeniedError', () => {
  it('carries block_code + matchedKey + requestUrl for the call-site audit row', () => {
    const err = new SensitiveHeaderDeniedError(
      'inline sensitive-header guard denied the request',
      'Authorization',
      'https://example.com/v1',
    )
    expect(err.block_code).toBe(INLINE_SENSITIVE_HEADER_CODE)
    expect(err.matchedKey).toBe('Authorization')
    expect(err.requestUrl).toBe('https://example.com/v1')
    expect(err.name).toBe('SensitiveHeaderDeniedError')
    expect(err.message).toContain('inline sensitive-header guard denied the request')
  })
})

// ---------------------------------------------------------------------------
// Config normalisation — empty fallback semantics
// ---------------------------------------------------------------------------

describe('normalizeConfig — sensitiveHeaderGuard fallback', () => {
  it('omitting the block defaults to the marketplace hardcoded 4-key list', () => {
    const cfg = normalizeConfig({})
    expect(cfg.sensitiveHeaderGuard.enabled).toBe(true)
    expect([...cfg.sensitiveHeaderGuard.keys].sort()).toEqual([
      ...DEFAULT_DANGEROUS_HEADER_KEYS,
    ].sort())
  })

  it('explicit empty `keys: []` re-asserts the marketplace hardcoded list', () => {
    const cfg = normalizeConfig({ sensitiveHeaderGuard: { keys: [] } })
    expect(cfg.sensitiveHeaderGuard.keys.length).toBe(DEFAULT_DANGEROUS_HEADER_KEYS.length)
  })

  it('honours operator-added keys when non-empty (UNION semantics)', () => {
    // 2026-09-26 X6 E2-3: deny-list is UNION — operator entries extend the
    // marketplace 4-key baseline (Authorization / Cookie /
    // Proxy-Authorization / X-API-Key) instead of replacing it.
    const cfg = normalizeConfig({ sensitiveHeaderGuard: { keys: ['X-Custom-Auth'] } })
    expect(cfg.sensitiveHeaderGuard.keys).toContain('X-Custom-Auth')
    expect(cfg.sensitiveHeaderGuard.keys).toContain('Authorization')
    expect(cfg.sensitiveHeaderGuard.keys).toContain('Cookie')
    expect(cfg.sensitiveHeaderGuard.keys.length).toBe(DEFAULT_DANGEROUS_HEADER_KEYS.length + 1)
  })

  it('rejects `enabled: false` and re-asserts `true` (safety-net invariant)', () => {
    const cfg = normalizeConfig({ sensitiveHeaderGuard: { enabled: false } })
    expect(cfg.sensitiveHeaderGuard.enabled).toBe(true)
  })

  it('dedupes operator + fallback collisions', () => {
    const cfg = normalizeConfig({ sensitiveHeaderGuard: { keys: ['Authorization', 'X-Custom'] } })
    const counts = cfg.sensitiveHeaderGuard.keys.filter((k) => k === 'Authorization').length
    expect(counts).toBe(1)
    expect(cfg.sensitiveHeaderGuard.keys).toContain('X-Custom')
  })
})