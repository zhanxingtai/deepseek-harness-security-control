/**
 * spec §7.4 blockCode 命名域校验。
 *
 * 命名域正则: ^[A-Z][A-Z0-9]*_[A-Z][A-Z0-9_]*_[0-9]{3}$
 * (3-segment: `<CATEGORY_UPPER>_<threat>_<NNN>`)
 *
 * 行为矩阵 (违规即 drop):
 *   - decision=block + 缺 blockCode       → advisory warn + 规则 drop
 *   - decision=block + blockCode 合规     → 0 warning + 规则保留
 *   - decision=block + blockCode 不合规   → advisory warn + 规则 drop
 *   - decision=block + blockCode 前缀不对齐 rule.category.toUpperCase()_  → advisory warn + 规则 drop
 *   - decision≠block + blockCode 存在      → advisory warn + 规则保留 (spec §5.2)
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

const DROPPED = 'dropped — spec §7.4 is enforced strictly'

function policy(action: Record<string, unknown>, category = 'intrusion_defense'): string {
  return JSON.stringify({
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'p' },
    rules: [
      {
        id: 'r',
        category,
        priority: 100,
        match: {},
        action,
      },
    ],
  })
}

describe('RuleLoader — blockCode 命名域 (spec §7.4, 违规即 drop)', () => {
  it('accepts well-formed blockCode silently', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'INTRUSION_DEFENSE_REVERSE_SHELL_001' }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })

  it('drops rule when decision=block lacks blockCode', () => {
    const result = loadPolicyFromText(policy({ decision: 'block', blockReason: 'x' }), '/tmp/x.json')
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) => m.includes('missing action.blockCode') && m.includes('spec §5.2'))).toBe(true)
    expect(result.warnings?.some((m) => m.includes(DROPPED))).toBe(true)
  })

  it('drops rule when blockCode violates the naming regex', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'DATA_LEAK_imds_001' }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) => m.includes('DATA_LEAK_imds_001') && m.includes('violates spec §7.4'))).toBe(true)
    expect(result.warnings?.some((m) => m.includes(DROPPED))).toBe(true)
  })

  it('drops rule when blockCode has no threat segment (2-segment shape)', () => {
    // Truly 2-segment shape — `CATEGORY_NNN` with no threat in between.
    // `SELF_PROTECTION_INSTALLER_UNINSTALL_010` happens to LOOK 2-segment but is actually 3-segment
    // (`SELF_PROTECTION` | `010` is wrong parsing; the regex matches
    // `SELF` | `PROTECTION_010` if 3-segment is enforced). So we use a
    // shape that genuinely fails the 3-segment regex:
    // `LEAK_001` (no CATEGORY) — fails the `^[A-Z][A-Z0-9]*_` prefix.
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'LEAK_001' }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) => m.includes('LEAK_001') && m.includes('violates spec §7.4'))).toBe(true)
  })

  it('drops rule when blockCode has non-digit NNN suffix', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'DATA_LEAK_IMDS_AB' }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) => m.includes('DATA_LEAK_IMDS_AB') && m.includes('violates spec §7.4'))).toBe(true)
  })

  it('warns but keeps rule on non-block decision carrying blockCode (spec §5.2)', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'warn', blockCode: 'INTRUSION_DEFENSE_REVERSE_SHELL_001' }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings?.some((m) => m.includes('blockCode present but decision is "warn"'))).toBe(true)
  })

  it('regression: DATA_LEAK_MONITORING_IMDS_009 passes (canonical example)', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'DATA_LEAK_MONITORING_IMDS_009' }, 'data_leak_monitoring'),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })

  it('regression: SELF_PROTECTION_UNINSTALL_001 passes', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'SELF_PROTECTION_UNINSTALL_001' }, 'self_protection'),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })

  it('regression: INTRUSION_DEFENSE_MASS_DELETION_005 passes (current shipped format)', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'INTRUSION_DEFENSE_MASS_DELETION_005' }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })
})