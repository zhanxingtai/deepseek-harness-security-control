/**
 * spec §7.4 `<CATEGORY 大写>` 段必须等于 rule.category.toUpperCase()。
 *
 * 行为矩阵:
 *   - blockCode 前缀 = rule.category.toUpperCase() + '_'    → 0 warning + 保留
 *   - blockCode 前缀 ≠ rule.category.toUpperCase() + '_'    → advisory + drop
 *
 * 例如: rule.category='intrusion_defense' 要求 blockCode 以 INTRUSION_DEFENSE_ 开头;
 *        POLICY_* / SELF_PROTECTION_* 这类历史散乱前缀一律 drop。
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

const DROPPED = 'dropped — spec §7.4 is enforced strictly'

function policy(action: Record<string, unknown>, category: string): string {
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

describe('RuleLoader — blockCode category-prefix alignment (spec §7.4)', () => {
  it('drops rule when blockCode prefix mismatches rule.category (POLICY_* under intrusion_defense)', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'POLICY_EXEC_REVERSE_SHELL_001' }, 'intrusion_defense'),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) =>
      m.includes('POLICY_EXEC_REVERSE_SHELL_001') &&
      m.includes('prefix does not match') &&
      m.includes('intrusion_defense'),
    )).toBe(true)
    expect(result.warnings?.some((m) => m.includes(DROPPED))).toBe(true)
  })

  it('drops rule when SELF_PROTECTION_* prefix under intrusion_defense', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'SELF_PROTECTION_LDSO_001' }, 'intrusion_defense'),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) => m.includes('prefix does not match'))).toBe(true)
  })

  it('drops rule when INTRUSION_DEFENSE_* prefix under data_leak_monitoring (wrong category layer)', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'INTRUSION_DEFENSE_FOO_BAR_001' }, 'data_leak_monitoring'),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) => m.includes('prefix does not match'))).toBe(true)
  })

  it('accepts rule when blockCode prefix matches rule.category (regression: shipped default-policy format)', () => {
    const result = loadPolicyFromText(
      policy({ decision: 'block', blockReason: 'x', blockCode: 'INTRUSION_DEFENSE_REVERSE_SHELL_001' }, 'intrusion_defense'),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })

  it('prefixes for the 8 spec §7.2 enum values all align', () => {
    const cases = [
      { category: 'self_protection', prefix: 'SELF_PROTECTION' },
      { category: 'intrusion_defense', prefix: 'INTRUSION_DEFENSE' },
      { category: 'data_leak_monitoring', prefix: 'DATA_LEAK_MONITORING' },
      { category: 'sensitive_data_access', prefix: 'SENSITIVE_DATA_ACCESS' },
      { category: 'supply_chain', prefix: 'SUPPLY_CHAIN' },
      { category: 'ssrf', prefix: 'SSRF' },
      { category: 'behavior_guidance', prefix: 'BEHAVIOR_GUIDANCE' },
      { category: 'data_desensitization', prefix: 'DATA_DESENSITIZATION' },
    ]
    for (const { category, prefix } of cases) {
      const result = loadPolicyFromText(
        policy({ decision: 'block', blockReason: 'x', blockCode: `${prefix}_THREAT_SUB_001` }, category),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules.map((r) => r.id)).toEqual(['r'])
      expect(result.warnings ?? []).toEqual([])
    }
  })

  it('severity=low downgrade is independent of category-prefix alignment (severity runs after compile-time validation)', () => {
    // Severity is checked at runtime by DecisionComposer; prefix alignment is
    // a compile-time concern. They don't interact — a properly-prefixed
    // blockCode rule with severity=low still passes compile.
    const result = loadPolicyFromText(
      JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [{
          id: 'r',
          category: 'intrusion_defense',
          priority: 100,
          severity: 'low',
          match: {},
          action: { decision: 'block', blockReason: 'x', blockCode: 'INTRUSION_DEFENSE_GENERIC_001' },
        }],
      }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })
})