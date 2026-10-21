/**
 * spec §3 evaluate 区段 deprecated。
 *
 * 历史: v1 SPL 用 `evaluate: { risk_level: X }` 区段承载风险定级。
 * v2 SPL 把 risk_level 改名/上移到顶层 severity, reg_clause 上移到
 * regClause (§3 表)。evaluate 区段因此零信息残留 —— 携带它的规则在
 * 加载期即被 drop, 而不是降级成 warning。
 *
 * 行为矩阵:
 *   - 规则含 evaluate 区段 → advisory warning(列出字段映射) + 规则 drop
 *   - 规则不含 evaluate 区段 → 0 warning, 规则保留
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

function policy(evaluate: Record<string, unknown> | undefined): string {
  return JSON.stringify({
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'p' },
    rules: [
      {
        id: 'r',
        category: 'intrusion_defense',
        priority: 100,
        match: {},
        action: { decision: 'allow' },
        ...(evaluate !== undefined ? { evaluate } : {}),
      },
    ],
  })
}

const DROPPED = 'the deprecated "evaluate:" section is not accepted'

describe('RuleLoader — evaluate 区段 deprecated (spec §3)', () => {
  it('drops rule when evaluate section is present', () => {
    const result = loadPolicyFromText(policy({ risk_level: 'critical' }), '/tmp/x.json')
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect(result.warnings?.some((m) => m.includes('"evaluate" section deprecated') && m.includes('risk_level→severity'))).toBe(true)
    expect(result.warnings?.some((m) => m.includes(DROPPED))).toBe(true)
  })

  it('does NOT warn when evaluate section is absent (canonical SPL v2)', () => {
    const result = loadPolicyFromText(policy(undefined), '/tmp/x.json')
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })

  it('emits exactly one advisory per rule with evaluate (not per field)', () => {
    const result = loadPolicyFromText(
      policy({ risk_level: 'high', reg_clause: 'PCI-DSS-3.4', notes: 'old field here' }),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    const advisories = (result.warnings ?? []).filter((m) => m.includes('"evaluate" section deprecated'))
    expect(advisories).toHaveLength(1)
    // The single advisory must name BOTH deprecated field mappings. The
    // loader emits them as one string (`risk_level→severity,
    // reg_clause→regClause`), so counting advisories alone does not prove
    // `reg_clause` is still mapped — assert the text.
    expect(advisories[0]).toContain('risk_level→severity')
    expect(advisories[0]).toContain('reg_clause→regClause')
  })
})