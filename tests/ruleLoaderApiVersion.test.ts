/**
 * spec §10 apiVersion gate — v2 only.
 *
 * 行为矩阵:
 *   - security.use/v2  → 接受, 0 warning
 *   - security.use/v1  → hard error(迁移层已下线)
 *   - security.use/v99 → hard error(未知值)
 *   - 缺失             → hard error
 *   - 非字符串类型      → hard error
 *
 * v1 不再"接受 + advisory"：那套迁移层依赖 `SPL_BLOCK_PHASE_2` 环境变量，
 * 而该变量允许任何能设置进程环境的人把 spec 违规降级回 warning。随
 * 迁移层一同下线，v1 策略在加载期即被拒，错误文案指向 §10 映射表。
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

const VALID_RULE = {
  id: 'r',
  category: 'intrusion_defense',
  priority: 100,
  match: {},
  action: { decision: 'allow' },
}

describe('RuleLoader — apiVersion v2-only (spec §10)', () => {
  it('accepts security.use/v2 silently', () => {
    const result = loadPolicyFromText(
      JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [VALID_RULE],
      }),
      '/tmp/v2.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r'])
    expect(result.warnings ?? []).toEqual([])
  })

  it('rejects security.use/v1 outright', () => {
    const result = loadPolicyFromText(
      JSON.stringify({
        apiVersion: 'security.use/v1',
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [VALID_RULE],
      }),
      '/tmp/v1.json',
    )
    expect(result.error).toBeDefined()
    expect(result.error).toMatch(/invalid or missing apiVersion/)
    expect(result.rules).toEqual([])
  })

  it('rejects unknown apiVersion with hard error', () => {
    const result = loadPolicyFromText(
      JSON.stringify({
        apiVersion: 'security.use/v99',
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [VALID_RULE],
      }),
      '/tmp/v99.json',
    )
    expect(result.error).toBeDefined()
    expect(result.error).toMatch(/invalid or missing apiVersion/)
    expect(result.error).toMatch(/security\.use\/v99/)
    expect(result.rules).toEqual([])
  })

  it('rejects missing apiVersion with hard error', () => {
    const result = loadPolicyFromText(
      JSON.stringify({
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [VALID_RULE],
      }),
      '/tmp/missing.json',
    )
    expect(result.error).toBeDefined()
    expect(result.error).toMatch(/invalid or missing apiVersion/)
    expect(result.rules).toEqual([])
  })

  it('rejects non-string apiVersion with hard error', () => {
    const result = loadPolicyFromText(
      JSON.stringify({
        apiVersion: 2,
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [VALID_RULE],
      }),
      '/tmp/int.json',
    )
    expect(result.error).toBeDefined()
    expect(result.error).toMatch(/invalid or missing apiVersion/)
    expect(result.rules).toEqual([])
  })

  it('rejects v1 even when the rule itself is well-formed (block)', () => {
    const result = loadPolicyFromText(
      JSON.stringify({
        apiVersion: 'security.use/v1',
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [
          {
            id: 'blocker',
            category: 'intrusion_defense',
            priority: 100,
            match: {},
            action: { decision: 'block', blockReason: 'x', blockCode: 'INTRUSION_DEFENSE_BLOCKER_001' },
          },
        ],
      }),
      '/tmp/block.json',
    )
    expect(result.error).toBeDefined()
    expect(result.rules).toEqual([])
  })
})