/**
 * spec 违规 fail-loud: 违规规则在加载期即被 drop, 策略本身仍然可用。
 *
 * 覆盖矩阵:
 *   - 规则含 `evaluate:` 区段(spec §3, v1 遗留)
 *
 * 「decision=block 缺 blockCode」与「blockCode 前缀与 category 错位」两条
 * 原本也各有一条用例, 但它们的输入与断言都被 `ruleLoaderBlockCodeNaming`
 * / `ruleLoaderCategoryPrefix` 以**更强**的形式覆盖(后者额外 pin 了
 * `spec §5.2` 子串), 属于零独有覆盖, 已移除以免两处各自漂移。
 *
 * 每条违规: warning(说明原因) + drop(规则不出现在 CompiledPolicy 里)。
 * 这套语义曾经是分两阶段落地的, 由 `SPL_BLOCK_PHASE_2` 环境变量在
 * "只警告" / "警告并丢弃" 之间切换 —— 该变量允许任何能设置进程环境的
 * 人把 spec 违规降级回 warning。迁移窗口已经结束, 现在只有严格一种行为。
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

function policyOf(rules: unknown[]): string {
  return JSON.stringify({
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'p' },
    rules,
  })
}

describe('RuleLoader — spec 违规 fail-loud (spec §3/§5.2/§7.4)', () => {
  it('drops rule when evaluate section is present', () => {
    const result = loadPolicyFromText(
      policyOf([{
        id: 'r-eval',
        category: 'intrusion_defense',
        priority: 100,
        match: {},
        action: { decision: 'allow' },
        evaluate: { risk_level: 'high' },
      }]),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual([])
    expect((result.warnings ?? []).some((m) => m.includes('"evaluate" section deprecated'))).toBe(true)
    expect((result.warnings ?? []).some((m) => m.includes('the deprecated "evaluate:" section is not accepted'))).toBe(true)
  })

  it('emits a "dropped" summary warning naming the offending rule', () => {
    const result = loadPolicyFromText(
      policyOf([
        { id: 'r-good', priority: 100, category: 'intrusion_defense', match: {}, action: { decision: 'allow' } },
        { id: 'r-bad', priority: 100, category: 'intrusion_defense', match: {}, action: { decision: 'block', blockReason: 'x' } },
      ]),
      '/tmp/x.json',
    )
    expect(result.rules.map((r) => r.id)).toEqual(['r-good'])
    const droppedWarnings = (result.warnings ?? []).filter((m) => m.includes('dropped — spec §7.4 is enforced strictly'))
    expect(droppedWarnings.length).toBeGreaterThanOrEqual(1)
    expect(droppedWarnings[0]).toContain('r-bad')
  })

  it('clean rule (no violations) loads with 0 warnings — invariant for default policy', () => {
    const result = loadPolicyFromText(
      policyOf([{
        id: 'r-clean',
        category: 'intrusion_defense',
        priority: 100,
        match: {},
        action: { decision: 'block', blockReason: 'x', blockCode: 'INTRUSION_DEFENSE_GENERIC_001' },
      }]),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r-clean'])
    expect(result.warnings ?? []).toEqual([])
  })

  it('one violating rule does not take the rest of the policy down', () => {
    const result = loadPolicyFromText(
      policyOf([
        { id: 'r-a', priority: 100, category: 'intrusion_defense', match: {}, action: { decision: 'allow' } },
        { id: 'r-bad', priority: 100, category: 'intrusion_defense', match: {}, action: { decision: 'block', blockReason: 'x' } },
        { id: 'r-b', priority: 100, category: 'intrusion_defense', match: {}, action: { decision: 'allow' } },
      ]),
      '/tmp/x.json',
    )
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r-a', 'r-b'])
  })
})