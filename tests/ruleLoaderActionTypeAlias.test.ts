/**
 * spec §4 actionType 历史别名归一 + 未知值 advisory。
 *
 * 完整别名表(loader 阶段, 5 个):
 *   tool_call      → agent_tool_call
 *   tool_result    → agent_tool_result
 *   http           → network_http
 *   http_request   → network_http
 *   process_spawn  → process_start
 *
 * 行为:
 *   - 命中别名 → 归一为规范值 + advisory warning + set 同时含别名(向后兼容)
 *   - 命中规范值 → 0 warning
 *   - 命中 `*` 通配 → 0 warning
 *   - 命中完全未知值 → 保留原值 + advisory warning(避免误伤自定义扩展)
 *
 * matcher 零影响: CompiledMatchClause.actionType 是 Set<string>,
 * 同时含 alias 与 canonical → RuleMatcher.Set.has(ctx.actionType) 双命中。
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

function policy(actionType: string[]): string {
  return JSON.stringify({
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'p' },
    rules: [
      {
        id: 'r',
        category: 'intrusion_defense',
        priority: 100,
        match: { actionType },
        action: { decision: 'allow' },
      },
    ],
  })
}

describe('RuleLoader — actionType 别名归一 (spec §4)', () => {
  describe('5 个别名 (loader 阶段)', () => {
    it('tool_call → agent_tool_call + advisory', () => {
      const result = loadPolicyFromText(policy(['tool_call']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('actionType "tool_call" is alias') && m.includes('canonical "agent_tool_call"'))).toBe(true)
    })

    it('tool_result → agent_tool_result + advisory', () => {
      const result = loadPolicyFromText(policy(['tool_result']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('tool_result') && m.includes('agent_tool_result'))).toBe(true)
    })

    it('http → network_http + advisory', () => {
      const result = loadPolicyFromText(policy(['http']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('http') && m.includes('network_http'))).toBe(true)
    })

    it('http_request → network_http + advisory (idempotent)', () => {
      const result = loadPolicyFromText(policy(['http_request']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('http_request') && m.includes('network_http'))).toBe(true)
    })

    it('process_spawn → process_start + advisory', () => {
      const result = loadPolicyFromText(policy(['process_spawn']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('process_spawn') && m.includes('process_start'))).toBe(true)
    })
  })

  describe('规范值 (no advisory)', () => {
    it('agent_tool_call canonical → 0 warning', () => {
      const result = loadPolicyFromText(policy(['agent_tool_call']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings ?? []).toEqual([])
    })

    it('network_http canonical → 0 warning', () => {
      const result = loadPolicyFromText(policy(['network_http']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings ?? []).toEqual([])
    })

    it('process_start canonical → 0 warning', () => {
      const result = loadPolicyFromText(policy(['process_start']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings ?? []).toEqual([])
    })

    it('* 通配 → 0 warning', () => {
      const result = loadPolicyFromText(policy(['*']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings ?? []).toEqual([])
    })
  })

  describe('完全未知值 (advisory, 不强拒)', () => {
    it('unknown actionType keeps the value + advisory', () => {
      const result = loadPolicyFromText(policy(['custom_event']), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.rules.map((r) => r.id)).toEqual(['r'])
      expect(result.warnings?.some((m) => m.includes('actionType "custom_event"') && m.includes('not a spec §4 canonical value'))).toBe(true)
    })

    it('mixed: canonical + alias + unknown', () => {
      const result = loadPolicyFromText(
        policy(['agent_tool_call', 'tool_call', 'mystery_event']),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules.map((r) => r.id)).toEqual(['r'])
      const aliases = (result.warnings ?? []).filter((m) => m.includes('is alias'))
      const unknown = (result.warnings ?? []).filter((m) => m.includes('not a spec §4 canonical value'))
      expect(aliases).toHaveLength(1)
      expect(unknown).toHaveLength(1)
    })
  })
})