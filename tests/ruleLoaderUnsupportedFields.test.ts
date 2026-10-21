/**
 * spec §0.5"未实现字段必告警"通则 — RuleLoader 8 类
 * 未消费字段 WARN 行为验证。
 *
 * 字段清单(spec 节号):
 *   - match.paramsNotRegex        (spec §4 负向正则) — 已由 RuleMatcher
 *     实现消费,按 spec §0.5 的反向口径**不**再 WARN(见 RuleLoader.ts
 *     `paramsNotRegex` 注释)。本文件因此不再断言它告警。
 *   - match.paramsContains        (spec §4 字面量子串)
 *   - match.sessionRegex          (spec §4 会话上下文正则)
 *   - match.fieldIn               (spec §4 枚举包含)
 *   - match.chain                 (spec §4 多步链式)
 *   - action.decisionChain        (spec §5.2 渐进升级链)
 *   - action.conditionalDecisions (spec §5.2 条件决策)
 *   - metadata.{author,tags,references} (spec §2 溯源字段)
 *
 * scope.workflows(spec §1)宽容忽略, 不 WARN。
 *
 * 断言: 字段出现 → LoadResult.warnings[] 包含对应 advisory,
 *       字段缺失 → 不出现。
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

function policyWith(match: Record<string, unknown> = {}, actionExtras: Record<string, unknown> = {}, metaExtras: Record<string, unknown> = {}): string {
  return JSON.stringify({
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'p', ...metaExtras },
    rules: [
      {
        id: 'r',
        category: 'intrusion_defense',
        priority: 100,
        match,
        action: {
          decision: 'allow',
          ...actionExtras,
        },
      },
    ],
  })
}

describe('RuleLoader — 8 类未实现字段 WARN (spec §0.5)', () => {
  describe('match 端 5 类字段', () => {
    // paramsNotRegex 不在此列:RuleMatcher 已消费它(spec §4 负向过滤),
    // 未实现字段才告警。反向断言见下方"已消费字段不告警"。
    it('does NOT warn on match.paramsNotRegex (consumed by RuleMatcher)', () => {
      const result = loadPolicyFromText(policyWith({ paramsNotRegex: { command: ['^foo$'] } }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('match.paramsNotRegex'))).toBe(false)
    })

    it('warns on match.paramsContains', () => {
      const result = loadPolicyFromText(policyWith({ paramsContains: { command: ['foo'] } }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('match.paramsContains'))).toBe(true)
    })

    it('warns on match.sessionRegex', () => {
      const result = loadPolicyFromText(policyWith({ sessionRegex: ['^sess_'] }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('match.sessionRegex'))).toBe(true)
    })

    it('warns on match.fieldIn', () => {
      const result = loadPolicyFromText(policyWith({ fieldIn: { tool: ['bash', 'sh'] } }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('match.fieldIn'))).toBe(true)
    })

    it('warns on match.chain', () => {
      const result = loadPolicyFromText(
        policyWith({ chain: { withinSteps: 3, prior: [{ ruleId: 'x' }] } }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('match.chain'))).toBe(true)
    })
  })

  describe('action 端 2 类字段', () => {
    it('warns on action.decisionChain', () => {
      const result = loadPolicyFromText(
        policyWith({}, { decisionChain: [{ after: 'attempts>3', decision: 'block' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('action.decisionChain'))).toBe(true)
    })

    it('warns on action.conditionalDecisions', () => {
      const result = loadPolicyFromText(
        policyWith({}, { conditionalDecisions: { if: 'first', then: 'warn' } }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('action.conditionalDecisions'))).toBe(true)
    })
  })

  describe('metadata 端 3 类字段 (政策级 advisory)', () => {
    it('warns on metadata.author', () => {
      const result = loadPolicyFromText(policyWith({}, {}, { author: 'platform-team' }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('metadata.author') && m.includes('loader does not consume'))).toBe(true)
    })

    it('warns on metadata.tags', () => {
      const result = loadPolicyFromText(policyWith({}, {}, { tags: ['exec', 'network'] }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('metadata.tags'))).toBe(true)
    })

    it('warns on metadata.references', () => {
      const result = loadPolicyFromText(policyWith({}, {}, { references: ['https://example.com/spec'] }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('metadata.references'))).toBe(true)
    })
  })

  describe('宽容忽略 (scope.workflows)', () => {
    it('does NOT warn on scope.workflows', () => {
      const raw = JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'p' },
        scope: { platforms: ['sst-security-control-dsh'], workflows: ['wf-1', 'wf-2'] },
        rules: [
          {
            id: 'r',
            category: 'intrusion_defense',
            priority: 100,
            match: {},
            action: { decision: 'allow' },
          },
        ],
      })
      const result = loadPolicyFromText(raw, '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('scope.workflows'))).toBe(false)
    })
  })

  describe('规则不被剔除 (advisory only)', () => {
    it('keeps the rule compiled even when 8 类字段混合出现', () => {
      const result = loadPolicyFromText(
        policyWith(
          {
            paramsNotRegex: { command: ['^x$'] },
            paramsContains: { command: ['y'] },
            sessionRegex: ['z'],
            fieldIn: { t: ['bash'] },
            chain: { withinSteps: 1, prior: [] },
          },
          {
            decisionChain: [],
            conditionalDecisions: {},
          },
          {
            author: 'a',
            tags: ['t'],
            references: ['r'],
          },
        ),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules.map((r) => r.id)).toEqual(['r'])
      // 9 条 advisory warning（10 个字段减去已实现的 paramsNotRegex）
      const advisories = (result.warnings ?? []).filter((m) => m.includes('matcher does not consume') || m.includes('engine does not consume') || m.includes('loader does not consume'))
      expect(advisories.length).toBeGreaterThanOrEqual(8)
    })
  })
})