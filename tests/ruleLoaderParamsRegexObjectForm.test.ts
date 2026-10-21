/**
 * spec §4 paramsRegex 对象形态支持。
 *
 * 形态: `paramsRegex.<field>: [{ pattern, flags?, input? }]`
 *   - `pattern` 必填, JS regex source 字符串
 *   - `flags` 仅允许 `i`(大小写不敏感); 其他 (`g/y/m/s/u`) → reject + warning
 *   - `input` `lowercased` / `raw`(默认 `raw`); `lowercased` 让 matcher 在
 *     匹配前小写预处理(用于 env-var 等 case-stable keyword)
 *
 * 字符串形态(legacy) 仍完整支持: `[ '^echo$' ]` → `new RegExp('^echo$', 'i')`
 *
 * 不安全 regex 模式仍在 detectUnsafeRegexPattern 阶段拒绝
 * ( 阶段 1: 复用 的 CatastrophicBacktracking guard)
 */

import { describe, expect, it } from 'vitest'
import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

function policy(paramsRegex: Record<string, unknown>): string {
  return JSON.stringify({
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'p' },
    rules: [
      {
        id: 'r',
        category: 'intrusion_defense',
        priority: 100,
        match: { actionType: ['agent_tool_call'], toolName: ['bash'], paramsRegex },
        action: { decision: 'allow' },
      },
    ],
  })
}

describe('RuleLoader — paramsRegex 对象形态 (spec §4)', () => {
  describe('字符串形态 (向后兼容)', () => {
    it('compiles a plain string pattern', () => {
      const result = loadPolicyFromText(policy({ command: ['^echo safe$'] }), '/tmp/x.json')
      expect(result.error).toBeUndefined()
      expect(result.rules).toHaveLength(1)
      expect(result.warnings ?? []).toEqual([])
    })
  })

  describe('对象形态基础', () => {
    it('compiles an object with pattern only (no flags)', () => {
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '^echo obj$' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules).toHaveLength(1)
      expect(result.warnings ?? []).toEqual([])
    })

    it('compiles an object with flags: i', () => {
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '^ECHO$', flags: 'i' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules).toHaveLength(1)
      expect(result.warnings ?? []).toEqual([])
    })

    it('records input: lowercased in entryInputs', () => {
      // Note: loader sets entryInputs but matcher hasn't been wired to consume it yet
      // (per spec §0.5 + plan §2C). For now, just verify compilation doesn't reject.
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '^BASH_ENV=', flags: 'i', input: 'lowercased' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules).toHaveLength(1)
      // The entryInputs advisory is internal; no external warning surfaces yet.
      expect(result.warnings ?? []).toEqual([])
    })

    it('accepts input: raw explicitly', () => {
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '^echo raw$', input: 'raw' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules).toHaveLength(1)
    })
  })

  describe('flag 白名单拒绝', () => {
    it.each([
      ['g', 'global'],
      ['m', 'multiline'],
      ['s', 'dotall'],
      ['y', 'sticky'],
      ['u', 'unicode'],
      ['gi', 'global+case-insensitive (mixed)'],
      ['im', 'invalid combo'],
    ])('rejects flags "%s" (%s) with a warning', (flags) => {
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '^echo$', flags }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes(`flags "${flags}" rejected`) && m.includes('only "i" allowed'))).toBe(true)
    })

    it('flags "ii" still passes (multi-i is a no-op)', () => {
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '^echo$', flags: 'ii' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('flags "ii" rejected'))).toBe(false)
    })
  })

  describe('regex 编译/安全失败 (沿用 行为)', () => {
    it('rejects a malformed regex pattern with a warning', () => {
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '[unclosed' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      // rule dropped because match.paramsRegex compile failed
      expect(result.rules).toEqual([])
      expect(result.warnings?.some((m) => m.includes('[unclosed') && m.includes('failed to compile'))).toBe(true)
    })

    it('rejects a catastrophic-backtracking pattern with a warning', () => {
      const result = loadPolicyFromText(
        policy({ command: [{ pattern: '(a+)+$' }] }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules).toEqual([])
      expect(result.warnings?.some((m) => m.includes('(a+)+$') && m.includes('catastrophic'))).toBe(true)
    })

    it('warns when object form is missing "pattern" string', () => {
      const result = loadPolicyFromText(
        // intentionally untyped object
        policy({ command: [{ flags: 'i' }] }) as unknown as Record<string, never>,
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.warnings?.some((m) => m.includes('missing "pattern" string'))).toBe(true)
    })
  })

  describe('混合 (string + object)', () => {
    it('compiles a mixed list (string + object form)', () => {
      const result = loadPolicyFromText(
        policy({
          command: ['^echo first$', { pattern: '^echo second$', flags: 'i' }],
        }),
        '/tmp/x.json',
      )
      expect(result.error).toBeUndefined()
      expect(result.rules).toHaveLength(1)
      expect(result.warnings ?? []).toEqual([])
    })
  })
})