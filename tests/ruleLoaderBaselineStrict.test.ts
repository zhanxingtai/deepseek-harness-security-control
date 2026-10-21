/**
 * strict 基线回归钉子。
 *
 * 在两条策略语料上断言"零 drop":
 *   (a) 内置的 policies/default-policy.spl.yaml
 *   (b) 钉在 tests/*.test.ts 里的 inline policy fixture 语料
 *
 * 内联语料会随测试改动漂移, 所以这里维护一份镜像; 对应 fixture 一变,
 * 同步改这里, 回归钉子才跟着走。
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { loadPolicyFromText } from '../src/intervention/RuleLoader.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = join(__dirname, '..')

interface DroppedEntry {
  rule: string
  reason: string
}

/**
 * Inline fixture corpus —— tests/*.test.ts 里内嵌的策略片段。
 * 每条与对应测试 fixture 的内容一致。
 */
const INLINE_FIXTURES: ReadonlyArray<{ name: string; text: string }> = [
  // dataLeakRules.test.ts minimal policy —— decision=block 携带与
  // category 对齐的 blockCode, 无 evaluate 区段。
  {
    name: 'dataLeakRules/minimal-policy',
    text: [
      'apiVersion: security.use/v2',
      'kind: Policy',
      'rules:',
      '  - id: block-process-credential-in-command',
      '    category: data_leak_monitoring',
      '    enabled: true',
      '    priority: 850',
      '    match:',
      '      actionType:',
      '        - process_start',
      '      paramsRegex:',
      '        command:',
      "          - 'curl\\s+--token\\s+\\S+'",
      '    action:',
      '      decision: block',
      '      blockReason: command carries an inline token',
      '      blockCode: DATA_LEAK_MONITORING_CREDENTIAL_CMD_002',
      '      appealable: false',
      '',
    ].join('\n'),
  },
  // interventionMultiPolicy.test.ts —— 代表性的 inline fixture。
  {
    name: 'interventionMultiPolicy/builtin.block (decision=block + blockCode)',
    text: JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'builtin' },
      rules: [
        {
          id: 'builtin.block',
          priority: 1000,
          category: 'intrusion_defense',
          match: { tools: ['bash'] },
          action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_BUILTIN_GUARD_001' },
        },
      ],
    }),
  },
  {
    name: 'interventionMultiPolicy/builtin.tie (decision=block + blockCode)',
    text: JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'builtin' },
      rules: [
        {
          id: 'builtin.tie',
          priority: 1000,
          category: 'intrusion_defense',
          match: { tools: ['bash'] },
          action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_BUILTIN_GUARD_002' },
        },
      ],
    }),
  },
  {
    name: 'interventionMultiPolicy/builtin.high (decision=block + blockCode)',
    text: JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'builtin' },
      rules: [
        {
          id: 'builtin.high',
          priority: 1100,
          category: 'intrusion_defense',
          match: { tools: ['bash'] },
          action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_BUILTIN_GUARD_003' },
        },
      ],
    }),
  },
]

describe('RuleLoader — strict baseline (零 drop)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-strict-baseline-'))
  })
  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('bundled default-policy.spl.yaml: 0 drops', () => {
    const path = join(PROJECT_ROOT, 'policies/default-policy.spl.yaml')
    const text = readFileSync(path, 'utf8')
    const result = loadPolicyFromText(text, path)
    const drops = (result.warnings ?? [])
      .filter((w) => /dropped/.test(w))
      .map((w) => ({ rule: w.match(/rule "([^"]+)"/)?.[1] ?? '?', reason: w }))
    if (drops.length > 0) {
      // eslint-disable-next-line no-console
      console.error('[strict-baseline] bundled drops:\n' + drops.map((d) => `  - ${d.rule}: ${d.reason}`).join('\n'))
    }
    expect(drops).toEqual([])
  })

  it('inline fixtures corpus: 0 drops', () => {
    const drops: DroppedEntry[] = []
    for (const f of INLINE_FIXTURES) {
      const path = join(tmpDir, `${f.name.replace(/[/: ]/g, '_')}.yaml`)
      writeFileSync(path, f.text)
      const result = loadPolicyFromText(f.text, path)
      for (const w of result.warnings ?? []) {
        if (/dropped/.test(w)) {
          drops.push({
            rule: w.match(/rule "([^"]+)"/)?.[1] ?? '?',
            reason: w,
          })
        }
      }
    }
    if (drops.length > 0) {
      // eslint-disable-next-line no-console
      console.error('[strict-baseline] inline drops:\n' + drops.map((d) => `  - ${d.rule}: ${d.reason}`).join('\n'))
    }
    expect(drops).toEqual([])
  })
})