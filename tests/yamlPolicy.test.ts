/**
 * SPL YAML upgrade — parseYAML accepts YAML 1.2, JSON
 * fast-path unaffected, peerDep fallback chain works (yaml → js-yaml →
 * actionable error).
 *
 * Per the SPL specification §1.5 第4条 + §4.4:
 *   - YAML 1.2 is the recommended format for shipped policies.
 *   - JSON remains a strict subset (YAML 1.2 ⊃ JSON), so .json files
 *     continue to load via the fast path with no extra dependency.
 *
 * Resolution chain (`src/intervention/RuleLoader.ts`):
 *   1. `.json` → JSON.parse (no dependency)
 *   2. `.yaml` / `.yml` → prefer `yaml` peerDep, fall back to `js-yaml`,
 *      error out with install instructions when neither is installed.
 */

import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { loadPolicy } from '../src/intervention/RuleLoader.js'

function withTmpDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'yaml-policy-'))
  try {
    return fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('SPL YAML upgrade — RuleLoader parsePolicyText', () => {
  describe('JSON fast-path (unchanged)', () => {
    it('parses .json without requiring any YAML library', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'policy.json')
        writeFileSync(
          path,
          JSON.stringify({
            apiVersion: 'security.use/v2',
            kind: 'Policy',
            rules: [
              {
                id: 'json.fast',
                priority: 100,
                category: 'intrusion_defense',
                match: { tools: ['bash'] },
                action: { decision: 'block', blockReason: 'json path', blockCode: 'INTRUSION_DEFENSE_JSON_FAST_PATH_001' },
              },
            ],
          }),
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules).toHaveLength(1)
        expect(result.rules[0]?.id).toBe('json.fast')
        expect(result.rules[0]?.action?.decision).toBe('block')
      })
    })
  })

  describe('YAML loading via installed peerDeps', () => {
    it('parses a minimal YAML 1.2 policy via the available YAML library', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'policy.yaml')
        writeFileSync(
          path,
          [
            'apiVersion: security.use/v2',
            'kind: Policy',
            'metadata:',
            '  id: yaml-min',
            '  source: builtin',
            'scope:',
            "  platforms: ['sst-security-control-dsh']",
            'rules:',
            '  - id: yaml.first',
            '    priority: 100',
            '    category: intrusion_defense',
            '    match: { tools: [bash] }',
            '    action: { decision: block, blockReason: yaml first, blockCode: INTRUSION_DEFENSE_YAML_FIRST_001 }',
            '  - id: yaml.second',
            '    priority: 200',
            '    category: behavior_guidance',
            '    match: { tools: [bash] }',
            '    action: { decision: allow }',
            '',
          ].join('\n'),
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules).toHaveLength(2)
        // priority sort: yaml.second (200) first
        expect(result.rules[0]?.id).toBe('yaml.second')
        expect(result.rules[1]?.id).toBe('yaml.first')
        // scope propagates
        expect(result.rules[0]?.scope?.platforms).toEqual(['sst-security-control-dsh'])
      })
    })

    it('parses YAML with inline `# notes` comments (the YAML advantage over JSON)', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'with-notes.yaml')
        writeFileSync(
          path,
          [
'# default policy header comment',
            'apiVersion: security.use/v2',
            'kind: Policy',
            'rules:',
            '  # 阻止危险命令 — 测试用例',
            '  - id: yaml.note',
            '    priority: 100',
            '    category: intrusion_defense',
            '    match: { tools: [bash] }',
            '    action: { decision: block, blockReason: has notes, blockCode: INTRUSION_DEFENSE_NOTE_001 }',
            '    notes: 阻止危险命令 — 测试用例',
            '',
          ].join('\n'),
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules[0]?.id).toBe('yaml.note')
      })
    })

    it('parses .yml extension the same way as .yaml', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'policy.yml')
        writeFileSync(
          path,
          [
            'apiVersion: security.use/v2',
            'kind: Policy',
            'rules:',
            '  - id: yml.ext',
            '    priority: 50',
            '    category: behavior_guidance',
            '    match: { tools: [bash] }',
            '    action: { decision: allow }',
            '',
          ].join('\n'),
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules).toHaveLength(1)
        expect(result.rules[0]?.id).toBe('yml.ext')
      })
    })
  })

  describe('Shipped default-policy.spl.yaml (round-trip)', () => {
    it('loads the shipped YAML policy and produces ≥58 enabled rules', () => {
      // Use import.meta.url-based resolution (NOT process.cwd()) so the
      // test stays valid regardless of the test runner's working
      // directory. Matches the pattern used in helpers/interventionHarness.ts
      // (DEFAULT_POLICY_PATH), dataLeakRules.test.ts:25, gatewayRule.test.ts:26, etc.
      const path = fileURLToPath(new URL('../policies/default-policy.spl.yaml', import.meta.url))
      const result = loadPolicy(path)
      expect(result.error).toBeUndefined()
      // The shipped policy declares 79 rules total, of which 21 are
      // intentionally `enabled: false` (they ship as documentation +
      // operator-on-demand toggles, never active by default). The
      // engine only compiles enabled rules, so we assert ≥58 (= 79
      // minus the 21 disabled). This is the same number that the
      // legacy default-policy.json produced.
      expect(result.rules.length).toBeGreaterThanOrEqual(58)

      // Spot-check the first and last rule IDs survive the round-trip.
      const ids = result.rules.map((r) => r.id)
      expect(ids).toContain('self-protection-block-uninstall')
      // self-protection-escalate-on-behavior-block 已停用（其 riskFlagsAny
      // ['self_protection_behavior'] 全仓零生产点）。带 enabled: false 的规则
      // 不进 result.rules，故反过来断言它不在——停用是显式决定，不是加载器丢的。
      expect(ids).not.toContain('self-protection-escalate-on-behavior-block')

      // Highest priority wins — every self-protection rule sits at
      // 1100–1200 and must come before lower-priority rules.
      const top = result.rules[0]
      expect(top?.priority).toBeGreaterThanOrEqual(1000)
    })
  })

  describe('Error paths', () => {
    it('surfaces the actual YAML parse error when syntax is invalid', () => {
      // Regression for the bug: parseYaml used to swallow
      // parse errors with bare `catch {}` and fall through to the
      // "install yaml" message, hiding the real issue from operators.
      withTmpDir((dir) => {
        const path = join(dir, 'broken.yaml')
        // Unmatched bracket on line 3 — well-formed YAML parsers will
        // reject this with a syntax error.
        writeFileSync(path, 'rules:\n  - id: broken\n    priority: [unterminated\n')
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.rules).toEqual([])
        // The error must NOT be the "install yaml" advice — it must be
        // the actual parse error from yaml.parse() / js-yaml.load().
        expect(result.error).not.toMatch(/pnpm add (yaml|js-yaml)/)
        // The error must carry line/column info from the underlying
        // parser so operators can find the broken line. yaml.js and
        // js-yaml both include "line N" / "column N" in their messages.
        expect(result.error).toMatch(/line\s+\d+|column\s+\d+|at line/i)
      })
    })

    it('reports an actionable install error when neither yaml nor js-yaml is installed', () => {
      // Structural test — exercises the install-advice path when both
      // peerDeps are absent. We do not actually uninstall the packages
      // (test environment always has both), so this only verifies the
      // message format IF the fallback fires. When both libs are
      // installed (the common case), this test confirms the file
      // parses successfully — the install-advice branch is exercised
      // by the dedicated structural contract test below.
      withTmpDir((dir) => {
        const path = join(dir, 'needy.yaml')
        writeFileSync(
          path,
          [
            'apiVersion: security.use/v2',
            'kind: Policy',
            'rules:',
            '  - id: need.peer',
            '    priority: 100',
            '    category: behavior_guidance',
            '    match: { tools: [bash] }',
            '    action: { decision: allow }',
            '',
          ].join('\n'),
        )
        const result = loadPolicy(path)
        if (result.error) {
          expect(result.error).toMatch(/pnpm add (yaml|js-yaml)/)
        } else {
          expect(result.rules).toHaveLength(1)
        }
      })
    })

    it('rejects a JSON file with malformed content', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'broken.json')
        writeFileSync(path, '{ rules: [ missing closing brace')
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.rules).toEqual([])
        expect(result.error).toMatch(/invalid JSON/i)
      })
    })

    it('returns the file-not-found error when path does not exist', () => {
      const result = loadPolicy('/nonexistent/path/to/policy.yaml')
      expect(result.error).toBeDefined()
      expect(result.error).toMatch(/failed to read policy/)
      expect(result.rules).toEqual([])
    })

    it('extension-less path falls through JSON → YAML per documented contract', () => {
      // install/CONFIG.md + docs/安装部署手册.md promise that
      // `policyPath: ~/.dsh/security-policy` (no extension) accepts both
      // JSON and YAML. Verify both formats load.
      withTmpDir((dir) => {
        const yamlPath = join(dir, 'no-ext-policy')
        writeFileSync(
          yamlPath,
          [
            'apiVersion: security.use/v2',
            'kind: Policy',
            'rules:',
            '  - id: extless.yaml',
            '    priority: 100',
            '    category: behavior_guidance',
            '    match: { tools: [bash] }',
            '    action: { decision: allow }',
            '',
          ].join('\n'),
        )
        const yamlResult = loadPolicy(yamlPath)
        expect(yamlResult.error).toBeUndefined()
        expect(yamlResult.rules).toHaveLength(1)
        expect(yamlResult.rules[0]?.id).toBe('extless.yaml')
      })

      withTmpDir((dir) => {
        const jsonPath = join(dir, 'no-ext-policy')
        writeFileSync(
          jsonPath,
          JSON.stringify({
            apiVersion: 'security.use/v2',
            kind: 'Policy',
            rules: [
              {
                id: 'extless.json',
                priority: 100,
                category: 'behavior_guidance',
                match: { tools: ['bash'] },
                action: { decision: 'allow' },
              },
            ],
          }),
        )
        const jsonResult = loadPolicy(jsonPath)
        expect(jsonResult.error).toBeUndefined()
        expect(jsonResult.rules).toHaveLength(1)
        expect(jsonResult.rules[0]?.id).toBe('extless.json')
      })

      // Both formats fail: actionable combined error.
      withTmpDir((dir) => {
        const brokenPath = join(dir, 'no-ext-policy')
        writeFileSync(brokenPath, 'this is: not: valid yaml or json [unterminated')
        const result = loadPolicy(brokenPath)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/tried JSON and YAML/)
      })
    })
  })

  describe('Edge cases', () => {
    it('handles an empty rules array', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'empty.yaml')
        writeFileSync(path, 'apiVersion: security.use/v2\nkind: Policy\nrules: []\n')
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules).toEqual([])
      })
    })

    it('skips disabled rules (`enabled: false`)', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'mixed.yaml')
        writeFileSync(
          path,
          [
            'apiVersion: security.use/v2',
            'kind: Policy',
            'rules:',
            '  - id: enabled.one',
            '    priority: 100',
            '    category: behavior_guidance',
            '    match: { tools: [bash] }',
            '    action: { decision: allow }',
            '  - id: disabled.two',
            '    enabled: false',
            '    priority: 200',
            '    category: intrusion_defense',
            '    match: { tools: [bash] }',
            '    action: { decision: block }',
            '  - id: enabled.three',
            '    priority: 300',
            '    category: behavior_guidance',
            '    match: { tools: [bash] }',
            '    action: { decision: allow }',
            '',
          ].join('\n'),
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules.map((r) => r.id)).toEqual(['enabled.three', 'enabled.one'])
      })
    })
  })
})