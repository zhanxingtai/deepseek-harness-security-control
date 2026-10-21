/**
 * SPL schema validation tests.
 *
 * Verifies that `loadPolicy` rejects malformed headers instead of
 * silently loading an empty rule set. Previously `parsePolicyText`
 * trusted whatever JSON/YAML shape came back and `compilePolicy`
 * read whatever it pleased — a file with `apiVersion: v2` or
 * `kind: Bananas` or missing `rules` would load successfully but
 * produce zero rules. The agent then ran with an empty rule set and
 * the audit log showed nothing because no events matched.
 *
 * Per-file errors flow through `MultiLoadResult.errors[]` so a
 * single malformed file does not break the merge (matches the
 * parse-error contract).
 */
import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { loadMultiplePolicies, loadPolicy } from '../src/intervention/RuleLoader.js'

function withTmpDir<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'rule-schema-'))
  try {
    return fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

function writeFile(dir: string, name: string, body: string): string {
  const path = join(dir, name)
  writeFileSync(path, body)
  return path
}

describe('RuleLoader schema validation', () => {
  describe('positive — valid headers parse cleanly', () => {
    it('accepts apiVersion: security.use/v2 + kind: Policy', () => {
      withTmpDir((dir) => {
        const path = writeFile(
          dir,
          'valid.yaml',
          [
            'apiVersion: security.use/v2',
            'kind: Policy',
            'rules:',
            '  - id: ok.one',
            '    priority: 100',
            '    category: intrusion_defense',
            '    match: { tools: [bash] }',
            '    action: { decision: allow }',
            '',
          ].join('\n'),
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules).toHaveLength(1)
        expect(result.rules[0]?.id).toBe('ok.one')
      })
    })

    it('accepts an empty rules array (zero-rule policy is legal)', () => {
      withTmpDir((dir) => {
        const path = writeFile(
          dir,
          'empty.yaml',
          'apiVersion: security.use/v2\nkind: Policy\nrules: []\n',
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules).toEqual([])
      })
    })
  })

  describe('negative — apiVersion validation', () => {
    it('rejects a missing apiVersion', () => {
      withTmpDir((dir) => {
        const path = writeFile(dir, 'no-version.yaml', 'kind: Policy\nrules: []\n')
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/invalid or missing apiVersion/)
        expect(result.error).toMatch(/security\.use\/v2/)
        expect(result.rules).toEqual([])
      })
    })

    it('rejects an unknown apiVersion', () => {
      withTmpDir((dir) => {
        // spec §10 只接受 security.use/v2; 这里用真正未知的
        // 'security.use/v99' 来验 API 拒绝路径。
        const path = writeFile(
          dir,
          'wrong-version.yaml',
          'apiVersion: security.use/v99\nkind: Policy\nrules: []\n',
        )
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/security\.use\/v99/)
        expect(result.rules).toEqual([])
      })
    })

    it('rejects a non-string apiVersion', () => {
      withTmpDir((dir) => {
        const path = writeFile(
          dir,
          'numeric-version.yaml',
          'apiVersion: 1\nkind: Policy\nrules: []\n',
        )
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/invalid or missing apiVersion/)
        expect(result.rules).toEqual([])
      })
    })
  })

  describe('negative — kind validation', () => {
    it('rejects a missing kind', () => {
      withTmpDir((dir) => {
        const path = writeFile(
          dir,
          'no-kind.yaml',
          'apiVersion: security.use/v2\nrules: []\n',
        )
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/invalid or missing kind/)
        expect(result.rules).toEqual([])
      })
    })

    it('rejects a non-Policy kind', () => {
      withTmpDir((dir) => {
        const path = writeFile(
          dir,
          'wrong-kind.yaml',
          'apiVersion: security.use/v2\nkind: Ruleset\nrules: []\n',
        )
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/invalid or missing kind/)
        expect(result.error).toMatch(/Ruleset/)
        expect(result.rules).toEqual([])
      })
    })
  })

  describe('negative — rules validation', () => {
    it('rejects a missing rules field', () => {
      withTmpDir((dir) => {
        const path = writeFile(
          dir,
          'no-rules.yaml',
          'apiVersion: security.use/v2\nkind: Policy\n',
        )
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/'rules' array/)
        expect(result.rules).toEqual([])
      })
    })

    it('rejects rules that is not an array', () => {
      withTmpDir((dir) => {
        const path = writeFile(
          dir,
          'rules-not-array.yaml',
          'apiVersion: security.use/v2\nkind: Policy\nrules: "foo"\n',
        )
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/'rules' array/)
        expect(result.rules).toEqual([])
      })
    })
  })

  describe('negative — root shape', () => {
    it('rejects a YAML array at the root', () => {
      withTmpDir((dir) => {
        const path = writeFile(dir, 'root-array.yaml', '- one\n- two\n')
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/must be a YAML\/JSON object/)
        expect(result.rules).toEqual([])
      })
    })

    it('rejects a JSON scalar at the root', () => {
      withTmpDir((dir) => {
        const path = writeFile(dir, 'root-string.json', '"just a string"\n')
        const result = loadPolicy(path)
        expect(result.error).toBeDefined()
        expect(result.error).toMatch(/must be a YAML\/JSON object/)
        expect(result.rules).toEqual([])
      })
    })
  })

  describe('error surfaces through MultiLoadResult', () => {
    it('isolates schema-validation errors per file', () => {
      withTmpDir((dir) => {
        const goodPath = writeFile(
          dir,
          'good.yaml',
          [
            'apiVersion: security.use/v2',
            'kind: Policy',
            'rules:',
            '  - id: good.one',
            '    priority: 100',
            '    category: intrusion_defense',
            '    match: { tools: [bash] }',
            '    action: { decision: deny, blockReason: ok, blockCode: INTRUSION_DEFENSE_SCHEMA_OK_001 }',
            '',
          ].join('\n'),
        )
        const badPath = writeFile(
          dir,
          'bad.yaml',
          'apiVersion: security.use/v9\nkind: Policy\nrules: []\n',
        )

        const merged = loadMultiplePolicies([goodPath, badPath])
        expect(merged.errors).toHaveLength(1)
        expect(merged.errors[0]?.path).toBe(badPath)
        expect(merged.errors[0]?.error).toMatch(/security\.use\/v9/)
        // The good file still contributes its rules.
        expect(merged.rules).toHaveLength(1)
        expect(merged.rules[0]?.id).toBe('good.one')
      })
    })
  })
})