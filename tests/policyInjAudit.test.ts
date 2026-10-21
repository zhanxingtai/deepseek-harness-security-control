/**
 * `INJECT_*` SPL rules regression guard.
 *
 * The original finding noted that design docs and code comments
 * referenced SPL `INJECT_*` rules, but no such rules existed in the
 * shipped policy file (`default-policy.spl.yaml`).
 * The inline `InlinePromptInjection` guard is the **sole**
 * prompt-injection defence — anything claiming a complementary SPL
 * layer is a documentation drift.
 *
 * `policies/legacy.yaml` removed — the audit
 * scope shrinks to `default-policy.spl.yaml` only.
 *
 * This test pins the contract:
 *
 *   1. The shipped policy MUST NOT carry any rule whose id / block
 *      code starts with `inject-` / `INJECT_` (the inline guard's
 *      own block code `INLINE_PROMPT_INJECTION_001` is excluded by
 *      requiring the `INJECT_` literal to be in a rule-id or SPL-
 *      block-code context — these don't exist in the shipped file).
 *   2. If a future SPL rule is added on purpose, this guard must be
 *      updated deliberately (the change is visible in the PR diff
 *      with both the new rule and the test update).
 *   3. The doc comment on `INLINE_PROMPT_INJECTION_CODE` MUST NOT
 *      reference a non-existent SPL `INJECT_*` series.
 *
 * The test reads the shipped policy files at runtime via
 * `import.meta.url` so it stays valid regardless of cwd (matches the
 * pattern used in `yamlPolicy.test.ts`, `dataLeakRules.test.ts`,
 * `p3cSPLRules.test.ts`).
 */
import { describe, expect, it } from 'vitest'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const POLICIES_DIR = fileURLToPath(new URL('../policies', import.meta.url))

function readPolicy(name: string): string {
  return readFileSync(join(POLICIES_DIR, name), 'utf8')
}

/**
 * Extract rule IDs from a YAML policy. Tolerant of YAML literal-block
 * scalars (the comment markers don't matter — we only look at `id:`
 * lines). Falls back to regex if the YAML library can't be required
 * (which would be a peerDep gap, not a policy-content gap, and is
 * handled by a separate structural test).
 */
function extractRuleIds(text: string): string[] {
  const out: string[] = []
  const re = /^\s*-\s*id:\s*['"]?([^'"\n#]+)['"]?\s*(?:#.*)?$/gm
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    out.push((m[1] ?? '').trim())
  }
  return out
}

/**
 * Extract block-code strings from YAML literal-block `blockCode:` /
 * `block_code:` lines. The shipped policies use both spellings
 * across rules.
 */
function extractBlockCodes(text: string): string[] {
  const out: string[] = []
  const re = /^\s*block_?code:\s*['"]?([A-Z][A-Z0-9_]+)['"]?\s*(?:#.*)?$/gim
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    out.push((m[1] ?? '').trim())
  }
  return out
}

describe('INJECT_* SPL rules audit', () => {
  describe('shipped policy files', () => {
    const defaultText = readPolicy('default-policy.spl.yaml')

    it('default-policy.spl.yaml has no INJECT_ rule IDs', () => {
      const ids = extractRuleIds(defaultText)
      const inj = ids.filter((id) => /^inject[-_]/i.test(id) || /INJECT_/i.test(id))
      expect(inj).toEqual([])
    })

    it('default-policy.spl.yaml has no INJECT_ block codes', () => {
      const codes = extractBlockCodes(defaultText)
      const inj = codes.filter((c) => c.startsWith('INJECT_'))
      expect(inj).toEqual([])
    })

    it('the inline guard is the ONLY prompt-injection defence (no SPL twin)', () => {
      // Sanity: the inline guard's own block code should be referenced
      // in code/comments but never as an SPL rule id.
      const allIds = extractRuleIds(defaultText)
      expect(allIds.some((id) => id.toLowerCase().includes('prompt-injection'))).toBe(false)
      expect(allIds.some((id) => id.toLowerCase().includes('inline-prompt-injection'))).toBe(false)
    })
  })

  describe('doc-vs-code consistency', () => {
    it('InlinePromptInjection no longer references non-existent SPL `INJECT_*` codes', () => {
      // The doc comment on `INLINE_PROMPT_INJECTION_CODE` was the
      // second stale reference. It now carries a historical
      // note instead. Pin the contract here.
      const src = readFileSync(
        fileURLToPath(new URL('../src/intervention/InlinePromptInjection.ts', import.meta.url)),
        'utf8',
      )
      // The historical note itself mentions "SPL `INJECT_*`" as a
      // quoted-but-disavowed reference — exclude the historical note
      // paragraph before the regression check.
      const blockCodeComment = src.match(
        /\/\*\*[\s\S]*?INLINE_PROMPT_INJECTION_CODE[\s\S]*?\*\//,
      )?.[0] ?? ''
      const idx = blockCodeComment.indexOf('Historical note')
      const cleaned = idx === -1 ? blockCodeComment : blockCodeComment.slice(0, idx)
      expect(cleaned).not.toMatch(/SPL\s+`?INJECT_/)
    })

    it('ApplicationCollector no longer references non-existent INJECT_* SPL rules', () => {
      const src = readFileSync(
        fileURLToPath(new URL('../src/collectors/ApplicationCollector.ts', import.meta.url)),
        'utf8',
      )
      expect(src).not.toMatch(/strip\s+INJECT_\*\s+SPL\s+rules/)
    })
  })
})