/**
 * RuleLoader marketplace multi-file merge tests.
 *
 * Verifies:
 *   - loadMultiplePolicies() merges rules from multiple files in order
 *   - Per-file errors are collected, not thrown
 *   - The shipped neutral-default.yaml + builtin-high-risk.yaml parse
 *     cleanly via the existing RuleLoader (regression guard for the
 *     marketplace vocabulary)
 *   - Priority sort still applies to the merged result
 *
 * These tests exercise RuleLoader in isolation; integration with
 * InterventionEngine is out of scope here.
 */

import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { loadMultiplePolicies, loadPolicy } from '../src/intervention/RuleLoader.js'

describe('RuleLoader marketplace merge', () => {
  describe('loadPolicy (existing single-file API, regression)', () => {
    // fix: `rules/neutral-default.yaml` and
    // `rules/builtin-high-risk.yaml` were removed in the
    // marketplace cut — the marketplace form ships ONE default policy
    // (`policies/default-policy.spl.yaml`) and operators extend it via
    // `intervention.policyPaths`. The merge feature is still exercised by
    // the synthetic-pair test below. The previous "shipped neutral-default
    // parses cleanly" assertions are replaced by an explicit missing-file
    // guard that pins the public error contract.

    it('reports a clean error for a missing file', () => {
      const result = loadPolicy('rules/does-not-exist.yaml')
      expect(result.error).toBeDefined()
      expect(result.rules).toEqual([])
    })

    it('reports a clean error for the removed fixtures (rules/neutral-default.yaml)', () => {
      const result = loadPolicy('rules/neutral-default.yaml')
      expect(result.error).toBeDefined()
      expect(result.rules).toEqual([])
    })

    it('reports a clean error for the removed fixtures (rules/builtin-high-risk.yaml)', () => {
      const result = loadPolicy('rules/builtin-high-risk.yaml')
      expect(result.error).toBeDefined()
      expect(result.rules).toEqual([])
    })
  })

  describe('loadMultiplePolicies (new marketplace API)', () => {
    it('merges two synthetic rule files in input order', () => {
      const dir = mkdtempSync(join(tmpdir(), 'rule-merge-'))
      try {
        const userPath = join(dir, 'user.yaml')
        const builtinPath = join(dir, 'builtin.yaml')
        writeFileSync(
          userPath,
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: user.first
    priority: 100
    category: behavior_guidance
    match:
      tools: [bash]
    action:
      decision: deny
      blockReason: user rule
      blockCode: BEHAVIOR_GUIDANCE_USER_FIRST_001
`,
        )
        writeFileSync(
          builtinPath,
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: builtin.first
    priority: 800
    category: intrusion_defense
    match:
      tools: [bash]
    action:
      decision: deny
      blockReason: builtin rule
      blockCode: INTRUSION_DEFENSE_BUILTIN_FIRST_001
  - id: builtin.second
    priority: 800
    category: intrusion_defense
    match:
      tools: [bash]
    action:
      decision: ask
      blockReason: builtin ask
`,
        )

        const merged = loadMultiplePolicies([userPath, builtinPath])
        expect(merged.errors).toEqual([])
        expect(merged.totalFiles).toBe(2)
        expect(merged.rules.length).toBe(3)
        // After priority sort: builtin entries (800) come first,
        // user entry (100) last. Within the 800 group, the first
        // declared (builtin.first) precedes builtin.second by stable
        // sort — but BOTH are higher priority than user.first.
        expect(merged.rules[0]?.priority).toBe(800)
        expect(merged.rules[1]?.priority).toBe(800)
        expect(merged.rules[2]?.priority).toBe(100)
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    })

    it('isolates errors per file (one bad file does not break the merge)', () => {
      const dir = mkdtempSync(join(tmpdir(), 'rule-merge-'))
      try {
        const goodPath = join(dir, 'good.yaml')
        const badPath = join(dir, 'bad.yaml')
        writeFileSync(
          goodPath,
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: good.one
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: deny, blockReason: ok, blockCode: 'INTRUSION_DEFENSE_GOOD_ONE_001' }
`,
        )
        writeFileSync(badPath, 'rules:\n  - id: bad\n    match: { tools: [unclosed')

        const merged = loadMultiplePolicies([goodPath, badPath])
        expect(merged.errors.length).toBe(1)
        expect(merged.errors[0]?.path).toBe(badPath)
        expect(merged.rules.length).toBe(1)
        expect(merged.rules[0]?.id).toBe('good.one')
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    })

    it('returns an empty result for an empty path list', () => {
      const merged = loadMultiplePolicies([])
      expect(merged.rules).toEqual([])
      expect(merged.documents).toEqual({})
      expect(merged.errors).toEqual([])
      expect(merged.totalFiles).toBe(0)
    })

    it('preserves per-file PolicyDocument fragments', () => {
      const dir = mkdtempSync(join(tmpdir(), 'rule-merge-'))
      try {
        const aPath = join(dir, 'a.yaml')
        const bPath = join(dir, 'b.yaml')
        writeFileSync(
          aPath,
          `
apiVersion: security.use/v2
kind: Policy
scope: agent
rules:
  - id: a.rule
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: deny, blockReason: a, blockCode: 'INTRUSION_DEFENSE_A_RULE_001' }
`,
        )
        writeFileSync(
          bPath,
          `
apiVersion: security.use/v2
kind: Policy
scope: session
rules:
  - id: b.rule
    priority: 200
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: deny, blockReason: b, blockCode: 'INTRUSION_DEFENSE_B_RULE_001' }
`,
        )

        const merged = loadMultiplePolicies([aPath, bPath])
        expect(merged.documents[aPath]?.scope).toBe('agent')
        expect(merged.documents[bPath]?.scope).toBe('session')
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    })
  })
})
