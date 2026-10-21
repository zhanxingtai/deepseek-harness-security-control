/**
 * RuleLoader marketplace vocabulary translation.
 *
 * Verifies the marketplace 3-action vocabulary (`allow | deny | ask`)
 * is translated to the SPL internal 10-action vocabulary
 * (`allow | block | escalate | ...`) at load time, while legacy
 * policies that already use internal decisions keep working
 * unchanged.
 *
 * Translation map (in `RuleLoader.normalizeRule`):
 *   `deny`  → `block`     (marketplace "deny" = SPL "block")
 *   `ask`   → `escalate`  (marketplace "ask"  = SPL "escalate")
 *   `allow` → `allow`     (no-op)
 *   any internal decision value passes through unchanged.
 *
 * These tests exercise RuleLoader directly with synthetic YAML /
 * JSON policies; integration with InterventionEngine is covered by
 * tests/interventionMultiPolicy.test.ts.
 */

import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  isMarketplaceDecision,
  loadMultiplePolicies,
  loadPolicy,
  mapMarketplaceToInternal,
} from '../src/intervention/RuleLoader.js'

describe('RuleLoader marketplace vocabulary translation', () => {
  describe('mapMarketplaceToInternal (pure function)', () => {
    it('translates `deny` to `block`', () => {
      expect(mapMarketplaceToInternal('deny')).toBe('block')
    })

    it('translates `ask` to `escalate`', () => {
      expect(mapMarketplaceToInternal('ask')).toBe('escalate')
    })

    it('passes `allow` through unchanged', () => {
      expect(mapMarketplaceToInternal('allow')).toBe('allow')
    })

    it('passes the full SPL internal 10-action enum through unchanged', () => {
      const internalDecisions = [
        'allow',
        'warn',
        'guide',
        'context_adjust',
        'modify',
        'substitute',
        'escalate',
        'degrade',
        'block',
        'approve',
      ] as const
      for (const decision of internalDecisions) {
        expect(mapMarketplaceToInternal(decision)).toBe(decision)
      }
    })

    it('passes unknown values through unchanged (does not throw)', () => {
      // The translation function does not validate; that's
      // DecisionComposer's responsibility (downstream). Rule-load
      // errors should not abort the entire merge, so unknown values
      // are forwarded as-is — the type-check at compilePolicy will
      // surface them via getLastLoadErrors().
      // The Decision union currently covers all valid values; this
      // branch documents the contract.
      const decision = 'unknown-future-decision' as never
      expect(mapMarketplaceToInternal(decision)).toBe(decision)
    })
  })

  describe('isMarketplaceDecision', () => {
    it('identifies allow / deny / ask as marketplace decisions', () => {
      expect(isMarketplaceDecision('allow')).toBe(true)
      expect(isMarketplaceDecision('deny')).toBe(true)
      expect(isMarketplaceDecision('ask')).toBe(true)
    })

    it('identifies the SPL internal decisions as non-marketplace', () => {
      expect(isMarketplaceDecision('block')).toBe(false)
      expect(isMarketplaceDecision('escalate')).toBe(false)
      expect(isMarketplaceDecision('warn')).toBe(false)
      expect(isMarketplaceDecision('degrade')).toBe(false)
      expect(isMarketplaceDecision('modify')).toBe(false)
      expect(isMarketplaceDecision('substitute')).toBe(false)
      expect(isMarketplaceDecision('guide')).toBe(false)
      expect(isMarketplaceDecision('context_adjust')).toBe(false)
      expect(isMarketplaceDecision('approve')).toBe(false)
    })
  })

  describe('loadPolicy — translates a marketplace rule on the wire', () => {
    // The shipped YAML files exercise the same path (they use
    // `deny` / `ask`); here we pin the contract with synthetic
    // policies so the translation is verified independently of the
    // shipped file contents.

    let tmpDir: string
    function writeYaml(name: string, body: string): string {
      const path = join(tmpDir, name)
      writeFileSync(path, body)
      return path
    }

    // Per-test tmpDir lifecycle so isolation is preserved.
    function withTmpDir<T>(fn: (dir: string) => T): T {
      const dir = mkdtempSync(join(tmpdir(), 's4-vocab-'))
      try {
        return fn(dir)
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    }

    it('translates `deny` to `block` in the compiled rule', () => {
      withTmpDir((dir) => {
        tmpDir = dir
        const path = writeYaml(
          'marketplace-deny.yaml',
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: mp.deny
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: deny, blockReason: marketplace deny, blockCode: INTRUSION_DEFENSE_MP_DENY_001 }
`,
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules[0]?.action?.decision).toBe('block')
      })
    })

    it('translates `ask` to `escalate` in the compiled rule', () => {
      withTmpDir((dir) => {
        tmpDir = dir
        const path = writeYaml(
          'marketplace-ask.yaml',
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: mp.ask
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: ask, blockReason: marketplace ask }
`,
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules[0]?.action?.decision).toBe('escalate')
      })
    })

    it('passes `allow` through unchanged', () => {
      withTmpDir((dir) => {
        tmpDir = dir
        const path = writeYaml(
          'marketplace-allow.yaml',
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: mp.allow
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: allow }
`,
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        expect(result.rules[0]?.action?.decision).toBe('allow')
      })
    })

    it('rejects v1 deprecated decisions (guide / context_adjust / substitute / degrade / approve) with a warning', () => {
      // SPL v2 spec §5.1 line 95 retires five v1
      // decisions. The loader drops each rule that carries one and
      // surfaces a `deprecated v1 decision "..." rejected by spec §5.1`
      // warning — the rule is NOT in `result.rules`, so the engine
      // falls through to the default `allow` verdict.
      withTmpDir((dir) => {
        tmpDir = dir
        const path = writeYaml(
          'legacy-internal.yaml',
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: legacy.warn
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: warn, blockReason: legacy warn }
  - id: legacy.modify
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: modify, blockReason: legacy modify }
  - id: legacy.degrade
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: degrade, blockReason: legacy degrade }
  - id: legacy.context_adjust
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: context_adjust, blockReason: legacy context_adjust }
  - id: legacy.guide
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: guide, blockReason: legacy guide }
  - id: legacy.substitute
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: substitute, blockReason: legacy substitute }
  - id: legacy.approve
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: approve, blockReason: legacy approve }
`,
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        // Only the two v2-safe decisions survive — warn + modify are
        // still in the v2 enum (warn/move); degrade / context_adjust /
        // guide / substitute / approve are dropped per §5.1.
        expect(result.rules.map((r) => r.id)).toEqual([
          'legacy.warn',
          'legacy.modify',
        ])
        expect(result.rules.map((r) => r.action?.decision)).toEqual(['warn', 'modify'])
        // The warnings name every rejected decision.
        const warnings = result.warnings ?? []
        for (const dropped of ['degrade', 'context_adjust', 'guide', 'substitute', 'approve']) {
          expect(warnings).toEqual(
            expect.arrayContaining([
              expect.stringContaining(dropped),
              expect.stringContaining('deprecated v1 decision'),
            ]),
          )
        }
      })
    })

    it('translates a mixed-vocabulary file: each rule translated independently', () => {
      // A rule file may mix marketplace (`deny`, `ask`) and internal
      // (`escalate`, `block`) values. Each is translated independently.
      withTmpDir((dir) => {
        tmpDir = dir
        const path = writeYaml(
          'mixed.yaml',
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: mixed.a
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: deny, blockReason: a, blockCode: INTRUSION_DEFENSE_MIXED_A_001 }
  - id: mixed.b
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: block, blockReason: b, blockCode: INTRUSION_DEFENSE_MIXED_B_001 }
  - id: mixed.c
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: ask, blockReason: c }
  - id: mixed.d
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: escalate, blockReason: d }
`,
        )
        const result = loadPolicy(path)
        expect(result.error).toBeUndefined()
        // After normalization: deny→block, block→block, ask→escalate,
        // escalate→escalate.
        expect(result.rules.map((r) => r.action?.decision)).toEqual([
          'block',
          'block',
          'escalate',
          'escalate',
        ])
      })
    })
  })

  describe('loadMultiplePolicies — translation applies across all files', () => {
    let tmpDir: string
    function withTmpDir<T>(fn: (dir: string) => T): T {
      const dir = mkdtempSync(join(tmpdir(), 's4-vocab-'))
      try {
        return fn(dir)
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    }

    it('translates both user and builtin files when mixing vocabularies', () => {
      withTmpDir((dir) => {
        tmpDir = dir
        const userPath = join(dir, 'user.yaml')
        const builtinPath = join(dir, 'builtin.yaml')
        writeFileSync(
          userPath,
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: user.mp
    priority: 100
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: deny, blockReason: user mp, blockCode: INTRUSION_DEFENSE_USER_MP_001 }
  - id: user.internal
    priority: 100
    category: behavior_guidance
    match: { tools: [bash] }
    action: { decision: warn, blockReason: user internal }
`,
        )
        writeFileSync(
          builtinPath,
          `
apiVersion: security.use/v2
kind: Policy
rules:
  - id: builtin.mp
    priority: 800
    category: intrusion_defense
    match: { tools: [bash] }
    action: { decision: ask, blockReason: builtin mp }
`,
        )
        const merged = loadMultiplePolicies([userPath, builtinPath])
        expect(merged.errors).toEqual([])
        const decisions = merged.rules.map((r) => r.action?.decision)
        // After priority sort: builtin.mp (priority 800) first
        // (ask→escalate), then user.mp (100, deny→block), then
        // user.internal (100, warn→warn). Stable sort keeps the two
        // priority-100 user rules in declared order.
        expect(decisions).toEqual(['escalate', 'block', 'warn'])
      })
    })
  })
})