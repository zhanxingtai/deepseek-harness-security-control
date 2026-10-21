/**
 * local policy cannot suppress self-protection rules.
 *
 * Background (SPL v2 spec §9.2): the local exemption channel (operator
 * writes a high-priority `allow` rule into `~/.dsh/...` and the merge
 * in `RuleLoader.mergeEntries` lets it outrank the priority=1200
 * self-protection block rules) is not allowed to suppress any rule
 * whose category is `self_protection` (or, until completes the
 * category rollout, whose id carries the `self-protection-` prefix).
 * Otherwise the local exemption channel becomes a legitimate
 * plugin-disabling channel.
 *
 * The arbitration seam lives in `DecisionComposer.composeDecision`.
 * Multi-file merge is unchanged — `matched[0]` is still the
 * priority-sorted head — but when head is a non-self_protection
 * allow/warn and any self_protection rule is also in `matched`, the
 * self_protection rule wins.
 *
 * Trace fields (mirror of `severity_downgraded` / `severity_rule_id`
 * from):
 *   - `self_protection_override: true` — arbitration flipped head
 *   - `overridden_rule_id` — id of the local rule that would have won
 *
 * Operators can grep the audit stream for `self_protection_override`
 * to find override attempts without needing a dedicated event type.
 */
import { describe, expect, it } from 'vitest'
import { composeDecision, isSelfProtectionRule } from '../src/intervention/DecisionComposer.js'
import type { CompiledRule } from '../src/intervention/InterventionEngine.js'

function makeRule(overrides: Partial<CompiledRule>): CompiledRule {
  return {
    id: 'r1',
    name: 'r1',
    enabled: true,
    priority: 1000,
    action: { decision: 'block' },
    ...overrides,
  }
}

describe('isSelfProtectionRule predicate', () => {
  it('recognises self-protection- id prefix', () => {
    expect(isSelfProtectionRule(makeRule({ id: 'self-protection-block-foo' }))).toBe(true)
  })

  it('recognises category: self_protection', () => {
    expect(isSelfProtectionRule(makeRule({ category: 'self_protection' }))).toBe(true)
  })

  it('rejects other rules', () => {
    expect(isSelfProtectionRule(makeRule({ id: 'block-exec-foo' }))).toBe(false)
    expect(isSelfProtectionRule(makeRule({ category: 'intrusion_defense' }))).toBe(false)
  })

  it('id prefix wins even without category', () => {
    // Back-compat with the 42 shipped `self-protection-*` rules that
    // predate the category rollout.
    expect(isSelfProtectionRule(makeRule({ id: 'self-protection-allow-pkg' }))).toBe(true)
  })
})

describe('composeDecision self-protection override', () => {
  it('local allow with higher priority cannot suppress self-protection block', () => {
    // Operator writes a malicious local allow with priority > 1200 to
    // try to disable plugin enforcement. Self-protection block rule
    // must still win.
    const d = composeDecision(
      [
        makeRule({
          id: 'local-allow-bypass',
          priority: 1300,
          action: { decision: 'allow' },
        }),
        makeRule({
          id: 'self-protection-block-uninstall',
          priority: 1200,
          category: 'self_protection',
          action: { decision: 'block', blockReason: '插件自保护' },
        }),
      ],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('block')
    expect(d.policy_id).toBe('self-protection-block-uninstall')
    expect(d.self_protection_override).toBe(true)
    expect(d.overridden_rule_id).toBe('local-allow-bypass')
    // Mirror on intervention
    expect(d.intervention.self_protection_override).toBe(true)
    expect(d.intervention.overridden_rule_id).toBe('local-allow-bypass')
  })

  it('local warn with higher priority cannot suppress self-protection block', () => {
    const d = composeDecision(
      [
        makeRule({
          id: 'local-warn-soften',
          priority: 1300,
          action: { decision: 'warn' },
        }),
        makeRule({
          id: 'self-protection-block-pkill',
          priority: 1200,
          action: { decision: 'block' },
        }),
      ],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('block')
    expect(d.policy_id).toBe('self-protection-block-pkill')
    expect(d.self_protection_override).toBe(true)
    expect(d.overridden_rule_id).toBe('local-warn-soften')
  })

  it('local allow with higher priority cannot suppress self-protection allow (allow allow互压仍受保护)', () => {
    // Even when the self-protection rule is itself an `allow` (the
    // shipped `self-protection-allow-package-manager-mention` shape),
    // a local allow cannot suppress it. Spec §9.2 protects the whole
    // category, not just block/warn.
    const d = composeDecision(
      [
        makeRule({
          id: 'local-allow-everything',
          priority: 1300,
          action: { decision: 'allow' },
        }),
        makeRule({
          id: 'self-protection-allow-pkg-mention',
          priority: 1200,
          action: { decision: 'allow' },
        }),
      ],
      'enforce',
      'fail_open',
    )
    // Without override: local allow wins, but override flips to self-protection rule.
    expect(d.policy_id).toBe('self-protection-allow-pkg-mention')
    expect(d.self_protection_override).toBe(true)
    expect(d.overridden_rule_id).toBe('local-allow-everything')
  })

  it('id-prefix self-protection detection works without category', () => {
    const d = composeDecision(
      [
        makeRule({
          id: 'local-allow-bypass',
          priority: 1300,
          action: { decision: 'allow' },
        }),
        makeRule({
          id: 'self-protection-block-foo',
          priority: 1200,
          action: { decision: 'block' },
        }),
      ],
      'enforce',
      'fail_open',
    )
    expect(d.policy_id).toBe('self-protection-block-foo')
    expect(d.self_protection_override).toBe(true)
  })

  it('local allow still wins when no self-protection rule is in matched set', () => {
    // Lock the documented back-compat behaviour: local allow/warn
    // exemptions against non-self_protection rules (the normal
    // operator exemption path) keep working unchanged.
    const d = composeDecision(
      [
        makeRule({
          id: 'local-allow-pkg',
          priority: 1150,
          action: { decision: 'allow' },
        }),
        makeRule({
          id: 'block-some-tool',
          priority: 900,
          action: { decision: 'block' },
        }),
      ],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('allow')
    expect(d.policy_id).toBe('local-allow-pkg')
    expect(d.self_protection_override).toBeUndefined()
    expect(d.overridden_rule_id).toBeUndefined()
  })

  it('local allow does NOT override self-protection when its priority is lower', () => {
    // Edge case: operator writes a local allow with priority < the
    // self-protection priority. The self-protection rule wins anyway
    // via the priority sort; no override trace because head was
    // already the self-protection rule (no arbitration needed).
    const d = composeDecision(
      [
        makeRule({
          id: 'self-protection-block-foo',
          priority: 1200,
          action: { decision: 'block' },
        }),
        makeRule({
          id: 'local-allow-low-priority',
          priority: 800,
          action: { decision: 'allow' },
        }),
      ],
      'enforce',
      'fail_open',
    )
    expect(d.policy_id).toBe('self-protection-block-foo')
    expect(d.decision).toBe('block')
    expect(d.self_protection_override).toBeUndefined()
  })

  it('self-protection rule keeps block under severity seam (regression guard for)', () => {
    // Combined test: even with severity=medium/low, the self-protection
    // block must stay block AND must not be suppressed
    // by a local allow.
    const d = composeDecision(
      [
        makeRule({
          id: 'local-allow-bypass',
          priority: 1300,
          action: { decision: 'allow' },
        }),
        makeRule({
          id: 'self-protection-block-foo',
          priority: 1200,
          severity: 'medium', // would normally trigger block→warn downgrade
          action: { decision: 'block' },
        }),
      ],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('block')
    expect(d.policy_id).toBe('self-protection-block-foo')
    expect(d.severity_downgraded).toBeUndefined()
    expect(d.self_protection_override).toBe(true)
    expect(d.overridden_rule_id).toBe('local-allow-bypass')
  })

  it('self-protection block at severity=medium stays block under audit mode too', () => {
    const d = composeDecision(
      [
        makeRule({
          id: 'local-allow-bypass',
          priority: 1300,
          action: { decision: 'allow' },
        }),
        makeRule({
          id: 'self-protection-block-foo',
          priority: 1200,
          severity: 'medium',
          action: { decision: 'block' },
        }),
      ],
      'audit',
      'fail_open',
    )
    // In audit mode the engine reports block but doesn't enforce;
    // arbitration still picks the self-protection rule.
    expect(d.policy_id).toBe('self-protection-block-foo')
    expect(d.self_protection_override).toBe(true)
  })
})