/**
 * `severity` field on policy rules driving a runtime
 * `block → warn` downgrade. This file exercises the seam directly on
 * `DecisionComposer.composeDecision` so the assertions are independent
 * of any shipped default policy. Engine-integration cases against the
 * default policy live in `tests/severityDefaultPolicy.test.ts`.
 */
import { describe, expect, it } from 'vitest'
import { composeDecision } from '../src/intervention/DecisionComposer.js'
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

describe('composeDecision severity downgrade', () => {
  it('severity=critical keeps block in enforce mode', () => {
    const d = composeDecision(
      [makeRule({ severity: 'critical' })],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('block')
    expect(d.severity).toBe('critical')
    expect(d.severity_downgraded).toBeUndefined()
  })

  it('severity=high keeps block in enforce mode', () => {
    const d = composeDecision(
      [makeRule({ severity: 'high' })],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('block')
    expect(d.severity).toBe('high')
    expect(d.severity_downgraded).toBeUndefined()
  })

  it('severity=medium downgrades block→warn + stamps trace fields', () => {
    const d = composeDecision(
      [makeRule({ severity: 'medium' })],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('warn')
    expect(d.severity).toBe('medium')
    expect(d.severity_downgraded).toBe(true)
    expect(d.severity_rule_id).toBe('r1')
    // Mirror on `intervention`
    expect(d.intervention.severity).toBe('medium')
    expect(d.intervention.severity_downgraded).toBe(true)
    expect(d.intervention.severity_rule_id).toBe('r1')
  })

  it('severity=low downgrades block→warn', () => {
    const d = composeDecision(
      [makeRule({ severity: 'low' })],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('warn')
    expect(d.severity).toBe('low')
    expect(d.severity_downgraded).toBe(true)
  })

  it('absent severity keeps block (back-compat with un-migrated policies)', () => {
    const d = composeDecision([makeRule({})], 'enforce', 'fail_open')
    expect(d.decision).toBe('block')
    expect(d.severity).toBeUndefined()
    expect(d.severity_downgraded).toBeUndefined()
  })

  it('self-protection by id prefix bypasses downgrade even at medium', () => {
    const d = composeDecision(
      [makeRule({ id: 'self-protection-block-foo', severity: 'medium' })],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('block')
    expect(d.severity).toBe('medium')
    expect(d.severity_downgraded).toBeUndefined()
  })

  it('self-protection by category bypasses downgrade even at low', () => {
    const d = composeDecision(
      [
        makeRule({
          severity: 'low',
          category: 'self_protection',
        }),
      ],
      'enforce',
      'fail_open',
    )
    expect(d.decision).toBe('block')
    expect(d.severity).toBe('low')
    expect(d.severity_downgraded).toBeUndefined()
  })

  it('severity downgrade applies in audit mode too (audit-row trace)', () => {
    const d = composeDecision(
      [makeRule({ severity: 'medium' })],
      'audit',
      'fail_open',
    )
    expect(d.decision).toBe('warn')
    expect(d.severity_downgraded).toBe(true)
    // mode is on the decision so audit consumers can disambiguate
    expect(d.mode).toBe('audit')
  })

  it('non-block decisions (modify/escalate/allow) are never downgraded', () => {
    const cases: Array<{ id: string; action: CompiledRule['action']; expected: string }> = [
      { id: 'r-mod', action: { decision: 'modify' }, expected: 'modify' },
      { id: 'r-esc', action: { decision: 'escalate' }, expected: 'escalate' },
      { id: 'r-allow', action: { decision: 'allow' }, expected: 'allow' },
    ]
    for (const c of cases) {
      const d = composeDecision(
        [makeRule({ id: c.id, severity: 'low', action: c.action })],
        'enforce',
        'fail_open',
      )
      expect(d.decision).toBe(c.expected)
      expect(d.severity_downgraded).toBeUndefined()
    }
  })
})