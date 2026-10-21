import { describe, expect, it } from 'vitest'
import { toMarketplaceDecision, type SplDecision } from '../src/utils/decisionVocabulary.js'

/**
 * 2026-09-22) — pins the"real enforcement capability"matrix that
 * the decision-vocabulary spec §2 now documents: of the SPL 10-action vocabulary
 * ONLY `block` is host-enforced (enforce mode), and on the marketplace
 * wire every advisory decision (warn/guide/context_adjust/modify/
 * substitute/escalate/degrade) collapses to `ask` for an operator —
 * never to `allow`. This is the regression net for "don't label an
 * unenforced action as supported".
 */
describe('toMarketplaceDecision — audit-only matrix', () => {
  it.each<[SplDecision, 'allow' | 'deny' | 'ask']>([
    ['allow', 'allow'],
    ['block', 'deny'],
    ['approve', 'ask'],
    ['ask', 'ask'],
    ['warn', 'ask'],
    ['guide', 'ask'],
    ['context_adjust', 'ask'],
    ['modify', 'ask'],
    ['substitute', 'ask'],
    ['escalate', 'ask'],
    ['degrade', 'ask'],
  ])('%s → %s', (spl, expected) => {
    expect(toMarketplaceDecision(spl)).toBe(expected)
  })

  it('never collapses an advisory decision to allow (fail-safe)', () => {
    const advisory: SplDecision[] = ['warn', 'guide', 'context_adjust', 'modify', 'substitute', 'escalate', 'degrade']
    for (const d of advisory) {
      expect(toMarketplaceDecision(d)).not.toBe('allow')
    }
  })

  it('unknown decision fails safe to ask, not allow', () => {
    expect(toMarketplaceDecision('not_a_real_decision')).toBe('ask')
  })

  it('marketplace vocabulary passes through unchanged', () => {
    expect(toMarketplaceDecision('deny')).toBe('deny')
    expect(toMarketplaceDecision('ask')).toBe('ask')
  })
})
