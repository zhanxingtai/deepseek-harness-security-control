/**
 * Auto-runs every YAML `testCases` block across all rules in
 * `policies/default-policy.spl.yaml`, verifying each `expectedDecision`
 * against `InterventionEngine.evaluate()`.
 *
 * `policies/legacy.yaml` removed — audit scope
 * shrinks to the single shipped policy file.
 *
 * closes the gap that YAML testCases were
 * documented contracts but no test runner executed them. Without this
 * file, anyone editing a regex can silently break a contract because
 * the YAML testCases field is purely descriptive.
 *
 * Mechanics:
 *   1. Load YAML policy via js-yaml
 *   2. For each rule with `testCases:`
 *      - Build InterventionContext from `input.{actionType,toolName,params,...}`
 *      - Run `engine.evaluate(ctx)`
 *      - Assert `decision === expectedDecision`
 *      - Optional: assert `block_reason` matches `expectedReason` substring
 *   3. Emit a per-rule report (counts of pass / fail / skip) so coverage
 *      gaps are visible in CI logs even when no test fails.
 *
 * Skips:
 *   - testCases where `input.actionType: tool_call` (or any other
 *     tool-layer type) but `params` references a key the engine can't
 *     evaluate without agent/session context (e.g. `riskFlagsAny`
 *     with no riskFlags injected). These are listed as `skip` rather
 *     than fail — the failure mode here is "we lack fixture data",
 *     not "the rule is wrong".
 *
 * Coverage report at end of suite: number of rules with testCases vs
 * total rules, listed by priority tier. If this number is non-zero we
 * can prove the YAML testCases are executed; if it drops, coverage
 * regressed.
 */

import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import * as yaml from 'js-yaml'

interface SplTestCase {
  name?: string
  input: {
    actionType?: string
    toolName?: string
    params?: Record<string, unknown>
    body?: string
    riskFlags?: string[]
    // asset_change / asset_remove 路径透传至 RuleMatcher.match.assetType
    assetType?: string
  }
  expectedDecision:
    | 'allow'
    | 'warn'
    | 'audit'
    | 'modify'
    | 'escalate'
    | 'block'
  expectedReason?: string
}

interface SplRule {
  id: string
  priority: number
  enabled?: boolean
  testCases?: SplTestCase[]
  // Required for "skip on disabled" filter
}

const POLICY_FILES = [
  'policies/default-policy.spl.yaml',
] as const

describe('YAML testCases auto-runner', () => {
  let tmpDir: string
  let config: Config
  let engine: InterventionEngine
  let totalCases = 0
  let passedCases = 0
  let failedCases = 0
  let skippedCases = 0
  const failureDetails: string[] = []
  const skippedDetails: string[] = []
  const rulesWithTestCases = new Set<string>()

  beforeAll(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-splcases-'))
    const defaultPolicyPath = fileURLToPath(
      new URL('../policies/default-policy.spl.yaml', import.meta.url),
    )
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPath: defaultPolicyPath, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
    })
    engine = new InterventionEngine(config)
    engine.initialize()
  })

  afterAll(() => {
    rmSync(tmpDir, { recursive: true, force: true })
    // Always emit a coverage report so CI logs surface gaps.
    // eslint-disable-next-line no-console
    console.log(
      `\n[splTestCases] coverage: ${passedCases}/${totalCases} passed, ${failedCases} failed, ${skippedCases} skipped; ${rulesWithTestCases.size} rules exercised`,
    )
    if (failureDetails.length > 0) {
      // eslint-disable-next-line no-console
      console.error('[splTestCases] failures:\n' + failureDetails.join('\n'))
    }
    if (skippedDetails.length > 0) {
      // eslint-disable-next-line no-console
      console.warn('[splTestCases] skips:\n' + skippedDetails.join('\n'))
    }
  })

  for (const policyFile of POLICY_FILES) {
    const doc = yaml.load(readFileSync(policyFile, 'utf8')) as {
      rules: SplRule[]
    }

    describe(`${policyFile}`, () => {
      for (const rule of doc.rules) {
        if (!rule.testCases || rule.testCases.length === 0) continue
        if (rule.enabled === false) continue // skip disabled rules

        rulesWithTestCases.add(rule.id)

        describe(`${rule.id} (priority=${rule.priority}, ${rule.testCases.length} cases)`, () => {
          for (const [idx, tc] of rule.testCases.entries()) {
            const caseLabel = tc.name ?? `case #${idx}`
            it(`${caseLabel}`, async () => {
              totalCases++

              // Skip cases that reference fields the engine can't evaluate
              // without rich session/agent fixtures. We currently lack a
              // session-fixture harness so we can only run simple
              // (actionType, params) cases end-to-end. toolName is optional
              // (process_start actionType often omits it).
              const ctx = tc.input
              if (!ctx.actionType) {
                skippedCases++
                skippedDetails.push(
                  `  - ${rule.id} / ${caseLabel}: skipped (missing actionType)`,
                )
                return
              }

              // Body-only redaction testCases (no params, just body) wrap
              // the body into params.body so the redaction evaluator sees it.
              const effectiveParams: Record<string, unknown> =
                ctx.params !== undefined
                  ? ctx.params
                  : ctx.body !== undefined
                    ? { body: ctx.body }
                    : {}

              const decision = await engine.evaluate({
                actionType: ctx.actionType,
                ...(ctx.toolName !== undefined ? { toolName: ctx.toolName } : {}),
                params: effectiveParams,
                ...(ctx.body !== undefined ? { body: ctx.body } : {}),
                ...(ctx.riskFlags !== undefined ? { riskFlags: ctx.riskFlags } : {}),
                ...(ctx.assetType !== undefined ? { assetType: ctx.assetType } : {}),
              })

              try {
                expect(decision.decision).toBe(tc.expectedDecision)
                if (tc.expectedReason) {
                  expect(decision.block_reason ?? '').toContain(tc.expectedReason)
                }
                passedCases++
              } catch (e) {
                failedCases++
                failureDetails.push(
                  `  - ${rule.id} / ${caseLabel}: expected ${tc.expectedDecision}, got ${decision.decision} (block_reason=${decision.block_reason ?? '<none>'})`,
                )
                throw e
              }
            })
          }
        })
      }
    })
  }

  // -----------------------------------------------------------------
  // Coverage report — separate describe block so it always runs even
  // if the case-iteration suite above has 100% pass (we want the
  // coverage metric to surface in CI logs unconditionally).
  // -----------------------------------------------------------------
  describe('coverage report', () => {
    it('reports rule-level testCase coverage', () => {
      const doc = yaml.load(readFileSync(POLICY_FILES[0], 'utf8')) as {
        rules: SplRule[]
      }
      const total = doc.rules.length
      const withCases = doc.rules.filter((r) => (r.testCases?.length ?? 0) > 0).length
      // eslint-disable-next-line no-console
      console.log(
        `[splTestCases] ${withCases}/${total} rules have testCases (${((withCases / total) * 100).toFixed(1)}%)`,
      )
      // every rule in default-policy.spl.yaml must
      // declare a `testCases:` block (coverage 100%). A drop signals
      // coverage regression — the auto-runner would silently stop
      // exercising that rule's regex.
      expect(withCases / total).toBe(1.0)
    })

    it('block/warn rules must declare ≥2 testCases (≥1 positive + ≥1 negative)', () => {
      // spec §3: decision=block|warn rules MUST ship with positive
      // and negative regression cases. Positive = input that matches
      // the rule's regex/fieldEquals → expectedDecision matches the
      // rule's action.decision; negative = a non-matching input that
      // should fall through to allow. The runner above verifies each
      // case, but we also assert the structural invariant here so a
      // future edit that drops a case fails the suite.
      const doc = yaml.load(readFileSync(POLICY_FILES[0], 'utf8')) as {
        rules: (SplRule & { action?: { decision?: string } })[]
      }
      const offenders: string[] = []
      for (const r of doc.rules) {
        if (r.action?.decision !== 'block' && r.action?.decision !== 'warn') continue
        const cases = r.testCases ?? []
        if (cases.length < 2) {
          offenders.push(`${r.id} (${r.action?.decision}): ${cases.length} cases`)
          continue
        }
        // Sanity: at least one positive (decision matches) + one negative (allow).
        // severity-based block→warn downgrade for medium/low severity:
        // for those rules, a positive case may legitimately assert
        // `expectedDecision: warn` even when `action.decision: block`, since the
        // engine returns warn. We accept either form as "the rule matched".
        const decision = r.action?.decision
        const downgraded = decision === 'block' && (r.severity === 'low' || r.severity === 'medium')
        const acceptedPositive = downgraded
          ? ['warn', 'block']
          : [decision ?? '']
        const hasPositive = cases.some((c) => acceptedPositive.includes(c.expectedDecision))
        const hasNegative = cases.some((c) => c.expectedDecision === 'allow')
        if (!hasPositive || !hasNegative) {
          offenders.push(
            `${r.id} (${r.action?.decision}): missing ${!hasPositive ? 'positive' : 'negative'} case`,
          )
        }
      }
      if (offenders.length > 0) {
        throw new Error(
          `block/warn rules without ≥1 positive + ≥1 negative testCase:\n  ${offenders.join('\n  ')}`,
        )
      }
    })

    it('priority-tier breakdown', () => {
      const doc = yaml.load(readFileSync(POLICY_FILES[0], 'utf8')) as {
        rules: SplRule[]
      }
      const tiers: Record<string, { total: number; withCases: number }> = {}
      for (const r of doc.rules) {
        const tier = tierName(r.priority)
        if (!tiers[tier]) tiers[tier] = { total: 0, withCases: 0 }
        tiers[tier].total++
        if ((r.testCases?.length ?? 0) > 0) tiers[tier].withCases++
      }
      // eslint-disable-next-line no-console
      console.log(
        '[splTestCases] priority-tier breakdown:\n' +
          Object.entries(tiers)
            .sort((a, b) => b[0].localeCompare(a[0]))
            .map(([t, v]) => `  ${t}: ${v.withCases}/${v.total}`).join('\n'),
      )
      // No assertion; informational only.
    })
  })
})

function tierName(priority: number): string {
  if (priority >= 1500) return 'critical-self'
  if (priority >= 1200) return 'self-protection'
  if (priority >= 1100) return 'high-risk'
  if (priority >= 1000) return 'sensitive-resource'
  if (priority >= 900) return 'exec-layer'
  if (priority >= 850) return 'supply-chain'
  if (priority >= 700) return 'low-warn'
  return 'audit-only'
}