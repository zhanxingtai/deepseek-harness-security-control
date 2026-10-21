#!/usr/bin/env node
/**
 * verify-test-cases-coverage.mjs — testCases coverage soft gate.
 *
 * Reads `policies/default-policy.spl.yaml` and checks that every
 * block / warn rule ships with `testCases:` declaring:
 *   - ≥2 entries (≥1 positive + ≥1 negative)
 *   - at least 1 case whose `expectedDecision` matches the rule's
 * `action.decision` (positive case). For severity
 *     downgrade, the positive case may use `expectedDecision: warn`
 *     for severity=medium/low rules that downgrade to warn.
 *   - at least 1 case with `expectedDecision: allow` (negative case)
 *
 * Soft-gate semantics ( plan):
 *   - Coverage gaps are emitted to `warnings[]` and printed with
 *     `console.warn`. They NEVER cause `process.exit(1)` in default
 *     mode. Summary line is always `PASS (N warnings)` so the CI
 *     green ✓ / red ✗ glyph only flips on hard errors.
 *   - Hard gate (write to `errors[]` + exit 1) engages when
 *     `DSH_TEST_CASES_COVERAGE_STRICT=1` is set — reserved for a
 *     future PR that promotes soft → hard without re-baselining.
 *
 * Exit codes:
 *   - default:  0 (warnings do not block)
 *   - strict:   1 (any coverage gap → errors)
 *
 * Run from repo root: `node scripts/verify-test-cases-coverage.mjs`
 */
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')

const errors = []
const warnings = []

function fail(msg) {
  errors.push(msg)
  console.error(`✗ ${msg}`)
}

function warn(msg) {
  warnings.push(msg)
  console.warn(`! ${msg}`)
}

function ok(msg) {
  console.log(`✓ ${msg}`)
}

const STRICT = process.env['DSH_TEST_CASES_COVERAGE_STRICT'] === '1'

// ---------------------------------------------------------------------------
// YAML loader — peer-deps allow `yaml` OR `js-yaml` (see RuleLoader.parseYaml
// for the fallback chain). Both expose a `load` function with the same shape
// we need here (sync, no schema validation).
// ---------------------------------------------------------------------------
async function loadYaml(p) {
  // Try `yaml` first (preferred; smaller AST).
  try {
    const mod = await import('yaml')
    return mod.parse(readFileSync(p, 'utf8'))
  } catch {
    // Fallback: js-yaml.
    const mod = await import('js-yaml')
    return mod.load(readFileSync(p, 'utf8'))
  }
}

const policyPath = join(root, 'policies/default-policy.spl.yaml')
if (!existsSync(policyPath)) {
  fail(`policy file not found: ${policyPath}`)
  console.error(`✗ verify-test-cases-coverage.mjs: FAIL (1 error, 0 warnings)`)
  process.exit(1)
}

const policy = await loadYaml(policyPath)
const rules = Array.isArray(policy?.rules) ? policy.rules : []

// Decisions that REQUIRE ≥1 positive + ≥1 negative case (spec §5.1 + the
// runtime aggregation seam in tests/splTestCases.test.ts).
const BLOCK_WARN_DECISIONS = new Set(['block', 'warn'])

// Issue : severity=medium / low block rules get downgraded to warn
// at runtime. The positive case for those rules may use
// expectedDecision=warn instead of matching `block` literally. We don't
// try to model the downgrade here — the splTestCases auto-runner does.
// We only flag the structural invariants: ≥2 cases + ≥1 allow.
function positiveMatchesRule(rule) {
  const decision = rule?.action?.decision
  if (!rule.testCases || rule.testCases.length === 0) return false
  return rule.testCases.some((c) => {
    const expected = c?.expectedDecision
    // Positive case = rule fires.
    // allow cases cannot be the positive — they're negative.
    if (expected === 'allow') return false
    return expected === decision || expected === 'warn' || expected === 'escalate'
  })
}

function hasNegativeCase(rule) {
  return Boolean(
    rule.testCases && rule.testCases.some((c) => c?.expectedDecision === 'allow'),
  )
}

let totalBlockWarn = 0
let totalWithFullCoverage = 0

for (const rule of rules) {
  if (!BLOCK_WARN_DECISIONS.has(rule?.action?.decision)) continue
  totalBlockWarn += 1
  const id = rule?.id ?? '<no-id>'
  const cases = Array.isArray(rule.testCases) ? rule.testCases : []
  const hasCases = cases.length >= 2
  const hasPositive = positiveMatchesRule(rule)
  const hasNegative = hasNegativeCase(rule)
  const total = cases.length

  if (hasCases && hasPositive && hasNegative) {
    totalWithFullCoverage += 1
    ok(`${id}: ${total}/2 cases (positive + negative present)`)
    continue
  }

  // Build a precise reason string.
  const reasons = []
  if (cases.length < 2) {
    reasons.push(`only ${cases.length} case(s) (need ≥2)`)
  }
  if (cases.length > 0 && !hasPositive) {
    reasons.push('missing positive case (expectedDecision matches action.decision)')
  }
  if (cases.length > 0 && !hasNegative) {
    reasons.push('missing negative case (expectedDecision=allow)')
  }
  if (cases.length === 0) {
    reasons.push('testCases: block missing entirely')
  }
  warn(`${id}: ${total}/2 cases — ${reasons.join('; ')}`)
}

if (totalBlockWarn === 0) {
  warn('no block/warn rules found in policy — verify the policy file is non-empty')
}

// Summary.
if (STRICT) {
  // Hard gate: any warning → error + exit 1.
  if (errors.length === 0 && warnings.length === 0) {
    console.log(`✓ verify-test-cases-coverage.mjs: PASS (${totalWithFullCoverage}/${totalBlockWarn} block/warn rules fully covered)`)
    process.exit(0)
  }
  // Promote warnings to errors under strict mode.
  if (warnings.length > 0) {
    console.error(`✗ verify-test-cases-coverage.mjs: FAIL — ${warnings.length} coverage gap(s) under DSH_TEST_CASES_COVERAGE_STRICT=1`)
    process.exit(1)
  }
  console.error(`✗ verify-test-cases-coverage.mjs: FAIL (${errors.length} errors, ${warnings.length} warnings)`)
  process.exit(1)
}

// Default (soft-gate) mode: warnings never block.
console.log(
  `✓ verify-test-cases-coverage.mjs: PASS (${totalWithFullCoverage}/${totalBlockWarn} block/warn rules fully covered, ${warnings.length} warnings)`,
)
process.exit(0)