#!/usr/bin/env node
/**
 * verify-spl-block-code-detector.mjs — SPL v2 spec §7.4 + §7.1 strict
 * deviation detector. Companion to `verify-policy-schema.mjs`: the schema
 * check enforces "the YAML parses and the regex passes shape"; this script
 * enforces the deeper semantic constraints the regex alone cannot catch
 * (and that the runtime `RuleLoader` started enforcing as advisory in
 * commit f9186ba of).
 *
 * Checks per rule (applies to `action.blockCode` when `action.decision`
 * ∈ {block, warn, escalate, modify} — i.e. any audit-visible decision):
 *
 *   HIGH §7.4 shape:
 *     - 3 segments split by `_`
 *     - segment[0] NNN = first word of `rule.category.uppercased().split('_')[0]`
 *       (per §7.4 example `INTRUSION_DEFENSE_MASS_DELETION_001` — first
 *       segment is `INTRUSION`, the first word of `intrusion_defense`;
 *       strict full-category equality would contradict the example)
 *     - after stripping the category prefix, remainder matches
 *       `^[A-Z][A-Z0-9_]*[A-Z0-9]_\d{3}$` (threat ≥ 1 letter, NNN exactly 3 digits)
 *     - threat segment MUST NOT contain `_CRITICAL_` (§6.4 双轨制约定：
 *       dual-track suffix belongs on rule.id, not in blockCode threat)
 *
 *   HIGH §7.1 id naming:
 *     - rule.id MUST be lowercase kebab-case, i.e. match
 *       `^[a-z][a-z0-9-]*$` (legacy `DATA_LEAK_*_NNN` UPPERCASE ids violate)
 *
 *   MEDIUM uniqueness:
 *     - NNN must be unique per category bucket (global cross-category
 *       uniqueness is fine, but intra-category duplication breaks audit
 *       traceability)
 *
 *   LOW:
 *     - WARN decision should not carry `blockCode` per spec §5.2 (advisory)
 *
 * Exit code:
 *   - HIGH > 0 → 1 (CI gate)
 *   - HIGH = 0 and MEDIUM > 0 → 0 (warn but pass)
 *   - clean → 0
 *
 * No network, no fs writes. Read-only detector.
 */
import { readFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')
const POLICY_PATH = join(root, 'policies', 'default-policy.spl.yaml')

const CATEGORIES = new Set([
  'self_protection',
  'intrusion_defense',
  'data_leak_monitoring',
  'sensitive_data_access',
  'supply_chain',
  'ssrf',
  'behavior_guidance',
  'data_desensitization',
])

const AUDIT_DECISIONS = new Set(['block', 'warn', 'escalate', 'modify'])
const ID_KEBAB_RE = /^[a-z][a-z0-9-]*$/
const THREAT_NNN_RE = /^[A-Z][A-Z0-9_]*[A-Z0-9]_\d{3}$/

let policyText
try {
  policyText = readFileSync(POLICY_PATH, 'utf8')
} catch (e) {
  console.error(`✗ failed to read ${relative(root, POLICY_PATH)}: ${e.message}`)
  process.exit(1)
}

let policy
try {
  const yamlMod = await import('js-yaml')
  policy = yamlMod.load(policyText)
} catch (e) {
  console.error(`✗ failed to parse ${relative(root, POLICY_PATH)} as YAML: ${e.message}`)
  process.exit(1)
}

const rules = Array.isArray(policy?.rules) ? policy.rules : []
if (rules.length === 0) {
  console.error(`✗ ${relative(root, POLICY_PATH)} contains no rules`)
  process.exit(1)
}

const apiVersion = policy?.apiVersion
const relPath = relative(root, POLICY_PATH)

/** @type {{ id: string; kind: 'HIGH' | 'MEDIUM' | 'LOW'; message: string }[]} */
const findings = []
/** @type {Map<string, Set<string>>} */
const nnnSeen = new Map()

for (const r of rules) {
  const id = r?.id
  const cat = r?.category
  const dec = r?.action?.decision
  const bc = r?.action?.blockCode

  // §7.1 id naming — applies to every rule.
  if (typeof id !== 'string' || !ID_KEBAB_RE.test(id)) {
    findings.push({
      id: String(id ?? '<missing>'),
      kind: 'HIGH',
      message: `rule.id "${id}" violates spec §7.1 — must be lowercase kebab-case matching ${ID_KEBAB_RE}`,
    })
  }

  // category enum — defensive cross-check (schema also enforces this).
  if (typeof cat !== 'string' || !CATEGORIES.has(cat)) {
    findings.push({
      id: String(id ?? '<missing>'),
      kind: 'HIGH',
      message: `rule.category "${cat}" not in spec §7.2 enum (one of ${[...CATEGORIES].join(', ')})`,
    })
    // Skip further blockCode checks: cannot validate prefix without category.
    continue
  }

  // blockCode checks — only for audit-visible decisions.
  if (!AUDIT_DECISIONS.has(dec)) continue

  if (typeof bc !== 'string' || bc.length === 0) {
    // LOW: WARN/ESCALATE/MODIFY without blockCode is acceptable.
    if (dec === 'block') {
      findings.push({
        id: String(id ?? '<missing>'),
        kind: 'HIGH',
        message: `rule "${id}" decision=block requires action.blockCode (spec §5.2)`,
      })
    }
    continue
  }

  const expectedPrefix = cat.toUpperCase() + '_'
  const segments = bc.split('_')

  // §7.4 first-segment check.
  //
  // Spec text says "第一段严格等于 rule.category.toUpperCase()", but the
  // §7.4 example uses `INTRUSION_DEFENSE_MASS_DELETION_001` whose first
  // segment is `INTRUSION`, not `INTRUSION_DEFENSE`. The form regex
  // `^[A-Z][A-Z0-9]*_[A-Z]...` also forbids underscores in segment-1,
  // forcing a first-word split. We follow the example + form regex:
  // segment-1 must equal the FIRST WORD of the uppercased category
  // (split by `_`). `POLICY`/`RULE`/`BLOCK`/`DETECT` are still flagged
  // because they don't appear as the first word of any §7.2 enum value.
  const firstSegment = segments[0]
  const expectedFirstWord = cat.toUpperCase().split('_')[0]
  if (firstSegment !== expectedFirstWord) {
    findings.push({
      id: String(id ?? '<missing>'),
      kind: 'HIGH',
      message: `action.blockCode "${bc}" first segment "${firstSegment}" does not match rule.category "${cat}" first-word "${expectedFirstWord}" — spec §7.4 forbids generic prefixes (POLICY_/RULE_/BLOCK_/DETECT_)`,
    })
  }

  // §7.4 remainder shape: <threat>_<NNN>.
  const remainder = bc.substring(expectedPrefix.length)
  if (!THREAT_NNN_RE.test(remainder)) {
    findings.push({
      id: String(id ?? '<missing>'),
      kind: 'HIGH',
      message: `action.blockCode "${bc}" — after category prefix "${expectedPrefix}" remainder "${remainder}" does not match <threat>_<NNN> (threat must contain ≥1 letter, NNN must be exactly 3 digits) per spec §7.4`,
    })
  }

  // §6.4 dual-track: `_CRITICAL_` suffix belongs on rule.id, not blockCode.
  if (remainder.includes('_CRITICAL_')) {
    findings.push({
      id: String(id ?? '<missing>'),
      kind: 'HIGH',
      message: `action.blockCode "${bc}" contains "_CRITICAL_" suffix in threat segment — redundant with rule.id "-critical" suffix. Per spec §6.4 dual-track, the suffix belongs on rule.id, not in blockCode (spec §7.4)`,
    })
  }

  // MEDIUM uniqueness — NNN unique per category bucket.
  const nnnMatch = remainder.match(/_(\d{3})$/)
  if (nnnMatch) {
    const nnn = nnnMatch[1]
    const bucketKey = cat
    if (!nnnSeen.has(bucketKey)) nnnSeen.set(bucketKey, new Set())
    const seen = nnnSeen.get(bucketKey)
    if (seen.has(nnn)) {
      findings.push({
        id: String(id ?? '<missing>'),
        kind: 'MEDIUM',
        message: `action.blockCode "${bc}" — NNN "${nnn}" already used within category "${cat}"; audit trail will conflate two rules`,
      })
    } else {
      seen.add(nnn)
    }
  }

  // LOW: WARN should not carry blockCode per §5.2 (advisory).
  if (dec === 'warn' && bc) {
    findings.push({
      id: String(id ?? '<missing>'),
      kind: 'LOW',
      message: `rule "${id}" decision=warn carries action.blockCode "${bc}" — spec §5.2 says blockCode is for block decisions; warn-decision blockCode is allowed but audited separately`,
    })
  }
}

const high = findings.filter((f) => f.kind === 'HIGH')
const medium = findings.filter((f) => f.kind === 'MEDIUM')
const low = findings.filter((f) => f.kind === 'LOW')

const fmt = (f) => `  [${f.kind}] rule "${f.id}": ${f.message}`

console.log(`SPL v2 §7.4 / §7.1 deviation detector (${relPath}, apiVersion=${apiVersion})`)
console.log(`Rules scanned: ${rules.length}`)
console.log(`Findings: HIGH=${high.length} MEDIUM=${medium.length} LOW=${low.length}`)
if (high.length > 0) {
  console.log('\nHIGH (CI gate):')
  for (const f of high) console.log(fmt(f))
}
if (medium.length > 0) {
  console.log('\nMEDIUM:')
  for (const f of medium) console.log(fmt(f))
}
if (low.length > 0) {
  console.log('\nLOW (advisory):')
  for (const f of low) console.log(fmt(f))
}

if (high.length > 0) {
  console.error(`\n✗ ${high.length} HIGH deviation(s) — blockCode/id naming violates spec §7.4/§7.1`)
  process.exit(1)
}
console.log(`\n✓ no HIGH deviations (${medium.length} MEDIUM, ${low.length} LOW)`)
process.exit(0)