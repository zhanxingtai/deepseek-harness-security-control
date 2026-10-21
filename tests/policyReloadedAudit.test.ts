/**
 * Tests for the `onReloaded`
 * callback + `policy_reloaded` security_audit event.
 *
 * Background: earlier the engine emitted a `policy_tamper` audit only
 * when a reload was REJECTED because the file hash diverged from
 * baseline. Operators had no audit signal for the success case — they
 * couldn't tell from NDJSON whether their file edit actually took
 * effect, or whether the watcher was silently broken.
 *
 * `onReloaded` fires on every SUCCESSFUL reload (first load and
 * subsequent) and pairs with `onTamper` to give operators a complete
 * "policy file activity" timeline:
 *   - `policy_reloaded` (audit_action=modify, severity=low)  — committed
 *   - `policy_tamper`   (audit_action=tamper, severity=high) — rejected
 *
 * The callback also emits a `changed: boolean` flag so operators can
 * distinguish "rule set actually changed" from "idempotent heartbeat"
 * (both severity=low — the platform severity enum has no 'info') —
 * useful when a fs.watch
 * fires but the operator's edit landed on the same byte content.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { normalizeConfig, type Config } from '../src/config.js'
import {
  InterventionEngine,
  type PolicyReloadedInfo,
} from '../src/intervention/InterventionEngine.js'

describe('policy_reloaded callback', () => {
  let tmpDir: string
  let config: Config
  const defaultPolicyPath = fileURLToPath(
    new URL('../policies/default-policy.spl.yaml', import.meta.url),
  )

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-policyreload-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('fires once with changed=false on subsequent identical reloads', () => {
    const events: PolicyReloadedInfo[] = []
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPath: defaultPolicyPath, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
    })
    const engine = new InterventionEngine(config, {
      onReloaded: (info) => events.push(info),
    })
    engine.initialize()
    // First load is committed; expect changed=true (no prior baseline)
    expect(events.length).toBe(1)
    expect(events[0].changed).toBe(true)
    expect(events[0].ruleCount).toBeGreaterThan(0)
    expect(events[0].combinedHash).toMatch(/^[a-f0-9]{64}$/)
    expect(events[0].ruleSetHash).toMatch(/^[a-f0-9]{64}$/)
    const firstHash = events[0].ruleSetHash

    // Second reload with no file change → changed=false
    events.length = 0
    engine.triggerReload()
    expect(events.length).toBe(1)
    expect(events[0].changed).toBe(false)
    // ruleSetHash MUST be stable across same-content reloads. Compare
    // against the value captured BEFORE the reload — comparing
    // events[0].ruleSetHash with itself is a tautology that asserts nothing.
    expect(events[0].ruleSetHash).toBe(firstHash)
  })

  it('fires with changed=true when the rule set fingerprint changes', async () => {
    // invariant: operator edits to a file
    // covered by tamper detection (default: user policyPaths) trip
    // `policy_tamper` instead of `policy_reloaded`. The
    // `trustedBaselineHash` constructor option flips the tamper
    // detector to "bundled-only" semantics so operator edits to
    // user files pass tamper and reach `onReloaded` instead.
    //
    // This test ships a user file + a fake bundled file whose
    // sha256(seed) we pre-compute and pass as `trustedBaselineHash`.
    // The bundled file's content stays constant across the test
    // (so the bundled-only tamper check never trips), but we mutate
    // the USER file to add a new rule. User file edits pass tamper
    // (bundled-only mode) and reach `onReloaded` with `changed=true`.
    const bundledPath = join(tmpDir, 'bundled-baseline.yaml')
    const bundledContent = 'apiVersion: security.use/v2\nkind: Policy\nrules: []\n'
    writeFileSync(bundledPath, bundledContent, 'utf8')
    // Mirror the engine's combined-hash format: sha256 over
    // `${path}:${sha256(content)}` joined. The bundled-only tamper
    // check computes `bundledHashForTamper` exactly this way, so we
    // need to seed `trustedBaselineHash` with the same shape.
    const bundledContentHash = createHash('sha256').update(bundledContent).digest('hex')
    const bundledHash = createHash('sha256').update(`${bundledPath}:${bundledContentHash}`).digest('hex')

    const userPolicyPath = join(tmpDir, 'user-policy.yaml')
    writeFileSync(
      userPolicyPath,
      [
        'apiVersion: security.use/v2',
        'kind: Policy',
        'rules:',
        '  - id: user-rule-A',
        '    category: intrusion_defense',
        '    priority: 1000',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["echo A"]',
        '    action:',
        '      decision: warn',
        '      blockReason: rule-A',
        '      blockCode: INTRUSION_DEFENSE_USER_RULE_A_001',
        '  - id: user-rule-B',
        '    category: intrusion_defense',
        '    priority: 1100',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["echo B"]',
        '    action:',
        '      decision: warn',
        '      blockReason: rule-B',
        '      blockCode: INTRUSION_DEFENSE_USER_RULE_B_001',
      ].join('\n'),
      'utf8',
    )

    const events: PolicyReloadedInfo[] = []
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPaths: [userPolicyPath], reloadIntervalMs: 0 },
    })
    const engine = new InterventionEngine(config, {
      onReloaded: (info) => events.push(info),
      // bundled-only tamper: bundledHash stays constant (we don't
      // mutate bundledPath), so user edits to userPolicyPath pass
      // tamper and reach onReloaded.
      builtinRulePaths: [bundledPath],
      trustedBaselineHash: bundledHash,
    })
    engine.initialize()
    // First load: 2 user rules + 0 bundled rules = 2 rules, changed=true
    expect(events.length).toBe(1)
    expect(events[0].ruleCount).toBe(2)
    expect(events[0].changed).toBe(true)
    const firstHash = events[0].ruleSetHash

    // Mutate the user policy (add a third rule)
    writeFileSync(
      userPolicyPath,
      [
        'apiVersion: security.use/v2',
        'kind: Policy',
        'rules:',
        '  - id: user-rule-A',
        '    category: intrusion_defense',
        '    priority: 1000',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["echo A"]',
        '    action:',
        '      decision: warn',
        '      blockReason: rule-A',
        '      blockCode: INTRUSION_DEFENSE_USER_RULE_A_001',
        '  - id: user-rule-B',
        '    category: intrusion_defense',
        '    priority: 1100',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["echo B"]',
        '    action:',
        '      decision: warn',
        '      blockReason: rule-B',
        '      blockCode: INTRUSION_DEFENSE_USER_RULE_B_001',
        '  - id: user-rule-C',
        '    category: intrusion_defense',
        '    priority: 1200',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["echo C"]',
        '    action:',
        '      decision: warn',
        '      blockReason: rule-C',
        '      blockCode: INTRUSION_DEFENSE_USER_RULE_C_001',
      ].join('\n'),
      'utf8',
    )
    // wait a tick so the file mtime advances (some FS need this for
    // fs.watch + the watcher's polling fallback to observe the change)
    await new Promise((resolve) => setTimeout(resolve, 5))
    engine.triggerReload()

    // Expect at least 2 events total: initial load + 1 change-load
    expect(events.length).toBeGreaterThanOrEqual(2)
    const last = events[events.length - 1]
    expect(last.changed).toBe(true)
    expect(last.ruleCount).toBe(3)
    expect(last.ruleSetHash).not.toBe(firstHash)
  })

  it('does NOT fire when the reload is rejected for tamper', () => {
    // invariant: onReloaded and onTamper
    // are mutually exclusive on a single reload cycle. If tamper
    // fires, onReloaded must NOT fire — the rule set was rejected,
    // nothing committed.
    const reloadedEvents: PolicyReloadedInfo[] = []
    const tamperEvents: unknown[] = []
    const userPolicyPath = join(tmpDir, 'tamper-test.yaml')
    writeFileSync(
      userPolicyPath,
      [
        'apiVersion: security.use/v2',
        'kind: Policy',
        'rules:',
        '  - id: rule-A',
        '    category: intrusion_defense',
        '    priority: 1000',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["echo A"]',
        '    action:',
        '      decision: warn',
        '      blockReason: rule-A',
        '      blockCode: INTRUSION_DEFENSE_RULE_A_001',
      ].join('\n'),
      'utf8',
    )
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPaths: [userPolicyPath], reloadIntervalMs: 0 },
    })
    const engine = new InterventionEngine(config, {
      onReloaded: (info) => reloadedEvents.push(info),
      onTamper: (info) => tamperEvents.push(info),
    })
    engine.initialize()
    expect(reloadedEvents.length).toBe(1) // first load committed
    expect(tamperEvents.length).toBe(0)

    // Tamper: edit the file
    writeFileSync(
      userPolicyPath,
      [
        'apiVersion: security.use/v2',
        'kind: Policy',
        'rules:',
        '  - id: rule-A',
        '    category: intrusion_defense',
        '    priority: 1000',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["echo A"]',
        '    action:',
        '      decision: warn',
        '      blockReason: rule-A-modified',
        '      blockCode: INTRUSION_DEFENSE_RULE_A_001',
      ].join('\n'),
      'utf8',
    )
    engine.triggerReload()
    // tamper rejected → onTamper fired, onReloaded did NOT fire
    expect(tamperEvents.length).toBe(1)
    expect(reloadedEvents.length).toBe(1) // unchanged from initial load
  })

  it('callback errors do NOT break the engine (invariant #3)', () => {
    const userPolicyPath = join(tmpDir, 'cb-error.yaml')
    writeFileSync(
      userPolicyPath,
      'apiVersion: security.use/v2\nkind: Policy\nrules: []\n',
      'utf8',
    )
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPaths: [userPolicyPath], reloadIntervalMs: 0 },
    })
    const engine = new InterventionEngine(config, {
      onReloaded: () => {
        throw new Error('intentional callback failure')
      },
    })
    // Should NOT throw — invariant #3 (never throw to host).
    expect(() => engine.initialize()).not.toThrow()
    // Subsequent reloads also tolerate the throwing callback.
    expect(() => engine.triggerReload()).not.toThrow()
  })

  it('does NOT fire when no policy file exists (silent skip)', () => {
    const events: PolicyReloadedInfo[] = []
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: {
        policyPath: '/nonexistent/path/policy.yaml',
        reloadIntervalMs: 0,
      },
    })
    const engine = new InterventionEngine(config, {
      onReloaded: (info) => events.push(info),
    })
    engine.initialize()
    // Existing.length === 0 → early-return branch → onReloaded never fires
    expect(events.length).toBe(0)
  })
})