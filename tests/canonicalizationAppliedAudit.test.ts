/**
 * Tests for the `canonicalization_applied`
 * security_audit event.
 *
 * Background: the SPL rule matcher is obfuscation-aware — fragment-variable
 * folding (`canonicalizeCommand`), env-carrier folding (`--setenv=VAR='lit'`),
 * unicode normalisation (`unicodeNormalizeCached`), and zero-width / RTL
 * stripping (`stripZeroWidthAndRtl`). When a matched rule fires on the
 * CANONICAL form rather than verbatim text, the decision surfaces
 * `canonicalization_applied: true` on the SecurityDecision. The collector
 * pairs each such agent_tool_call with a `security_audit/canonicalization_applied`
 * row so operators can SEE the obfuscation arms-race (which rules needed
 * canonical matching, how often, what the obfuscation looked like).
 *
 * Audit shape:
 *   - `event_type: 'security_audit'`
 *   - `audit_category: 'behavior'`, `audit_action: 'detect'`
 *   - `severity: 'low'` — observability, not a policy decision (platform
 *     severity enum has no 'info')
 *   - `outcome: 'success'`, `reason: 'detect'`
 *   - `tool_call_id` joins back to the paired `agent_tool_call`
 *   - `audit_details.event_type_alias: 'canonicalization_applied'`
 *   - `audit_details.{rule_id, block_code, policy_id, decision}` — winning SPL rule
 *   - `audit_details.tool_arguments_excerpt` — first 256 chars of the obfuscated
 *     `arguments`, NOT the full blob (would leak tokens to NDJSON)
 *
 * Obfuscation strategies used in these tests (all chosen to NOT trip the
 * inline PromptInjection / SensitivePath / EnvPassthrough guards, so the
 * request reaches the SPL pipeline):
 *   - Fragment-variable fold: `J="security-"; K="monitor"; echo "${J}${K}"`
 *   - Env-carrier fold: `--setenv=A='security' --setenv=B='-monitor' bash -c 'echo $A$B'`
 *   - Two-var concat: `A="security"; B="-monitor"; echo "${A}${B}" 2>&1 | head`
 *   - Verbatim (control, no obfuscation): `echo security-monitor`
 *
 * Note: U+200B zero-width separator obfuscation is NOT exercised here —
 * the inline PromptInjection guard U02 (`Zero-width characters used to
 * fragment literal text`) catches it BEFORE the SPL pipeline runs, so the
 * `inline_prompt_injection_detect` audit is the observability surface for
 * that obfuscation class. The canonicalization_applied audit specifically
 * covers the obfuscation classes that survive the inline guard chain.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizeConfig, type Config } from '../src/config.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../src/collectors/ApplicationCollector.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import { validateEvent } from '../src/utils/schema.js'
import type { Agent, ToolExecution } from '../src/types/external.js'

function makeAgent(): Agent {
  return {
    id: 'agent-1',
    session: { header: { id: 'session-canon-1', createdAt: Date.now() }, events: [] },
    options: { provider: 'test', model: 'test-model' },
  } as Agent
}

function mkExec(agent: Agent, name: string, arguments_: Record<string, unknown>, callId: string): ToolExecution {
  return {
    callId,
    rootCallId: callId,
    name,
    arguments: arguments_,
    agent,
    signal: new AbortController().signal,
  }
}

function readEvents(outputPath: string): Array<Record<string, unknown>> {
  return readFileSync(outputPath, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
}

describe('canonicalization_applied audit', () => {
  let tmpDir: string
  let config: Config
  let eventCollector: LocalNdjsonSink
  let app: ApplicationCollector
  let agent: Agent

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-canon-applied-'))
    config = normalizeConfig({
      mode: 'enforce',
      collector: {
        localOutputPath: join(tmpDir, 'security-events.jsonl'),
        flushIntervalMs: 10,
      },
      intervention: {
        // Custom policy: a single rule keyed to the literal `security-monitor`
        // token. Fragment-variable / env-carrier / two-var-concat obfuscation
        // must trigger canonical matching + canonicalization_applied=true.
        policyPath: join(tmpDir, 'policy.yaml'),
        reloadIntervalMs: 0,
      },
    })
    // Write a tiny policy file targeting bash + 'security-monitor'.
    writeFileSync(
      config.intervention.policyPath,
      [
        'apiVersion: security.use/v2',
        'kind: Policy',
        'rules:',
        '  - id: KILL_SECURITY_MONITOR',
        '    category: self_protection',
        '    priority: 1200',
        '    enabled: true',
        '    match:',
        '      actionType: [tool_call]',
        '      toolName: [bash]',
        '      paramsRegex:',
        '        command: ["security-monitor"]',
        '    action:',
        '      decision: block',
        '      blockReason: kill-attempt',
        '      blockCode: SELF_PROTECTION_KILL_BLOCKED_001',
      ].join('\n'),
      'utf8',
    )
    eventCollector = new LocalNdjsonSink(config)
    const interventionEngine = new InterventionEngine(config)
    interventionEngine.initialize()
    app = new ApplicationCollector(config, eventCollector, interventionEngine)
    eventCollector.initialize()
    app.initialize()
    agent = makeAgent()
    app.onAgentSessionStart({ agent, source: 'test-source' })
  })

  afterEach(() => {
    app.shutdown()
    eventCollector.shutdown()
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true })
  })

  it('emits paired canonicalization_applied audit on fragment-variable fold', async () => {
    // Fragment-variable: J="security-"; K="monitor"; echo "$J$K" — verbatim
    // text contains no "security-monitor" substring (the dash terminates the
    // first fragment), so a plain regex match would miss. `canonicalizeCommand`
    // folds `$J$K` → `security-monitor` and the rule fires on the canonical
    // form.
    const exec = mkExec(
      agent,
      'bash',
      { command: 'J="security-"; K="monitor"; echo "${J}${K}" > /tmp/x' },
      'call-fragment',
    )
    const decision = await app.evaluateTool(exec)
    app.onToolPreExecute(exec, decision)
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const audit = events.find(
      (e) =>
        e.event_type === 'security_audit' &&
        e.audit_details &&
        (e.audit_details as Record<string, unknown>).event_type_alias === 'canonicalization_applied',
    )

    expect(audit).toBeDefined()
    expect(audit!.audit_category).toBe('behavior')
    expect(audit!.audit_action).toBe('detect')
    expect(audit!.severity).toBe('low')
    expect(audit!.outcome).toBe('success')
    expect(audit!.reason).toBe('detect')
    expect(audit!.tool_name).toBe('bash')
    // Synthetic tool_call_id from ApplicationCollector, NOT exec.callId
    expect(audit!.tool_call_id).toMatch(/^session-canon-1:session-canon-1:bash:\d+$/)
    expect(audit!.session_id).toBe('session-canon-1')
    const details = audit!.audit_details as Record<string, unknown>
    expect(details.rule_id).toBe('KILL_SECURITY_MONITOR')
    expect(details.block_code).toBe('SELF_PROTECTION_KILL_BLOCKED_001')
    expect(details.tool_arguments_excerpt).toBeDefined()
    // Excerpt is a bounded string (NOT the full arguments blob)
    expect(typeof details.tool_arguments_excerpt).toBe('string')
    expect((details.tool_arguments_excerpt as string).length).toBeLessThanOrEqual(257) // 256 + ellipsis

    // Engine-side signal: decision.canonicalization_applied MUST be true
    // for the audit row to fire (see ApplicationCollector.onToolPreExecute).
    expect(decision?.canonicalization_applied).toBe(true)
  })

  it('emits paired canonicalization_applied audit on env-carrier fold', async () => {
    // Env-carrier: --setenv=A='security' --setenv=B='-monitor' — the literal
    // string `security-monitor` does not appear verbatim anywhere. `foldEnvCarriers`
    // records both `--setenv` literals into the variable map, then
    // `substituteRefs` expands `$A` → `security` and `$B` → `-monitor`. The
    // assembled `echo "security-monitor"` reaches the rule.
    const exec = mkExec(
      agent,
      'bash',
      { command: "systemd-run --setenv=A='security' --setenv=B='-monitor' /bin/bash -c 'echo \"$A$B\"'" },
      'call-env',
    )
    const decision = await app.evaluateTool(exec)
    app.onToolPreExecute(exec, decision)
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const audit = events.find(
      (e) =>
        e.event_type === 'security_audit' &&
        e.audit_details &&
        (e.audit_details as Record<string, unknown>).event_type_alias === 'canonicalization_applied',
    )
    expect(audit).toBeDefined()
    const details = audit!.audit_details as Record<string, unknown>
    expect(details.rule_id).toBe('KILL_SECURITY_MONITOR')
    expect(details.block_code).toBe('SELF_PROTECTION_KILL_BLOCKED_001')
    expect(decision?.canonicalization_applied).toBe(true)
  })

  it('does NOT emit canonicalization_applied audit on verbatim match (no obfuscation)', async () => {
    // Plain `echo security-monitor` — verbatim regex matches; no folding
    // needed. canonicalization_applied MUST be false/undefined → no paired
    // audit row. The matched rule still emits agent_tool_call + decision,
    // just not the audit companion.
    const exec = mkExec(agent, 'bash', { command: 'echo security-monitor' }, 'call-verbatim')
    const decision = await app.evaluateTool(exec)
    app.onToolPreExecute(exec, decision)
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const audits = events.filter(
      (e) =>
        e.event_type === 'security_audit' &&
        e.audit_details &&
        (e.audit_details as Record<string, unknown>).event_type_alias === 'canonicalization_applied',
    )
    expect(audits.length).toBe(0)

    // But the agent_tool_call is still there + still carries the block
    // decision (synthetic tool_call_id, NOT exec.callId; the ApplicationCollector
    // stamps `<sessionId>:<runId>:<toolName>:<stepIndex>` and stepIndex
    // monotonically increments per session).
    const toolCall = events.find((e) => e.event_type === 'agent_tool_call' && e.tool_name === 'bash')
    expect(toolCall).toBeDefined()
    expect((toolCall!.intervention as Record<string, unknown>)?.decision).toBe('deny')
    // Sanity: decision.canonicalization_applied should be undefined here
    expect(decision?.canonicalization_applied).toBeUndefined()
  })

  it('canonicalization_applied audit row passes validateEvent (schema-clean)', async () => {
    // Schema invariant: every persisted event must pass validateEvent. A
    // malformed audit row would be dropped silently — defeats the
    // operator-visibility promise. Two-var concat with dash separator:
    // `A="security"; B="-monitor"; $A$B --help` — verbatim text contains
    // `security` and `-monitor` separately but no contiguous `security-monitor`.
    // Canonical fold: `$A$B` → `security-monitor` → rule fires canonicalized.
    const exec = mkExec(
      agent,
      'bash',
      { command: 'A="security"; B="-monitor"; $A$B --help 2>&1 | head' },
      'call-schema',
    )
    const decision = await app.evaluateTool(exec)
    app.onToolPreExecute(exec, decision)
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const audit = events.find(
      (e) =>
        e.event_type === 'security_audit' &&
        e.audit_details &&
        (e.audit_details as Record<string, unknown>).event_type_alias === 'canonicalization_applied',
    )
    expect(audit).toBeDefined()
    // validateEvent returns ValidationIssue[] — empty array = clean
    const issues = validateEvent(audit as never)
    expect(issues).toEqual([])
    if (issues.length > 0) {
      // Diagnostic surface for schema regression triage
      throw new Error(`canonicalization_applied audit failed schema: ${JSON.stringify(issues)}`)
    }
  })

  it('emits exactly one canonicalization_applied audit per canonicalized tool call', async () => {
    // Invariant: a single tool call that triggers canonical matching emits
    // exactly ONE canonicalization_applied row — duplicates would inflate
    // the audit volume metric and skew per-rule dashboards. Wrap the
    // concatenation in `eval` so the test also covers eval-context folding
    // (eval is just a no-op wrapper around its body for our purposes —
    // `substituteRefs` doesn't care about eval syntax).
    const exec = mkExec(
      agent,
      'bash',
      { command: 'X="security-"; Y="monitor"; eval "${X}${Y}" 2>&1 || true' },
      'call-once',
    )
    const decision = await app.evaluateTool(exec)
    app.onToolPreExecute(exec, decision)
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const audits = events.filter(
      (e) =>
        e.event_type === 'security_audit' &&
        e.audit_details &&
        (e.audit_details as Record<string, unknown>).event_type_alias === 'canonicalization_applied',
    )
    expect(audits.length).toBe(1)
    expect(decision?.canonicalization_applied).toBe(true)
  })
})