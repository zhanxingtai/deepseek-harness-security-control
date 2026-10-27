/**
 * `scripts/inspect-events.mjs` — the operator's triage view over a
 * captured NDJSON audit trail.
 *
 * WHY THIS FILE EXISTS
 *
 * The per-type tally the tool prints answers "what was recorded". The
 * THREAT TRIAGE section answers the question the operator actually
 * has: "is this a real finding or noise?". It groups the high /
 * critical rows by their finding signature and marks how many of them
 * were actual blocks — a burst of unattributed observations is then
 * visible at a glance instead of hiding behind a row count.
 *
 * It also reports the three signals that used to be silent:
 *   - rows with NO top-level `severity` (invisible to a
 *     severity-filtered dashboard),
 *   - `audit_category: 'integrity'` gaps,
 *   - mode divergence (the runtime posture vs the verdict posture) —
 *     expected only for the mode-independent safety nets.
 *
 * The tool is a shipped artefact (it goes out in the tarball), so the
 * triage contract is worth a regression test: a silent regression here
 * would hide exactly the rows the operator is looking for.
 */
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

const repoRoot = resolve(process.cwd())

function baseEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    comm: 'sst-security-control-dsh',
    event_id: 'evt-1',
    event_type: 'agent_tool_call',
    layer: 'application',
    ts: 1700000000000,
    pid: 1,
    host_id: 'host',
    container_id: 'host',
    ...overrides,
  }
}

describe('inspect-events threat triage', () => {
  let tmpDir: string
  let eventPath: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-inspect-'))
    eventPath = join(tmpDir, 'security-events.jsonl')
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function run(lines: Array<Record<string, unknown>>): string {
    writeFileSync(eventPath, lines.map((l) => JSON.stringify(l)).join('\n') + '\n', 'utf8')
    return execFileSync('node', ['scripts/inspect-events.mjs', eventPath], {
      cwd: repoRoot,
      encoding: 'utf8',
    })
  }

  it('reports the severity distribution and the rows that carry no severity', () => {
    const out = run([
      baseEvent({ event_id: 'a', severity: 'high', blocked: true, intervention: { decision: 'deny', mode: 'enforce', block_code: 'SPL_001' } }),
      baseEvent({ event_id: 'b', severity: 'low' }),
      baseEvent({ event_id: 'c' }),
    ])
    expect(out).toContain('severity: high=1  low=1')
    // The row without a top-level severity is invisible to a
    // severity-filtered dashboard — the triage names the count.
    expect(out).toContain('rows without a top-level severity: 1')
  })

  it('groups high rows by finding signature and marks how many were blocks', () => {
    const out = run([
      baseEvent({ event_id: 'a', severity: 'high', blocked: true, intervention: { decision: 'deny', mode: 'enforce', block_code: 'SELF_PROTECTION_001' } }),
      baseEvent({ event_id: 'b', severity: 'high', blocked: false, audit_details: { event_type_alias: 'watcher_observation' } }),
      baseEvent({ event_id: 'c', severity: 'high', blocked: false, audit_details: { event_type_alias: 'watcher_observation' } }),
    ])
    expect(out).toContain('[1] block:SELF_PROTECTION_001  (blocked: 1)')
    expect(out).toContain('[2] audit:watcher_observation  (blocked: 0)')
  })

  it('counts integrity gaps and separates mode divergence from mode-independent denials', () => {
    const out = run([
      baseEvent({ event_id: 'a', event_type: 'security_audit', audit_category: 'integrity', severity: 'high', audit_details: { integrity: 'file_deleted' } }),
      // The runtime posture differs from the verdict posture WITHOUT the
      // marker — that is the divergence the mode contract must prevent.
      baseEvent({ event_id: 'b', severity: 'high', policy_evaluation: { mode: 'audit' }, intervention: { decision: 'deny', mode: 'enforce' } }),
      // The marker makes "denied in audit mode, by design" explicable.
      baseEvent({ event_id: 'c', severity: 'high', policy_evaluation: { mode: 'audit' }, intervention: { decision: 'deny', mode: 'enforce', mode_independent: true } }),
    ])
    expect(out).toContain('integrity gaps (audit_category=integrity): 1')
    expect(out).toContain('mode divergence (runtime posture != verdict posture): 1')
    expect(out).toContain('mode-independent denials (expected in audit mode): 1')
    expect(out).toContain('[1] integrity:file_deleted  (blocked: 0)')
  })

  it('says "none" when there is no high or critical finding', () => {
    const out = run([baseEvent({ event_id: 'a', severity: 'low' })])
    expect(out).toContain('high/critical findings: none')
  })
})
