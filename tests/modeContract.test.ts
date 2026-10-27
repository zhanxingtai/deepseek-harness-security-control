/**
 * The mode contract — one effective mode, honored everywhere.
 *
 * WHY THIS FILE EXISTS
 *
 * `intervention.mode` is the operator-facing switch (the Config UI edits
 * exactly that key; the README documents it as the single knob). The
 * top-level `mode` is a legacy alias for old patch YAMLs.
 *
 * Before 2026-10-27 the two were resolved INDEPENDENTLY and could
 * disagree:
 *
 *   - the enforcement seam (`src/handlers.ts`) read the TOP-LEVEL
 *     `config.mode`;
 *   - the engine — and therefore every audit row — read the NESTED
 *     `config.intervention.mode`.
 *
 * The 2026-10-27 real capture is the proof: the operator's Config-UI
 * switch was `audit`, the audit trail said `policy_evaluation.mode:
 * "audit"` for every row, and the tool layer nevertheless HARD-BLOCKED
 * the `npm uninstall` call (the top-level default was `enforce`). The
 * trail described a posture the runtime was not in.
 *
 * These tests lock the fixed contract:
 *   1. the effective mode is honored by the enforcement seam,
 *   2. the audit trail reports the SAME mode,
 *   3. a blocked event carries the rule's severity on the top level and
 *      a truthful `risk_level` (both were missing / fabricated).
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply } from '../src/index.js'
import type { Agent, Context, ToolExecution } from '../src/types/external.js'

function makeContext(): Context & { getListeners(): Record<string, ((...args: unknown[]) => unknown)[]> } {
  const listeners: Record<string, ((...args: unknown[]) => unknown)[]> = {}
  return {
    logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    on: (event, listener) => {
      listeners[event] = listeners[event] ?? []
      listeners[event].push(listener as (...args: unknown[]) => unknown)
    },
    effect: (dispose) => {
      dispose()
    },
    reflect: { get: () => undefined },
    getListeners: () => listeners,
  } as Context & { getListeners(): typeof listeners }
}

function makeAgent(): Agent {
  return {
    id: 'agent-1',
    session: { header: { id: 'session-1', createdAt: Date.now() }, events: [] },
    options: { provider: 'test', model: 'test-model' },
  }
}

/** A tool call the bundled self-protection rule matches (SPL rule
 *  `self-protection-block-uninstall`, severity `critical`). */
function makeUninstallExec(): ToolExecution {
  return {
    callId: 'call-1',
    rootCallId: 'call-1',
    name: 'pwsh',
    arguments: { command: 'npm uninstall sst-security-control-dsh' },
    agent: makeAgent(),
    signal: new AbortController().signal,
  } as ToolExecution
}

interface RunResult {
  outcome: unknown
  events: Array<Record<string, unknown>>
}

async function runPreExecute(interventionMode: 'audit' | 'enforce'): Promise<RunResult> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-mode-contract-'))
  const ctx = makeContext()
  const outPath = join(tmpDir, 'events.jsonl')
  apply(ctx, {
    enabled: true,
    // The top-level alias keeps the value the schema default gave it
    // ('enforce') — exactly the shape that produced the capture: the
    // operator set the nested switch in the UI, the alias kept the
    // default, and the two disagreed. (The config-integrity gate
    // requires the top-level `mode` key to be present, so it cannot be
    // omitted here.)
    mode: 'enforce',
    collector: { localOutputPath: outPath, flushIntervalMs: 10 },
    application: { enabled: true },
    intervention: { mode: interventionMode },
  } as never)

  const preExec = ctx.getListeners()['tools/pre-execute']![0]!
  const outcome = await preExec(makeUninstallExec(), async () => ({ kind: 'allow' }))
  await new Promise((resolve) => setTimeout(resolve, 80))

  let events: Array<Record<string, unknown>> = []
  try {
    events = readFileSync(outPath, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, unknown>)
  } catch {
    events = []
  }
  rmSync(tmpDir, { recursive: true, force: true })
  return { outcome, events }
}

function toolCallEvent(events: Array<Record<string, unknown>>): Record<string, unknown> | undefined {
  return events.find((e) => e.event_type === 'agent_tool_call')
}

describe('mode contract — one effective mode, honored everywhere', () => {
  // HOME isolation — `apply()` deep-merges the operator's config draft
  // (`~/.dsh/security-monitor-config.draft.json`) over the config it is
  // given. A draft left on a dev machine (e.g. `patch.mode: "audit"`)
  // would silently override the mode under test and make the contract
  // untestable. Point HOME at an empty temp dir so the draft path
  // resolves into a directory that holds no draft.
  let originalHome: string | undefined
  let homeRoot: string

  beforeEach(() => {
    originalHome = process.env.HOME
    homeRoot = mkdtempSync(join(tmpdir(), 'dsh-mode-contract-home-'))
    process.env.HOME = homeRoot
  })

  afterEach(() => {
    if (originalHome === undefined) delete process.env.HOME
    else process.env.HOME = originalHome
    rmSync(homeRoot, { recursive: true, force: true })
  })

  it('audit mode does NOT block the call (the operator switch is effective)', async () => {
    const { outcome } = await runPreExecute('audit')
    // The next() continuation ran → the call was NOT denied.
    expect(outcome).toEqual({ kind: 'allow' })
  })

  it('enforce mode blocks the call', async () => {
    const { outcome } = await runPreExecute('enforce')
    expect((outcome as { kind?: string })?.kind).toBe('deny')
  })

  it('the audit trail reports the SAME mode the runtime enforced', async () => {
    // Audit mode: the trail says audit.
    const audited = await runPreExecute('audit')
    const auditedRow = toolCallEvent(audited.events)
    expect(auditedRow).toBeDefined()
    expect((auditedRow!.policy_evaluation as { mode?: string })?.mode).toBe('audit')
    expect((auditedRow!.intervention as { mode?: string })?.mode).toBe('audit')

    // Enforce mode: the trail says enforce.
    const enforced = await runPreExecute('enforce')
    const enforcedRow = toolCallEvent(enforced.events)
    expect(enforcedRow).toBeDefined()
    expect((enforcedRow!.policy_evaluation as { mode?: string })?.mode).toBe('enforce')
    expect((enforcedRow!.intervention as { mode?: string })?.mode).toBe('enforce')
  })

  it('a blocked event carries the rule severity on the top level and in risk_level', async () => {
    const { events } = await runPreExecute('enforce')
    const row = toolCallEvent(events)
    expect(row).toBeDefined()
    // The rule is `severity: critical`. Before the fix the event had NO
    // top-level severity at all (so a severity-filtered dashboard
    // missed it) and the risk assessment claimed `risk_level: 'medium'`
    // (a hard-coded fallback that also shadowed the sink's own
    // `inferRiskLevel` fallback).
    expect(row!.severity).toBe('critical')
    const risk = (row!.intervention as { risk_assessment?: { risk_level?: string } })?.risk_assessment
    expect(risk?.risk_level).toBe('critical')
    // The platform's per-match risk_level follows the same value.
    const matches = (row!.policy_evaluation as { matches?: Array<{ risk_level?: string }> })?.matches ?? []
    expect(matches[0]?.risk_level).toBe('critical')
  })
})
