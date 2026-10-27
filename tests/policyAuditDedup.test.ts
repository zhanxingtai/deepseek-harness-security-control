/**
 * Policy-path security_audit dedup — integration.
 *
 * Drives the real bootstrap path (apply() with a headless ctx) and
 * verifies that the `policy/modify` emitter behind `onReloaded` swallows
 * same-content reload heartbeats inside `collector.auditDedupWindowMs`
 * while ALWAYS emitting when the rule-set content actually changes.
 *
 * Real-data motivation: 268/326 security_audit rows were identical
 * policy/modify heartbeats (fs.watch bursts + the 30 s reload poll), 12
 * rows inside one 10 s window.
 */
import { describe, expect, it, afterEach, beforeEach } from 'vitest'
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { apply } from '../src/index.js'
import type { Context } from '../src/types/external.js'

function makeHeadlessContext(): Context {
  return {
    logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
    on: () => {},
    effect: () => {},
    inject: () => {},
    reflect: { get: () => undefined, _getImpl: () => undefined, store: {}, props: {} },
  } as unknown as Context
}

let tmpDir: string
let eventsPath: string
let policyPath: string

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'dsh-policy-dedup-'))
  eventsPath = join(tmpDir, 'security-events.jsonl')
  policyPath = join(tmpDir, 'policy.spl.yaml')
  copyFileSync(
    fileURLToPath(new URL('../policies/default-policy.spl.yaml', import.meta.url)),
    policyPath,
  )
})

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

function readEvents(): Array<Record<string, unknown>> {
  try {
    return readFileSync(eventsPath, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>)
  } catch {
    return []
  }
}

const modifyRows = () =>
  readEvents().filter(
    (e) => e['event_type'] === 'security_audit' && e['audit_action'] === 'modify',
  )

async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!cond()) {
    if (Date.now() > deadline) throw new Error('waitFor timed out')
    await new Promise((r) => setTimeout(r, 50))
  }
}

describe('policy/modify audit dedup (bootstrap onReloaded)', () => {
  it('swallows same-content reload heartbeats inside the window; real changes still emit', async () => {
    const ctx = makeHeadlessContext()
    apply(ctx, {
      enabled: true,
      mode: 'audit',
      collector: { localOutputPath: eventsPath, flushIntervalMs: 10 },
      application: { enabled: true },
      intervention: { mode: 'audit', policyPath, reloadIntervalMs: 0 },
    })
    // Let the deferred subprocess lookup + the initial policy load settle.
    await new Promise((r) => setTimeout(r, 300))

    const initial = modifyRows()
    expect(initial.length).toBeGreaterThanOrEqual(1) // the initial load commits one row

    // Rewrite the SAME bytes — fs.watch fires, the engine reloads, the
    // combinedHash is unchanged → heartbeat. Pre-dedup this wrote a new
    // policy/modify row; the deduper must swallow it.
    const original = readFileSync(policyPath, 'utf8')
    for (let i = 0; i < 3; i++) {
      writeFileSync(policyPath, original)
      await new Promise((r) => setTimeout(r, 150))
    }
    await new Promise((r) => setTimeout(r, 400))
    expect(modifyRows().length).toBe(initial.length)

    // A REAL content change (append a comment — valid YAML) must emit a
    // new row immediately, hash difference wins over the window.
    writeFileSync(policyPath, `${original}\n# operator edit ${Date.now()}\n`)
    await waitFor(() => modifyRows().length >= initial.length + 1)
  }, 15_000)
})
