/**
 * BUG-5 — surface degradation visibility.
 *
 * The ticket: all five operator surfaces (UI / CLI / Remote / HTTP /
 * Subprocess) degraded via `ctx.logger.warn + no-op`, leaving the
 * "surface silently missing" symptom with no persistent trace in
 * headless mode (the harness logger doesn't pipe plugin warns to
 * stdout). The fix lands on two planes:
 *
 *  1. debugLog plane — every degraded surface writes a
 *     `surface_unavailable` NDJSON line to
 *     `collector.debugLogPath` (`security-monitor-debug.log`), keeping
 *     the existing `ctx.logger.warn` alongside it. Covered here for
 *     the CLI (`ctx.commands` missing) and Remote (`ctx.remote.$mount`
 *     missing) surfaces; the Subprocess seam failure already writes
 *     `runtime_hook_install_failed` and the network-capture failure
 *     writes `network_capture_install_failed` + `surface_unavailable`.
 * 2. NDJSON plane — the startup diagnostic (an `agent_start` row
 *     distinguished by `collector.hook_name === 'plugin_startup'`)
 *     carries a `metadata.surfaces` block (`ui` / `cli` / `remote` /
 *     `network` / `subprocess`) so the FIRST startup event in
 *     `security-events.jsonl` shows the whole availability map.
 *
 * Marketplace scope notes (2026-09-22):
 * The pre-marketplace"HTTP surface"(platform HTTP upload / NodeActivity)
 *    was deleted with the marketplace refactor — its living in-process
 *    analog is the network capture seam, reported as `network`.
 *  - The UI surface (`src/client/index.ts`) is a browser bundle running
 *    in the host webview; it cannot write the plugin's debug log, so
 *    `surfaces.ui.available` is `null` (unobservable from the plugin
 *    process) rather than a potentially lying boolean.
 *
 * The ctx stub below deliberately omits `commands` / `remote` /
 * `subprocess` / `inject` — this mirrors a headless marketplace node
 * without the optional peer packages, which is exactly the BUG-5
 * symptom scenario.
 */
import { describe, expect, it, afterEach, beforeEach } from 'vitest'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply } from '../src/index.js'
import type { Context } from '../src/types/external.js'

function makeHeadlessContext(): Context {
  return {
    logger: {
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    },
    on: () => {},
    effect: () => {},
    inject: () => {},
    // the surface probes use the safe
    // `ctx.reflect.get(name)` accessor (returns undefined when the
    // service is not registered, never throws). The fixture mirrors
    // a headless marketplace node with NO optional peers (the
    // BUG-5 symptom scenario) — `get` returns undefined for every
    // service so both `cli` and `remote` surfaces degrade to `false`.
    reflect: {
      get: () => undefined,
      _getImpl: () => undefined,
      store: {},
      props: {},
    },
    // Deliberately NO commands/remote/subprocess — headless marketplace
    // node without the optional peers.
  } as unknown as Context
}

interface DebugLine {
  ts: number
  phase: string
  surface?: string
  reason?: string
  peer?: string
}

interface StartupEvent {
  event_type: string
  session_id?: string | null
  run_id?: string | null
  agent_id?: string | null
  collector?: { hook_name?: string }
  metadata?: {
    surfaces?: Record<string, { available?: boolean | null; note?: string }>
  }
}

let tmpDir: string
let eventsPath: string
let debugLogPath: string

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'dsh-bug5-surface-'))
  eventsPath = join(tmpDir, 'security-events.jsonl')
  debugLogPath = join(tmpDir, 'security-monitor-debug.log')
})

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

async function bootHeadless(): Promise<void> {
  const ctx = makeHeadlessContext()
  apply(ctx, {
    enabled: true,
    mode: 'audit',
    collector: {
      localOutputPath: eventsPath,
      flushIntervalMs: 10,
      debugLogPath,
    },
    application: { enabled: true },
    intervention: { mode: 'audit', policyPath: '/nonexistent.json' },
  })
  // Let the deferred setTimeout(0) subprocess lookup + async flush run.
  await new Promise((resolve) => setTimeout(resolve, 100))
}

function readDebugLines(): DebugLine[] {
  return readFileSync(debugLogPath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as DebugLine)
}

function readEvents(): StartupEvent[] {
  return readFileSync(eventsPath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as StartupEvent)
}

describe('BUG-5 surface degradation visibility', () => {
  it('writes surface_unavailable breadcrumbs for the CLI and Remote surfaces on a headless boot', async () => {
    await bootHeadless()
    const lines = readDebugLines()
    const unavailable = lines.filter((entry) => entry.phase === 'surface_unavailable')
    const surfaces = unavailable.map((entry) => entry.surface).sort()
    expect(surfaces).toEqual(['cli', 'remote'])
    const cli = unavailable.find((entry) => entry.surface === 'cli')
    expect(cli?.reason).toMatch(/ctx\.commands is unavailable/)
    const remote = unavailable.find((entry) => entry.surface === 'remote')
    // 2026-09-23 typert-bridge fix: a host WITH inject defers the
    // registration instead of declaring terminal unavailability — the
    // breadcrumb reason reflects the deferred state. The uniform
    // `surface_unavailable` phase name is kept so operators can grep
    // one phase for every degraded/pending surface.
    expect(remote?.reason).toMatch(/deferred: waiting for the typert registry/)
  })

  it('the first startup event in NDJSON carries the 5-field surfaces block', async () => {
    await bootHeadless()
    const events = readEvents()
    const startup = events.find(
      (event) =>
        event.event_type === 'agent_start' &&
        (event.collector as { hook_name?: string } | undefined)?.hook_name === 'plugin_startup',
    )
    expect(startup).toBeDefined()
    const surfaces = startup?.metadata?.surfaces
    expect(surfaces).toBeDefined()
    // CLI + Remote peers are absent on this headless node → false.
    expect(surfaces?.['cli']?.available).toBe(false)
    expect(surfaces?.['remote']?.available).toBe(false)
    // No subprocess runtime on the stub → the seam did not wrap.
    expect(surfaces?.['subprocess']?.available).toBe(false)
    // The in-process http.request/fetch capture installed fine → true.
    expect(surfaces?.['network']?.available).toBe(true)
    // UI is a browser bundle; the plugin process cannot observe it.
    expect(surfaces?.['ui']?.available).toBeNull()
  })

  // T4 (2026-10-27): the producer writes null identity — the platform
  // rule is "never invent a correlation id"; an undeterminable identity
  // is explicit JSON null, never a fabricated sentinel. The startup row
  // additionally rides the standard agent_start type (plugin_startup is
  // kept only as collector.hook_name).
  it('the startup event carries explicit null identity and rides agent_start', async () => {
    await bootHeadless()
    const events = readEvents()
    const startup = events.find(
      (event) =>
        event.event_type === 'agent_start' &&
        (event.collector as { hook_name?: string } | undefined)?.hook_name === 'plugin_startup',
    )
    expect(startup).toBeDefined()
    expect(startup?.session_id).toBe(null)
    expect(startup?.run_id).toBe(null)
    expect(startup?.agent_id).toBe(null)
  })
})
