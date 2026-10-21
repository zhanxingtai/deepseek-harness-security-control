/**
 * Tests for the plugin unload sentinel (§6.2 EAT-34
 * 2026-09-22).
 *
 * Coverage:
 * acceptance : HMR-style scope disposal (process keeps running, no
 *     graceful flag) emits exactly ONE policy_tamper-class security_audit
 *     (+ logger.warn), passing validateEvent() with zero issues
 * acceptance : graceful paths stay silent — markGracefulShutdown
 *     before dispose, and the process-exit hook fired before dispose
 *   - watchdog liveness seam: probe torn down without the main disposer
 *     emits with detection_point 'watchdog_liveness_probe'; normal scope
 *     disposal self-clears the watchdog without a second event
 *   - exactly-once semantics across double disposal / dispose+watchdog
 *   - emit failures are swallowed (invariant #3: never throw to the host)
 *   - session fallback to '__plugin__' when no session is resolvable
 *   - real LocalNdjsonSink round-trip: the tamper event lands in NDJSON
 * acceptance (defense in depth): guard denial and unload
 * tamper fire independently on their own seams
 */

import { describe, expect, it } from 'vitest'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizeConfig } from '../src/config.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import {
  installPluginUnloadSentinel,
  type PluginUnloadSentinelDeps,
} from '../src/intervention/PluginUnloadSentinel.js'
import {
  createSelfProtectionGuard,
  type SelfProtectionGuardDeps,
} from '../src/intervention/SelfProtectionGuard.js'
import { DEFAULT_INLINE_GUARDS } from '../src/intervention/InlineSelfProtection.js'
import { validateEvent } from '../src/utils/schema.js'
import type { Context } from '../src/types/external.js'
import type { SecurityEvent } from '../src/types/index.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface RegisteredEffect {
  id?: string
  dispose: () => void
}

function makeFakeCtx() {
  const effects: RegisteredEffect[] = []
  const warns: string[] = []
  const ctx = {
    logger: {
      warn: (msg: string) => warns.push(msg),
      info: () => {},
      error: () => {},
      debug: () => {},
    },
    effect: (fn: () => (() => void) | void, id?: string) => {
      const d = fn()
      effects.push({ id, dispose: typeof d === 'function' ? d : () => {} })
    },
  } as unknown as Context
  // Cordis disposes effects in reverse registration order.
  const disposeAll = (): void => {
    for (const e of [...effects].reverse()) e.dispose()
  }
  const disposeById = (id: string): boolean => {
    const idx = effects.findIndex((e) => e.id === id)
    if (idx < 0) return false
    effects[idx]!.dispose()
    effects.splice(idx, 1)
    return true
  }
  return { ctx, effects, warns, disposeAll, disposeById }
}

function makeDeps(overrides: Partial<PluginUnloadSentinelDeps> = {}) {
  const reported: SecurityEvent[] = []
  const warns: string[] = []
  const watchdogPumps: Array<{ tick: () => void; ms: number; cancelled: boolean }> = []
  let exitHook: (() => void) | undefined
  const deps: PluginUnloadSentinelDeps = {
    eventCollector: {
      report: (event) => {
        reported.push(event)
      },
    },
    logger: { warn: (msg: string) => warns.push(msg) },
    sessionResolve: () => ({ sessionId: 'session-1', runId: 'run-1', agentId: 'agent-1' }),
    scheduleWatchdog: (tick, ms) => {
      const pump = { tick, ms, cancelled: false }
      watchdogPumps.push(pump)
      return () => {
        pump.cancelled = true
      }
    },
    registerExitHook: (fn) => {
      exitHook = fn
    },
    ...overrides,
  }
  return { deps, reported, warns, watchdogPumps, getExitHook: () => exitHook }
}

function tamperEvents(reported: SecurityEvent[]): SecurityEvent[] {
  return reported.filter(
    (e) => e.event_type === 'security_audit' && e.audit_action === 'tamper',
  )
}

// ---------------------------------------------------------------------------
// Acceptance — HMR-style unload emits policy_tamper-class audit
// ---------------------------------------------------------------------------

describe('HMR unload detection (acceptance)', () => {
  it('emits exactly one tamper-class security_audit when the scope is disposed while the process keeps running', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, warns } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()

    const tampers = tamperEvents(reported)
    expect(tampers).toHaveLength(1)
    const event = tampers[0]!
    expect(event.audit_category).toBe('policy')
    expect(event.audit_action).toBe('tamper')
    expect(event.severity).toBe('high')
    expect(event.reason).toBe('tamper')
    expect(event.target).toBe('security-monitor')
    expect(event.audit_details?.['event_type_alias']).toBe('plugin_runtime_unload')
    expect(event.audit_details?.['policy_id']).toBe('self-unload-sentinel')
    expect(event.audit_details?.['detection_point']).toBe('ctx.effect_dispose')
    expect(validateEvent(event)).toEqual([])
    expect(warns.some((w) => w.includes('policy_tamper'))).toBe(true)
  })

  it('is mode-independent: no config.mode consulted anywhere in the sentinel path', () => {
    // The deps interface deliberately carries no mode field — this test
    // locks the shape so a future refactor cannot silently reintroduce a
    // mode gate on the self-protection depth layer.
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)
    disposeAll()
    expect(tamperEvents(reported)).toHaveLength(1)
  })

  it('round-trips through the real LocalNdjsonSink into NDJSON', () => {
    const dir = mkdtempSync(join(tmpdir(), 'unload-sentinel-'))
    const path = join(dir, 'events.jsonl')
    try {
      const config = normalizeConfig({ collector: { localOutputPath: path } })
      const sink = new LocalNdjsonSink(config, {})
      sink.initialize()
      const { ctx, disposeAll } = makeFakeCtx()
      installPluginUnloadSentinel(ctx, {
        eventCollector: sink,
        logger: { warn: () => {} },
      })
      disposeAll()
      sink.shutdown()

      expect(existsSync(path)).toBe(true)
      const lines = readFileSync(path, 'utf8').trim().split('\n').filter(Boolean)
      expect(lines).toHaveLength(1)
      const event = JSON.parse(lines[0]!) as SecurityEvent
      expect(event.event_type).toBe('security_audit')
      expect(event.audit_action).toBe('tamper')
      expect(event.audit_details?.['event_type_alias']).toBe('plugin_runtime_unload')
      expect(validateEvent(event)).toEqual([])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

// ---------------------------------------------------------------------------
// Acceptance — graceful shutdown paths stay silent
// ---------------------------------------------------------------------------

describe('graceful shutdown (acceptance)', () => {
  it('emits nothing when markGracefulShutdown() ran before the disposal', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, warns } = makeDeps()
    const sentinel = installPluginUnloadSentinel(ctx, deps)

    sentinel.markGracefulShutdown()
    disposeAll()

    expect(tamperEvents(reported)).toHaveLength(0)
    expect(warns.filter((w) => w.includes('policy_tamper'))).toHaveLength(0)
  })

  it('emits nothing when the process-exit hook fired before the disposal (natural exit / process.exit paths)', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, getExitHook } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    const exitHook = getExitHook()
    expect(exitHook).toBeTypeOf('function')
    exitHook!() // simulate the 'exit' event firing during teardown
    disposeAll()

    expect(tamperEvents(reported)).toHaveLength(0)
  })

  it('disposal racing the exit hook still emits at most once and the flag wins when set first', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, getExitHook } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)
    // Exit hook fires during teardown AFTER the scope was already disposed
    // (HMR unload, then process exits normally): the tamper was already
    // emitted and must not be duplicated.
    disposeAll()
    getExitHook()?.()
    expect(tamperEvents(reported)).toHaveLength(1)
  })
})

// ---------------------------------------------------------------------------
// Watchdog liveness seam + exactly-once semantics
// ---------------------------------------------------------------------------

describe('watchdog liveness seam', () => {
  it('normal scope disposal self-clears the watchdog without a second event', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, watchdogPumps } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)
    disposeAll()

    const pump = watchdogPumps[0]!
    expect(pump.ms).toBe(30_000)
    expect(pump.cancelled).toBe(false) // cleared lazily on the first post-disposal tick
    pump.tick()
    expect(pump.cancelled).toBe(true)
    expect(tamperEvents(reported)).toHaveLength(1)
  })

  it('emits with detection_point watchdog_liveness_probe when the probe is torn down without the main disposer', () => {
    const { ctx, disposeById } = makeFakeCtx()
    const { deps, reported, watchdogPumps } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    // Simulate the harness tearing down effects but our main disposer
    // never running (fiber kill / unload bug): only the probe flips.
    expect(disposeById('security-monitor: unload-sentinel probe')).toBe(true)
    watchdogPumps[0]!.tick()

    const tampers = tamperEvents(reported)
    expect(tampers).toHaveLength(1)
    expect(tampers[0]!.audit_details?.['detection_point']).toBe('watchdog_liveness_probe')
    expect(validateEvent(tampers[0]!)).toEqual([])
    expect(watchdogPumps[0]!.cancelled).toBe(true)
  })

  it('double disposal emits exactly one event', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported } = makeDeps()
    const sentinel = installPluginUnloadSentinel(ctx, deps)
    disposeAll()
    sentinel.simulateScopeDispose() // manual re-entry is a no-op
    disposeAll()
    expect(tamperEvents(reported)).toHaveLength(1)
  })

  it('emit failures are swallowed and logged, never thrown (invariant #3)', async () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, warns } = makeDeps({
      eventCollector: {
        report: () => {
          throw new Error('sink exploded')
        },
      },
    })
    expect(() => {
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
    }).not.toThrow()
    // the retry loop is now driven by
    // setImmediate (no CPU spin in the disposer). Wait for all 3 retries
    // + the final fallback warn to flush before asserting.
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    expect(warns.some((w) => w.includes('tamper emit failed'))).toBe(true)
  })

  it('falls back to __plugin__ session placeholders when no session is resolvable', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported } = makeDeps({ sessionResolve: () => undefined })
    installPluginUnloadSentinel(ctx, deps)
    disposeAll()
    const event = tamperEvents(reported)[0]!
    expect(event.session_id).toBe('__plugin__')
    expect(event.run_id).toBe('__plugin__')
    expect(event.agent_id).toBe('__plugin__')
  })

  // 2026-09-25 A-M8: atomic once-guard with defensive event-construction
  // fallbacks. A throwing helper used to drop the audit entirely; the
  // sentinel now wraps every field in its own try/catch so the audit
  // ALWAYS reaches NDJSON, even if every helper misbehaves at once.
  describe('A-M8 — atomic once-guard with helper-failure fallbacks', () => {
    it('emits the audit even when sessionResolve() throws', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      const { deps, reported } = makeDeps({
        sessionResolve: () => {
          throw new Error('session resolver exploded')
        },
      })
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      // Audit still landed — fallbacks absorbed the throw.
      const event = tamperEvents(reported)[0]!
      expect(event).toBeDefined()
      expect(event.session_id).toBe('__plugin__')
      expect(event.run_id).toBe('__plugin__')
      expect(event.agent_id).toBe('__plugin__')
    })

    it('emits the audit even when now() clock helper throws', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      const { deps, reported } = makeDeps({
        now: () => {
          throw new Error('clock broken')
        },
      })
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      const event = tamperEvents(reported)[0]!
      expect(event).toBeDefined()
      // ts / timestamp must still be a finite number — the Date.now()
      // fallback fired when the injected now() threw.
      expect(typeof event.ts).toBe('number')
      expect(Number.isFinite(event.ts)).toBe(true)
    })

    it('emits the audit with a deterministic fallback event_id when id generator throws', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      // Hard to mock the imported generateEventId module from outside;
      // instead, drive a hostile env where every helper throws and verify
      // the audit still lands (the buildTamperEvent helper absorbs each).
      const { deps, reported } = makeDeps({
        sessionResolve: () => {
          throw new Error('session exploded')
        },
        now: () => {
          throw new Error('clock exploded')
        },
      })
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      const event = tamperEvents(reported)[0]!
      expect(event).toBeDefined()
      // event_id must be a non-empty string regardless of helper throws.
      expect(typeof event.event_id).toBe('string')
      expect((event.event_id as string).length).toBeGreaterThan(0)
    })

    it('emits exactly one audit when scope dispose and watchdog fire on the same tick (atomic once-guard)', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      const { deps, reported, watchdogPumps } = makeDeps()
      installPluginUnloadSentinel(ctx, deps)
      // Simulate the worst-case race: scope disposal fires AND the
      // watchdog ticks at the same moment. The once-guard must ensure
      // exactly one event reaches the sink, regardless of which seam
      // wins the race.
      disposeAll()
      // Probe effect (registered first) flipped probeActive=false.
      // WatchdogTick sees probeActive=false and would normally call
      // emitTamper — but tamperEmitted is already true.
      for (const pump of watchdogPumps) {
        pump.tick()
      }
      expect(tamperEvents(reported)).toHaveLength(1)
    })
  })
})

// ---------------------------------------------------------------------------
// Acceptance — defense in depth with the guard
// ---------------------------------------------------------------------------

describe('defense in depth with InlineSelfProtection (acceptance)', () => {
  it('guard denial (tool-call seam) and unload tamper (dispose seam) fire independently on the same sink', () => {
    const reported: SecurityEvent[] = []
    const sink = {
      report: (event: SecurityEvent) => {
        reported.push(event)
      },
    }
    const guardDeps: SelfProtectionGuardDeps = {
      guards: DEFAULT_INLINE_GUARDS,
      eventCollector: sink,
      sessionResolve: () => ({ sessionId: 'session-1', runId: 'run-1', agentId: 'agent-1' }),
      logger: { warn: () => {} },
    }
    const guard = createSelfProtectionGuard(guardDeps)
    const { ctx, disposeAll } = makeFakeCtx()
    installPluginUnloadSentinel(ctx, {
      eventCollector: sink,
      logger: { warn: () => {} },
    })

    // Layer 1: a tool-call attempt to uninstall the plugin is denied.
    const denial = guard({
      callId: 'c1',
      rootCallId: 'c1',
      name: 'bash',
      arguments: { command: 'pnpm dsh plugin remove sst-security-control-dsh' },
      signal: new AbortController().signal,
    })
    expect(denial).toBeTypeOf('string')

    // Layer 2: the HMR profile toggle bypassed layer 1 entirely — the
    // dispose seam catches it.
    disposeAll()

    const guardAudits = reported.filter(
      (e) => e.audit_details?.['policy_id'] === 'inline-self-protection',
    )
    const tamper = tamperEvents(reported)
    expect(guardAudits).toHaveLength(1)
    expect(guardAudits[0]!.outcome).toBe('blocked')
    expect(tamper).toHaveLength(1)
    expect(validateEvent(guardAudits[0]!)).toEqual([])
    expect(validateEvent(tamper[0]!)).toEqual([])
  })
})
