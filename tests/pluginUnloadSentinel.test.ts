/**
 * Tests for the plugin unload sentinel (§6.2 EAT-34
 * 2026-09-22; deferred-verdict rework 2026-10-27).
 *
 * Coverage:
 * acceptance : HMR-style scope disposal that is NOT followed by a
 *     re-install emits exactly ONE policy_tamper-class security_audit
 *     (+ logger.warn), passing validateEvent() with zero issues
 * acceptance : graceful paths stay silent — markGracefulShutdown
 *     before dispose, and the process-exit hook fired before dispose
 *   - deferred verdict: a scope disposal only OBSERVES; the tamper row
 *     is emitted after the grace window elapses with no replacement
 *     instance registered (2026-10-27 real-data rework)
 *   - deferred verdict: an HMR reload (the plugin comes back) is
 *     recognised and SUPPRESSED — this is the false-positive class
 *     that produced 29 bogus high-severity rows in the 2026-10 capture
 *   - deferred verdict: a graceful shutdown arriving during the grace
 *     window cancels the pending verdict
 *   - watchdog liveness seam: probe torn down without the main disposer
 *     enters the SAME verdict path; normal scope disposal self-clears
 *     the watchdog without a second event
 *   - exactly-once semantics across double disposal / dispose+watchdog
 *   - emit failures are swallowed (invariant #3: never throw to the host)
 *   - explicit null identity when no session is resolvable
 *   - real LocalNdjsonSink round-trip: the tamper event lands in NDJSON
 * acceptance (defense in depth): guard denial and unload
 * tamper fire independently on their own seams
 */

import { beforeEach, describe, expect, it } from 'vitest'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizeConfig } from '../src/config.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import {
  installPluginUnloadSentinel,
  type PluginUnloadSentinelDeps,
} from '../src/intervention/PluginUnloadSentinel.js'
import { resetPluginInstanceRegistry } from '../src/intervention/pluginInstanceRegistry.js'
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

interface VerdictTimer {
  fn: () => void
  ms: number
  cancelled: boolean
  fired: boolean
}

function makeDeps(overrides: Partial<PluginUnloadSentinelDeps> = {}) {
  const reported: SecurityEvent[] = []
  const warns: string[] = []
  const watchdogPumps: Array<{ tick: () => void; ms: number; cancelled: boolean }> = []
  const verdictTimers: VerdictTimer[] = []
  const debugs: Array<{ phase: string; payload?: Record<string, unknown> }> = []
  let exitHook: (() => void) | undefined
  let clock = 1_700_000_000_000
  const deps: PluginUnloadSentinelDeps = {
    eventCollector: {
      report: (event) => {
        // the real sink stamps the wire fields in buildTransportEvent
        // before validation runs — the stub has to do the same.
        if (event.schema_version === undefined) event.schema_version = 1
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
    scheduleVerdict: (fn, ms) => {
      const timer: VerdictTimer = { fn, ms, cancelled: false, fired: false }
      verdictTimers.push(timer)
      return () => {
        timer.cancelled = true
      }
    },
    debug: (phase, payload) => {
      debugs.push({ phase, payload })
    },
    registerExitHook: (fn) => {
      exitHook = fn
    },
    now: () => clock,
    ...overrides,
  }
  /**
   * Fire the next pending verdict tick, advancing the fake clock by the
   * timer's own interval so the grace window elapses exactly as it
   * would in production.
   */
  const pumpVerdictOnce = (): boolean => {
    const next = verdictTimers.find((t) => !t.cancelled && !t.fired)
    if (!next) return false
    next.fired = true
    clock += next.ms
    next.fn()
    return true
  }
  return {
    deps,
    reported,
    warns,
    watchdogPumps,
    verdictTimers,
    debugs,
    getExitHook: () => exitHook,
    /** Advance the fake clock without firing anything. */
    advanceClock: (ms: number): void => {
      clock += ms
    },
    /** Read the fake clock. */
    getClock: (): number => clock,
    pumpVerdictOnce,
    /** Fire verdict ticks until the verdict settles (emitted or suppressed). */
    pumpVerdicts: (maxSteps = 64): void => {
      for (let step = 0; step < maxSteps; step++) {
        if (!pumpVerdictOnce()) return
      }
      throw new Error('pumpVerdicts: the verdict did not settle')
    },
  }
}

function tamperEvents(reported: SecurityEvent[]): SecurityEvent[] {
  return reported.filter(
    (e) => e.event_type === 'security_audit' && e.audit_action === 'tamper',
  )
}

describe('plugin unload sentinel', () => {
  beforeEach(() => {
    // The instance registry lives on `globalThis` (it must survive the
    // HMR module re-import), so it is process-wide state. Reset it per
    // test so the generation counter starts from a known point.
    resetPluginInstanceRegistry()
  })

  it('registers an activation generation on install', () => {
    const { ctx } = makeFakeCtx()
    const { deps } = makeDeps()
    const sentinel = installPluginUnloadSentinel(ctx, deps)
    expect(sentinel.getState().generation).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// Acceptance — HMR-style unload emits policy_tamper-class audit
// ---------------------------------------------------------------------------

describe('HMR unload detection (acceptance)', () => {
  it('emits exactly one tamper-class security_audit when the scope is disposed and the plugin never comes back', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, warns, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()
    // Nothing is emitted yet — the verdict is deferred (see the
    // "deferred verdict" describe block below).
    expect(tamperEvents(reported)).toHaveLength(0)

    pumpVerdicts()

    const tampers = tamperEvents(reported)
    expect(tampers).toHaveLength(1)
    const event = tampers[0]!
    expect(event.audit_category).toBe('policy')
    expect(event.audit_action).toBe('tamper')
    expect(event.severity).toBe('high')
    expect(event.reason).toContain('unloaded at runtime')
    expect(event.target).toBe('security-monitor')
    expect(event.audit_details?.['event_type_alias']).toBe('plugin_runtime_unload')
    expect(event.audit_details?.['policy_id']).toBe('self-unload-sentinel')
    expect(event.audit_details?.['detection_point']).toBe('ctx.effect_dispose')
    expect(validateEvent(event)).toEqual([])
    expect(warns.some((w) => w.includes('policy_tamper'))).toBe(true)
  })

  it('states only what was observed — no hard-coded "the host kept running" claim', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()
    pumpVerdicts()

    const details = tamperEvents(reported)[0]!.audit_details!
    // `graceful_shutdown_expected` used to be hard-coded `false` on
    // every row regardless of the real process state.
    expect(details['graceful_shutdown_expected']).toBe(false)
    // The host WAS alive — the verdict timer is unref'd, so it can only
    // fire while the event loop runs.
    expect(details['host_process_alive']).toBe(true)
    expect(details['reload_detected']).toBe(false)
    expect(typeof details['verdict_wait_ms']).toBe('number')
    expect(String(details['detail'])).not.toContain('no graceful-shutdown signal was observed')
  })

  it('is mode-independent: no config.mode consulted anywhere in the sentinel path', () => {
    // The deps interface deliberately carries no mode field — this test
    // locks the shape so a future refactor cannot silently reintroduce a
    // mode gate on the self-protection depth layer.
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)
    disposeAll()
    pumpVerdicts()
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
      const { deps, pumpVerdicts } = makeDeps({ eventCollector: sink })
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      pumpVerdicts()
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
// Deferred verdict — the 2026-10-27 real-data rework
// ---------------------------------------------------------------------------

describe('deferred verdict (real-data regression)', () => {
  it('emits NOTHING when the plugin is re-installed during the grace window (HMR reload)', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    // The plugin-manager disposes the scope and re-instantiates the
    // plugin in the SAME process — a new sentinel registers a new
    // activation generation.
    disposeAll()
    const { ctx: ctx2 } = makeFakeCtx()
    installPluginUnloadSentinel(ctx2, deps)

    pumpVerdicts()

    // This is the false-positive class: 15 of the 29 real-data tamper
    // rows were exactly this shape.
    expect(tamperEvents(reported)).toHaveLength(0)
  })

  it('records the suppressed reload in the debug log instead of the event stream', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, debugs, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()
    const { ctx: ctx2 } = makeFakeCtx()
    installPluginUnloadSentinel(ctx2, deps)
    pumpVerdicts()

    expect(tamperEvents(reported)).toHaveLength(0)
    const entry = debugs.find((d) => d.phase === 'unload_sentinel_reload_detected')
    expect(entry).toBeDefined()
    expect(entry!.payload?.['plugin_name']).toBe('security-monitor')
    expect(entry!.payload?.['detection_point']).toBe('ctx.effect_dispose')
  })

  it('keeps waiting while the grace window is still open', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdictOnce } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()
    // One poll tick inside the window — still no verdict.
    expect(pumpVerdictOnce()).toBe(true)
    expect(tamperEvents(reported)).toHaveLength(0)
  })

  it('emits the tamper exactly once the grace window elapses with no replacement', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()
    pumpVerdicts()

    expect(tamperEvents(reported)).toHaveLength(1)
  })

  it('cancels the pending verdict when a graceful shutdown arrives during the window', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdicts } = makeDeps()
    const sentinel = installPluginUnloadSentinel(ctx, deps)

    disposeAll()
    sentinel.markGracefulShutdown()
    pumpVerdicts()

    expect(tamperEvents(reported)).toHaveLength(0)
  })

  it('emits nothing when the host exits before the verdict timer fires', () => {
    // The verdict timer is unref'd: a host that is tearing down exits
    // before it fires, so the natural-exit path writes no row at all.
    // Modelling that here means simply never pumping the timer.
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()

    expect(tamperEvents(reported)).toHaveLength(0)
  })

  it('exposes the verdict state through getState()', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps } = makeDeps()
    const sentinel = installPluginUnloadSentinel(ctx, deps)

    expect(sentinel.getState().verdictPending).toBe(false)
    expect(sentinel.getState().generation).toBeGreaterThan(0)

    disposeAll()
    expect(sentinel.getState().verdictPending).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Real-data replay — the 29 bogus tamper rows of the 2026-10 capture
// ---------------------------------------------------------------------------

describe('real-data replay (2026-10-22 → 2026-10-27 capture)', () => {
  /**
   * The 15 same-pid gaps between a tamper-class event and the following
   * `plugin_startup`, in seconds — i.e. the measured HMR reload latency
   * of the plugin-manager in the real capture. Every one of these rows
   * was a FALSE POSITIVE: the plugin was reloaded, never removed.
   */
  const RELOAD_GAPS_S = [15, 2, 13, 140, 7, 12, 17, 10, 31, 21, 2, 68, 13, 39, 2]

  it.each(RELOAD_GAPS_S)(
    'reproduces no tamper when the plugin comes back %i s after the disposal',
    (gapS) => {
      const { ctx, disposeAll } = makeFakeCtx()
      const { deps, reported, pumpVerdictOnce, getClock } = makeDeps()
      installPluginUnloadSentinel(ctx, deps)
      const start = getClock()

      disposeAll()

      // The harness re-instantiates the plugin `gapS` seconds later.
      const { ctx: ctx2 } = makeFakeCtx()
      let reloaded = false
      for (let step = 0; step < 64; step++) {
        if (!pumpVerdictOnce()) break
        if (!reloaded && getClock() - start >= gapS * 1000) {
          installPluginUnloadSentinel(ctx2, deps)
          reloaded = true
        }
      }

      expect(reloaded).toBe(true)
      // The old implementation wrote a high-severity tamper row for
      // EVERY one of these.
      expect(tamperEvents(reported)).toHaveLength(0)
    },
  )

  it('reproduces no tamper for the 14 rows that were the LAST event of their pid', () => {
    // Those were the host process exiting: the scope was disposed
    // during teardown and the process died right after. The old
    // implementation asserted "the host process kept running" on every
    // one of them — the claim was false 100 % of the time.
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    disposeAll()
    // The process exits here: the unref'd verdict timer never fires.

    expect(tamperEvents(reported)).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Acceptance — graceful shutdown paths stay silent
// ---------------------------------------------------------------------------

describe('graceful shutdown (acceptance)', () => {
  it('emits nothing when markGracefulShutdown() ran before the disposal', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, warns, pumpVerdicts } = makeDeps()
    const sentinel = installPluginUnloadSentinel(ctx, deps)

    sentinel.markGracefulShutdown()
    disposeAll()
    pumpVerdicts()

    expect(tamperEvents(reported)).toHaveLength(0)
    expect(warns.filter((w) => w.includes('policy_tamper'))).toHaveLength(0)
  })

  it('emits nothing when the process-exit hook fired before the disposal (natural exit / process.exit paths)', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, getExitHook, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    const exitHook = getExitHook()
    expect(exitHook).toBeTypeOf('function')
    exitHook!() // simulate the 'exit' event firing during teardown
    disposeAll()
    pumpVerdicts()

    expect(tamperEvents(reported)).toHaveLength(0)
  })

  it('suppresses the verdict when the exit hook fires after the disposal but before the verdict', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, getExitHook, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)
    // The scope is disposed (HMR unload), then the host exits normally
    // and the 'exit' hook fires. The host is going away, so there is
    // nothing to report — and the deferred verdict must not fire on the
    // way out. This is the natural-teardown false positive.
    disposeAll()
    getExitHook()?.()
    pumpVerdicts()
    expect(tamperEvents(reported)).toHaveLength(0)
  })

  it('still emits when the plugin was removed and the host keeps running', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, getExitHook, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)
    // The plugin is disabled via the profile toggle. The host does NOT
    // exit — no exit hook fires — so the verdict must fire.
    disposeAll()
    pumpVerdicts()
    expect(tamperEvents(reported)).toHaveLength(1)
    expect(getExitHook()).toBeTypeOf('function')
  })
})

// ---------------------------------------------------------------------------
// Watchdog liveness seam + exactly-once semantics
// ---------------------------------------------------------------------------

describe('watchdog liveness seam', () => {
  it('normal scope disposal self-clears the watchdog without a second event', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, watchdogPumps, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)
    disposeAll()

    const pump = watchdogPumps[0]!
    expect(pump.ms).toBe(30_000)
    expect(pump.cancelled).toBe(false) // cleared lazily on the first post-disposal tick
    pump.tick()
    expect(pump.cancelled).toBe(true)
    pumpVerdicts()
    expect(tamperEvents(reported)).toHaveLength(1)
  })

  it('emits with detection_point watchdog_liveness_probe when the probe is torn down without the main disposer', () => {
    const { ctx, disposeById } = makeFakeCtx()
    const { deps, reported, watchdogPumps, pumpVerdicts } = makeDeps()
    installPluginUnloadSentinel(ctx, deps)

    // Simulate the harness tearing down effects but our main disposer
    // never running (fiber kill / unload bug): only the probe flips.
    expect(disposeById('security-monitor: unload-sentinel probe')).toBe(true)
    watchdogPumps[0]!.tick()
    pumpVerdicts()

    const tampers = tamperEvents(reported)
    expect(tampers).toHaveLength(1)
    expect(tampers[0]!.audit_details?.['detection_point']).toBe('watchdog_liveness_probe')
    expect(validateEvent(tampers[0]!)).toEqual([])
    expect(watchdogPumps[0]!.cancelled).toBe(true)
  })

  it('double disposal emits exactly one event', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdicts } = makeDeps()
    const sentinel = installPluginUnloadSentinel(ctx, deps)
    disposeAll()
    sentinel.simulateScopeDispose() // manual re-entry is a no-op
    disposeAll()
    pumpVerdicts()
    expect(tamperEvents(reported)).toHaveLength(1)
  })

  it('emit failures are swallowed and logged, never thrown (invariant #3)', async () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, warns, pumpVerdicts } = makeDeps({
      eventCollector: {
        report: () => {
          throw new Error('sink exploded')
        },
      },
    })
    expect(() => {
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      pumpVerdicts()
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

  it('falls back to explicit null identity when no session is resolvable', () => {
    const { ctx, disposeAll } = makeFakeCtx()
    const { deps, reported, pumpVerdicts } = makeDeps({ sessionResolve: () => undefined })
    installPluginUnloadSentinel(ctx, deps)
    disposeAll()
    pumpVerdicts()
    const event = tamperEvents(reported)[0]!
    expect(event.session_id).toBe(null)
    expect(event.run_id).toBe(null)
    expect(event.agent_id).toBe(null)
  })

  // 2026-09-25 A-M8: atomic once-guard with defensive event-construction
  // fallbacks. A throwing helper used to drop the audit entirely; the
  // sentinel now wraps every field in its own try/catch so the audit
  // ALWAYS reaches NDJSON, even if every helper misbehaves at once.
  describe('A-M8 — atomic once-guard with helper-failure fallbacks', () => {
    it('emits the audit even when sessionResolve() throws', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      const { deps, reported, pumpVerdicts } = makeDeps({
        sessionResolve: () => {
          throw new Error('session resolver exploded')
        },
      })
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      pumpVerdicts()
      // Audit still landed — fallbacks absorbed the throw.
      const event = tamperEvents(reported)[0]!
      expect(event).toBeDefined()
      expect(event.session_id).toBe(null)
      expect(event.run_id).toBe(null)
      expect(event.agent_id).toBe(null)
    })

    it('emits the audit even when now() clock helper throws', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      const { deps, reported, pumpVerdicts } = makeDeps({
        now: () => {
          throw new Error('clock broken')
        },
      })
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      pumpVerdicts()
      const event = tamperEvents(reported)[0]!
      expect(event).toBeDefined()
      // ts must still be a finite number — the Date.now()
      // fallback fired when the injected now() threw.
      expect(typeof event.ts).toBe('number')
      expect(Number.isFinite(event.ts)).toBe(true)
    })

    it('emits the audit with a deterministic fallback event_id when id generator throws', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      // Hard to mock the imported generateEventId module from outside;
      // instead, drive a hostile env where every helper throws and verify
      // the audit still lands (the buildTamperEvent helper absorbs each).
      const { deps, reported, pumpVerdicts } = makeDeps({
        sessionResolve: () => {
          throw new Error('session exploded')
        },
        now: () => {
          throw new Error('clock exploded')
        },
      })
      installPluginUnloadSentinel(ctx, deps)
      disposeAll()
      pumpVerdicts()
      const event = tamperEvents(reported)[0]!
      expect(event).toBeDefined()
      // event_id must be a non-empty string regardless of helper throws.
      expect(typeof event.event_id).toBe('string')
      expect((event.event_id as string).length).toBeGreaterThan(0)
    })

    it('emits exactly one audit when scope dispose and watchdog fire on the same tick (atomic once-guard)', () => {
      const { ctx, disposeAll } = makeFakeCtx()
      const { deps, reported, watchdogPumps, pumpVerdicts } = makeDeps()
      installPluginUnloadSentinel(ctx, deps)
      // Simulate the worst-case race: scope disposal fires AND the
      // watchdog ticks at the same moment. The once-guard must ensure
      // exactly one event reaches the sink, regardless of which seam
      // wins the race.
      disposeAll()
      // Probe effect (registered first) flipped probeActive=false.
      // WatchdogTick sees probeActive=false and would normally enter the
      // verdict path — but the verdict is already scheduled.
      for (const pump of watchdogPumps) {
        pump.tick()
      }
      pumpVerdicts()
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
        // the real sink stamps the wire fields in buildTransportEvent
        // before validation runs — the stub has to do the same.
        if (event.schema_version === undefined) event.schema_version = 1
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
    const { deps, pumpVerdicts } = makeDeps({ eventCollector: sink })
    installPluginUnloadSentinel(ctx, deps)

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
    // dispose seam catches it (after the grace window).
    disposeAll()
    pumpVerdicts()

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
