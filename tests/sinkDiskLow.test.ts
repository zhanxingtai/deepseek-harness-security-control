import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { LocalNdjsonSink, isEnforcementCriticalEvent } from '../src/collectors/LocalNdjsonSink.js'
import { normalizeConfig, type Config } from '../src/config.js'
import type { SecurityEvent } from '../src/types/index.js'
import { validateEvent } from '../src/utils/schema.js'
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// LocalNdjsonSink disk-low degradation.
// Crossing `collector.diskLowWatermarkBytes` must not silently stop
// accepting — the sink emits `security_audit/sink_disk_low`, enters a
// temporary enforce-only persistence mode (only enforcement-critical
// events keep landing), and exits with hysteresis
// (`sinkDiskLow.recoverMarginBytes`) emitting `sink_disk_recovered`
// with the dropped-event summary.
//
// Free-disk values are injected through the `freeDiskBytes` test seam so
// the state machine is driven deterministically (real `statfsSync` reads
// the actual disk, which is always > the small test watermarks).
const LOW = 1000
const MARGIN = 500
const RECOVER = LOW + MARGIN

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    comm: 'sst-security-control-dsh',
    event_id: 'evt-test-1',
    event_type: 'agent_message',
    layer: 'application',
    ts: 1700000000000,
    timestamp: 1700000000000,
    pid: 1,
    host_id: 'host',
    container_id: 'host',
    session_id: 's-1',
    role: 'assistant',
    content: 'hello',
    blocked: false,
    ...overrides,
  }
}

function makeConfig(path: string, sinkDiskLow: Record<string, unknown> = { recoverMarginBytes: MARGIN }): Config {
  return normalizeConfig({
    collector: {
      localOutputPath: path,
      batchSize: 1,
      flushIntervalMs: 60_000, // disable timer flush
      validateEvents: true,
      diskLowWatermarkBytes: LOW,
      diskWarnWatermarkBytes: LOW * 2,
    },
    sinkDiskLow,
  })
}

function lines(path: string): SecurityEvent[] {
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l))
}

/** Mutable free-disk probe: tests flip `probe.free` to drive the state machine. */
function makeProbe(initial: number | null) {
  let free = initial
  let calls = 0
  return {
    get free(): number | null {
      return free
    },
    set free(v: number | null) {
      free = v
    },
    get calls(): number {
      return calls
    },
    fn(_dir: string): number | null {
      calls += 1
      return free
    },
  }
}

describe('LocalNdjsonSink disk-low degradation', () => {
  let tmpDir: string
  let path: string
  let logger: { log: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-disklow-'))
    path = join(tmpDir, 'security-events.jsonl')
    logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('acceptance : emits security_audit/sink_disk_low when free disk crosses diskLowWatermarkBytes', () => {
    const probe = makeProbe(100_000)
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, freeDiskBytes: probe.fn })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))

    probe.free = LOW - 1 // dip below the low watermark on the next write
    ec.report(makeEvent({ event_id: 'a-2', blocked: true }))

    const all = lines(path)
    const low = all.find((e) => e.audit_details?.event_type_alias === 'sink_disk_low')
    expect(low).toBeDefined()
    // The transition event must be a valid SecurityEvent (invariant:
    // everything the sink persists passes validateEvent()).
    expect(validateEvent(low)).toEqual([])
    expect(low!.event_type).toBe('security_audit')
    expect(low!.audit_category).toBe('sink')
    expect(low!.audit_action).toBe('escalate') // upstream-visible escalation semantics
    expect(low!.outcome).toBe('failure')
    expect(low!.severity).toBe('high')
    expect(low!.audit_details?.free_bytes).toBe(LOW - 1)
    expect(low!.audit_details?.watermark_bytes).toBe(LOW)
    expect(low!.audit_details?.recover_margin_bytes).toBe(MARGIN)
    expect(low!.target).toBe(path)
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('disk below low watermark'))
    ec.shutdown()
  })

  it('acceptance : starting below the watermark enters degraded mode at initialize', () => {
    const probe = makeProbe(LOW - 1)
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, freeDiskBytes: probe.fn })
    ec.initialize()

    expect(ec.getDiskLowState()).toEqual({ active: true, droppedWhileActive: 0 })
    const all = lines(path)
    expect(all).toHaveLength(1)
    expect(all[0].audit_details?.event_type_alias).toBe('sink_disk_low')
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('low disk space at startup'))
    ec.shutdown()
  })

  it('acceptance : degraded mode drops non-critical events but keeps the enforcement trail', () => {
    const probe = makeProbe(LOW - 1)
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, freeDiskBytes: probe.fn })
    ec.initialize()

    ec.report(makeEvent({ event_id: 'n-1' })) // plain agent_message → dropped
    ec.report(
      makeEvent({ event_id: 'n-2', event_type: 'file_write', path: '/tmp/x' }),
    ) // non-critical file event → dropped
    ec.report(
      makeEvent({
        event_id: 'c-1',
        event_type: 'agent_tool_call',
        session_id: 's-1',
        tool_call_id: 'tc-1',
        tool_name: 'bash',
        tool_params: '{"command":"ls"}',
        blocked: true,
      }),
    ) // SPL block → lands
    ec.report(
      makeEvent({
        event_id: 'c-2',
        event_type: 'runtime_spawn_denied',
        cmdline: 'rm -rf /',
        exe: '/bin/rm',
      }),
    ) // spawn-seam denial → lands
    ec.report(
      makeEvent({
        event_id: 'c-3',
        event_type: 'security_audit',
        audit_category: 'policy',
        audit_action: 'tamper',
      }),
    ) // policy tamper audit → lands
    ec.report(
      makeEvent({
        event_id: 'c-4',
        event_type: 'security_audit',
        audit_category: 'integrity',
        audit_action: 'detect',
        outcome: 'failure',
      }),
    ) // failure-outcome audit → lands
    ec.report(
      makeEvent({
        event_id: 'n-3',
        event_type: 'security_audit',
        audit_category: 'behavior',
        audit_action: 'detect',
        outcome: 'success',
      }),
    ) // successful detection audit → dropped

    const persisted = lines(path).map((e) => e.event_id)
    expect(persisted.filter((id) => id.startsWith('c-'))).toEqual(['c-1', 'c-2', 'c-3', 'c-4'])
    expect(persisted).not.toContain('n-1')
    expect(persisted).not.toContain('n-2')
    expect(persisted).not.toContain('n-3')
    expect(ec.getStats().droppedDiskLow).toBe(3)
    expect(ec.getDiskLowState()).toEqual({ active: true, droppedWhileActive: 3 })
    ec.shutdown()
  })

  it('truncate fires once per episode — the degraded mode must not erase the trail it keeps', () => {
    const probe = makeProbe(100_000)
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, freeDiskBytes: probe.fn })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))

    probe.free = LOW - 1
    // Pre-F24 behaviour truncated before EVERY append below the watermark,
    // so only the last critical event would survive. truncates on
    // episode entry only — the whole enforcement trail must accumulate.
    ec.report(makeEvent({ event_id: 'c-1', blocked: true }))
    ec.report(makeEvent({ event_id: 'c-2', blocked: true }))
    ec.report(makeEvent({ event_id: 'c-3', blocked: true }))

    expect(ec.getStats().rotatedCount).toBe(1) // exactly the entry truncate
    const persisted = lines(path).map((e) => e.event_id)
    expect(persisted.filter((id) => id.startsWith('c-'))).toEqual(['c-1', 'c-2', 'c-3'])
    ec.shutdown()
  })

  it('sink_disk_low is edge-triggered — no repeat emissions while still below the watermark', () => {
    const probe = makeProbe(LOW - 1)
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, freeDiskBytes: probe.fn })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'c-1', blocked: true }))
    ec.report(makeEvent({ event_id: 'c-2', blocked: true }))
    ec.flush()

    const lowEvents = lines(path).filter((e) => e.audit_details?.event_type_alias === 'sink_disk_low')
    expect(lowEvents).toHaveLength(1)
    ec.shutdown()
  })

  it('acceptance : hysteresis-gated recovery emits sink_disk_recovered with the dropped summary', () => {
    const probe = makeProbe(LOW - 1)
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, freeDiskBytes: probe.fn })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'n-1' }))
    ec.report(makeEvent({ event_id: 'n-2' }))
    expect(ec.getDiskLowState().droppedWhileActive).toBe(2)

    // Below low + margin → still degraded, no recovery (no flapping).
    probe.free = RECOVER - 1
    ec.flush()
    expect(ec.getDiskLowState().active).toBe(true)
    expect(lines(path).some((e) => e.audit_details?.event_type_alias === 'sink_disk_recovered')).toBe(false)

    // Reach low + margin → recover on the idle flush tick (the flush timer
    // doubles as the periodic recovery probe, so a quiet host still exits
    // the degraded mode).
    probe.free = RECOVER
    ec.flush()
    expect(ec.getDiskLowState()).toEqual({ active: false, droppedWhileActive: 0 })

    const recovered = lines(path).find((e) => e.audit_details?.event_type_alias === 'sink_disk_recovered')
    expect(recovered).toBeDefined()
    expect(validateEvent(recovered)).toEqual([])
    expect(recovered!.audit_category).toBe('sink')
    expect(recovered!.audit_action).toBe('warn')
    expect(recovered!.outcome).toBe('success')
    expect(recovered!.severity).toBe('medium')
    expect(recovered!.audit_details?.dropped_events).toBe(2)

    // Mode is back to normal — non-critical events land again.
    ec.report(makeEvent({ event_id: 'a-2' }))
    expect(lines(path).map((e) => e.event_id)).toContain('a-2')
    ec.shutdown()
  })

  it('null probe (statfs unsupported) is a no-op — events flow normally', () => {
    const probe = makeProbe(null)
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, freeDiskBytes: probe.fn })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    ec.flush()

    expect(ec.getDiskLowState()).toEqual({ active: false, droppedWhileActive: 0 })
    expect(lines(path).map((e) => e.event_id)).toEqual(['a-1'])
    expect(logger.error).not.toHaveBeenCalled()
    ec.shutdown()
  })

  it('a throwing probe never crashes the sink (invariant #3: never throw to host)', () => {
    const ec = new LocalNdjsonSink(makeConfig(path), {
      logger,
      freeDiskBytes: () => {
        throw new Error('statfs exploded')
      },
    })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    ec.flush()

    expect(lines(path).map((e) => e.event_id)).toEqual(['a-1'])
    expect(ec.getDiskLowState()).toEqual({ active: false, droppedWhileActive: 0 })
    ec.shutdown()
  })
})

describe('isEnforcementCriticalEvent', () => {
  it('classifies enforcement outcomes as critical', () => {
    expect(isEnforcementCriticalEvent(makeEvent({ blocked: true }))).toBe(true)
    expect(
      isEnforcementCriticalEvent(makeEvent({ event_type: 'runtime_spawn_denied', cmdline: 'x', exe: '/bin/x' })),
    ).toBe(true)
    for (const action of ['block', 'deny', 'tamper', 'escalate'] as const) {
      expect(
        isEnforcementCriticalEvent(
          makeEvent({ event_type: 'security_audit', audit_category: 'policy', audit_action: action }),
        ),
      ).toBe(true)
    }
    expect(
      isEnforcementCriticalEvent(
        makeEvent({
          event_type: 'security_audit',
          audit_category: 'integrity',
          audit_action: 'detect',
          outcome: 'failure',
        }),
      ),
    ).toBe(true)
  })

  it('classifies observability-only events as non-critical', () => {
    expect(isEnforcementCriticalEvent(makeEvent())).toBe(false)
    expect(isEnforcementCriticalEvent(makeEvent({ event_type: 'file_read', path: '/tmp/x' }))).toBe(false)
    for (const action of ['approve', 'warn', 'guide', 'detect', 'allow'] as const) {
      expect(
        isEnforcementCriticalEvent(
          makeEvent({ event_type: 'security_audit', audit_category: 'behavior', audit_action: action, outcome: 'success' }),
        ),
      ).toBe(false)
    }
  })
})

describe('sinkDiskLow config normalization', () => {
  it('defaults recoverMarginBytes to 50 MiB', () => {
    const cfg = normalizeConfig({})
    expect(cfg.sinkDiskLow.recoverMarginBytes).toBe(50 * 1024 * 1024)
  })

  it('honours an operator override', () => {
    const cfg = normalizeConfig({ sinkDiskLow: { recoverMarginBytes: 1234 } })
    expect(cfg.sinkDiskLow.recoverMarginBytes).toBe(1234)
  })

  it('falls back to the default for non-finite / negative values', () => {
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, 'abc' as unknown as number]) {
      const cfg = normalizeConfig({ sinkDiskLow: { recoverMarginBytes: bad } })
      expect(cfg.sinkDiskLow.recoverMarginBytes).toBe(50 * 1024 * 1024)
    }
  })
})
