/**
 * 2026-09-28 — LocalNdjsonSink wire-field backfill + invalid-drop warn
 * rate-limit.
 *
 * Background (operator report): the log filled with lines like
 *   [LocalNdjsonSink] dropped invalid event evt-…: host_id: missing
 *   required field: host_id; container_id: missing required field: …
 * — one warn PER dropped event, and the events themselves were lost.
 *
 * Root cause: several producers (RuntimeHook subprocess events, bootstrap
 * startup events, intervention paths) build SecurityEvents without the
 * platform-mandated `host_id` / `container_id` wire fields. The sink's
 * `ensureSessionContext` backfilled agent/session/run but not host/container,
 * so `validateEvent` rejected the event at the sink boundary.
 *
 * Fix under test:
 *   1. `ensureSessionContext` backfills `host_id` / `container_id` from the
 *      normalized Config (operator-configured values win; normalizeConfig
 *      guarantees both are non-empty strings). Events are persisted instead
 *      of dropped; explicit producer values are never overwritten.
 *   2. The invalid-event drop warn is rate-limited: the first drop logs
 *      immediately, drops within 30 s collapse into a `(+N suppressed)`
 *      suffix on the next emitted line. `stats.dropped` still counts all.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { hostname } from 'node:os'
import { join } from 'node:path'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { normalizeConfig, type Config } from '../src/config.js'
import type { SecurityEvent } from '../src/types/index.js'

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

function makeConfig(path: string, extra: Record<string, unknown> = {}): Config {
  return normalizeConfig({
    collector: {
      localOutputPath: path,
      batchSize: 1,
      flushIntervalMs: 60_000, // disable timer flush
      validateEvents: true,
    },
    ...extra,
  })
}

function lines(path: string): SecurityEvent[] {
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l))
}

describe('LocalNdjsonSink wire-field backfill (2026-09-28)', () => {
  let tmpDir: string
  let path: string
  let logger: { log: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-wirefields-'))
    path = join(tmpDir, 'security-events.jsonl')
    logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('backfills missing host_id / container_id from the normalized config instead of dropping the event', () => {
    const sink = new LocalNdjsonSink(makeConfig(path), { logger })
    sink.initialize()
    // Producer omitted host_id / container_id (the RuntimeHook/bootstrap
    // pattern that used to be dropped with a per-event warn).
    const event = makeEvent({ event_id: 'evt-nohost' })
    delete event.host_id
    delete event.container_id

    sink.report(event)

    const all = lines(path)
    const persisted = all.find((e) => e.event_id === 'evt-nohost')
    expect(persisted).toBeDefined()
    // normalizeConfig defaults: hostId → hostname(), containerId → 'host'.
    expect(persisted!.host_id).toBe(hostname())
    expect(persisted!.container_id).toBe('host')
    expect(sink.getStats().dropped).toBe(0)
    // No drop warn at all — the event was accepted.
    expect(logger.warn).not.toHaveBeenCalledWith(expect.stringContaining('dropped invalid event'))
    sink.shutdown()
  })

  it('honours operator-configured hostId / containerId when backfilling', () => {
    const sink = new LocalNdjsonSink(
      makeConfig(path, { hostId: 'edge-node-7', containerId: 'container-42' }),
      { logger },
    )
    sink.initialize()
    const event = makeEvent({ event_id: 'evt-custom-host' })
    delete event.host_id
    delete event.container_id

    sink.report(event)

    const persisted = lines(path).find((e) => e.event_id === 'evt-custom-host')
    expect(persisted).toBeDefined()
    expect(persisted!.host_id).toBe('edge-node-7')
    expect(persisted!.container_id).toBe('container-42')
    sink.shutdown()
  })

  it('never overwrites explicit producer-supplied host_id / container_id', () => {
    const sink = new LocalNdjsonSink(makeConfig(path, { hostId: 'edge-node-7' }), { logger })
    sink.initialize()
    sink.report(makeEvent({ event_id: 'evt-explicit', host_id: 'producer-host', container_id: 'producer-c' }))

    const persisted = lines(path).find((e) => e.event_id === 'evt-explicit')
    expect(persisted).toBeDefined()
    expect(persisted!.host_id).toBe('producer-host')
    expect(persisted!.container_id).toBe('producer-c')
    sink.shutdown()
  })

  it('rate-limits the invalid-event drop warn (first drop logs, rest collapse into +N suppressed)', () => {
    const sink = new LocalNdjsonSink(makeConfig(path), { logger })
    sink.initialize()
    // Craft an event that stays invalid for a DIFFERENT reason after the
    // wire-field backfill: missing event_type.
    const bad = () => {
      const e = makeEvent({ event_id: `evt-bad-${Math.random()}` })
      delete (e as Record<string, unknown>)['event_type']
      return e
    }

    sink.report(bad())
    sink.report(bad())
    sink.report(bad())

    expect(sink.getStats().dropped).toBe(3)
    const dropWarns = logger.warn.mock.calls.filter((c) =>
      String(c[0]).includes('dropped invalid event'),
    )
    expect(dropWarns.length).toBe(1)
    expect(String(dropWarns[0][0])).not.toContain('suppressed')
    sink.shutdown()
  })
})
