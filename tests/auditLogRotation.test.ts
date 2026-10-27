import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { normalizeConfig, type Config } from '../src/config.js'
import type { SecurityEvent } from '../src/types/index.js'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, renameSync, statSync, symlinkSync, utimesSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// 2026-10-27 batch-4: distinguish a COMPLIANT external rotation (an operator /
// harness housekeeping job renamed the audit log to an archive sibling) from
// a HOSTILE deletion of the audit trail. Real data had a `file_deleted`
// integrity alert whose prev_bytes sat well under the size cap — that was a
// rotation, not an attack. Rotation re-baselines silently; only unexplained
// deletion raises integrity/detect.
describe('LocalNdjsonSink audit-log rotation whitelist', () => {
  let tmpDir: string
  let path: string
  let logger: { log: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-rotation-'))
    path = join(tmpDir, 'security-events.jsonl')
    logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function makeConfig(p: string): Config {
    return normalizeConfig({
      collector: {
        localOutputPath: p,
        batchSize: 1,
        flushIntervalMs: 60_000, // disable timer flush
        validateEvents: true,
      },
    })
  }

  function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
    return {
      comm: 'sst-security-control-dsh',
      event_id: 'evt-test-1',
      event_type: 'agent_message',
      layer: 'application',
      ts: 1700000000000,
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

  function lines(p: string): SecurityEvent[] {
    if (!existsSync(p)) return []
    return readFileSync(p, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l))
  }

  it('external rotation with a fresh archive sibling: silent re-baseline, no integrity alert', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    // Housekeeping rotates the log aside.
    renameSync(path, `${path}.1`)

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    // No integrity/detect row; the new file carries on with the next event.
    expect(all.map((e) => e.event_id)).toEqual(['a-2'])
    expect(all.some((e) => e.event_type === 'security_audit')).toBe(false)
    expect(logger.error).not.toHaveBeenCalled()
    expect(ec.getStats().rotatedCount).toBe(1)
    ec.shutdown()
  })

  it('stale archive sibling (> 60s) does NOT whitelist — still alerts', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    renameSync(path, `${path}.1`)
    const stale = Date.now() - 120_000
    utimesSync(`${path}.1`, new Date(stale), new Date(stale))

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all[0].event_type).toBe('security_audit')
    expect(all[0].audit_details?.integrity).toBe('file_deleted')
    expect(all[0].audit_details?.prev_bytes).toBeGreaterThan(0)
    expect(all[1].event_id).toBe('a-2')
    ec.shutdown()
  })

  it('unrelated sibling name does NOT whitelist — still alerts', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    rmSync(path)
    // Unrelated file in the same directory — not an archive of the log.
    writeFileSync(join(tmpDir, 'unrelated.txt'), 'noise')

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all[0].event_type).toBe('security_audit')
    expect(all[0].audit_details?.integrity).toBe('file_deleted')
    ec.shutdown()
  })
})

// 2026-10-27 batch-D: a SINGLE failed stat of the audit log cannot tell
// "the trail was deleted" from "the trail is being rotated right now" —
// an external rotator that renames the log away and creates a fresh one
// leaves the path missing for the few milliseconds between the two steps,
// and a stat landing in that window reports a hostile deletion that never
// happened. The sink now CONFIRMS a missing path with a second stat before
// alarming. The operator escape hatch for rotators the sibling heuristic
// cannot recognise (copytruncate, cross-directory moves) is the explicit
// `collector.externallyManagedLog` declaration.
describe('LocalNdjsonSink audit-log lifecycle confirmation', () => {
  let tmpDir: string
  let path: string
  let logger: { log: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-lifecycle-'))
    path = join(tmpDir, 'security-events.jsonl')
    logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function makeConfig(p: string, overrides: Record<string, unknown> = {}): Config {
    return normalizeConfig({
      collector: {
        localOutputPath: p,
        batchSize: 1,
        flushIntervalMs: 60_000, // disable timer flush
        validateEvents: true,
        ...overrides,
      },
    })
  }

  function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
    return {
      comm: 'sst-security-control-dsh',
      event_id: 'evt-test-1',
      event_type: 'agent_message',
      layer: 'application',
      ts: 1700000000000,
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

  function lines(p: string): SecurityEvent[] {
    if (!existsSync(p)) return []
    return readFileSync(p, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l))
  }

  /** The confirmation seam — a real rotation window is a filesystem race
   *  that a test cannot schedule from the outside, so the second stat is
   *  driven deterministically here. */
  type Confirmer = { confirmPathReappeared: () => { reappeared: boolean; stat?: import('node:fs').Stats } }

  it('a path that is momentarily absent (rotation window) does NOT raise an integrity gap', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    // The rotator renames the log away — the path is missing for a moment.
    renameSync(path, `${path}.1`)
    // The confirmation re-stat finds the path back (the rotator recreated it).
    vi.spyOn(ec as unknown as Confirmer, 'confirmPathReappeared').mockReturnValue({
      reappeared: true,
      stat: statSync(`${path}.1`),
    })

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all.some((e) => e.event_type === 'security_audit')).toBe(false)
    expect(logger.error).not.toHaveBeenCalled()
    ec.shutdown()
  })

  it('a path that is still absent after the confirmation IS reported as a deletion', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger, integrityConfirmDelayMs: 1 })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    rmSync(path)

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all[0].event_type).toBe('security_audit')
    expect(all[0].audit_details?.integrity).toBe('file_deleted')
    ec.shutdown()
  })

  it('a path that comes back as a NON-regular file is reported as a replacement', async (ctx) => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    rmSync(path)
    // The confirmation finds the path back — but as a symlink, not a file.
    const target = join(tmpDir, 'target.txt')
    writeFileSync(target, '')
    try {
      symlinkSync(target, path)
    } catch {
      // Windows without Developer Mode cannot create symlinks. The
      // platform-gated case is skipped rather than faked — a fake would
      // assert the mock, not the behaviour.
      ctx.skip()
      return
    }

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all[0].event_type).toBe('security_audit')
    expect(all[0].audit_details?.integrity).toBe('file_replaced')
    expect(all[0].audit_details?.stat_kind).toBe('symlink')
    ec.shutdown()
  })

  it('externally managed log: a deleted log re-baselines with a warning, no integrity gap', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path, { externallyManagedLog: true }), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    rmSync(path)

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all.some((e) => e.event_type === 'security_audit')).toBe(false)
    expect(all.map((e) => e.event_id)).toEqual(['a-2'])
    expect(logger.warn).toHaveBeenCalled()
    ec.shutdown()
  })

  it('externally managed log: a truncated log re-baselines, no integrity gap', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path, { externallyManagedLog: true }), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    // copytruncate shape: the file is emptied in place.
    writeFileSync(path, '')

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all.some((e) => e.event_type === 'security_audit')).toBe(false)
    expect(all.map((e) => e.event_id)).toEqual(['a-2'])
    ec.shutdown()
  })

  it('externally managed log: a swapped file (new inode) re-baselines, no integrity gap', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path, { externallyManagedLog: true }), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    rmSync(path)
    // A NEW file (new inode) — the content does not matter, the inode does.
    writeFileSync(path, '')

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all.some((e) => e.event_type === 'security_audit')).toBe(false)
    ec.shutdown()
  })

  it('the DEFAULT posture still reports a truncated log as an integrity gap', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    writeFileSync(path, '')

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all[0].event_type).toBe('security_audit')
    expect(all[0].audit_details?.integrity).toBe('file_truncated')
    expect(all[0].severity).toBe('high')
    ec.shutdown()
  })

  it('externallyManagedLog defaults to false (the anomaly is reported)', () => {
    expect(normalizeConfig(undefined).collector.externallyManagedLog).toBe(false)
    expect(normalizeConfig({ collector: { externallyManagedLog: true } }).collector.externallyManagedLog).toBe(true)
  })
})
