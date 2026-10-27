import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { normalizeConfig, type Config } from '../src/config.js'
import type { SecurityEvent } from '../src/types/index.js'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, statSync, symlinkSync, renameSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Audit-log transparency: the local NDJSON is the source of truth (invariant
//so a deletion or truncation of that file must be surfaced with a
// synthetic `security_audit` event (category=integrity) instead of being
// silently absorbed. Regression for the 2026-08-17 uninstall attack, which
// erased the audit trail by deleting security-events.jsonl mid-session.
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

function makeConfig(path: string): Config {
  return normalizeConfig({
    collector: {
      localOutputPath: path,
      batchSize: 1,
      flushIntervalMs: 60_000, // disable timer flush
      validateEvents: true,
    },
  })
}

function lines(path: string): SecurityEvent[] {
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l))
}

describe('LocalNdjsonSink audit-log integrity (2026-08-17 tamper regression, formerly EventCollector)', () => {
  let tmpDir: string
  let path: string
  let logger: { log: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-integrity-'))
    path = join(tmpDir, 'security-events.jsonl')
    logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('first write of a process is a clean baseline (no false positive)', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()
    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()
    expect(lines(path).map((e) => e.event_id)).toEqual(['a-1', 'a-2'])
    expect(logger.error).not.toHaveBeenCalled()
    ec.shutdown()
  })

  it('detects audit log deletion and records security_audit first', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    rmSync(path) // attacker wipes the trail mid-session

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    expect(all[0].event_type).toBe('security_audit') // evidence lands first
    expect(all[0].audit_category).toBe('integrity')
    expect(all[0].audit_action).toBe('detect')
    expect(all[0].audit_details?.integrity).toBe('file_deleted')
    expect(all[0].audit_details?.prev_bytes).toBeGreaterThan(0)
    expect(all[0].agent_id).toBe(null)
    expect(all[0].session_id).toBe(null)
    expect(all[0].run_id).toBe(null)
    expect(all[1].event_id).toBe('a-2')
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('被删除'))
    ec.shutdown()
  })

  it('integrity security_audit resolves session from resolveSessionByPid', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), {
      logger,
      resolveSessionByPid: () => ({
        sessionId: 'sess-integrity',
        runId: 'run-integrity',
        agentId: 'agent-integrity',
      }),
    })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    rmSync(path)

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    const all = lines(path)
    const integrity = all.find((e) => e.event_type === 'security_audit')
    expect(integrity).toBeDefined()
    expect(integrity?.agent_id).toBe('agent-integrity')
    expect(integrity?.session_id).toBe('sess-integrity')
    expect(integrity?.run_id).toBe('run-integrity')
    ec.shutdown()
  })

  it('detects audit log truncation between writes', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()
    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()
    const before = readFileSync(path, 'utf8')

    // Truncate to just the first line — the second line is gone.
    writeFileSync(path, before.split('\n')[0] + '\n')

    ec.report(makeEvent({ event_id: 'a-3' }))
    await ec.flush()

    const all = lines(path)
    const integrity = all.find((e) => e.event_type === 'security_audit')
    expect(integrity).toBeDefined()
    expect(integrity?.audit_category).toBe('integrity')
    expect(integrity?.audit_action).toBe('detect')
    expect(integrity?.audit_details?.integrity).toBe('file_truncated')
    expect(integrity?.audit_details?.prev_bytes).toBeGreaterThan(0)
    expect(all.at(-1)?.event_id).toBe('a-3')
    ec.shutdown()
  })

  // 2026-10-10 fix regression: `checkLocalIntegrity` used `statSync`,
  // which FOLLOWS symlinks — replacing the audit file with a symlink
  // resolved to the target's stat, so the `isSymbolicLink()` branch was
  // dead code and the swap could pass every check. Now `lstatSync` stats
  // the link itself; a symlink fails `isFile()` and is reported as
  // `file_replaced` / `stat_kind: 'symlink'` on the integrity channel.
  it('detects audit log replaced by a symlink (2026-10-10 lstat fix)', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()

    // Swap the audit file for a symlink pointing at a sibling decoy.
    const decoy = join(tmpDir, 'decoy.jsonl')
    writeFileSync(decoy, '')
    rmSync(path)
    try {
      symlinkSync(decoy, path)
    } catch {
      // Symlink creation needs extra privileges on some hosts (Windows
      // without developer mode) — nothing platform-specific to assert.
      ec.shutdown()
      return
    }

    ec.report(makeEvent({ event_id: 'a-2' }))
    await ec.flush()

    // Appends follow the link, so both the integrity event and a-2 land
    // in the decoy target.
    const all = lines(decoy)
    const integrity = all.find((e) => e.event_type === 'security_audit')
    expect(integrity).toBeDefined()
    expect(integrity?.audit_category).toBe('integrity')
    expect(integrity?.audit_details?.integrity).toBe('file_replaced')
    expect(integrity?.audit_details?.stat_kind).toBe('symlink')
    ec.shutdown()
  })

  it('a restarted process re-baselines (deletion while down is not double-reported)', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'a-1' }))
    await ec.flush()
    ec.shutdown()

    rmSync(path) // tamper while the plugin is stopped

    const ec2 = new LocalNdjsonSink(makeConfig(path), { logger })
    ec2.initialize()
    ec2.report(makeEvent({ event_id: 'b-1' }))
    await ec2.flush()
    const all = lines(path)
    expect(all.map((e) => e.event_type)).toEqual(['agent_message']) // no integrity noise
    expect(all[0].event_id).toBe('b-1')
    ec2.shutdown()
  })

  it('injects agent_id from resolveSessionByPid for events missing it', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), {
      logger,
      resolveSessionByPid: () => ({
        sessionId: 'sess-resolved',
        runId: 'run-resolved',
        agentId: 'agent-resolved',
      }),
    })
    ec.initialize()
    ec.report({
      ...makeEvent({ event_id: 'a-1' }),
      agent_id: undefined,
      session_id: undefined,
      run_id: undefined,
    })
    await ec.flush()
    const all = lines(path)
    expect(all[0].agent_id).toBe('agent-resolved')
    expect(all[0].session_id).toBe('sess-resolved')
    expect(all[0].run_id).toBe('run-resolved')
    ec.shutdown()
  })

  it('falls back to explicit null identity for events from the plugin process without a session', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report({
      ...makeEvent({ event_id: 'a-1' }),
      pid: process.pid,
      agent_id: undefined,
      session_id: undefined,
      run_id: undefined,
    })
    await ec.flush()
    const all = lines(path)
    expect(all[0].agent_id).toBe(null)
    expect(all[0].session_id).toBe(null)
    expect(all[0].run_id).toBe(null)
    ec.shutdown()
  })

  it('falls back to explicit null identity for external events without a session', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report({
      ...makeEvent({ event_id: 'a-1' }),
      pid: 99999,
      agent_id: undefined,
      session_id: undefined,
      run_id: undefined,
    })
    await ec.flush()
    const all = lines(path)
    expect(all[0].agent_id).toBe(null)
    expect(all[0].session_id).toBe(null)
    expect(all[0].run_id).toBe(null)
    ec.shutdown()
  })

  it('external rotation (archive sibling) re-baselines WITHOUT an integrity alert', async () => {
    // Real-data regression: operator/harness housekeeping renamed the log
    // to an archive sibling; the next write flagged a hostile file_deleted.
    // A fresh `<name>.<suffix>` sibling within the last minute marks the
    // deletion as a compliant rotation.
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'rot-1' }))
    await ec.flush()
    expect(existsSync(path)).toBe(true)

    // External rotation: rename to an archive sibling (fresh mtime).
    renameSync(path, `${path}.1`)
    ec.report(makeEvent({ event_id: 'rot-2' }))
    await ec.flush()

    const audits = lines(path).filter(
      (e) => e.event_type === 'security_audit' && e.audit_details?.['integrity'],
    )
    expect(audits).toHaveLength(0)
    // The post-rotation write landed in a fresh file.
    expect(lines(path).some((e) => e.event_id === 'rot-2')).toBe(true)
    ec.shutdown()
  })

  it('hostile deletion (no archive sibling) still raises the integrity alert', async () => {
    const ec = new LocalNdjsonSink(makeConfig(path), { logger })
    ec.initialize()
    ec.report(makeEvent({ event_id: 'del-1' }))
    await ec.flush()

    rmSync(path)
    ec.report(makeEvent({ event_id: 'del-2' }))
    await ec.flush()

    const audits = lines(path).filter(
      (e) => e.event_type === 'security_audit' && e.audit_details?.['integrity'],
    )
    expect(audits).toHaveLength(1)
    expect(audits[0].audit_details?.['integrity']).toBe('file_deleted')
    ec.shutdown()
  })

  // §十一 A3 : the size cap + disk watermarks must
  // be read from config, not hardcoded class constants. The previous
  // implementation carried private `MAX_FILE_BYTES = 50 MiB` and
  // `DISK_*_WATERMARK_BYTES = 100/10 MiB` which silently diverged from
  // the 50 / 500 / 100 MiB defaults in `DEFAULTS_COLLECTOR`, so operators
  // who tuned the UI got a false sense of control. These two cases pin
  // the new behaviour.

  it('respects custom maxFileBytes from config ( A3 regression)', async () => {
    // Cap the local NDJSON at ~200 bytes — a single ~660-byte event
    // already overflows the cap. Without config-driven behaviour this
    // would silently use the old 50 MiB class constant.
    //
    // Note: the cap fires inside `appendToCappedNdjson` (which the sink
    // uses for both single-event and batch paths). We assert on the
    // observable contract — file stays bounded by the configured cap and
    // never holds more than one event after rotation — rather than on the
    // internal `rotatedCount` counter, which the single-event path
    // doesn't bump (a separate, unrelated defect).
    const cap = 200
    const cfg = normalizeConfig({
      collector: {
        localOutputPath: path,
        batchSize: 1,
        flushIntervalMs: 60_000,
        maxFileBytes: cap,
      },
    })
    // Sanity: normalizeConfig must surface the operator-facing field.
    expect(cfg.collector.maxFileBytes).toBe(cap)

    const ec = new LocalNdjsonSink(cfg, { logger })
    ec.initialize()

    // Write several events that each individually exceed the cap.
    for (let i = 0; i < 6; i++) {
      ec.report(makeEvent({ event_id: `r-${i}`, content: 'x'.repeat(200) }))
      await ec.flush()
    }

    // After every append the file is bounded by the cap (≈ 660 bytes per
    // event, but the cap kicks in BEFORE the append and unlinks the file
    // — only the freshly appended line survives).
    const finalSize = statSync(path).size
    expect(finalSize).toBeLessThanOrEqual(cap + 800) // one event + JSON overhead

    // Only the last write can survive — proves the cap actually fired and
    // truncated the file between writes (not a no-op).
    const persisted = lines(path).map((e) => e.event_id)
    expect(persisted).toEqual(['r-5'])
    ec.shutdown()
  })

  it('respects custom disk watermarks from config ( A3 regression)', () => {
    // Use an obviously distinctive huge watermark so the log message
    // text unambiguously carries the config-supplied number. Any real
    // free-disk value (bytes) is < Number.MAX_SAFE_INTEGER, so the low
    // watermark branch fires deterministically and the message text
    // contains the exact config number — proving the comparison uses
    // `this.config.diskLowWatermarkBytes` and not a private constant.
    const hugeWatermark = Number.MAX_SAFE_INTEGER
    const cfg = normalizeConfig({
      collector: {
        localOutputPath: path,
        diskWarnWatermarkBytes: hugeWatermark,
        diskLowWatermarkBytes: hugeWatermark,
      },
    })
    const ec = new LocalNdjsonSink(cfg, { logger })
    ec.initialize()
    const errorMsgs = logger.error.mock.calls.map((c) => String(c[0])).join('\n')
    expect(errorMsgs).toContain('low disk space at startup')
    expect(errorMsgs).toContain(String(hugeWatermark))
    // The previous 100 MiB constant would NOT match `hugeWatermark`,
    // so a false pass against the old code would print a different
    // number. Guard explicitly to make the regression intent obvious.
    expect(errorMsgs).not.toContain('104857600') // 100 MiB — old DISK_WARN_WATERMARK_BYTES
    ec.shutdown()
  })

  // BUG-8 : `writeLocalDirect` (the single-event path
  // used by `report()`) discarded `appendToCappedNdjson`'s `truncated`
  // return, so the size-cap rotation only bumped `rotatedCount` on the
  // batch-flush path. Pre-fix, an operator setting a tight `maxFileBytes`
  // cap and observing `getStats().rotatedCount` would see 0 even after
  // dozens of single-event cap rotations. This test pins the fix.
  it('writeLocalDirect bumps rotatedCount when the size cap truncates ( BUG-8 regression)', async () => {
    const cap = 200
    const cfg = normalizeConfig({
      collector: {
        localOutputPath: path,
        batchSize: 1,
        flushIntervalMs: 60_000,
        maxFileBytes: cap,
      },
    })
    const ec = new LocalNdjsonSink(cfg, { logger })
    ec.initialize()

    // First report creates the file (no prior baseline → no rotation).
    ec.report(makeEvent({ event_id: 'd-1', content: 'x'.repeat(200) }))
    // Second report sees an over-cap file and triggers a rotation.
    ec.report(makeEvent({ event_id: 'd-2', content: 'x'.repeat(200) }))
    // Third report — another rotation.
    ec.report(makeEvent({ event_id: 'd-3', content: 'x'.repeat(200) }))

    const stats = ec.getStats()
    expect(stats.rotatedCount).toBe(2)
    expect(stats.lastRotationAt).not.toBeNull()
    // Only the last event survives — proves cap actually fired.
    expect(lines(path).map((e) => e.event_id)).toEqual(['d-3'])
    ec.shutdown()
  })
})