import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { rmSync, mkdtempSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizeConfig, type Config } from '../src/config.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../src/collectors/ApplicationCollector.js'
import type { Agent, FsObservation, FsTarget } from '../src/types/external.js'

function makeAgent(overrides?: Partial<Agent>): Agent {
  return {
    id: 'agent-1',
    session: {
      header: { id: 'session-1', createdAt: Date.now() },
      events: [],
    },
    options: { provider: 'test', model: 'test-model' },
    ...overrides,
  } as Agent
}

function makeConfig(tmpDir: string): Config {
  return normalizeConfig({
    collector: {
      localOutputPath: join(tmpDir, 'security-events.jsonl'),
      flushIntervalMs: 10,
    },
  })
}

function readEvents(filePath: string): Array<Record<string, unknown>> {
  return readFileSync(filePath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line))
}

// The fs/observed + fs/write-intent surface maps onto the platform-standard
// file classes — the custom types file_observed / file_write_intent are GONE
// from the stream (2026-08-17 data-alignment pass). Rules:
//   - fs/observed with NO matching write-intent  →  file_read  (+ path)
//   - fs/observed ABSORBING a write-intent       →  file_write (+ path + fs_write_intent)
//   - un-absorbed write-intent flushed by TTL    →  file_write (+ path)
describe('ApplicationCollector fs/* handlers → file_read / file_write', () => {
  let tmpDir: string
  let config: Config
  let eventCollector: LocalNdjsonSink
  let collector: ApplicationCollector

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'sst-security-control-dsh-fs-'))
    config = makeConfig(tmpDir)
    eventCollector = new LocalNdjsonSink(config)
    collector = new ApplicationCollector(config, eventCollector)
    eventCollector.initialize()
    collector.initialize()
  })

  afterEach(() => {
    collector.shutdown()
    eventCollector.shutdown()
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('emits file_read with present observation when fs/observed fires without an intent', async () => {
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:1', displayPath: '/tmp/example.txt' }
    const observation: FsObservation = { kind: 'present', version: 'v-abc123' }
    collector.onFsObserved(target, observation, { name: 'file_read' })
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.event_type).toBe('file_read')
    // Spec file_read: top-level `path` is the mandatory carrier.
    expect(observed.path).toBe('/tmp/example.txt')
    expect(observed.target_key).toBe('fs:1')
    expect(observed.observation_kind).toBe('present')
    expect(observed.file_version).toBe('v-abc123')
    expect(observed.tool_name).toBe('file_read')
    expect(observed.layer).toBe('application')
    expect(observed.session_id).toBe('session-1')
  })

  it('emits file_read with absent observation and no file_version', async () => {
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:2', displayPath: '/tmp/missing.txt' }
    const observation: FsObservation = { kind: 'absent' }
    collector.onFsObserved(target, observation, { name: 'file_read' })
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.observation_kind).toBe('absent')
    expect(observed.file_version).toBeUndefined()
  })

  it('emits file_read without tool_name when actor is undefined', async () => {
    const target: FsTarget = { targetKey: 'fs:3', displayPath: '/tmp/no-actor.txt' }
    const observation: FsObservation = { kind: 'present', version: 'v-1' }
    collector.onFsObserved(target, observation, undefined)
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.tool_name).toBeUndefined()
  })

  it('emits file_read even with no active session (multi-session ambiguity)', async () => {
    const target: FsTarget = { targetKey: 'fs:4', displayPath: '/tmp/orphan.txt' }
    const observation: FsObservation = { kind: 'present', version: 'v-2' }
    // No session started — the event must still land in the audit log.
    collector.onFsObserved(target, observation, undefined)
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.target_key).toBe('fs:4')
    // No session context → stub session_id ('') but the event is still emitted
    // and the common-required fields (comm/event_id/event_type/layer/ts) are
    // populated. Audit correlation falls back to target_key + tool_name.
    expect(observed.session_id).toBe('')
    expect(observed.comm).toBe('sst-security-control-dsh')
    expect(observed.event_id).toBeDefined()
    expect(observed.layer).toBe('application')
  })

  it('absorbs fs/write-intent into a single file_write (replaceIfVersion) and returns next() untouched', async () => {
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:5', displayPath: '/tmp/edit.txt' }
    const upstreamPayload = { kind: 'replaceIfVersion', version: 'v-current' } as const
    const returned = await collector.onFsWriteIntent(target, { name: 'edit' }, () => upstreamPayload)
    expect(returned).toEqual(upstreamPayload) // upstream decision is NOT replaced

    // The intent is held, not emitted: no standalone file_write yet.
    await eventCollector.flush()
    const before = readEvents(config.collector.localOutputPath)
    expect(before.find((e) => e.event_type === 'file_write' && e.path === '/tmp/edit.txt')).toBeUndefined()

    // The matching fs/observed absorbs the decision into ONE audit record.
    collector.onFsObserved(target, { kind: 'present', version: 'v-after' }, { name: 'edit' })
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_write')
    expect(observed).toBeDefined()
    expect(observed.event_type).toBe('file_write')
    expect(observed.path).toBe('/tmp/edit.txt')
    expect(observed.target_key).toBe('fs:5')
    expect(observed.tool_name).toBe('edit')
    expect(observed.file_version).toBe('v-after')
    expect(observed.fs_write_intent).toEqual({ kind: 'replaceIfVersion', version: 'v-current' })
    // Single audit record for the mutation — not a file_write_intent + file_observed pair.
    expect(events.filter((e) => e.target_key === 'fs:5')).toHaveLength(1)
  })

  it('absorbs fs/write-intent as createIfAbsent when upstream returns undefined', async () => {
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:6', displayPath: '/tmp/new.txt' }
    const returned = await collector.onFsWriteIntent(target, { name: 'write' }, () => undefined)
    expect(returned).toBeUndefined() // we don't fabricate a payload when upstream declined

    collector.onFsObserved(target, { kind: 'present', version: 'v-new' }, { name: 'write' })
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_write')
    expect(observed).toBeDefined()
    expect(observed.fs_write_intent).toEqual({ kind: 'createIfAbsent' })
  })

  it('absorbs fs/write-intent when next() returns createIfAbsent', async () => {
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:7', displayPath: '/tmp/created.txt' }
    const returned = await collector.onFsWriteIntent(target, { name: 'write' }, () => ({ kind: 'createIfAbsent' }))
    expect(returned).toEqual({ kind: 'createIfAbsent' })

    collector.onFsObserved(target, { kind: 'present', version: 'v-1' }, { name: 'write' })
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_write')
    expect(observed).toBeDefined()
    expect(observed.fs_write_intent).toEqual({ kind: 'createIfAbsent' })
  })

  it('absorbs fs/write-intent with replaceIfVersion and no version (defensive)', async () => {
    // Defensive: per the harness type contract, replaceIfVersion MUST carry
    // a version, but if a misbehaving listener returns it without one we
    // still absorb the intent shape without crashing.
    const target: FsTarget = { targetKey: 'fs:8', displayPath: '/tmp/x.txt' }
    // Cast through unknown to bypass the type guard — simulating a misbehaving listener.
    const malformed = { kind: 'replaceIfVersion' } as unknown as { kind: 'replaceIfVersion'; version: string }
    const returned = await collector.onFsWriteIntent(target, { name: 'write' }, () => malformed)
    expect(returned).toBe(malformed)

    collector.onFsObserved(target, { kind: 'present', version: 'v-1' }, { name: 'write' })
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_write')
    expect(observed).toBeDefined()
    expect(observed.fs_write_intent).toEqual({ kind: 'replaceIfVersion', version: undefined })
  })

  it('flushes an un-absorbed fs/write-intent as a standalone file_write after fsIntentAbsorbMs', async () => {
    // A write-intent that never sees a matching fs/observed (write failed, or
    // targeted a non-fs path that bypasses the observed emitter) must still
    // surface in the audit trail. Fallback window is fsIntentAbsorbMs (default
    // 2000ms); use a 1ms window + a short delay to test the sweep deterministically.
    const fallbackCollector = new ApplicationCollector(config, eventCollector, undefined, { fsIntentAbsorbMs: 1 })
    fallbackCollector.initialize()
    try {
      const orphan: FsTarget = { targetKey: 'fs:99', displayPath: '/tmp/orphan-write.txt' }
      await fallbackCollector.onFsWriteIntent(orphan, { name: 'write' }, () => ({ kind: 'createIfAbsent' }))
      await new Promise((resolve) => setTimeout(resolve, 10))

      // A later intent (or observed) triggers the sweep of the stale orphan.
      await fallbackCollector.onFsWriteIntent(
        { targetKey: 'fs:100', displayPath: '/tmp/unrelated.txt' },
        undefined,
        () => undefined,
      )
      await eventCollector.flush()

      const events = readEvents(config.collector.localOutputPath)
      const intent = events.find((e) => e.event_type === 'file_write')
      expect(intent).toBeDefined()
      // The orphan is the write that never landed — path identifies it as
      // file_write with fs_write_intent marking the attempt.
      expect(intent.event_type).toBe('file_write')
      expect(intent.path).toBe('/tmp/orphan-write.txt')
      expect(intent.target_key).toBe('fs:99')
      expect(intent.tool_name).toBe('write')
      expect(intent.fs_write_intent).toEqual({ kind: 'createIfAbsent' })
    } finally {
      fallbackCollector.shutdown()
    }
  })

  it('rethrows next() errors so fs-observation-policy can still observe them', async () => {
    const target: FsTarget = { targetKey: 'fs:9', displayPath: '/tmp/boom.txt' }
    await expect(
      collector.onFsWriteIntent(target, undefined, () => {
        throw new Error('upstream blew up')
      }),
    ).rejects.toThrow('upstream blew up')
  })

  it('does not block tools/pre-execute when fs/observed fires (audit-only)', async () => {
    // fs/observed is an emit (not a waterfall) — the handler is fire-and-forget.
    // We verify that emitting the event does not throw and does not mutate
    // the session context in unexpected ways.
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:10', displayPath: '/tmp/post.txt' }
    const observation: FsObservation = { kind: 'present', version: 'v-after' }
    expect(() => collector.onFsObserved(target, observation, { name: 'write' })).not.toThrow()

    await eventCollector.flush()
    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.file_version).toBe('v-after')
  })

  it('correlation by actor: fs/observed attributes tool_name from the actor', async () => {
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:11', displayPath: '/workspace/notes.md' }
    collector.onFsObserved(target, { kind: 'present', version: 'v-1' }, { name: 'str_replace_editor' })

    await eventCollector.flush()
    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.tool_name).toBe('str_replace_editor')
  })

  it('correlation by actor: fs/observed surfaces tool_call_id from actor.callId', async () => {
    // file_read double-fire fix: the fs/observed record is
    // now joinable to the matching `agent_tool_call` / `agent_tool_result`
    // pair via `tool_call_id` (extracted from actor.callId — the same
    // ToolExecution field that the Cordis pre-execute path carries). This
    // closes the "fs-side has no tool_call_id" blind spot that left
    // file_read / file_write records context-less after the
    // pre-execute → agent_tool_call reclassification.
    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:12', displayPath: '/workspace/note.md' }
    const actor = { name: 'file_read', callId: 'call-abc-123' }
    collector.onFsObserved(target, { kind: 'present', version: 'v-1' }, actor)

    await eventCollector.flush()
    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.tool_name).toBe('file_read')
    expect(observed.tool_call_id).toBe('call-abc-123')
  })

  it('correlation by actor: fs/observed emits no tool_call_id when actor.callId is absent', async () => {
    // Defensive regression: if the harness ever delivers an actor without
    // a callId (e.g. a custom tool wrapper that synthesises fs/observed
    // outside the pre-execute path), we must NOT stamp a leftover or
    // synthesised tool_call_id. The field is simply absent.
    const target: FsTarget = { targetKey: 'fs:13', displayPath: '/tmp/anonymous.txt' }
    collector.onFsObserved(target, { kind: 'present', version: 'v-1' }, { name: 'file_read' })

    await eventCollector.flush()
    const events = readEvents(config.collector.localOutputPath)
    const observed = events.find((e) => e.event_type === 'file_read')
    expect(observed).toBeDefined()
    expect(observed.tool_name).toBe('file_read')
    expect(observed.tool_call_id).toBeUndefined()
  })

  // BUG-7 : when `onFsWriteIntent` is wired with a
  // throwing `next()`, the collector emits a `logger.warn` line. The
  // pre-fix implementation had a private inline factory that routed the
  // line into `console` with a `[sst-security-control-dsh]` prefix, bypassing
  // Cordis entirely. Bootstrap should inject `ctx.logger` so the line
  // surfaces in the operator's harness console; this test pins both
  // halves: (1) the seam accepts the injected logger, (2) a real
  // throwing handler emits through it.
  it('onFsWriteIntent routes warn lines through the injected logger ( BUG-7 regression)', async () => {
    const logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
    // Tear down the default collector (which uses console fallback) and
    // rebuild with the injected logger. Mirrors how bootstrap.ts wires
    // `ctx.logger` into the constructor in production.
    collector.shutdown()
    eventCollector.shutdown()
    eventCollector = new LocalNdjsonSink(config, { logger })
    collector = new ApplicationCollector(config, eventCollector, undefined, { logger })
    eventCollector.initialize()
    collector.initialize()

    const agent = makeAgent()
    collector.onAgentSessionStart({ agent, source: 'test' })

    const target: FsTarget = { targetKey: 'fs:50', displayPath: '/tmp/throwing.txt' }
    const boom = new Error('upstream handler exploded')
    await expect(
      collector.onFsWriteIntent(target, { name: 'write' }, () => {
        throw boom
      }),
    ).rejects.toThrow('upstream handler exploded')

    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('fs/write-intent: next() threw'),
      expect.anything(),
    )
  })
})