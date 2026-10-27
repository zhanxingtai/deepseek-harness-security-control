/**
 * policy_evaluation local-volume compression.
 *
 * Background: every persisted event used to carry the full
 * policy_evaluation block (`status` + `matches: []` + `final_match: null`
 * on the empty-hit path, ~110 bytes/event). The empty case is fully
 * derivable — status from the event type's policy applicability,
 * matches/final_match constants — so the sink now persists the minimal
 * `{ schema_version, mode, policy_decision }` when nothing matched, and
 * keeps the full matched shape untouched. An uploader must expand the
 * minimal form back to the platform contract before batch upload.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { normalizeConfig, type Config } from '../src/config.js'
import type { SecurityEvent } from '../src/types/index.js'

function makeConfig(path: string): Config {
  return normalizeConfig({
    collector: {
      localOutputPath: path,
      batchSize: 1,
      flushIntervalMs: 60_000,
      validateEvents: true,
    },
  })
}

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    comm: 'sst-security-control-dsh',
    event_id: 'evt-pe-1',
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

function lines(path: string): SecurityEvent[] {
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l))
}

describe('LocalNdjsonSink policy_evaluation compression', () => {
  let tmpDir: string
  let path: string
  let logger: { log: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-pe-compress-'))
    path = join(tmpDir, 'security-events.jsonl')
    logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('persists the minimal { schema_version, mode, policy_decision } block when nothing matched', () => {
    const sink = new LocalNdjsonSink(makeConfig(path), { logger })
    sink.initialize()
    sink.report(makeEvent({ event_id: 'evt-empty' }))
    sink.shutdown()

    const persisted = lines(path).find((e) => e.event_id === 'evt-empty')!
    expect(persisted).toBeDefined()
    expect(persisted.policy_evaluation).toBeDefined()
    const pe = persisted.policy_evaluation as Record<string, unknown>
    // Default runtime mode is 'enforce'; the minimal block claims it.
    expect(pe).toEqual({ schema_version: 1, mode: 'enforce', policy_decision: 'allow' })
    // The empty-case constants are omitted, not persisted as null/[].
    expect('status' in pe).toBe(false)
    expect('matches' in pe).toBe(false)
    expect('final_match' in pe).toBe(false)
  })

  it('claims the runtime mode on the minimal block (not a hardcoded audit)', () => {
    const sink = new LocalNdjsonSink(
      normalizeConfig({
        mode: 'enforce',
        collector: { localOutputPath: path, batchSize: 1, flushIntervalMs: 60_000, validateEvents: true },
      }),
      { logger },
    )
    sink.initialize()
    sink.report(makeEvent({ event_id: 'evt-enforce-mode' }))
    sink.shutdown()

    const persisted = lines(path).find((e) => e.event_id === 'evt-enforce-mode')!
    expect(persisted.policy_evaluation).toEqual({ schema_version: 1, mode: 'enforce', policy_decision: 'allow' })
  })

  it('keeps the full matched shape (status/matches/final_match) when an intervention is present', () => {
    const sink = new LocalNdjsonSink(makeConfig(path), { logger })
    sink.initialize()
    sink.report(
      makeEvent({
        event_id: 'evt-matched',
        blocked: true,
        intervention: {
          decision: 'deny',
          decision_internal: 'block',
          mode: 'enforce',
          policy_id: 'block-exec-reverse-shell',
          policy_name: 'block-exec-reverse-shell',
        },
      }),
    )
    sink.shutdown()

    const persisted = lines(path).find((e) => e.event_id === 'evt-matched')!
    const pe = persisted.policy_evaluation as Record<string, unknown>
    expect(pe['status']).toBe('matched')
    expect(pe['policy_decision']).toBe('block')
    expect(Array.isArray(pe['matches'])).toBe(true)
    expect((pe['matches'] as unknown[]).length).toBe(1)
    expect(pe['final_match']).toEqual((pe['matches'] as unknown[])[0])
    // block is enforced on the wire shape.
    expect(persisted.blocked).toBe(true)
  })
})
