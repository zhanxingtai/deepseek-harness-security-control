import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { rmSync, mkdtempSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply, name } from '../src/index.js'
import type { Agent, Context, ToolExecution } from '../src/types/external.js'

function makeContext(tmpDir: string): Context & { getListeners(): Record<string, ((...args: unknown[]) => unknown)[]> } {
  const listeners: Record<string, ((...args: unknown[]) => unknown)[]> = {}
  return {
    logger: {
      debug: () => {},
      info: (msg: string) => {},
      warn: (msg: string) => {},
      error: (msg: string) => {},
    },
    on: (event, listener) => {
      listeners[event] = listeners[event] ?? []
      listeners[event].push(listener as (...args: unknown[]) => unknown)
    },
    effect: (dispose) => {
      // Simulate Cordis effect registration; call dispose immediately for cleanup.
      dispose()
    },
    // 2026-09-22 a17a0f2: bootstrap.ts surface probes read
    // `ctx.reflect.get('commands'|'remote')` (the safe-access
    // ReflectService form). The headless fixture mirrors a
    // marketplace node with no optional peers registered, so
    // `get` returns undefined for every name and both surfaces
    // degrade to unavailable — same shape as
    // tests/surfaceVisibility.test.ts.
    reflect: {
      get: () => undefined,
    },
    getListeners: () => listeners,
  } as Context & { getListeners(): typeof listeners }
}

function makeAgent(): Agent {
  return {
    id: 'agent-1',
    session: {
      header: { id: 'session-1', createdAt: Date.now() },
      events: [],
    },
    options: { provider: 'test', model: 'test-model' },
  }
}

describe('Plugin entry point', () => {
  it('exports plugin name', () => {
    // Marketplace short name is `security-monitor` (the
    // bundle id). The wire-protocol `comm` identifier on emitted events
    // is still `sst-security-control-dsh` (see collectors/LocalNdjsonSink.ts
    // header comment) because ingest consumers key off that string.
    expect(name).toBe('security-monitor')
  })

  it('initializes without errors when enabled=false', () => {
    const ctx = makeContext('')
    expect(() => apply(ctx, { enabled: false })).not.toThrow()
  })

  it('registers listeners and emits events to local NDJSON', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'sst-security-control-dsh-'))
    const ctx = makeContext(tmpDir)
    const config = {
      enabled: true,
      mode: 'audit',
      collector: {
        localOutputPath: join(tmpDir, 'events.jsonl'),
        flushIntervalMs: 10,
      },
      application: { enabled: true },
      intervention: { mode: 'audit', policyPath: '/nonexistent.json' },
      // 2026-09-19: pre-marketplace platform-deployment blocks `system` /
      // `assetMonitor` / `environment` removed ( marketplace form).
    }
    apply(ctx, config)

    const toolExec: ToolExecution = {
      callId: 'call-1',
      rootCallId: 'call-1',
      name: 'file_read',
      arguments: { path: '/etc/passwd' },
      agent: makeAgent(),
      signal: new AbortController().signal,
    }

    // Simulate Harness firing the pre-execute event.
    const listeners = ctx.getListeners()
    expect(listeners['tools/pre-execute']).toHaveLength(1)
    const preExec = listeners['tools/pre-execute'][0]
    await preExec(toolExec, async () => ({ kind: 'allow' }))

    // Give the async flush a moment to complete.
    await new Promise((resolve) => setTimeout(resolve, 50))

    const content = readFileSync(join(tmpDir, 'events.jsonl'), 'utf8')
    const events = content
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))

    expect(events.length).toBeGreaterThan(0)
    expect(events[0].comm).toBe('sst-security-control-dsh')
    // 2026-08-18: apply() now emits a `plugin_startup` diagnostic as the
    // first event in headless mode. Filter to the first tool event for
    // assertions about the tools/pre-execute contract.
    const toolEvents = events.filter((e) => e.event_type === 'agent_tool_call')
    expect(toolEvents.length).toBeGreaterThan(0)
    // file_read double-fire fix: the `file_read` event_type
    // is now produced exclusively by `fs/observed`. The pre-execute path
    // emits `agent_tool_call` for file-shaped tools (with the normalised
    // `path` so SPL rules keyed to `path` continue to match).
    expect(toolEvents[0].event_type).toBe('agent_tool_call')
    expect(toolEvents[0].tool_name).toBe('file_read')
    expect(toolEvents[0].path).toBe('/etc/passwd')

    rmSync(tmpDir, { recursive: true, force: true })
  })
})
