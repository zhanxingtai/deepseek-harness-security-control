import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { rmSync, mkdtempSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { normalizeConfig, type Config } from '../src/config.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../src/collectors/ApplicationCollector.js'
import { PidBindingStore } from '../src/collectors/pidBindingStore.js'
import { validateEvent } from '../src/utils/schema.js'
import type { Agent, ToolExecution } from '../src/types/external.js'

// table-driven refactor of this file. The helpers below are
// deliberately local — tests/helpers/interventionHarness.ts is owned by
// intervention.test.ts and couples to the SPL engine; this file's
// collector-only fixtures stay self-contained.

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

/** Build a ToolExecution bound to `agent`. */
function mkExec(
  agent: Agent,
  name: string,
  arguments_: Record<string, unknown>,
  callId = `call-${name}`,
): ToolExecution {
  return { callId, rootCallId: callId, name, arguments: arguments_, agent, signal: new AbortController().signal }
}

function md5HexFor(s: string): string {
  return createHash('md5').update(s, 'utf8').digest('hex')
}

/** Read the local NDJSON sink's current contents into JSON rows. */
function readEvents(outputPath: string): Array<Record<string, unknown>> {
  return readFileSync(outputPath, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
}

/** Session-start `agent` (a fresh one by default) and return it. */
function sessionStart(app: ApplicationCollector, agent: Agent = makeAgent()): Agent {
  app.onAgentSessionStart({ agent, source: 'test-source' })
  return agent
}

/** Boot a sink + collector pair for `config`; shutdown is guaranteed in
 *  finally. Replaces the try/finally boilerplate that used to precede every
 *  tight-config detector test. */
async function withApp(
  config: Config,
  fn: (app: ApplicationCollector, sink: LocalNdjsonSink) => Promise<void>,
): Promise<void> {
  const sink = new LocalNdjsonSink(config)
  const app = new ApplicationCollector(config, sink)
  sink.initialize()
  app.initialize()
  try {
    await fn(app, sink)
  } finally {
    app.shutdown()
    sink.shutdown()
  }
}

interface CollectorHarness {
  tmpDir: string
  config: Config
  eventCollector: LocalNdjsonSink
  collector: ApplicationCollector
}

/** : boots sink + collector against a fresh tmp dir for each test. The
 *  three top-level describes used to carry byte-identical copies of this
 *  beforeEach/afterEach pair. */
function useCollectorHarness(tmpPrefix: string): () => CollectorHarness {
  const ctx = {} as CollectorHarness
  beforeEach(() => {
    ctx.tmpDir = mkdtempSync(join(tmpdir(), tmpPrefix))
    ctx.config = makeConfig(ctx.tmpDir)
    ctx.eventCollector = new LocalNdjsonSink(ctx.config)
    ctx.collector = new ApplicationCollector(ctx.config, ctx.eventCollector)
    ctx.eventCollector.initialize()
    ctx.collector.initialize()
  })
  afterEach(() => {
    ctx.collector.shutdown()
    ctx.eventCollector.shutdown()
    if (existsSync(ctx.tmpDir)) rmSync(ctx.tmpDir, { recursive: true, force: true })
  })
  return () => ctx
}

describe('ApplicationCollector', () => {
  const h = useCollectorHarness('sst-security-control-dsh-')

  /** helper: session-start + drive callback + flush; returns the emitted
   *  events. Covers every test whose shape is "start a session, drive the
   *  collector, assert on what was persisted". */
  async function runSession(
    drive: (app: ApplicationCollector, agent: Agent) => void | Promise<void>,
  ): Promise<Array<Record<string, unknown>>> {
    const { collector, eventCollector, config } = h()
    const agent = sessionStart(collector)
    await drive(collector, agent)
    await eventCollector.flush()
    return readEvents(config.collector.localOutputPath)
  }

  /** helper: runSession for the single-tool pre-execute shape; returns the
   *  emitted events plus the exec for post-execute follow-ups. */
  async function runTool(
    name: string,
    arguments_: Record<string, unknown>,
    callId?: string,
  ): Promise<{ events: Array<Record<string, unknown>>; exec: ToolExecution }> {
    let exec!: ToolExecution
    const events = await runSession((app, agent) => {
      exec = mkExec(agent, name, arguments_, callId)
      app.onToolPreExecute(exec)
    })
    return { events, exec }
  }

  /** The spec-conformant `agents` descriptor array on `agent_start` for the
   *  default makeAgent() identity. */
  const agentDescriptor = (skills: string[] | null, tools: string[] | null) => [
    { id: 'agent-1', name: 'agent-1', agentDir: null, config: null, skills, tools },
  ]

  // table-driven. The two session-start tests share an identical
  // onAgentSessionStart → flush → assert shape; only the agent overrides and
  // the assertions differ.
  const SESSION_START_CASES: ReadonlyArray<{
    name: string
    agentOverrides?: Partial<Agent>
    asserts: (events: Array<Record<string, unknown>>) => void
  }> = [
    {
      name: 'emits agent_session_start and agent_start on session start',
      asserts: (events) => {
        expect(events).toHaveLength(2)
        expect(events[0].event_type).toBe('agent_session_start')
        expect(events[0].agent_id).toBe('agent-1')
        expect(events[0].session_id).toBe('session-1')
        // fix: `agents` is the spec-conformant descriptor array
        // on `agent_start`. Cordis only surfaces `id` + `options.{provider,
        // model}`, so `agentDir` / `config` / `skills` / `tools` are emitted
        // as `null` (ebpf collectors can fill them from /proc). The loose
        // `agent_id` / `agent_config` / `model_*` keys remain alongside for
        // backward compat.
        expect(events[1].event_type).toBe('agent_start')
        expect(events[1].agent_id).toBe('agent-1')
        expect(events[1].skills).toBeUndefined()
        expect(events[1].tools).toBeUndefined()
        expect(events[1].agents).toEqual(agentDescriptor(null, null))
      },
    },
    {
      name:'emits agent_start with skills and tools when Cordis exposes them',
      agentOverrides: {
        options: { provider: 'test', model: 'test-model', skills: ['web-search'], tools: ['read', 'write'] },
      },
      asserts: (events) => {
        const start = events.find((e) => e.event_type === 'agent_start')
        expect(start).toBeDefined()
        expect(start!.skills).toEqual(['web-search'])
        expect(start!.tools).toEqual(['read', 'write'])
        expect(start!.agents).toEqual(agentDescriptor(['web-search'], ['read', 'write']))
      },
    },
  ]

  it.each(SESSION_START_CASES)('$name', async (tc) => {
    const { collector, eventCollector, config } = h()
    sessionStart(collector, makeAgent(tc.agentOverrides))
    await eventCollector.flush()
    tc.asserts(readEvents(config.collector.localOutputPath))
  })

  // table-driven. The 6 tool-shape tests share an identical
  // session-start → pre-execute → flush → find-by-event_type shape; only the
  // tool name / arguments and the assertions differ, so the assertions ride
  // on each case as `asserts`.
  const TOOL_EVENT_CASES: ReadonlyArray<{
    name: string
    toolName: string
    arguments: Record<string, unknown>
    asserts: (events: Array<Record<string, unknown>>) => void
  }> = [
    {
      name:'emits file_privilege for native chmod/chown/setfacl tools',
      toolName: 'chmod',
      arguments: { path: '/etc/shadow', mode: '777' },
      asserts: (events) => {
        const toolCall = events.find((e) => e.event_type === 'agent_tool_call' && e.tool_name === 'chmod')
        expect(toolCall).toBeDefined()
        const privilege = events.find((e) => e.event_type === 'file_privilege')
        expect(privilege).toBeDefined()
        expect(privilege!.path).toBe('/etc/shadow')
        expect(privilege!.operation).toBe('chmod')
        expect(privilege!.tool_call_id).toBe(toolCall!.tool_call_id)
        expect(privilege!.session_id).toBe('session-1')
      },
    },
    {
      name:'emits file_privilege for shell-derived privilege ops',
      toolName: 'bash',
      arguments: { command: 'chmod 600 /etc/passwd && chown root /etc/passwd' },
      asserts: (events) => {
        const toolCall = events.find((e) => e.event_type === 'agent_tool_call' && e.tool_name === 'bash')
        expect(toolCall).toBeDefined()
        expect(toolCall!.derived_file_ops).toEqual(
          expect.arrayContaining([expect.objectContaining({ op: 'privilege', path: '/etc/passwd' })]),
        )
        const privileges = events.filter((e) => e.event_type === 'file_privilege')
        expect(privileges.length).toBeGreaterThanOrEqual(1)
        expect(privileges.some((e) => e.path === '/etc/passwd')).toBe(true)
      },
    },
    {
      name: 'emits agent_tool_call on tool pre-execute',
      toolName: 'file_read',
      arguments: { path: '/etc/passwd' },
      asserts: (events) => {
        // file_read double-fire fix: the file_read tool
        // now emits `agent_tool_call` from `tools/pre-execute` (the
        // `file_read` event_type is owned by `fs/observed`). The path
        // still rides on the event so SPL rules keyed to `path` continue
        // to fire, and the platform joins the two records by `tool_call_id`.
        const toolCall = events.find((e) => e.event_type === 'agent_tool_call' && e.tool_name === 'file_read')
        expect(toolCall).toBeDefined()
        expect(toolCall!.tool_name).toBe('file_read')
        expect(toolCall!.path).toBe('/etc/passwd')
        expect(toolCall!.session_id).toBe('session-1')
        expect(toolCall!.layer).toBe('application')
        expect(toolCall!.comm).toBe('sst-security-control-dsh')
      },
    },
    {
      // Marketplace form: `tool_params` (the JSON-string carrier) is the
      // only wire-level tool-args field. Sensitive keys are masked in it
      // via `redactRawParams` (invariant "Sensitive keys are masked on
      // persist"), and the ORIGINAL byte length + sha256 fingerprint of
      // the pre-redaction JSON survive on `raw_params_hash` /
      // `raw_params_length` (platform agent contract) for forensic replay.
      name: 'redacts sensitive tool params (tool_params masked, raw fingerprint kept)',
      toolName: 'exec',
      arguments: {
        command: 'curl -H "Authorization: Bearer abc123" https://api.example.com',
        api_key: 'super-secret',
      },
      asserts: (events) => {
        const toolCall = events.find((e) => e.event_type === 'agent_tool_call')
        const params = JSON.parse(toolCall!.tool_params ?? '{}') as Record<string, unknown>
        // tool_params JSON: sensitive KEY-based redaction applies
        // (api_key → ***). KEY-based — a token embedded INSIDE a
        // `command` string survives. Value-pattern scanning is a future
        // extension (audit re-merge boundary).
        expect(params.api_key).toBe('***')
        expect(toolCall!.redacted_keys).toContain('api_key')
        // The marketplace form unconditionally
        // masks tool_params (post-marketplace audit contract — the
        // `collector.redactRawParams` opt-out knob was removed).
        expect(toolCall!.tool_params).not.toContain('super-secret')
        expect(toolCall!.tool_params).toContain('***')
        // Forensic replay fingerprint of the ORIGINAL raw JSON.
        expect(toolCall!.raw_params_length).toBeGreaterThan(0)
        expect(toolCall!.raw_params_hash).toMatch(/^[0-9a-f]{64}$/)
        // JSON.stringify escapes inner double-quotes in the string value, so
        // `Authorization: Bearer abc123` shows up with backslash-escaped quotes.
        // This KEY is NOT in the sensitive-key list, so the value stays.
        expect(toolCall!.tool_params).toContain('Authorization: Bearer abc123')
      },
    },
    {
      // Regression for the 2026-08-17 web run: two `file_write` events dropped
      // as `path: missing required field`. A tool promoted by NAME SUBSTRING
      // (`edit_issue`) whose params carry no file path must not vanish — it
      // should persist as a generic tool_call with its full params.
      name: 'degrades path-less write-named tools to agent_tool_call (no silent drop)',
      toolName: 'edit_issue',
      arguments: { issue_id: 'DSH-42', body: 'close as fixed' },
      asserts: (events) => {
        const toolCall = events.find((e) => e.tool_name === 'edit_issue')
        expect(toolCall).toBeDefined()
        expect(toolCall!.event_type).toBe('agent_tool_call')
        expect(JSON.parse(toolCall!.tool_params ?? '{}')).toMatchObject({ issue_id: 'DSH-42', body: 'close as fixed' })
        expect(events.some((e) => e.event_type === 'file_write')).toBe(false)
      },
    },
    {
      // file_read double-fire fix: `write` emits
      // `agent_tool_call` from the pre-execute path; the `file_write`
      // event_type is produced by `fs/observed`. The path-resolution
      // aliases (destination → path) still flow into the agent_tool_call
      // event so SPL rules keyed to `path` continue to match.
      name: 'resolves destination aliases for write-tool paths',
      toolName: 'write',
      arguments: { destination: '/tmp/dst.txt', content: 'x' },
      asserts: (events) => {
        const write = events.find((e) => e.tool_name === 'write')
        expect(write!.event_type).toBe('agent_tool_call')
        expect(write!.path).toBe('/tmp/dst.txt')
      },
    },
  ]

  it.each(TOOL_EVENT_CASES)('$name', async (tc) => {
    const { events } = await runTool(tc.toolName, tc.arguments)
    tc.asserts(events)
  })

  it('classifies edit/modify/patch as file_write (via fs/observed-only path)', async () => {
    // file_read double-fire fix: edit/modify/patch used to
    // emit `file_write` from `tools/pre-execute`. They now emit
    // `agent_tool_call` (with the normalised path so SPL rules keyed to
    // `path` still fire), and the authoritative `file_write` event_type is
    // produced exclusively by `fs/observed`. We assert on the
    // `agent_tool_call` side here, and the
    // `translates fs/observed into file_read/file_write` suite covers the
    // fs-side classification.
    const events = await runSession(async (app, agent) => {
      for (const toolName of ['edit', 'modify', 'patch']) {
        app.onToolPreExecute(mkExec(agent, toolName, { file_path: '/tmp/x.txt' }, `call-${toolName}`))
      }
    })

    const writes = events.filter(
      (e) => e.event_type === 'agent_tool_call' && ['edit', 'modify', 'patch'].includes(e.tool_name as string),
    )
    expect(writes).toHaveLength(3)
    for (const w of writes) {
      expect(w.path).toBe('/tmp/x.txt')
    }
  })

  it('skips empty agent_message events (post-block harness re-entry)', async () => {
    // Simulate Cordis re-firing agent/pre-step with empty messages — the
    // pattern observed after a blocked tool call (harness retries the loop).
    const events = await runSession(async (app, agent) => {
      await app.onAgentPreStep({ agent, messages: [], turn: 1, signal: new AbortController().signal })
      await app.onAgentPreStep({
        agent,
        messages: [{ role: 'user', content: [{ type: 'text', text: 'real prompt' }] }],
        turn: 2,
        signal: new AbortController().signal,
      })
    })

    const messages = events.filter((e) => e.event_type === 'agent_message')
    expect(messages).toHaveLength(1)
    expect(messages[0].content).toBe('real prompt')
    // message_index must be 0 — only the non-empty turn increments it.
    expect(messages[0].message_index).toBe(0)
  })

  // table-driven. The 4 derived_file_ops cases share an identical
  // setup-then-assert shape (onToolPreExecute → flush → find by tool_name);
  // only the tool name, arguments, and expected derived_file_ops differ.
  const DERIVED_FILE_OPS_CASES: ReadonlyArray<{
    name: string
    toolName: string
    arguments: Record<string, unknown>
    expectOps: unknown  // the expected `derived_file_ops` value (array or undefined)
    expectEventType?: string
  }> = [
    {
      name: 'bash commands reading sensitive files attach shell-derived read+write',
      toolName: 'bash',
      arguments: { command: 'cat /etc/passwd | grep root > /tmp/leak.txt' },
      expectOps: [
        { op: 'read', path: '/etc/passwd', source: 'shell' },
        { op: 'write', path: '/tmp/leak.txt', source: 'shell' },
      ],
      // event_type stays agent_tool_call — derived_file_ops is additive, not a reclassification.
      expectEventType: 'agent_tool_call',
    },
    {
      name: 'python -c inline scripts attach python-derived read',
      toolName: 'python3',
      arguments: { command: `python3 -c "open('/etc/shadow').read()"` },
      expectOps: [{ op: 'read', path: '/etc/shadow', source: 'python' }],
    },
    {
      // Even though args contain "command", this is NOT a shell tool, so the
      // parser must not run — false positives on text payloads are worse than
      // missing them.
      name: 'non-shell tools do NOT attach derived_file_ops',
      toolName: 'web_search',
      arguments: { command: 'cat /etc/passwd' },
      expectOps: undefined,
    },
    {
      // Parser ran (it's a shell-like tool) but found nothing → field is absent.
      name: 'shell tools with no file op omit derived_file_ops',
      toolName: 'exec',
      arguments: { command: 'ls -la /tmp' },
      expectOps: undefined,
      expectEventType: 'agent_tool_call',
    },
  ]

  it.each(DERIVED_FILE_OPS_CASES)('$name', async (tc) => {
    const { events } = await runTool(tc.toolName, tc.arguments)
    const toolCall = events.find((e) => e.tool_name === tc.toolName)
    expect(toolCall).toBeDefined()
    expect(toolCall!.derived_file_ops).toEqual(tc.expectOps)
    if (tc.expectEventType !== undefined) {
      expect(toolCall!.event_type).toBe(tc.expectEventType)
    }
  })

  it('computes a real duration from pre-execute to post-execute', async () => {
    const events = await runSession(async (app, agent) => {
      const exec = mkExec(agent, 'read', { path: '/tmp/x' }, 'call-dur')
      app.onToolPreExecute(exec)
      // Force an observable gap between pre- and post-execute so the duration
      // can't accidentally round to 0.
      await new Promise((r) => setTimeout(r, 25))
      app.onToolPostExecute(exec, {
        isError: false,
        value: null,
        content: [{ type: 'text', text: 'file contents' }],
      })
    })

    const result = events.find((e) => e.event_type === 'agent_tool_result')
    expect(result).toBeDefined()
    // 25ms is a floor; allow some slack but reject the stub's "always 0".
    expect(result!.duration).toBeGreaterThanOrEqual(20)
    expect(result!.execution_duration_ms).toBe(result!.duration)
  })

  // table-driven. Hash attachment tests share the same setup-then-find
  // shape: onToolPreExecute, optionally onToolPostExecute, flush, find the
  // emitted event by (event_type, tool_name), assert the .hash field. The
  // `body` field is the source the md5 was computed from; `eventType` and
  // `toolName` identify which event to find.
  const HASH_ATTACHMENT_CASES: ReadonlyArray<{
    name: string
    toolName: string
    arguments: Record<string, unknown>
    eventType: string
    body: string
    postExecute?: { isError: boolean; value: unknown; content: Array<{ type: string; text: string }>; error?: { message: string } }
    /** Optional extras to assert on the found event beyond .hash. */
    extraAsserts?: (events: Array<Record<string, unknown>>, found: Record<string, unknown>) => void
  }> = [
    {
      // file_read double-fire fix: the intent hash is now
      // attached to the `agent_tool_call` event for write-shaped tools,
      // not to a `file_write` event. The hash is computed from the
      // `content` / `data` / `text` field aliases, gated on the event
      // carrying a normalised path (see onToolPreExecute). The platform
      // uses this hash to correlate "agent tried to write content X" with
      // subsequent reads of the same path, even when the write was blocked.
      name: 'attaches intent hash to write-class agent_tool_call (content fingerprint)',
      toolName: 'write',
      arguments: { path: '/tmp/out.txt', content: 'hello world' },
      eventType: 'agent_tool_call',
      body: 'hello world',
      extraAsserts: (_events, found) => {
        expect(found.path).toBe('/tmp/out.txt')
      },
    },
    {
      // file_read double-fire fix: the code-mode classifier
      // path is unchanged — `run_code` still emits `code_mode_exec`
      // because the file_* classification was the only one removed (the
      // `code_mode_exec` branch in classifyToolEvent is preserved verbatim).
      // The hash is computed from the `code` body. This test guards against
      // a regression accidentally folding code_mode_exec into the generic
      // agent_tool_call stream.
      name: 'attaches intent hash to code_mode_exec (code fingerprint)',
      toolName: 'run_code',
      arguments: { code: 'print(1+1)', language: 'python' },
      eventType: 'code_mode_exec',
      body: 'print(1+1)',
      extraAsserts: (_events, found) => {
        // Hash should match md5('print(1+1)') and be a valid 32-char hex.
        expect(found.hash).toMatch(/^[0-9a-f]{32}$/)
      },
    },
    {
      name: 'attaches result hash to agent_tool_result on success',
      toolName: 'read',
      arguments: { path: '/etc/hostname' },
      eventType: 'agent_tool_result',
      body: 'myhost',
      postExecute: { isError: false, value: null, content: [{ type: 'text', text: 'myhost' }] },
      // Full result is emitted when it fits under toolResultMaxChars (default
      // 100k) — the spec's required `result` carrier (2026-08-17 alignment).
      extraAsserts: (_events, found) => {
        expect(found.result).toBe('myhost')
        expect(found.result_truncated).toBeUndefined()
        expect(found.result_size).toBe(6)
      },
    },
  ]

  it.each(HASH_ATTACHMENT_CASES)('$name', async (tc) => {
    const events = await runSession(async (app, agent) => {
      const exec = mkExec(agent, tc.toolName, tc.arguments)
      app.onToolPreExecute(exec)
      if (tc.postExecute !== undefined) {
        app.onToolPostExecute(exec, tc.postExecute)
      }
    })

    const found = events.find((e) => e.event_type === tc.eventType && e.tool_name === tc.toolName)
    expect(found).toBeDefined()
    expect(found!.hash).toBe(md5HexFor(tc.body))
    tc.extraAsserts?.(events, found!)
  })

  it('emits truncated agent_tool_result when result exceeds toolResultMaxChars', async () => {
    const { eventCollector, config, tmpDir } = h()

    const smallConfig = normalizeConfig({
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      application: { toolResultMaxChars: 8 },
    })
    const smallCollector = new ApplicationCollector(smallConfig, eventCollector)
    smallCollector.initialize()
    try {
      const agent = sessionStart(smallCollector)
      const exec = mkExec(agent, 'bash', { command: 'echo hi' }, 'call-big')
      smallCollector.onToolPreExecute(exec)
      smallCollector.onToolPostExecute(exec, {
        isError: false,
        value: null,
        content: [{ type: 'text', text: 'this output is longer than eight' }],
      })
      await eventCollector.flush()

      const events = readEvents(config.collector.localOutputPath)
      const result = events.find((e) => e.event_type === 'agent_tool_result')
      expect(result).toBeDefined()
      expect(result!.result).toBeUndefined()
      expect(result!.result_truncated).toBe(true)
      expect((result!.result_preview as string).length).toBeLessThanOrEqual(4000)
      expect(result!.result_size).toBe(32)
      // Full-length fingerprint survives even when the content is dropped.
      expect(result!.hash).toBe(md5HexFor('this output is longer than eight'))
    } finally {
      smallCollector.shutdown()
    }
  })

  it('does NOT attach result hash when the tool failed', async () => {
    const events = await runSession((app, agent) => {
      const exec = mkExec(agent, 'read', { path: '/nope' }, 'call-fail')
      app.onToolPreExecute(exec)
      app.onToolPostExecute(exec, {
        isError: true,
        error: { message: 'ENOENT' },
        content: [],
      })
    })

    const result = events.find((e) => e.event_type === 'agent_tool_result')
    expect(result).toBeDefined()
    expect(result!.hash).toBeUndefined()
    expect(result!.error_message).toBe('ENOENT')
    // fix: failure path now emits `result:''` so the
    // platform spec's required-field contract holds for the failure class
    // too. Without this, joins on `result` would lose every failure event.
    expect(result!.result).toBe('')
  })

  it('emits agent_stop.duration = now - sessionStartTs (  fix)', async () => {
    // Force an observable gap between session start and turn-stopping so the
    // computed duration is unambiguously non-zero.
    const events = await runSession(async (app, agent) => {
      await new Promise((r) => setTimeout(r, 25))
      app.onAgentTurnStopping({ agent, turn: 1 })
    })

    const stop = events.find((e) => e.event_type === 'agent_stop')
    expect(stop).toBeDefined()
    // 6 fix: agent_stop exit_code is **required** by the platform
    // per-type schema. Cordis doesn't surface one, so we derive 0 (clean) or
    // 64 (any prior tool_call in this session was `blocked`).
    expect(typeof stop!.exit_code).toBe('number')
    expect(Number.isInteger(stop!.exit_code)).toBe(true)
    expect(typeof stop!.duration).toBe('number')
    expect(stop!.duration).toBeGreaterThanOrEqual(20)
  })

  it('honors DSH_TOOLS_MODE=code env when computing is_code_mode', async () => {
    const prev = process.env.DSH_TOOLS_MODE
    process.env.DSH_TOOLS_MODE = 'code'
    try {
      // NOT run_code — should still be flagged as code mode via env
      const events = await runSession((app, agent) => {
        app.onToolPreExecute(mkExec(agent, 'bash', { command: 'echo hi' }, 'call-env-code'))
      })

      const toolCall = events.find((e) => e.event_type === 'agent_tool_call' && e.tool_name === 'bash')
      expect(toolCall).toBeDefined()
      expect(toolCall!.is_code_mode).toBe(true)
    } finally {
      if (prev === undefined) delete process.env.DSH_TOOLS_MODE
      else process.env.DSH_TOOLS_MODE = prev
    }
  })

  it('correlates concurrent tool invocations by callId (not synthetic stepIndex)', async () => {
    // fix: three concurrent reads with distinct callIds each
    // get a unique synthetic tool_call_id on pre-execute (:read:0 /
    // :read:1 / :read:2). The post-executes used to rebuild tool_call_id
    // from the CURRENT stepIndex, so by the time post-execute fired for
    // the first two reads, stepIndex had already advanced to 2 — all three
    // post-executes collapsed onto :read:2's pending entry, losing two
    // results and emitting three results under :read:2's id. The fix keys
    // pendingToolStarts / blockedCalls by `exec.callId`; synthetic ids on
    // emitted events are unchanged.
    const { collector, eventCollector, config } = h()
    const agent = sessionStart(collector)

    const reads = [
      { callId: 'call-r0', path: '/tmp/a', content: 'AAA' },
      { callId: 'call-r1', path: '/tmp/b', content: 'BBB' },
      { callId: 'call-r2', path: '/tmp/c', content: 'CCC' },
    ]
    for (const r of reads) {
      collector.onToolPreExecute(mkExec(agent, 'read', { path: r.path }, r.callId))
      // Stagger pre-executes so each one sees a fresh stepIndex.
      await new Promise((res) => setTimeout(res, 5))
    }
    // Post in REVERSE order to exercise the previous lookup-collision path
    // (the latest pre-execute is the first to fire its post-execute).
    for (const r of [reads[2], reads[0], reads[1]]) {
      collector.onToolPostExecute(mkExec(agent, 'read', { path: r.path }, r.callId), {
        isError: false,
        value: null,
        content: [{ type: 'text', text: r.content }],
      })
    }
    await eventCollector.flush()

    const events = readEvents(config.collector.localOutputPath)
    const toolCalls = events.filter((e) => e.event_type === 'agent_tool_call' && e.tool_name === 'read')
    const toolResults = events.filter((e) => e.event_type === 'agent_tool_result' && e.tool_name === 'read')

    expect(toolCalls).toHaveLength(3)
    expect(toolResults).toHaveLength(3)

    // The three synthetic ids are distinct — pre-execute stamped one each
    // and post-execute recovered the matching one (not the latest sibling).
    const callIds = new Set(toolCalls.map((e) => e.tool_call_id as string))
    expect(callIds.size).toBe(3)
    // Every pre-execute id is echoed by exactly one post-execute.
    for (const id of callIds) {
      expect(toolResults.some((r) => r.tool_call_id === id)).toBe(true)
    }

    // Pair pre/post by tool_call_id and assert each pair carries the same
    // path (call side) and its own result body (result side) — the
    // pre-fix bug collapsed all three onto one id, so the call:0 path
    // ended up under call:2's result, etc.
    const callsById = new Map(toolCalls.map((e) => [e.tool_call_id as string, e]))
    const resultsById = new Map(toolResults.map((e) => [e.tool_call_id as string, e]))
    for (const r of reads) {
      const expectedId = `${agent.session.header.id}:${agent.session.header.id}:read:${reads.indexOf(r)}`
      const tc = callsById.get(expectedId)
      const tr = resultsById.get(expectedId)
      expect(tc).toBeDefined()
      expect(tr).toBeDefined()
      expect(tc!.path).toBe(r.path)
      expect(tr!.result).toBe(r.content)
    }
  })

  // invariant #6 leak fix — every `agent_tool_call`
  // event surfaces `user_prompt` on the audit row, and users frequently
  // paste Bearer tokens / API keys / URLs with query secrets into
  // prompts. Pre-fix the prompt landed on disk verbatim; post-fix the
  // same `redactStreamContent` helper the stdio mirror uses
  // masks the prompt AND surfaces the family on the union
  // `redacted_keys` list so audit consumers can see prompt-side hits
  // alongside the tool_params-side hits.
  describe('user_prompt invariant #6 leak fix', () => {
    it('redacts Bearer tokens in user_prompt before emit', async () => {
      const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc'
      const events = await runSession(async (app, agent) => {
        await app.onAgentPreStep({
          agent,
          messages: [{ role: 'user', content: [{ type: 'text', text: `Help me debug this curl call: curl -H "Authorization: Bearer ${token}" https://api.example.com` }] }],
          turn: 1,
          signal: new AbortController().signal,
        })
        const exec = mkExec(agent, 'read', { path: '/tmp/x' }, 'call-redact')
        app.onToolPreExecute(exec)
      })
      const toolCall = events.find((e) => e.event_type === 'agent_tool_call')
      expect(toolCall).toBeDefined()
      // The raw token must NOT survive on the audit row.
      expect(JSON.stringify(toolCall)).not.toContain(token)
      expect(toolCall!.user_prompt).toContain('Bearer ***')
      expect(toolCall!.user_prompt).not.toContain(token)
      // user_prompt-side hits land on the union `redacted_keys` list.
      expect(Array.isArray(toolCall!.redacted_keys)).toBe(true)
      expect(toolCall!.redacted_keys).toContain('bearer_token')
      // The union `redacted_keys` includes the prompt-side hit too.
      expect(toolCall!.redacted_keys).toContain('bearer_token')
    })

    it('redacts URL query-string secrets in user_prompt', async () => {
      const events = await runSession(async (app, agent) => {
        await app.onAgentPreStep({
          agent,
          messages: [{ role: 'user', content: [{ type: 'text', text: 'open https://api.example.com/?token=secret123&user=alice' }] }],
          turn: 1,
          signal: new AbortController().signal,
        })
        const exec = mkExec(agent, 'read', { path: '/tmp/x' }, 'call-qs')
        app.onToolPreExecute(exec)
      })
      const toolCall = events.find((e) => e.event_type === 'agent_tool_call')
      expect(toolCall).toBeDefined()
      expect(JSON.stringify(toolCall)).not.toContain('secret123')
      expect(toolCall!.user_prompt).toContain('token=***')
      expect(toolCall!.user_prompt).toContain('user=alice')
      expect(toolCall!.redacted_keys).toContain('query.token')
    })

    it('leaves benign user_prompt untouched (clean control)', async () => {
      const events = await runSession(async (app, agent) => {
        await app.onAgentPreStep({
          agent,
          messages: [{ role: 'user', content: [{ type: 'text', text: 'please list files in /tmp' }] }],
          turn: 1,
          signal: new AbortController().signal,
        })
        const exec = mkExec(agent, 'read', { path: '/tmp/x' }, 'call-clean')
        app.onToolPreExecute(exec)
      })
      const toolCall = events.find((e) => e.event_type === 'agent_tool_call')
      expect(toolCall!.user_prompt).toBe('please list files in /tmp')
      expect(toolCall!.redacted_keys).toEqual([])
    })
  })
})

describe('ApplicationCollector PID session cache', () => {
  const h = useCollectorHarness('dsh-app-pid-')

  // table-driven. The two pure-resolution tests share identical
  // setup (onAgentSessionStart → resolve by pid → assert sessionId) and
  // differ only in which resolver method + which field is asserted.
  const PID_RESOLVE_CASES: ReadonlyArray<{
    name: string
    resolve: (pid: number) => { sessionId: string; agentId?: string; httpSessionId?: string } | undefined
    expectedSessionId: string
    expectedAgentId?: string
  }> = [
    {
      name: 'binds process.pid to session on session start and pre-execute',
      resolve: (pid) => h().collector.resolveSessionByPid(pid),
      expectedSessionId: 'session-1',
      expectedAgentId: 'agent-1',
    },
    {
      name: 'resolves HTTP session by pid fallback',
      resolve: (pid) => h().collector.resolveHttpSessionByPid(pid),
      expectedSessionId: 'session-1',
    },
  ]

  it.each(PID_RESOLVE_CASES)('$name', (tc) => {
    sessionStart(h().collector)
    const resolved = tc.resolve(process.pid)
    expect(resolved).toBeDefined()
    expect(resolved!.sessionId).toBe(tc.expectedSessionId)
    if (tc.expectedAgentId !== undefined) {
      expect(resolved!.agentId).toBe(tc.expectedAgentId)
    }
  })

  it('evicts stale pid bindings during TTL sweep', () => {
    const { collector } = h()
    const agent = sessionStart(collector)
    expect(collector.resolveSessionByPid(process.pid)).toBeDefined()
    // Directly invoke the private sweep to avoid the long timer interval
    // (default 15 min). The sweep prunes entries older than sessionTtlMs.
    const priv = collector as unknown as {
      evictStaleSessions: () => void
      pidSessionMap: { setTs: (pid: number, ts: number) => void }
      sessions: Map<string, { lastUserMessageAt?: number }>
    }
    // a fresh session-start alone leaves
    // `lastUserMessageAt` undefined — the FIRST evictStaleSessions pass
    // would (correctly, current) treat that as expired and delete both
    // the session AND its pid bindings, so the previous assertion that
    // `resolveSessionByPid` stays defined used to depend on the orphan-
    // binding bug the fix closed. To preserve the"fresh session
    // pid still bound" baseline we stamp lastUserMessageAt = nowMs() so
    // the session survives the first sweep and only the artificially-
    // aged pid binding is pruned by the second sweep.
    priv.sessions.get(agent.session.header.id)!.lastUserMessageAt = Date.now()
    priv.evictStaleSessions()
    expect(collector.resolveSessionByPid(process.pid)).toBeDefined()
    // Artificially age the binding beyond TTL by mutating its `ts` via
    // the test-only `setTs ` helper on PidBindingStore (added by —
    // the pre-refactor code mutated `entry.ts = 0` directly on the Map's
    // returned reference; post-refactor PidBindingStore.get() returns a
    // fresh copy so callers cannot accidentally re-order the eviction).
    priv.pidSessionMap.setTs(process.pid, 0)
    priv.evictStaleSessions()
    expect(collector.resolveSessionByPid(process.pid)).toBeUndefined()
  })

  // A-L2 (2026-09-25): defensive guards layered onto bindPidToSession.
  // Without them, a cross-platform pid_t of 0/-1/NaN or a fork burst
  // could pollute the resolver or grow the map unbounded.
  describe('A-L2 — pid binding defensive guards', () => {
    it('rejects invalid PIDs (≤1, NaN, ±Infinity)', () => {
      const { collector } = h()
      sessionStart(collector)
      const priv = collector as unknown as {
        pidSessionMap: { size: number }
        sessions: Map<string, { sessionId: string; runId: string; agentId: string }>
      }
      const baseline = priv.pidSessionMap.size
      // The synthetic session we pass into bindPidToSession must be a real
      // SessionContext — pull one out of the in-memory cache via the private
      // surface (the public API exposes SessionContext only via the agent
      // path on onAgentSessionStart, which we don't want to repeat here).
      const session = priv.sessions.values().next().value as { sessionId: string; runId: string; agentId: string }
      expect(session).toBeDefined()
      // Negative/zero/one PIDs are kernel/init sentinels — must NOT bind.
      collector.bindPidToSession(0, session)
      collector.bindPidToSession(1, session)
      collector.bindPidToSession(-1, session)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      collector.bindPidToSession(Number.NaN as any, session)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      collector.bindPidToSession(Number.POSITIVE_INFINITY as any, session)
      expect(priv.pidSessionMap.size).toBe(baseline)
    })

    it('force-evicts oldest entries when the cap is exceeded', () => {
      const { collector } = h()
      sessionStart(collector)
      const priv = collector as unknown as {
        pidSessionMap: {
          size: number
          has: (pid: number) => boolean
        }
        sessions: Map<string, { sessionId: string; runId: string; agentId: string }>
      }
      const session = priv.sessions.values().next().value as { sessionId: string; runId: string; agentId: string }
      expect(session).toBeDefined()
      // cap constant moved from ApplicationCollector to
      // PidBindingStore.MAX_SIZE. The test still seeds the map to exactly
      // the cap with synthetic pid bindings and asserts the LRU-by-`ts`
      // eviction order on the (1_000_000 + i) seed range.
      const max = PidBindingStore.MAX_SIZE
      // Seed the map to exactly the cap with synthetic pid bindings.
      for (let i = 0; i < max; i += 1) {
        collector.bindPidToSession(1_000_000 + i, session)
      }
      expect(priv.pidSessionMap.size).toBe(max)
      // One more bind crosses the cap and triggers force-eviction of the
      // oldest entry (pid=1_000_000, ts=smallest).
      collector.bindPidToSession(2_000_000, session)
      expect(priv.pidSessionMap.size).toBe(max)
      // The freshest binding is preserved; the oldest is gone.
      expect(priv.pidSessionMap.has(2_000_000)).toBe(true)
      expect(priv.pidSessionMap.has(1_000_000)).toBe(false)
      // A second bind crosses again and evicts the next-oldest.
      collector.bindPidToSession(2_000_001, session)
      expect(priv.pidSessionMap.size).toBe(max)
      expect(priv.pidSessionMap.has(2_000_001)).toBe(true)
      expect(priv.pidSessionMap.has(1_000_001)).toBe(false)
    })

    it('shutdown() clears pidSessionMap alongside sessions + recentUserMessages', () => {
      const { collector } = h()
      sessionStart(collector)
      const priv = collector as unknown as {
        pidSessionMap: { size: number }
      }
      expect(priv.pidSessionMap.size).toBeGreaterThan(0)
      collector.shutdown()
      expect(priv.pidSessionMap.size).toBe(0)
    })
  })

  // §6.2 : looped-tool detector integration. The detector
  // is wired into onToolPreExecute (record call) and evictStaleSessions
  // (clearSession). Threshold + window can be tightened via config so
  // the test runs in ms rather than waiting for 100 calls / minute.
  describe('looped tool detector', () => {
    function tightDetectorConfig(overrides: Record<string, unknown> = {}): Config {
      return normalizeConfig({
        collector: {
          localOutputPath: join(h().tmpDir, 'security-events.jsonl'),
          flushIntervalMs: 10,
        },
        loopedToolDetector: {
          enabled: true,
          windowMs: 60_000,
          thresholdPerWindow: 5,
          ...overrides,
        },
      })
    }

    it('emits a security_audit/looped_tool event when a single tool crosses the threshold', async () => {
      const config = tightDetectorConfig()
      await withApp(config, async (app, sink) => {
        const agent = sessionStart(app)
        // 6 calls of bash within the window; threshold=5 → first 5 stay
        // silent, the 6th fires the audit event.
        for (let i = 0; i < 6; i++) {
          app.onToolPreExecute(mkExec(agent, 'bash', { command: `echo ${i}` }, `call-bash-${i}`))
        }
        await sink.flush()

        const events = readEvents(config.collector.localOutputPath)
        const audit = events.find(
          (e) => e.event_type === 'security_audit' && e.audit_action === 'detect',
        )
        expect(audit).toBeDefined()
        expect(audit!.audit_category).toBe('behavior')
        expect(audit!.severity).toBe('medium')
        expect(audit!.tool_name).toBe('bash')
        expect(audit!.session_id).toBe('session-1')
        expect(audit!.reason).toContain('per-tool loop detected')
        expect(audit!.reason).toContain('bash')
        expect(audit!.reason).toContain('6/5')
        const details = audit!.audit_details as Record<string, unknown>
        expect(details.event_type_alias).toBe('looped_tool')
        expect(details.tool_name).toBe('bash')
        expect(details.session_id).toBe('session-1')
        expect(details.call_count).toBe(6)
        expect(details.threshold).toBe(5)
        expect(details.window_ms).toBe(60_000)
      })
    })

    // table-driven. The three no-fire cases share an identical boot →
    // drive calls → flush → expect zero detect-audits shape; only the
    // detector config overrides and the driven calls differ.
    const LOOPED_NOFIRE_CASES: ReadonlyArray<{
      name: string
      overrides: Record<string, unknown>
      drive: (app: ApplicationCollector, agent: Agent) => void
    }> = [
      {
        name: 'does NOT emit when the threshold is not crossed',
        overrides: {},
        // 4 calls — strictly below threshold=5. No audit expected.
        drive: (app, agent) => {
          for (let i = 0; i < 4; i++) {
            app.onToolPreExecute(mkExec(agent, 'bash', { command: `echo ${i}` }, `call-bash-${i}`))
          }
        },
      },
      {
        name: 'isolates the counter per (session, tool) pair',
        overrides: {},
        // Interleave bash + edit; each tool gets its own counter, so
        // neither crosses the threshold individually.
        drive: (app, agent) => {
          for (let i = 0; i < 4; i++) {
            app.onToolPreExecute(mkExec(agent, 'bash', { command: `echo ${i}` }, `call-bash-${i}`))
            app.onToolPreExecute(mkExec(agent, 'edit', { path: `/tmp/${i}` }, `call-edit-${i}`))
          }
        },
      },
      {
        name: 'disabled config is a no-op even when the threshold would fire',
        overrides: { enabled: false, thresholdPerWindow: 1 },
        drive: (app, agent) => {
          for (let i = 0; i < 5; i++) {
            app.onToolPreExecute(mkExec(agent, 'bash', { command: `echo ${i}` }, `call-bash-${i}`))
          }
        },
      },
    ]

    it.each(LOOPED_NOFIRE_CASES)('$name', async (tc) => {
      const config = tightDetectorConfig(tc.overrides)
      await withApp(config, async (app, sink) => {
        const agent = sessionStart(app)
        tc.drive(app, agent)
        await sink.flush()

        const events = readEvents(config.collector.localOutputPath)
        const audits = events.filter(
          (e) => e.event_type === 'security_audit' && e.audit_action === 'detect',
        )
        expect(audits).toHaveLength(0)
      })
    })

    it('clearSession via evictStaleSessions drops the per-session detector state', async () => {
      // Construct a collector, drive 4 calls in session-1, then directly
      // invoke the private sweep to drop session-1 (after artificially
      // aging the lastUserMessageAt). A fresh session with the same id
      // should start at zero — verify by driving 4 calls again and
      // confirming the audit event did not fire.
      const config = tightDetectorConfig()
      await withApp(config, async (app) => {
        const agent = sessionStart(app)
        for (let i = 0; i < 4; i++) {
          app.onToolPreExecute(mkExec(agent, 'bash', { command: `echo ${i}` }, `call-pre-${i}`))
        }
        // Age the session past TTL so the sweep evicts it.
        const sessions = (app as unknown as { sessions: Map<string, { lastUserMessageAt?: number }> }).sessions
        const session = sessions.get('session-1')
        expect(session).toBeDefined()
        session!.lastUserMessageAt = 0
        ;(app as unknown as { evictStaleSessions: () => void }).evictStaleSessions()
        // After eviction, the detector state is dropped. A fresh session
        // start with the same id should start at zero.
        sessionStart(app)
        for (let i = 0; i < 4; i++) {
          app.onToolPreExecute(mkExec(agent, 'bash', { command: `echo ${i}` }, `call-post-${i}`))
        }
        // 4 calls in the new session stay below threshold=5 — the
        // detector state was cleared by evictStaleSessions, so the
        // post-eviction 4 calls do not carry over the pre-eviction count.
        const detector = (app as unknown as { loopedToolDetector: { size: () => number } }).loopedToolDetector
        expect(detector.size()).toBe(4)
      })
    })
  })

  // §6.2 : token-usage burst detector
  // integration. The detector is fed by the `llm/stream` tee
  // (`onLlmStream`) and cleared by `evictStaleSessions`. Learning floor +
  // burst factor are configurable so the test runs in one stream.
  describe('token usage detector', () => {
    function tightTokenConfig(overrides: Record<string, unknown> = {}): Config {
      return normalizeConfig({
        collector: {
          localOutputPath: join(h().tmpDir, 'security-events.jsonl'),
          flushIntervalMs: 10,
        },
        tokenUsageDetector: {
          enabled: true,
          windowMs: 60_000,
          burstFactor: 3,
          minBaselineSamples: 5,
          ...overrides,
        },
      })
    }

    async function drain(stream: AsyncIterable<unknown>): Promise<unknown[]> {
      const out: unknown[] = []
      for await (const chunk of stream) out.push(chunk)
      return out
    }

    async function* streamOf(chunks: Array<Record<string, unknown>>): AsyncIterable<Record<string, unknown>> {
      for (const c of chunks) yield c
    }

    function usageChunk(total: number): Record<string, unknown> {
      return {
        type: 'usage',
        usage: { inputTokens: Math.round(total / 2), outputTokens: total - Math.round(total / 2), totalTokens: total },
      }
    }

    /** Session-start + one tool pre-execute so the detector's session
     *  attribution (mostRecentSession) resolves to session-1. */
    function establishSession(app: ApplicationCollector): void {
      const agent = sessionStart(app)
      app.onToolPreExecute(mkExec(agent, 'bash', { command: 'echo warm' }, 'call-0'))
    }

    it('emits security_audit/anomalous_token_usage on a 10x burst while the stream passes through untouched', async () => {
      const config = tightTokenConfig()
      await withApp(config, async (app, sink) => {
        establishSession(app)
        const chunks: Record<string, unknown>[] = [
          { type: 'text', text: 'turn 1' },
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(1000), // 6th call, 10x the learned 100-token baseline
          { type: 'text', text: 'done' },
        ]
        const out = (await drain(app.onLlmStream({}, streamOf(chunks)))) as Record<string, unknown>[]
        // Tee transparency: every chunk delivered, identity preserved.
        expect(out).toEqual(chunks)
        expect(out[6]).toBe(chunks[6])

        await sink.flush()
        const events = readEvents(config.collector.localOutputPath)
        const audit = events.find(
          (e) =>
            e.event_type === 'security_audit' &&
            (e.audit_details as Record<string, unknown> | undefined)?.event_type_alias ===
              'anomalous_token_usage',
        )
        expect(audit).toBeDefined()
        expect(audit!.audit_category).toBe('behavior')
        expect(audit!.audit_action).toBe('detect')
        expect(audit!.severity).toBe('medium')
        expect(audit!.session_id).toBe('session-1')
        expect(audit!.token_usage_total).toBe(1000)
        expect(audit!.token_usage_prompt).toBe(500)
        expect(audit!.token_usage_completion).toBe(500)
        expect(audit!.reason).toContain('anomalous token usage')
        const details = audit!.audit_details as Record<string, unknown>
        expect(details.event_type_alias).toBe('anomalous_token_usage')
        expect(details.session_id).toBe('session-1')
        expect(details.total_tokens).toBe(1000)
        expect(details.baseline_tokens).toBe(100)
        expect(details.ratio).toBe(10)
        expect(details.burst_factor).toBe(3)
        expect(details.sample_count).toBe(6)
        expect(details.window_ms).toBe(60_000)
        // The emitted event must pass the platform schema validator.
        expect(validateEvent(audit)).toEqual([])
      })
    })

    // table-driven. Both no-fire cases share an identical establish →
    // stream usage chunks → drain → expect zero detect-audits shape; only
    // the config overrides and chunk list differ.
    const TOKEN_NOFIRE_CASES: ReadonlyArray<{
      name: string
      overrides: Record<string, unknown>
      chunks: Array<Record<string, unknown>>
    }> = [
      {
        name: 'learning floor: a 10x burst inside the first 5 calls emits nothing',
        overrides: {},
        chunks: [
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(1000), // 5th call — still inside minBaselineSamples=5
        ],
      },
      {
        name: 'disabled config is a no-op even on a 10x burst',
        overrides: { enabled: false },
        chunks: [
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(100),
          usageChunk(1000),
        ],
      },
    ]

    it.each(TOKEN_NOFIRE_CASES)('$name', async (tc) => {
      const config = tightTokenConfig(tc.overrides)
      await withApp(config, async (app, sink) => {
        establishSession(app)
        await drain(app.onLlmStream({}, streamOf(tc.chunks)))
        await sink.flush()

        const events = readEvents(config.collector.localOutputPath)
        const audits = events.filter((e) => e.event_type === 'security_audit' && e.audit_action === 'detect')
        expect(audits).toHaveLength(0)
      })
    })
  })
})

describe('ApplicationCollector.emitFailSafeAudit (A-L1 — 2026-09-25)', () => {
  // A-L1 closes the operator-visibility gap: when a Cordis listener wrapped
  // by safeHandler throws, the warn line scrolls past but operators have
  // no aggregate signal. emitFailSafeAudit writes a `security_audit/fail_safe`
  // event so sustained bursts of handler failures become queryable.

  it('emits a security_audit/fail_safe event with handler_name + error_class + message', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-failsafe-'))
    const config = makeConfig(tmpDir)
    await withApp(config, async (app, sink) => {
      const handlerError = new Error('something exploded')
      handlerError.name = 'CustomBoom'
      app.emitFailSafeAudit('agent/pre-step', handlerError)
      await sink.flush()

      const events = readEvents(config.collector.localOutputPath)
      const audit = events.find(
        (e) =>
          e.event_type === 'security_audit' &&
          (e.audit_details as Record<string, unknown> | undefined)?.event_type_alias === 'fail_safe',
      )
      expect(audit).toBeDefined()
      expect(audit!.audit_category).toBe('runtime')
      expect(audit!.audit_action).toBe('detect')
      expect(audit!.severity).toBe('medium')
      expect(audit!.outcome).toBe('success')
      // Session identity is best-effort; no session context exists at
      // emit time (handler may have crashed before session-start), so
      // the audit falls back to the plugin-level identity.
      expect(audit!.session_id).toBe(null)
      expect(audit!.agent_id).toBe(null)
      expect(audit!.reason).toContain('agent/pre-step')
      expect(audit!.reason).toContain('CustomBoom')

      const details = audit!.audit_details as Record<string, unknown>
      expect(details.event_type_alias).toBe('fail_safe')
      expect(details.handler_name).toBe('agent/pre-step')
      expect(details.error_class).toBe('CustomBoom')
      expect(details.error_message).toBe('something exploded')
      // detail explains the safety-net catch to operators
      expect(details.detail).toContain('agent/pre-step')
      expect(details.detail).toContain('invariant #3')

      // The emitted event must pass the platform schema validator.
      expect(validateEvent(audit)).toEqual([])
    })
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('handles non-Error throws (string, undefined) by stringifying safely', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-failsafe-string-'))
    const config = makeConfig(tmpDir)
    await withApp(config, async (app, sink) => {
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      app.emitFailSafeAudit('tools/result', 'string-throw-not-an-error')
      app.emitFailSafeAudit('tools/post-execute', undefined)
      await sink.flush()

      const events = readEvents(config.collector.localOutputPath)
      const audits = events.filter(
        (e) =>
          e.event_type === 'security_audit' &&
          (e.audit_details as Record<string, unknown> | undefined)?.event_type_alias === 'fail_safe',
      )
      expect(audits).toHaveLength(2)

      const stringAudit = audits.find(
        (a) => (a.audit_details as Record<string, unknown>).handler_name === 'tools/result',
      )
      expect(stringAudit).toBeDefined()
      const stringDetails = stringAudit!.audit_details as Record<string, unknown>
      expect(stringDetails.error_class).toBe('string')
      expect(stringDetails.error_message).toBe('string-throw-not-an-error')

      const undefAudit = audits.find(
        (a) => (a.audit_details as Record<string, unknown>).handler_name === 'tools/post-execute',
      )
      expect(undefAudit).toBeDefined()
      const undefDetails = undefAudit!.audit_details as Record<string, unknown>
      expect(undefDetails.error_class).toBe('undefined')
      expect(undefDetails.error_message).toBe('undefined')
    })
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('truncates long error messages to keep the NDJSON entry bounded', async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-failsafe-trunc-'))
    const config = makeConfig(tmpDir)
    await withApp(config, async (app, sink) => {
      const long = 'x'.repeat(5000)
      app.emitFailSafeAudit('agent/created', new Error(long))
      await sink.flush()

      const events = readEvents(config.collector.localOutputPath)
      const audit = events.find(
        (e) =>
          e.event_type === 'security_audit' &&
          (e.audit_details as Record<string, unknown> | undefined)?.event_type_alias === 'fail_safe',
      )
      const details = audit!.audit_details as Record<string, unknown>
      // truncateString caps at 240 chars for error_message and appends
      // an ellipsis suffix ("...") when truncated, so the actual
      // observed bound is 240 + 3 = 243. The audit entry is bounded —
      // a 5000-char message would otherwise balloon the NDJSON file.
      expect((details.error_message as string).length).toBeLessThanOrEqual(243)
      expect((details.error_message as string).length).toBeGreaterThan(0)
    })
    rmSync(tmpDir, { recursive: true, force: true })
  })
})
