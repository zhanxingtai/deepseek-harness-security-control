/**
 * Tests for the /security CLI handler.
 *
 * Coverage:
 *  - registration path: `ctx.commands.register` is called with the
 *    expected command shape (name + subcommand handler)
 *  - `status` subcommand reads sink + engine and renders text
 *  - `recent` reads NDJSON tail and filters block decisions
 *  - `rules` lists the loaded rule set
 *  - `reload` delegates to `InterventionEngine.requestReload()` and
 *    renders success / error
 *  - unknown subcommand → error result
 *
 * Mocks: a minimal `LocalNdjsonSink`-shaped object (just `getStats`,
 * `getLocalOutputPath`) and a real `InterventionEngine` constructed
 * against a temporary policy file so `getLoadedPolicy()` returns a
 * deterministic rule set.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  registerSecurityCommand,
  type CommandDefinition,
  type CommandInvocation,
  type CommandRuntimeShape,
} from '../../src/commands/security.js'
import { InterventionEngine } from '../../src/intervention/InterventionEngine.js'
import type { Context, Logger } from '../../src/types/external.js'
import { normalizeConfig, type Config } from '../../src/config.js'

interface FakeSink {
  getStats: () => { queued: number; flushed: number; dropped: number; errors: number }
  getLocalOutputPath: () => string | undefined
}

function buildContext(commands: CommandRuntimeShape | undefined): Context {
  const logger: Logger = {
    debug() {
      /* noop */
    },
    info() {
      /* noop */
    },
    warn() {
      /* noop */
    },
    error() {
      /* noop */
    },
  }
  // Mirrors the runtime pattern used in src/index.ts: the `commands`
  // service lives on `ctx.commands` once Cordis has resolved
  // `@deepseek-ai/dsh-commands`. The cast makes the stub type pass.
  const ctx = {
    logger,
    on() {
      /* noop */
    },
    effect() {
      /* noop */
    },
    inject() {
      /* noop */
    },
    commands,
  } as unknown as Context
  return ctx
}

function captureRegister(): {
  commands: CommandRuntimeShape
  state: { definition: CommandDefinition | null }
} {
  const state: { definition: CommandDefinition | null } = { definition: null }
  const commands: CommandRuntimeShape = {
    register(definition) {
      state.definition = definition
      return () => {
        /* disposer */
      }
    },
  }
  return { commands, state }
}

function makeInvocation(rawInput: string): CommandInvocation {
  return {
    commandId: 'cmd-test',
    rawInput,
  }
}

let dir: string
let policyPath: string
let engine: InterventionEngine
let config: Config

beforeEach(() => {
  config = normalizeConfig({})

  dir = mkdtempSync(join(tmpdir(), 'sec-mgr-'))
  policyPath = join(dir, 'policy.json')
  writeFileSync(
    policyPath,
    JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'test', version: '1' },
      rules: [
        {
          id: 'TEST_RULE_A',
          name: 'always-block-test-tool',
          enabled: true,
          priority: 100,
          category: 'intrusion_defense',
          match: { toolName: ['test-tool'] },
          action: { decision: 'block', blockReason: 'test reason A', blockCode: 'INTRUSION_DEFENSE_TEST_001' },
        },
        {
          id: 'TEST_RULE_B_DISABLED',
          name: 'disabled rule',
          enabled: false,
          priority: 50,
          category: 'behavior_guidance',
          match: {},
          action: { decision: 'warn' },
        },
      ],
    }),
    'utf8',
  )
  engine = new InterventionEngine(
    {
      intervention: {
        mode: 'audit',
        failStrategy: 'fail_open',
        decisionTimeoutMs: 50,
        policyPath,
        policyPaths: [],
        reloadIntervalMs: 0,
      },
      inlineGuards: { enabled: false },
    } as unknown as Parameters<typeof InterventionEngine.prototype.constructor>[0],
  )
  engine.initialize()
})

afterEach(() => {
  engine.shutdown()
  rmSync(dir, { recursive: true, force: true })
})

describe('registerSecurityCommand', () => {
  it('registers the security command on the dsh-commands runtime', () => {
    const { commands } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    const dispose = registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    expect(typeof dispose).toBe('function')
    // We need a fresh capture object to read the definition; the test
    // above just confirms no throw + disposer is callable.
    dispose()
  })

  it('registers the expected command shape (name + hint + subcommands)', () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    expect(state.definition).not.toBeNull()
    expect(state.definition?.name).toBe('security')
    expect(state.definition?.description).toMatch(/Inspect the security monitor/)
    expect(state.definition?.input?.hint).toMatch(/status.*recent.*rules.*reload/)
    expect(typeof state.definition?.handler).toBe('function')
  })

  it('handler `status` returns a multi-line status text', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 5, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => '/tmp/sink.jsonl',
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    const result = await state.definition!.handler(makeInvocation('status'))
    expect(result.kind).toBe('success')
    if (result.kind === 'success') {
      expect(result.text).toMatch(/mode: /)
      expect(result.text).toMatch(/events: /)
      expect(result.text).toMatch(/rules loaded: 1/)
      expect(result.text).toMatch(/output: \/tmp\/sink.jsonl/)
    }
  })

  it('handler `rules` lists enabled rules and excludes disabled ones', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    const result = await state.definition!.handler(makeInvocation('rules'))
    expect(result.kind).toBe('success')
    if (result.kind === 'success') {
      expect(result.text).toMatch(/1 enabled \/ 1 loaded/)
      expect(result.text).toMatch(/TEST_RULE_A/)
      expect(result.text).not.toMatch(/TEST_RULE_B_DISABLED/)
    }
  })

  it('handler `recent` reads NDJSON tail and filters block decisions', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    // Build a fake NDJSON file with mixed decisions.
    const ndjson = join(dir, 'events.jsonl')
    const lines: string[] = []
    for (let i = 0; i < 5; i++) {
      lines.push(
        JSON.stringify({
          event_type: 'agent_tool_call',
          ts: 1_000 + i,
          session_id: `s-${i}`,
          tool_name: `tool-${i}`,
          intervention: { decision: i === 2 ? 'block' : 'allow' },
        }),
      )
    }
    writeFileSync(ndjson, lines.join('\n') + '\n', 'utf8')
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 5, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    const result = await state.definition!.handler(makeInvocation('recent 5'))
    expect(result.kind).toBe('success')
    if (result.kind === 'success') {
      expect(result.text).toMatch(/recent blocks: 1/)
      expect(result.text).toMatch(/tool-2/)
    }
  })

  it('handler `reload` delegates to engine.requestReload', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    const result = await state.definition!.handler(makeInvocation('reload'))
    expect(result.kind).toBe('success')
    if (result.kind === 'success') {
      expect(result.text).toMatch(/policy reloaded: 1 rules/)
    }
  })

  it('handler returns error for unknown subcommand', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    const result = await state.definition!.handler(makeInvocation('frobnicate'))
    expect(result.kind).toBe('error')
    if (result.kind === 'error') {
      expect(result.text).toMatch(/unknown subcommand/)
    }
  })

  it('handler is forgiving when the engine throws', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    // Patch getLoadedPolicy to throw — the handler must catch and
    // render an error result rather than crash the command runtime.
    const original = engine.getLoadedPolicy.bind(engine)
    engine.getLoadedPolicy = () => {
      throw new Error('simulated engine failure')
    }
    try {
      const result = await state.definition!.handler(makeInvocation('rules'))
      expect(result.kind).toBe('error')
      if (result.kind === 'error') {
        expect(result.text).toMatch(/simulated engine failure/)
      }
    } finally {
      engine.getLoadedPolicy = original
    }
  })

  it('handler `status` returns degraded text when sink is not initialized', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    const result = await state.definition!.handler(makeInvocation('status'))
    expect(result.kind).toBe('success')
    if (result.kind === 'success') {
      expect(result.text).toMatch(/output: \(sink not initialized\)/)
      expect(result.text).toMatch(/0 blocks in last 24h/)
    }
  })

  it('handler `recent` returns an error result when sink is not initialized', async () => {
    const { commands, state } = captureRegister()
    const ctx = buildContext(commands)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityCommand(ctx, sink as unknown as Parameters<typeof registerSecurityCommand>[1], engine, config)
    const result = await state.definition!.handler(makeInvocation('recent 10'))
    expect(result.kind).toBe('error')
    if (result.kind === 'error') {
      expect(result.text).toMatch(/sink not initialized/)
    }
  })
})
