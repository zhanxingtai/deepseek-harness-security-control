/**
 * Graceful-degradation tests for /security.
 *
 * When the marketplace node does not have `@deepseek-ai/dsh-commands`
 * installed (or the lockfile did not pin it to a 0.1.5-rc.2 version),
 * `ctx.commands` is undefined. The register function must:
 *
 *  - return a no-op disposer (never throw, never crash plugin startup)
 *  - emit exactly ONE warn line via `ctx.logger` so operators see
 *    why the CLI is missing
 *  - not call into any field on `ctx.commands` (which would TypeError)
 *
 * The LocalNdjsonSink / InterventionEngine arguments are irrelevant
 * for the degradation path because the function returns before
 * touching them.
 */
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { registerSecurityCommand } from '../../src/commands/security.js'
import { InterventionEngine } from '../../src/intervention/InterventionEngine.js'
import { DebugLog } from '../../src/utils/debugLog.js'
import { normalizeConfig, type Config } from '../../src/config.js'
import type { Context, Logger } from '../../src/types/external.js'

interface WarnCall {
  message: string
  args: unknown[]
}

function buildContextWithoutCommands(): { ctx: Context; warns: WarnCall[] } {
  const warns: WarnCall[] = []
  const logger: Logger = {
    debug() {
      /* noop */
    },
    info() {
      /* noop */
    },
    warn(message, ...args) {
      warns.push({ message, args })
    },
    error() {
      /* noop */
    },
  }
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
    // `commands` deliberately absent — mirrors a marketplace node
    // without `@deepseek-ai/dsh-commands` installed.
  } as unknown as Context
  return { ctx, warns }
}

function buildSinkStub() {
  return {
    getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
    getLocalOutputPath: () => undefined,
  }
}

let dir: string
let engine: InterventionEngine
let config: Config

beforeEach(() => {
  config = normalizeConfig({})

  dir = mkdtempSync(join(tmpdir(), 'sec-mgr-deg-'))
  engine = new InterventionEngine({
    intervention: {
      mode: 'audit',
      failStrategy: 'fail_open',
      decisionTimeoutMs: 50,
      policyPath: join(dir, 'policy.json'),
      policyPaths: [],
      reloadIntervalMs: 0,
    },
    inlineGuards: { enabled: false },
  } as unknown as Parameters<typeof InterventionEngine.prototype.constructor>[0])
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('registerSecurityCommand graceful degradation', () => {
  it('returns a no-op disposer when ctx.commands is undefined', () => {
    const { ctx } = buildContextWithoutCommands()
    const dispose = registerSecurityCommand(
      ctx,
      buildSinkStub() as unknown as Parameters<typeof registerSecurityCommand>[1],
      engine,
      config,
    )
    expect(typeof dispose).toBe('function')
    // Calling the disposer twice is safe (no throw, no side effect).
    expect(() => {
      dispose()
      dispose()
    }).not.toThrow()
  })

  it('emits a single warn line explaining the missing dependency', () => {
    const { ctx, warns } = buildContextWithoutCommands()
    registerSecurityCommand(
      ctx,
      buildSinkStub() as unknown as Parameters<typeof registerSecurityCommand>[1],
      engine,
      config,
    )
    expect(warns.length).toBe(1)
    expect(warns[0]!.message).toMatch(/\/security CLI not registered/)
    expect(warns[0]!.message).toMatch(/@deepseek-ai\/dsh-commands/)
  })

  it('does not crash when ctx is a strict typed object (no commands field)', () => {
    // This is the same path as the warn test but with a tighter
    // constructor — we use `as unknown as Context` so the absence of
    // `commands` is typed at the cast boundary.
    const { ctx } = buildContextWithoutCommands()
    expect(() => {
      const dispose = registerSecurityCommand(
        ctx,
        buildSinkStub() as unknown as Parameters<typeof registerSecurityCommand>[1],
        engine,
        config,
      )
      // The disposer must NOT touch ctx.commands (it does not exist).
      expect(() => dispose()).not.toThrow()
    }).not.toThrow()
  })

  it('does not require the sink or engine to be initialized for the degradation path', () => {
    const { ctx } = buildContextWithoutCommands()
    // Pass deliberately broken sink + engine: the degradation path
    // returns before touching them, so the broken stubs survive.
    const brokenSink = {} as unknown as Parameters<typeof registerSecurityCommand>[1]
    const brokenEngine = {} as unknown as InterventionEngine
    expect(() => {
      const dispose = registerSecurityCommand(ctx, brokenSink, brokenEngine, config)
      dispose()
    }).not.toThrow()
  })

  it('BUG-5 : writes a surface_unavailable breadcrumb to the debug log when the CLI surface is missing', () => {
    const { ctx } = buildContextWithoutCommands()
    const debugLogPath = join(dir, 'security-monitor-debug.log')
    const debugLog = new DebugLog({ path: debugLogPath, logger: ctx.logger })
    const dispose = registerSecurityCommand(
      ctx,
      buildSinkStub() as unknown as Parameters<typeof registerSecurityCommand>[1],
      engine,
      config,
      debugLog,
    )
    dispose()
    const lines = readFileSync(debugLogPath, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { phase: string; surface?: string; reason?: string; peer?: string })
    const unavailable = lines.filter((entry) => entry.phase === 'surface_unavailable')
    expect(unavailable).toHaveLength(1)
    expect(unavailable[0]!.surface).toBe('cli')
    expect(unavailable[0]!.reason).toMatch(/ctx\.commands is unavailable/)
    expect(unavailable[0]!.peer).toMatch(/@deepseek-ai\/dsh-commands/)
  })

  it('BUG-5 : stays silent on the debug log when no DebugLog handle is passed (legacy call sites)', () => {
    const { ctx } = buildContextWithoutCommands()
    // The debugLog parameter is optional — apply() always passes it, but
    // any out-of-tree caller using the old 3-arg form must not crash.
    expect(() => {
      const dispose = registerSecurityCommand(
        ctx,
        buildSinkStub() as unknown as Parameters<typeof registerSecurityCommand>[1],
        engine,
        config,
      )
      dispose()
    }).not.toThrow()
  })
})
