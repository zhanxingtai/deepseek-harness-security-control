/**
 * Tests for src/utils/safeHandler.ts — see ticket + A-L1.
 *
 * Invariant under test ("Never throw to the host"):
 *   a sync or async throw inside a Cordis listener MUST NOT propagate;
 *   it MUST emit a warn through ctx.logger and the Cordis pipeline MUST
 *   continue (chain listeners fall through to `next`).
 *
 * The helper exists to replace the per-handler boilerplate that lived
 * in `src/index.ts` before this refactor (8 nearly-identical blocks).
 * If these tests fail the host will start crashing on plugin bugs.
 *
 * A-L1 adds an optional audit sink: when the listener throws, safeHandler
 * invokes `sink(handlerName, error)` so the host's ApplicationCollector
 * can emit a `security_audit/fail_safe` event. Operators need that audit
 * signal to spot sustained bursts of handler failures that the warn
 * line alone would scroll past. These tests cover the sink contract:
 *   - sink is invoked exactly once per caught error (sync + async)
 *   - sink receives the wrapped event name + the raw error
 *   - sink is NOT invoked on the happy path
 *   - sink invocation is best-effort: a throwing sink does not break the
 *     warn/fall-through path
 *   - sink is optional: callers without a sink still get warn + fall-through
 */
import { describe, expect, it, vi } from 'vitest'
import { safeHandler, type FailSafeAuditSink } from '../src/utils/safeHandler.js'
import type { Context, Logger } from '../src/types/external.js'

interface MockLogger extends Logger {
  warns: string[]
}

function makeContext(): Context & { logger: MockLogger } {
  const warns: string[] = []
  const logger = {
    debug: () => {},
    info: () => {},
    warn: (msg: string) => {
      warns.push(msg)
    },
    error: () => {},
    warns,
  } as MockLogger
  const ctx = {
    logger,
    on: () => {},
    effect: () => {},
  } as Context & { logger: MockLogger }
  return ctx
}

describe('safeHandler', () => {
  it('logs a warn and does not rethrow on sync throw', () => {
    const ctx = makeContext()
    let captured: ((payload: { id: string }) => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as (payload: { id: string }) => void
    }

    safeHandler(ctx, 'agent/created', () => {
      throw new Error('boom')
    })

    expect(captured).toBeDefined()
    expect(() => captured!({ id: 'session-1' })).not.toThrow()
    expect(ctx.logger.warns).toHaveLength(1)
    expect(ctx.logger.warns[0]).toContain('agent/created')
    expect(ctx.logger.warns[0]).toContain('boom')
  })

  it('does not log on normal return', () => {
    const ctx = makeContext()
    let captured: ((payload: { id: string }) => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as (payload: { id: string }) => void
    }

    safeHandler(ctx, 'agent/created', () => {
      // no-op
    })

    captured!({ id: 'session-1' })
    expect(ctx.logger.warns).toHaveLength(0)
  })

  it('on async throw, logs warn and falls through to trailing next()', async () => {
    const ctx = makeContext()
    let captured:
      | ((payload: { id: string }, next: () => Promise<unknown>) => Promise<unknown>)
      | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as (payload: { id: string }, next: () => Promise<unknown>) => Promise<unknown>
    }

    let nextCalled = false
    safeHandler(ctx, 'agent/pre-step', async () => {
      throw new Error('async boom')
    })

    const result = await captured!({ id: 'session-1' }, () => {
      nextCalled = true
      return Promise.resolve('chained')
    })

    expect(ctx.logger.warns).toHaveLength(1)
    expect(ctx.logger.warns[0]).toContain('agent/pre-step')
    expect(ctx.logger.warns[0]).toContain('async boom')
    expect(nextCalled).toBe(true)
    expect(result).toBe('chained')
  })

  it('repeated throws still log and swallow (no leak)', () => {
    const ctx = makeContext()
    let captured: (() => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as () => void
    }

    safeHandler(ctx, 'tools/result', () => {
      throw new Error('always fails')
    })

    for (let i = 0; i < 5; i += 1) {
      expect(() => captured!()).not.toThrow()
    }
    expect(ctx.logger.warns).toHaveLength(5)
    expect(ctx.logger.warns.every((w) => w.includes('tools/result'))).toBe(true)
  })

  it('returns the listener return value when no throw occurs', async () => {
    const ctx = makeContext()
    let captured:
      | ((payload: { id: string }, next: () => Promise<string>) => Promise<string>)
      | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as (payload: { id: string }, next: () => Promise<string>) => Promise<string>
    }

    safeHandler(ctx, 'agent/pre-step', async (_payload, next) => {
      const v = await next()
      return v.toUpperCase()
    })

    const result = await captured!({ id: 'session-1' }, () => Promise.resolve('ok'))
    expect(result).toBe('OK')
    expect(ctx.logger.warns).toHaveLength(0)
  })
})

describe('safeHandler auditSink (A-L1 — 2026-09-25)', () => {
  it('invokes the sink exactly once on sync throw, passing the handler name + error', () => {
    const ctx = makeContext()
    let captured: ((payload: { id: string }) => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as (payload: { id: string }) => void
    }
    const sink = vi.fn<FailSafeAuditSink>()
    const originalError = new Error('sync boom')

    safeHandler(
      ctx,
      'agent/created',
      () => {
        throw originalError
      },
      sink,
    )

    expect(() => captured!({ id: 'session-1' })).not.toThrow()
    expect(sink).toHaveBeenCalledTimes(1)
    expect(sink).toHaveBeenCalledWith('agent/created', originalError)
    // warn line is still emitted (invariant #3 + back-compat)
    expect(ctx.logger.warns).toHaveLength(1)
  })

  it('invokes the sink exactly once on async throw (after the await resolves)', async () => {
    const ctx = makeContext()
    let captured:
      | ((payload: { id: string }, next: () => Promise<unknown>) => Promise<unknown>)
      | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as (payload: { id: string }, next: () => Promise<unknown>) => Promise<unknown>
    }
    const sink = vi.fn<FailSafeAuditSink>()
    const asyncError = new Error('async boom')

    safeHandler(
      ctx,
      'agent/pre-step',
      async () => {
        throw asyncError
      },
      sink,
    )

    await captured!({ id: 'session-1' }, () => Promise.resolve('chained'))

    expect(sink).toHaveBeenCalledTimes(1)
    expect(sink).toHaveBeenCalledWith('agent/pre-step', asyncError)
    expect(ctx.logger.warns).toHaveLength(1)
  })

  it('does NOT invoke the sink on the happy path', () => {
    const ctx = makeContext()
    let captured: (() => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as () => void
    }
    const sink = vi.fn<FailSafeAuditSink>()

    safeHandler(
      ctx,
      'tools/result',
      () => {
        // no-op
      },
      sink,
    )

    captured!()
    expect(sink).not.toHaveBeenCalled()
    expect(ctx.logger.warns).toHaveLength(0)
  })

  it('a throwing sink does NOT break the warn + fall-through path', () => {
    const ctx = makeContext()
    let captured: (() => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as () => void
    }
    // Sink throws synchronously — the safety net itself must not become
    // a fault source.
    const sink: FailSafeAuditSink = () => {
      throw new Error('sink crashed')
    }

    safeHandler(
      ctx,
      'tools/result',
      () => {
        throw new Error('handler crashed')
      },
      sink,
    )

    expect(() => captured!()).not.toThrow()
    expect(ctx.logger.warns).toHaveLength(1)
    expect(ctx.logger.warns[0]).toContain('handler crashed')
  })

  it('sink omission preserves original behavior (back-compat)', () => {
    const ctx = makeContext()
    let captured: (() => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as () => void
    }

    // No sink argument — must not throw at registration or at handler fire.
    safeHandler(ctx, 'tools/result', () => {
      throw new Error('legacy caller')
    })

    expect(() => captured!()).not.toThrow()
    expect(ctx.logger.warns).toHaveLength(1)
  })

  it('non-Error throws (string, undefined) flow through to the sink', () => {
    const ctx = makeContext()
    let captured: (() => void) | undefined
    ;(ctx as unknown as { on: (n: string, l: unknown) => void }).on = (name, listener) => {
      captured = listener as () => void
    }
    const sink = vi.fn<FailSafeAuditSink>()

    safeHandler(
      ctx,
      'tools/result',
      () => {
        // throw a string (legal JS) — the sink must still see it
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
        throw 'string-throw'
      },
      sink,
    )

    expect(() => captured!()).not.toThrow()
    expect(sink).toHaveBeenCalledWith('tools/result', 'string-throw')
  })
})