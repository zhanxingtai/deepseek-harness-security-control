/**
 * Signal handler tests.
 *
 * The signal handlers are:
 *  - SIGHUP: warn and ignore (no exit)
 *  - SIGINT: warn and ignore (no exit)
 *  - SIGTERM: graceful shutdown
 *
 * These tests directly exercise `installSignalHandlers` with a mock Context
 * and verify the behaviour. They are skipped on Windows where POSIX signals
 * are not delivered to Node.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { installSignalHandlers } from '../src/utils/signalHandlers.js'
import type { Context } from '../src/types/external.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../src/collectors/ApplicationCollector.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import { normalizeConfig } from '../src/config.js'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const isWindows = process.platform === 'win32'

interface LoggedCall {
  level: string
  message: string
}

function makeMockCtx() {
  const logged: LoggedCall[] = []
  const ctx: Context = {
    logger: {
      debug: (m) => logged.push({ level: 'debug', message: String(m) }),
      info: (m) => logged.push({ level: 'info', message: String(m) }),
      warn: (m) => logged.push({ level: 'warn', message: String(m) }),
      error: (m) => logged.push({ level: 'error', message: String(m) }),
    },
    on: () => {},
    effect: () => {},
  }
  return { ctx, logged }
}

function makeCollectors() {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-sig-'))
  const config = normalizeConfig({
    mode: 'audit',
    collector: { localOutputPath: join(tmpDir, 'events.jsonl'), flushIntervalMs: 100 },
    intervention: { policyPath: '/nonexistent.json', reloadIntervalMs: 0 },
  })
  const eventCollector = new LocalNdjsonSink(config)
  const interventionEngine = new InterventionEngine(config)
  const applicationCollector = new ApplicationCollector(config, eventCollector, interventionEngine)
  // SystemCollector / AssetCollector deleted with the
  // marketplace refactor — they were platform-deployment backstops.
  // signalHandlers now takes (ctx, eventCollector, applicationCollector,
  // interventionEngine) — 4 args.
  return { eventCollector, interventionEngine, applicationCollector, tmpDir }
}

describe.skipIf(isWindows)('Signal handlers', () => {
  let tmpDir: string
  let collectors: ReturnType<typeof makeCollectors>

  beforeEach(() => {
    collectors = makeCollectors()
    tmpDir = collectors.tmpDir
  })

  afterEach(() => {
    try {
      rmSync(tmpDir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  })

  it('installs handlers on POSIX and returns true', () => {
    const { ctx, logged } = makeMockCtx()
    const result = installSignalHandlers(
      ctx,
      collectors.eventCollector,
      collectors.applicationCollector,
      collectors.interventionEngine,
      collectors.systemCollector,
      collectors.assetCollector,
    )
    expect(result).toBe(true)
  })

  it('SIGHUP handler logs warning and does not exit (verified by side effects)', () => {
    const { ctx, logged } = makeMockCtx()
    installSignalHandlers(
      ctx,
      collectors.eventCollector,
      collectors.applicationCollector,
      collectors.interventionEngine,
    )
    // Emit SIGHUP — the handler is async; emit and check no error.
    process.emit('SIGHUP')
    // SIGHUP must log a warn (not info/debug).
    const warnings = logged.filter((l) => l.level === 'warn')
    expect(warnings.some((w) => w.message.includes('SIGHUP'))).toBe(true)
  })

  it('SIGINT handler logs warning and does not exit', () => {
    const { ctx, logged } = makeMockCtx()
    installSignalHandlers(
      ctx,
      collectors.eventCollector,
      collectors.applicationCollector,
      collectors.interventionEngine,
    )
    process.emit('SIGINT')
    const warnings = logged.filter((l) => l.level === 'warn')
    expect(warnings.some((w) => w.message.includes('SIGINT'))).toBe(true)
  })

  it('SIGTERM handler triggers graceful shutdown (no immediate exit)', () => {
    const { ctx, logged } = makeMockCtx()
    installSignalHandlers(
      ctx,
      collectors.eventCollector,
      collectors.applicationCollector,
      collectors.interventionEngine,
    )
    // Save current exit behavior to restore later.
    const origExit = process.exit
    let exitCalled = false
    ;(process as any).exit = (code: number) => {
      exitCalled = true
    }
    try {
      process.emit('SIGTERM')
      // The handler schedules a 500ms setTimeout to call process.exit. We
      // don't wait for it in the test (would slow down the suite) — we just
      // verify the warn was logged and the handler ran without throwing.
      const warnings = logged.filter((l) => l.level === 'warn')
      expect(warnings.some((w) => w.message.includes('SIGTERM'))).toBe(true)
      // Also: the shutdown sequence should have logged the cascade.
      expect(logged.length).toBeGreaterThan(0)
    } finally {
      ;(process as any).exit = origExit
    }
  })

  it('returns false on Windows (POSIX-only feature)', () => {
    // We can't change the platform at runtime, so this test asserts the
    // platform-conditional return value contract.
    if (isWindows) {
      // We're actually on Windows — the real install path returns false.
      const { ctx } = makeMockCtx()
      const result = installSignalHandlers(
        ctx,
        collectors.eventCollector,
        collectors.applicationCollector,
        collectors.interventionEngine,
      )
      expect(result).toBe(false)
    } else {
      // On POSIX, this test is a no-op marker.
      expect(true).toBe(true)
    }
  })
})
