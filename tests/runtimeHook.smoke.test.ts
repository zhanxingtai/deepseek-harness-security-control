/**
 * Smoke test for RuntimeHook (synchronous passthrough).
 *
 * Spawns a real child process through a stub SubprocessRuntimeLike whose
 * `spawn` method actually calls `child_process.spawn` and returns a
 * handle-shaped `SubprocessSpawnResult` SYNCHRONOUSLY (mirroring the real
 * harness `SubprocessHandle`). Confirms:
 *   - the child process actually starts and `handle.done` settles (the
 *     bash-local consumption pattern `spawn(...); await handle.done`)
 *   - the wrapper returns the handle synchronously, NOT a Promise
 *   - the runtime_spawn_intent event lands in the collector with the
 *     correct cmdline + argv (via a queue flush — SPL-path events are
 * emitted from a background promise)
 *   - blockAtSubprocess:false (the default) means no throw even on a
 *     hypothetical block decision
 * SPL enforce-block degrades to best-effort terminate post-spawn
 *
 * Skipped on environments without a usable shell (the test harness probes
 * bash / pwsh / cmd presence and skips cleanly).
 */
import { afterEach, describe, expect, it } from 'vitest'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { rmSync } from 'node:fs'
import {
  RuntimeHook,
  type RuntimeHookSessionContext,
} from '../src/intervention/RuntimeHook.js'
import type { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import type {
  ApplicationConfig,
} from '../src/config.js'
import type {
  SecurityDecision,
  SecurityEvent,
} from '../src/types/index.js'
import type {
  SubprocessRuntimeLike,
  SubprocessSpawnResult,
  SubprocessSpawnSpec,
} from '../src/types/external.js'

class CapturingCollector {
  events: SecurityEvent[] = []
  report(event: SecurityEvent): void {
    this.events.push(event)
  }
}

function makeEngine(decision: SecurityDecision): InterventionEngine {
  return { evaluate: async () => decision } as unknown as InterventionEngine
}

function makeConfig(overrides: Partial<ApplicationConfig['runtimeHooks']> = {}): ApplicationConfig['runtimeHooks'] {
  return {
    enabled: true,
    networkEnabled: true,
    logPath: '/tmp/unused.jsonl',
    hookPath: '',
    excludeCommandLines: [],
    enabledAtSubprocess: true,
    blockAtSubprocess: false,
    failOpenOnError: true,
    ...overrides,
  }
}

/** : let the background SPL-eval promise chain settle. */
async function flushAsync(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve))
}

/** Probe for a usable shell. Returns argv[0] for the test, or null. */
function probeShell(): { argv: string[] } | null {
  if (process.platform === 'win32') {
    const comspec = process.env.ComSpec ?? 'cmd.exe'
    return { argv: [comspec, '/c', 'exit', '0'] }
  }
  // bash is the most portable POSIX shell.
  return { argv: ['bash', '-c', 'exit 0'] }
}

/**
 * Build a SubprocessRuntimeLike whose spawn() does a real child_process.spawn
 * using the spec's executable + argv, and returns a handle-shaped
 * `SubprocessSpawnResult` SYNCHRONOUSLY (Node's spawn returns a
 * ChildProcess synchronously; the real harness wraps it in a
 * SubprocessHandle whose `done` promise settles on exit).
 */
function makeRealSubprocessRuntime(): SubprocessRuntimeLike & {
  spawned: SubprocessSpawnSpec[]
  handles: SubprocessSpawnResult[]
  terminated: number
} {
  const spawned: SubprocessSpawnSpec[] = []
  const handles: SubprocessSpawnResult[] = []
  const extended = {
    spawned,
    handles,
    terminated: 0,
  } as SubprocessRuntimeLike & {
    spawned: SubprocessSpawnSpec[]
    handles: SubprocessSpawnResult[]
    terminated: number
  }
  const rt: SubprocessRuntimeLike = {
    spawn(spec: SubprocessSpawnSpec): SubprocessSpawnResult {
      spawned.push(spec)
      const argv0 = spec.argv[0]
      if (!argv0) {
        return {
          done: Promise.resolve({ exitCode: 0, signal: null }),
          terminate() { /* no-op */ },
          waitForExit: async () => true,
        }
      }
      const child = spawn(argv0, spec.argv.slice(1), {
        cwd: spec.cwd,
        env: { ...process.env, ...(spec.env ?? {}) },
        stdio: 'ignore',
      })
      const done = new Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }>((resolve) => {
        child.once('exit', (code, signal) => resolve({ exitCode: code, signal }))
        child.once('error', () => resolve({ exitCode: -1, signal: null }))
      })
      const handle: SubprocessSpawnResult = {
        done,
        terminate: () => { extended.terminated++; child.kill() },
        waitForExit: async () => { await done; return true },
      }
      handles.push(handle)
      return handle
    },
    async spawnTerminal() {
      throw new Error('terminal not used in smoke')
    },
  }
  return Object.assign(extended, rt)
}

describe('RuntimeHook smoke', () => {
  const cleanup: string[] = []

  afterEach(() => {
    while (cleanup.length > 0) {
      const dir = cleanup.pop()
      if (!dir) continue
      try {
        rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
      } catch {
        // best-effort
      }
    }
  })

  it('spawns a real bash and records the intent event', async () => {
    const shell = probeShell()
    if (!shell) return
    const tmp = mkdtempSync(join(tmpdir(), 'rt-hook-smoke-'))
    cleanup.push(tmp)
    const collector = new CapturingCollector()
    const target = makeRealSubprocessRuntime()
    const session: RuntimeHookSessionContext = {
      sessionId: 'smoke-s',
      runId: 'smoke-r',
      agentId: 'smoke-a',
    }
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine({ decision: 'allow', mode: 'audit', latency_ms: 1 }),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => session,
    })
    hook.install(target)
    // Spawn through the wrapper using a fresh spec (argv[0] must be the
    // command, realSubprocess passes argv.slice(1) to child_process.spawn).
    // the wrapper returns the handle SYNCHRONOUSLY — the exact
    // consumption pattern bash-local uses (`spawn(...); await handle.done`).
    const handle = hook.wrap({
      argv: shell.argv,
      cwd: tmp,
    })
    expect(typeof (handle as { then?: unknown }).then).not.toBe('function')
    expect(handle).toBe(target.handles[0])
    expect(handle.done).toBeInstanceOf(Promise)
    await handle.done
    await flushAsync()
    // The intent event was emitted from the background SPL eval.
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_intent')
    expect(collector.events[0]?.cmdline).toBe(shell.argv.join(' '))
    expect(collector.events[0]?.session_id).toBe('smoke-s')
    expect(collector.events[0]?.exe).toBe(shell.argv[0])
    expect(collector.events[0]?.cwd).toBe(tmp)
    expect(target.spawned.length).toBe(1)
    expect(hook.stats.spawned).toBe(1)
    expect(hook.stats.blocked).toBe(0)
    hook.uninstall()
  })

  it('audit-only block: fork still proceeds (default blockAtSubprocess:false)', async () => {
    const shell = probeShell()
    if (!shell) return
    const collector = new CapturingCollector()
    const target = makeRealSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine({
        decision: 'block',
        mode: 'audit',
        block_reason: 'inline 015 (test)',
        block_code: 'INLINE_SELF_PROTECTION_015',
        latency_ms: 1,
      }),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: false }),
      mode: 'enforce', // even with mode=enforce, blockAtSubprocess:false → no enforced block
      sessionResolve: () => undefined,
    })
    hook.install(target)
    const handle = hook.wrap({
      argv: shell.argv,
    })
    expect(handle).toBe(target.handles[0])
    expect(target.spawned.length).toBe(1)
    await handle.done
    await flushAsync()
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_intent')
    expect(collector.events[0]?.blocked).toBe(true)
    expect(collector.events[0]?.intervention?.block_reason).toBe('inline 015 (test)')
    hook.uninstall()
  })

  /**
   * SEMANTIC CHANGE: an SPL `block` decision now arrives AFTER the
   * synchronous passthrough, so the fork cannot be prevented — enforce mode
   * records intent + denied events and terminates the freshly-spawned
   * child (best-effort). Pre- this test asserted a pre-fork throw; that
   * behavior required returning a Promise to a caller that consumes the
   * handle synchronously, breaking every shell tool call.
   */
  it('enforce + blockAtSubprocess:true (SPL block): fork proceeds, child terminated, denied recorded', async () => {
    const shell = probeShell()
    if (!shell) return
    const collector = new CapturingCollector()
    const target = makeRealSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine({
        decision: 'block',
        mode: 'enforce',
        block_reason: 'restart-no-patch (test)',
        block_code: 'SELF_PROTECTION_RESTART_WITHOUT_PATCH_015',
        latency_ms: 1,
      }),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: true }),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    // No throw — the caller already holds the handle.
    const handle = hook.wrap({
      argv: shell.argv,
    })
    expect(handle).toBe(target.handles[0])
    expect(target.spawned.length).toBe(1)
    await flushAsync()
    expect(target.terminated).toBe(1)
    expect(hook.stats.blocked).toBe(1)
    expect(collector.events.map((e) => e.event_type)).toContain('runtime_spawn_denied')
    hook.uninstall()
  })
})