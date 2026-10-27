/**
 * Unit tests for RuntimeHook (synchronous passthrough).
 *
 * Tests cover the wrapper's contract:
 *  - allow → original spawn runs SYNCHRONOUSLY, its handle returned verbatim
 *  - block + audit mode → original spawn runs + intent event recorded
 *  - inline-guard block + enforce + blockAtSubprocess → synchronous throw
 * BEFORE the fork (the only pre-fork block left —)
 *  - SPL block + enforce + blockAtSubprocess → spawn already happened;
 * denied event recorded + best-effort terminate ( semantic change)
 *  - block + enforce + blockAtSubprocess:false → audit-only
 *  - SPL evaluation error + failOpenOnError:true → child keeps running
 *  - SPL evaluation error + failOpenOnError:false → child terminated
 *  - install/uninstall idempotency + restoration
 *  - sessionResolve missing → untracked event with no session_id
 *  - argv-derived body feeds the SPL rule matcher via params/body
 *  - emit event always carries cmdline + exe
 *
 * Uses a stub SubprocessRuntimeLike + a stub EventCollector that captures
 * the SecurityEvent objects report() receives. The stub's spawn returns a
 * handle-shaped `SubprocessSpawnResult` SYNCHRONOUSLY (mirroring the real
 * harness `SubprocessHandle` — subprocess/src/types.ts:169-196); SPL-path
 * events are emitted from a background promise, so event assertions flush
 * the queue first (`flushAsync`).
 */
import { beforeEach, describe, expect, it } from 'vitest'
import {
  RuntimeHook,
  type RuntimeHookSessionContext,
} from '../src/intervention/RuntimeHook.js'
import type { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import type {
  ApplicationConfig,
  StdioMirrorConfig,
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
import { resolveStdioMirrorWrapperPath } from '../src/runtime/stdioMirrorEntry.js'

/** Minimal stub EventCollector that records every report() call. */
class StubEventCollector {
  events: SecurityEvent[] = []
  report(event: SecurityEvent): void {
    this.events.push(event)
  }
}

/** Minimal stub InterventionEngine. The test sets `decision` directly. */
function makeEngine(decision: SecurityDecision): InterventionEngine {
  return {
    evaluate: async () => decision,
  } as unknown as InterventionEngine
}

/**
 * drain the background SPL-eval promise chain. Engine decisions are
 * `async` stubs, so one macrotask turn is enough for the intent/denied
 * events to land in the collector.
 */
async function flushAsync(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve))
}

function makeConfig(
  overrides: Partial<ApplicationConfig['runtimeHooks']> = {},
): ApplicationConfig['runtimeHooks'] {
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

function makeAllowDecision(): SecurityDecision {
  return {
    decision: 'allow',
    mode: 'audit',
    latency_ms: 1,
  }
}

function makeBlockDecision(reason = 'blocked by test policy', code = 'TEST_001'): SecurityDecision {
  return {
    decision: 'block',
    mode: 'audit',
    block_reason: reason,
    block_code: code,
    latency_ms: 1,
  }
}

/**
 * Stub runtime whose spawn() returns a handle-shaped
 * `SubprocessSpawnResult` SYNCHRONOUSLY — the real harness contract
 *`handles` records every returned handle (identity comparison
 * against the wrapper's return value) and `terminated` counts
 * `terminate()` calls for post-spawn enforcement assertions.
 */
function makeSubprocessRuntime(): SubprocessRuntimeLike & {
  spawnCalls: SubprocessSpawnSpec[]
  handles: SubprocessSpawnResult[]
  terminated: number
} {
  const calls: SubprocessSpawnSpec[] = []
  const handles: SubprocessSpawnResult[] = []
  const extended = {
    spawnCalls: calls,
    handles,
    terminated: 0,
  } as SubprocessRuntimeLike & {
    spawnCalls: SubprocessSpawnSpec[]
    handles: SubprocessSpawnResult[]
    terminated: number
  }
  const rt: SubprocessRuntimeLike = {
    spawn(spec) {
      calls.push(spec)
      const handle: SubprocessSpawnResult = {
        done: Promise.resolve({ exitCode: 0, signal: null }),
        terminate: () => { extended.terminated++ },
        waitForExit: async () => true,
      }
      handles.push(handle)
      return handle
    },
    async spawnTerminal() {
      return { pid: 5678 }
    },
  }
  return Object.assign(extended, rt)
}

describe('RuntimeHook install / uninstall', () => {
  let collector: StubEventCollector
  let engine: InterventionEngine
  let config: ApplicationConfig['runtimeHooks']
  let sessionResolve: () => RuntimeHookSessionContext | undefined

  beforeEach(() => {
    collector = new StubEventCollector()
    engine = makeEngine(makeAllowDecision())
    config = makeConfig()
    sessionResolve = () => undefined
  })

  it('install is idempotent', () => {
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: config,
      mode: 'audit',
      sessionResolve,
    })
    hook.install(target)
    hook.install(target) // second call must short-circuit
    expect(hook.stats.installed).toBe(true)
    hook.uninstall()
    expect(hook.stats.installed).toBe(false)
    // After uninstall, target.spawn is restored to the original (NOT the wrapper).
    expect(target.spawn).not.toBe(hook.wrap.bind(hook))
  })

  it('uninstall restores the original spawn method', () => {
    const target = makeSubprocessRuntime()
    const origSpawn = target.spawn
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: config,
      mode: 'audit',
      sessionResolve,
    })
    hook.install(target)
    expect(target.spawn).not.toBe(origSpawn)
    hook.uninstall()
    expect(target.spawn).toBe(origSpawn)
  })

  it('does not wrap when enabledAtSubprocess is false', () => {
    const target = makeSubprocessRuntime()
    const origSpawn = target.spawn
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: makeConfig({ enabledAtSubprocess: false }),
      mode: 'audit',
      sessionResolve,
    })
    hook.install(target)
    // The method is still reassigned (we mark installed) but the wrapper
    // short-circuits internally. Either way, the original behavior is
    // preserved — the spawn call produces no event and no eval.
    expect(target.spawn).toBe(origSpawn)
  })
})

describe('RuntimeHook wrap — allow path', () => {
  it('forwards allow-decision spawns to the underlying subprocess runtime synchronously', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    const result = hook.wrap({
      argv: ['bash', '-c', 'echo hi'],
    })
    // synchronous passthrough — the caller gets the ORIGINAL handle
    // verbatim (identity-equal, non-Promise), exactly what an unwrapped
    // `ctx.subprocess.spawn` would return.
    expect(typeof (result as { then?: unknown }).then).not.toBe('function')
    expect(result).toBe(target.handles[0])
    expect(result.done).toBeInstanceOf(Promise)
    expect(target.spawnCalls.length).toBe(1)
    expect(target.spawnCalls[0]?.argv).toEqual(['bash', '-c', 'echo hi'])
    await flushAsync()
    // Audit event recorded.
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_intent')
    expect(collector.events[0]?.cmdline).toBe('bash -c echo hi')
    expect(collector.events[0]?.exe).toBe('bash')
    expect(collector.events[0]?.blocked).toBe(false)
    expect(collector.events[0]?.session_id).toBeUndefined()
    // The platform process contract is `anyOf [cmdline, exe]` — the
    // cmdline string carries the spawn verbatim (the structured argv
    // vector no longer rides on the wire event).
    expect(collector.events[0]?.cmdline).toBe('bash -c echo hi')
  })

  it('tags unpatched engine launches with risk_flags', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    hook.wrap({
      argv: ['/usr/bin/pnpm', 'dsh', 'web'],
    })
    await flushAsync()
    const event = collector.events[0]
    expect(event?.risk_flags).toContain('unpatched_engine')
  })

  it('does NOT flag a legitimate patched engine launch', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    hook.wrap({
      argv: ['/usr/bin/pnpm', 'dsh', '--patch', '/abs/security-monitor.patch.yml'],
    })
    await flushAsync()
    const event = collector.events[0]
    expect(event?.risk_flags ?? []).not.toContain('unpatched_engine')
  })

  it('forwards session metadata from sessionResolve', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const session: RuntimeHookSessionContext = {
      sessionId: 's-1',
      runId: 'r-1',
      agentId: 'a-1',
      // explicit task/turn ids ride along with the
      // session context. When supplied by the ApplicationCollector they
      // are stamped verbatim onto the runtime_*_intent event.
      taskId: 'task-1',
      turnId: 'turn-7',
    }
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => session,
    })
    hook.install(target)
    hook.wrap({ argv: ['/bin/cat', '/etc/hostname'] })
    await flushAsync()
    const event = collector.events[0]
    expect(event?.session_id).toBe('s-1')
    expect(event?.run_id).toBe('r-1')
    expect(event?.agent_id).toBe('a-1')
    // explicit task_id / turn_id carried through to the event.
    expect(event?.task_id).toBe('task-1')
    expect(event?.turn_id).toBe('turn-7')
    expect(hook.stats.untracked).toBe(0)
  })

  it('writes null task_id / turn_id when the session carries no real task ids', async () => {
    // Platform identity rule (common.json): a task_id that duplicates
    // session_id is drift and must not be written — an undeterminable
    // identity is explicit JSON null. The pre-2026-10-27 fallback mirrored
    // sessionId/runId here, creating SOC false correlations.
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const session: RuntimeHookSessionContext = {
      sessionId: 's-2',
      runId: 'r-2',
      agentId: 'a-2',
      // no taskId / turnId
    }
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => session,
    })
    hook.install(target)
    hook.wrap({ argv: ['/bin/cat', '/etc/hostname'] })
    await flushAsync()
    const event = collector.events[0]
    expect(event?.session_id).toBe('s-2')
    expect(event?.run_id).toBe('r-2')
    expect(event?.task_id).toBe(null)
    expect(event?.turn_id).toBe(null)
  })

  it('counts untracked spawns when sessionResolve returns undefined', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    await hook.wrap({ argv: ['/bin/cat'] })
    expect(hook.stats.untracked).toBe(1)
  })

  /**
   * the real `SubprocessHandle` exposes no pid
   * (subprocess/src/types.ts:169-196) — the spawn seam can no longer
   * populate `child_pid` or bind a child PID to the session. The earlier
   * assertions (`child_pid === 1234`, bindChildPid called) tested the
   * fabricated `{ handle, pid }` stub shape. Correlation falls back to
   * session_id / run_id / cmdline.
   */
  it('does not populate child_pid or bind a pid at the spawn seam', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const boundPids: Array<{ pid: number; sessionId: string }> = []
    const session: RuntimeHookSessionContext = {
      sessionId: 's-child',
      runId: 'r-child',
      agentId: 'a-child',
    }
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => session,
      bindChildPid: (pid, sessionId) => boundPids.push({ pid, sessionId }),
    })
    hook.install(target)
    const result = hook.wrap({ argv: ['/bin/cat', '/etc/hostname'] })
    expect(result).toBe(target.handles[0])
    await flushAsync()
    expect(boundPids).toEqual([])
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_intent')
    expect(collector.events[0]?.child_pid).toBeUndefined()
    expect(collector.events[0]?.pid).toBe(process.pid)
  })

  it('does not bind child_pid when the session is missing', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const boundPids: Array<{ pid: number; sessionId: string }> = []
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => undefined,
      bindChildPid: (pid, sessionId) => boundPids.push({ pid, sessionId }),
    })
    hook.install(target)
    hook.wrap({ argv: ['/bin/cat'] })
    await flushAsync()
    expect(boundPids.length).toBe(0)
    // no pid source on the real handle — child_pid stays unset even
    // without a session.
    expect(collector.events[0]?.child_pid).toBeUndefined()
  })
})

describe('RuntimeHook wrap — block path', () => {
  it('audit-only block: spawn still runs, intent event recorded', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeBlockDecision('inline 015', 'INLINE_SELF_PROTECTION_015')),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: false }),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    const result = hook.wrap({
      argv: ['pnpm', 'dsh', 'web'],
    })
    expect(target.spawnCalls.length).toBe(1)
    expect(result).toBe(target.handles[0])
    expect(hook.stats.blocked).toBe(0) // blockAtSubprocess:false → no enforced block
    await flushAsync()
    // Audit event recorded with block reason.
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_intent')
    expect(collector.events[0]?.blocked).toBe(true)
    expect(collector.events[0]?.intervention?.block_reason).toBe('inline 015')
  })

  /**
   * SEMANTIC CHANGE: an SPL `block` decision arrives AFTER the
   * synchronous passthrough — the caller already holds the handle, so a
   * pre-fork throw is physically impossible (the earlier wrapper achieved
   * the throw only by deferring `origSpawn` behind the async eval, which
   * returned a Promise to a caller that consumes the handle synchronously
   * and broke every shell tool call). Enforce mode now records intent +
   * denied events and terminates the freshly-spawned child on a
   * best-effort basis. The synchronous pre-fork throw survives ONLY for
   * inline-guard hits — see tests/runtimeHookSyncPassthrough.test.ts.
   */
  it('enforce+block (SPL): spawn proceeds, single denied event + best-effort terminate', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeBlockDecision('restart no patch', 'SELF_PROTECTION_RESTART_WITHOUT_PATCH_015')),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: true }),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    const result = hook.wrap({
      argv: ['/usr/bin/pnpm', 'dsh', 'web'],
    })
    // The fork already happened — the caller holds the original handle.
    expect(result).toBe(target.handles[0])
    expect(target.spawnCalls.length).toBe(1)
    await flushAsync()
    expect(hook.stats.blocked).toBe(1)
    // Best-effort post-spawn enforcement: the child is terminated.
    expect(target.terminated).toBe(1)
    // fix: enforce-mode block emits ONE `runtime_spawn_denied`
    // event (the prior pair (intent + denied) was an N=2 audit fan-out —
    // both events carried the same payload except for the isDenied flag).
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_denied')
    expect(collector.events[0]?.block_reason).toBe('restart no patch')
    // The cmdline string captures the blocked restart attempt's exact
    // command — `pnpm dsh web` without the security-monitor patch.
    expect(collector.events[0]?.cmdline).toBe('/usr/bin/pnpm dsh web')
  })

  it('enforce+block:false (audit mode) does NOT throw', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeBlockDecision()),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: false }),
      mode: 'audit', // not enforce
      sessionResolve: () => undefined,
    })
    hook.install(target)
    const result = hook.wrap({ argv: ['bash', '-c', 'echo hi'] })
    expect(result).toBe(target.handles[0])
    expect(target.spawnCalls.length).toBe(1)
  })
})

describe('RuntimeHook wrap — eval failure', () => {
  it('failOpenOnError:true keeps the spawned child running', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const engine = {
      evaluate: async () => {
        throw new Error('engine on fire')
      },
    } as unknown as InterventionEngine
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: makeConfig({ failOpenOnError: true }),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    // the spawn happens synchronously BEFORE the background eval, so
    // the caller always gets the handle; the eval error can only be
    // recorded, not thrown.
    const result = hook.wrap({ argv: ['/bin/cat'] })
    expect(target.spawnCalls.length).toBe(1)
    expect(result).toBe(target.handles[0])
    await flushAsync()
    expect(hook.stats.errors).toBe(1)
    expect(target.terminated).toBe(0) // fail-open: child keeps running
    // The hook surfaces the eval failure as runtime_hook_error event.
    expect(collector.events.some((e) => e.event_type === 'runtime_hook_error')).toBe(true)
  })

  /**
   * earlier this path re-threw the eval error to the caller (the
   * spawn was deferred until the eval settled). With the synchronous
   * passthrough the spawn has already happened when the eval fails, so
   * fail-closed degrades to a best-effort terminate of the spawned child.
   */
  it('failOpenOnError:false terminates the spawned child (fail-closed, post-spawn)', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const engine = {
      evaluate: async () => {
        throw new Error('engine on fire')
      },
    } as unknown as InterventionEngine
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: makeConfig({ failOpenOnError: false }),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    const result = hook.wrap({ argv: ['/bin/cat'] })
    // No throw — the caller already holds the handle.
    expect(result).toBe(target.handles[0])
    expect(target.spawnCalls.length).toBe(1)
    await flushAsync()
    expect(hook.stats.errors).toBe(1)
    expect(target.terminated).toBe(1)
    expect(collector.events.some((e) => e.event_type === 'runtime_hook_error')).toBe(true)
  })
})

describe('RuntimeHook wrapTerminal', () => {
  it('forwards terminal spawns and emits intent event (no block)', async () => {
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeBlockDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)
    await hook.wrapTerminal({
      argv: ['/bin/bash'],
    })
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_terminal_intent')
    // Terminal intent carries the canonical cmdline string.
    expect(collector.events[0]?.cmdline).toBe('/bin/bash')
  })

  it('terminal intent carries task_id / turn_id from sessionResolve', async () => {
    // the same task/turn stamping as runtime_spawn_intent
    // applies to runtime_terminal_intent — audit consumers expect a
    // consistent shape across all three runtime_*_intent classes.
    const collector = new StubEventCollector()
    const target = makeSubprocessRuntime()
    const session: RuntimeHookSessionContext = {
      sessionId: 's-3',
      runId: 'r-3',
      taskId: 'task-3',
      turnId: 'turn-9',
    }
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine(makeAllowDecision()),
      runtimeHookConfig: makeConfig(),
      mode: 'audit',
      sessionResolve: () => session,
    })
    hook.install(target)
    await hook.wrapTerminal({
      argv: ['/bin/bash'],
    })
    const event = collector.events[0]
    expect(event?.event_type).toBe('runtime_terminal_intent')
    expect(event?.task_id).toBe('task-3')
    expect(event?.turn_id).toBe('turn-9')
  })
})

// ---------------------------------------------------------------------------
// stdio pipe mirror integration — §6.2
//
// The RuntimeHook seam is the host-side wrapper around the bundled
// `lib/runtime/stdio-mirror.js`. When `stdioMirror.config.enabled === true`
// AND at least one stdio stream is worth mirroring, `wrap()` rewrites the
// harness's spec.argv to `[node, wrapperPath, --flags, --, ...originalArgv]`.
// Eval happens on the ORIGINAL argv (before rewrite); the rewrite is
// observability-only.
//
// These cases lock in the dispatch contract:
//   1. enabled + non-ignore stdio → argv is rewritten
//   2. disabled                    → argv passes through unchanged
//   3. enabled + stdio === 'ignore' → argv passes through unchanged
// (string form — stub/test only)
//   4. enabled + object stdio with every fd 'ignore'/absent → passes through
//      (the production-form deep-check that replaces the dead
//      `spec.stdio !== 'ignore'` gate — real harness stdio is always an
//      object, subprocess/src/types.ts:77-107)
// ---------------------------------------------------------------------------

function makeStdioMirrorConfig(overrides: Partial<StdioMirrorConfig> = {}): StdioMirrorConfig {
  return {
    enabled: true,
    payloadLimitBytes: 1024 * 1024,
    outputPath: '/tmp/dsh-mirror-test.jsonl',
    ...overrides,
  }
}

describe('RuntimeHook stdio mirror integration', () => {
  let collector: StubEventCollector
  let engine: InterventionEngine
  let config: ApplicationConfig['runtimeHooks']

  beforeEach(() => {
    collector = new StubEventCollector()
    engine = makeEngine(makeAllowDecision())
    config = makeConfig()
  })

  it('rewrites argv to wrapper form when stdio mirror is enabled', async () => {
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: config,
      inlineGuards: { engineLaunchers: [], pluginPackageName: 'security-monitor', patchMarkers: [] },
      stdioMirror: {
        config: makeStdioMirrorConfig(),
        wrapperPath: resolveStdioMirrorWrapperPath(),
      },
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)

    await target.spawn({
      argv: ['echo', 'hello'],
      stdio: 'inherit',
    })

    const calls = (target as unknown as { spawnCalls: SubprocessSpawnSpec[] }).spawnCalls
    expect(calls.length).toBe(1)
    const argv = calls[0]?.argv ?? []
    // argv[0] is the host's node binary (process.execPath).
    expect(argv[0]).toBe(process.execPath)
    // argv[1] is the wrapper script (resolves to lib/runtime/stdio-mirror.js
    // in production; in the test env it points to src/runtime/runtime/
    // stdio-mirror.js because vitest resolves from the source module —
    // the suffix /runtime/stdio-mirror.js is the stable contract).
    expect(argv[1]).toMatch(/stdio-mirror\.js$/)
    // --stdio-spec must carry the per-stream triple.
    const stdioSpecArg = argv.find((a) => a.startsWith('--stdio-spec='))
    expect(stdioSpecArg).toBeDefined()
    const parsed = JSON.parse(stdioSpecArg!.slice('--stdio-spec='.length))
    expect(parsed.stdin.mode).toBe('inherit')
    expect(parsed.stdout.mode).toBe('inherit')
    expect(parsed.stderr.mode).toBe('inherit')
    // -- separator + original argv at the tail.
    const dashIdx = argv.indexOf('--')
    expect(dashIdx).toBeGreaterThan(0)
    expect(argv.slice(dashIdx + 1)).toEqual(['echo', 'hello'])
    hook.uninstall()
  })

  it('does NOT rewrite when stdio mirror is disabled', async () => {
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: config,
      inlineGuards: { engineLaunchers: [], pluginPackageName: 'security-monitor', patchMarkers: [] },
      stdioMirror: {
        config: makeStdioMirrorConfig({ enabled: false }),
        wrapperPath: resolveStdioMirrorWrapperPath(),
      },
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)

    const originalArgv = ['echo', 'hello']
    await target.spawn({ argv: originalArgv, stdio: 'inherit' })

    const calls = (target as unknown as { spawnCalls: SubprocessSpawnSpec[] }).spawnCalls
    expect(calls.length).toBe(1)
    // argv must be the ORIGINAL argv (no wrapper prefix).
    expect(calls[0]?.argv).toEqual(originalArgv)
    hook.uninstall()
  })

  it('skips wrapper when stdio is "ignore"', async () => {
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: config,
      inlineGuards: { engineLaunchers: [], pluginPackageName: 'security-monitor', patchMarkers: [] },
      stdioMirror: {
        config: makeStdioMirrorConfig(),
        wrapperPath: resolveStdioMirrorWrapperPath(),
      },
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)

    const originalArgv = ['echo', 'hello']
    target.spawn({ argv: originalArgv, stdio: 'ignore' })

    const calls = (target as unknown as { spawnCalls: SubprocessSpawnSpec[] }).spawnCalls
    expect(calls.length).toBe(1)
    // When stdio === 'ignore', the wrapper is irrelevant — no point
    // mirroring bytes the harness has already told us to discard.
    expect(calls[0]?.argv).toEqual(originalArgv)
    hook.uninstall()
  })

  /**
   * the real harness ALWAYS sends stdio as the per-stream object
   * (`SubprocessStdio`, subprocess/src/types.ts:77-107), so the earlier
   * `spec.stdio !== 'ignore'` gate was dead code in production. The gate is
   * now a per-fd deep check: an object spec with every stream 'ignore' (or
   * absent) must skip the wrapper just like the string form.
   */
  it('skips wrapper when object-form stdio has every fd ignore/absent', async () => {
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: config,
      inlineGuards: { engineLaunchers: [], pluginPackageName: 'security-monitor', patchMarkers: [] },
      stdioMirror: {
        config: makeStdioMirrorConfig(),
        wrapperPath: resolveStdioMirrorWrapperPath(),
      },
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)

    const originalArgv = ['echo', 'hello']
    target.spawn({
      argv: originalArgv,
      // Real-harness-shaped spec: fully-specified object with every stream
      // ignored. Nothing to mirror → argv passes through unchanged.
      stdio: { stdin: 'ignore', stdout: 'ignore', stderr: 'ignore' },
    })

    const calls = (target as unknown as { spawnCalls: SubprocessSpawnSpec[] }).spawnCalls
    expect(calls.length).toBe(1)
    expect(calls[0]?.argv).toEqual(originalArgv)
    hook.uninstall()
  })

  /**
   * counterpart: an object-form spec with at least one live stream
   * (the production norm) still gets the mirror rewrite.
   */
  it('rewrites argv for object-form stdio with a live stream', async () => {
    const target = makeSubprocessRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: engine,
      runtimeHookConfig: config,
      inlineGuards: { engineLaunchers: [], pluginPackageName: 'security-monitor', patchMarkers: [] },
      stdioMirror: {
        config: makeStdioMirrorConfig(),
        wrapperPath: resolveStdioMirrorWrapperPath(),
      },
      mode: 'audit',
      sessionResolve: () => undefined,
    })
    hook.install(target)

    target.spawn({
      argv: ['echo', 'hello'],
      // Real-harness-shaped spec: collected stdout is the production norm.
      stdio: { stdin: 'pipe', stdout: { maxBytes: 1024 }, stderr: 'pipe' },
    })

    const calls = (target as unknown as { spawnCalls: SubprocessSpawnSpec[] }).spawnCalls
    expect(calls.length).toBe(1)
    const argv = calls[0]?.argv ?? []
    expect(argv[0]).toBe(process.execPath)
    expect(argv[1]).toMatch(/stdio-mirror\.js$/)
    const dashIdx = argv.indexOf('--')
    expect(dashIdx).toBeGreaterThan(0)
    expect(argv.slice(dashIdx + 1)).toEqual(['echo', 'hello'])
    hook.uninstall()
  })
})