/**
 * synchronous-consumption integration tests for the RuntimeHook
 * spawn seam.
 *
 * The harness's `ctx.subprocess.spawn(spec)` returns a `SubprocessHandle`
 * SYNCHRONOUSLY (the host local subprocess adapter),
 * and callers consume it synchronously:
 * `const handle = this.ctx.subprocess.spawn(...); await handle.done`
 * (the host shell adapter). The earlier wrapper
 * deferred `origSpawn` behind the async SPL eval and returned a Promise on
 * every path, so callers saw `Promise.done === undefined` and every shell
 * tool call broke with `enabledAtSubprocess: true` (the default).
 *
 * These tests drive the seam THROUGH the patched runtime method — exactly
 * like the harness does — with a stub whose `spawn` synchronously returns
 * a handle carrying `.done`, and assert:
 *   - audit/allow path: the wrapper returns the ORIGINAL handle verbatim
 *     (non-Promise, identity-equal, `.done` intact) — the shape parity
 *     contract: wrapped vs unwrapped, the caller sees the same object
 *   - enforce + inline-guard hit (sensitive-path deny-list): throws
 *     `SpawnDeniedError` SYNCHRONOUSLY before the fork (asserted with
 *     `expect(...).toThrow`, not a rejected-promise catch)
 *   - audit-mode inline block: sync handle returned, blocked intent
 *     recorded synchronously
 *   - enforce + SPL block: the fork already happened (handle in caller's
 *     hands) — denied event recorded + best-effort `terminate()`; this is
 * the documented semantic change, locked in here so it can't
 *     silently regress into a broken Promise-returning "fix"
 */
import { describe, expect, it } from 'vitest'
import {
  RuntimeHook,
  SpawnDeniedError,
  type RuntimeHookSessionContext,
} from '../src/intervention/RuntimeHook.js'
import type { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import type { ApplicationConfig } from '../src/config.js'
import type { SensitivePathGuardConfig } from '../src/intervention/SensitivePathGuard.js'
import { DEFAULT_SENSITIVE_PATHS } from '../src/intervention/SensitivePathGuard.js'
import type { SecurityDecision, SecurityEvent } from '../src/types/index.js'
import type {
  SubprocessRuntimeLike,
  SubprocessSpawnResult,
  SubprocessSpawnSpec,
} from '../src/types/external.js'

class StubEventCollector {
  events: SecurityEvent[] = []
  report(event: SecurityEvent): void {
    this.events.push(event)
  }
}

function makeEngine(decision: SecurityDecision): InterventionEngine {
  return { evaluate: async () => decision } as unknown as InterventionEngine
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
    blockAtSubprocess: true,
    failOpenOnError: true,
    ...overrides,
  }
}

/** Enabled sensitive-path guard on the DEFAULT deny-list (/etc/shadow etc.). */
function makeSensitivePathGuard(): SensitivePathGuardConfig {
  // NOTE: the guard itself does NOT fall back to DEFAULT_SENSITIVE_PATHS
  // on an empty list (that fallback lives in normalizeConfig) — pass the
  // defaults explicitly.
  return { enabled: true, paths: [...DEFAULT_SENSITIVE_PATHS], watchEnabled: false, watchDebounceMs: 500 }
}

/** Drain the background SPL-eval promise chain. */
async function flushAsync(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve))
}

/**
 * Stub runtime whose `spawn` returns a handle-shaped
 * `SubprocessSpawnResult` SYNCHRONOUSLY — the real harness contract.
 * `handles` records every returned handle for identity assertions;
 * `terminated` counts `terminate()` calls.
 */
function makeSyncHandleRuntime(): SubprocessRuntimeLike & {
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
      return { pid: 42 }
    },
  }
  return Object.assign(extended, rt)
}

describe('RuntimeHook synchronous passthrough', () => {
  it('allow path: returns the original handle synchronously (non-Promise, identity-equal)', async () => {
    const collector = new StubEventCollector()
    const target = makeSyncHandleRuntime()
    const session: RuntimeHookSessionContext = {
      sessionId: 's-sync',
      runId: 'r-sync',
      agentId: 'a-sync',
    }
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine({ decision: 'allow', mode: 'audit', latency_ms: 1 }),
      runtimeHookConfig: makeConfig(),
      sensitivePathGuard: makeSensitivePathGuard(),
      mode: 'audit',
      sessionResolve: () => session,
    })
    hook.install(target)

    // Drive the seam through the patched method — exactly how the harness
    // calls it. This MUST NOT be awaited as a promise: the caller consumes
    // the handle synchronously (bash-local: `spawn(...); await handle.done`).
    const handle = target.spawn({ argv: ['bash', '-c', 'echo hi'] })

    // Shape parity: wrapped vs unwrapped, the caller sees the same object.
    expect(handle).not.toBeInstanceOf(Promise)
    expect(typeof (handle as { then?: unknown }).then).not.toBe('function')
    expect(handle).toBe(target.handles[0])
    expect(handle.done).toBeInstanceOf(Promise)
    // The bash-local consumption pattern keeps working end to end.
    await expect(handle.done).resolves.toEqual({ exitCode: 0, signal: null })
    expect(target.spawnCalls.length).toBe(1)

    // The SPL intent event lands from the background eval — async by
    // design, but the spawn itself was never deferred.
    await flushAsync()
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_intent')
    expect(collector.events[0]?.blocked).toBe(false)
    expect(collector.events[0]?.session_id).toBe('s-sync')
    hook.uninstall()
  })

  it('enforce + inline-guard hit: throws SpawnDeniedError SYNCHRONOUSLY before the fork', () => {
    const collector = new StubEventCollector()
    const target = makeSyncHandleRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine({ decision: 'allow', mode: 'enforce', latency_ms: 1 }),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: true }),
      sensitivePathGuard: makeSensitivePathGuard(),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)

    // fork reading a credential file hits the hardcoded sensitive-path
    // deny-list. The inline decision is known synchronously, so enforce
    // mode can — and MUST — still throw BEFORE the fork. toThrow asserts
    // the throw is synchronous; a rejected promise would fail this.
    expect(() =>
      target.spawn({ argv: ['cat', '/etc/shadow'] }),
    ).toThrow(SpawnDeniedError)

    expect(target.spawnCalls.length).toBe(0) // NO fork
    expect(target.handles.length).toBe(0)
    expect(hook.stats.blocked).toBe(1)
    // fix: enforce-mode inline-block emits a SINGLE
    // `runtime_spawn_denied` event (the prior intent + denied pair was an
    // N=2 audit fan-out — both events carried the same payload except for
    // the isDenied flag). The leading `runtime_spawn_intent` is redundant
    // once the denial is on the record.
    expect(collector.events.map((e) => e.event_type)).toEqual([
      'runtime_spawn_denied',
    ])
    hook.uninstall()
  })

  it('audit-mode inline block: sync handle returned, blocked intent recorded synchronously', () => {
    const collector = new StubEventCollector()
    const target = makeSyncHandleRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine({ decision: 'allow', mode: 'audit', latency_ms: 1 }),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: true }),
      sensitivePathGuard: makeSensitivePathGuard(),
      mode: 'audit', // audit → no throw even on inline block
      sessionResolve: () => undefined,
    })
    hook.install(target)

    const handle = target.spawn({ argv: ['cat', '/etc/shadow'] })
    expect(handle).toBe(target.handles[0])
    expect(target.spawnCalls.length).toBe(1)
    // Inline decisions are recorded synchronously — no flush needed.
    expect(collector.events.length).toBe(1)
    expect(collector.events[0]?.event_type).toBe('runtime_spawn_intent')
    expect(collector.events[0]?.blocked).toBe(true)
    expect(collector.events[0]?.intervention?.block_reason).toBeDefined()
    hook.uninstall()
  })

  it('enforce + SPL block: fork already happened — denied event + best-effort terminate ( semantic change)', async () => {
    const collector = new StubEventCollector()
    const target = makeSyncHandleRuntime()
    const hook = new RuntimeHook({
      eventCollector: collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
      interventionEngine: makeEngine({
        decision: 'block',
        mode: 'enforce',
        block_reason: 'restart no patch',
        block_code: 'SELF_PROTECTION_RESTART_WITHOUT_PATCH_015',
        latency_ms: 1,
      }),
      runtimeHookConfig: makeConfig({ blockAtSubprocess: true }),
      sensitivePathGuard: makeSensitivePathGuard(),
      mode: 'enforce',
      sessionResolve: () => undefined,
    })
    hook.install(target)

    // The synchronous API contract forbids deferring the spawn, so the
    // caller holds the handle before the SPL decision exists. The throw-
    // before-fork of earlier is physically impossible here — the locked-in
    // behavior is: passthrough → denied events → best-effort terminate.
    const handle = target.spawn({ argv: ['pnpm', 'dsh', 'web'] })
    expect(handle).toBe(target.handles[0])
    expect(target.spawnCalls.length).toBe(1)

    await flushAsync()
    expect(hook.stats.blocked).toBe(1)
    expect(target.terminated).toBe(1)
    // fix: enforce-mode SPL block emits a SINGLE
    // `runtime_spawn_denied` event (see inline-block test above for the
    // N=2 fan-out rationale — `intent + denied` was redundant).
    expect(collector.events.map((e) => e.event_type)).toEqual([
      'runtime_spawn_denied',
    ])
    expect(collector.events[0]?.block_reason).toBe('restart no patch')
    hook.uninstall()
  })
})
