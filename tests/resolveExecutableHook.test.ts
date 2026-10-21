/**
 * Unit tests for the resolveExecutable audit seam.
 *
 * Attack under test: an attacker plants `node_modules/.bin/<safe-name>` as
 * a symlink to a malicious bin. The argv layer (spawn seam + tool layer)
 * sees only the innocent-looking name, so the SPL deny-list lets it
 * through. The seam wraps `ctx.subprocess.resolveExecutable`: after the
 * original resolver returns, the result is realpath'd and the real target
 * text runs through the same `InterventionEngine.evaluate` pipeline.
 *
 * Acceptance coverage:
 *  1. symlink → malicious target is BLOCKED (audit records
 *     `runtime_resolve_denied`; enforce mode throws
 *     `ResolveExecutableDeniedError`)
 *  2. benign resolution is NOT blocked (real path returns normally, only
 *     `runtime_resolve_intent` is recorded)
 *
 * Uses a stub SubprocessRuntimeLike + stub EventCollector (same fixture
 * style as tests/runtimeHook.test.ts); `realpathFn` is injected so the
 * symlink divergence is modelled deterministically without Windows
 * symlink privileges. A separate test exercises a real filesystem
 * junction/symlink end to end (skipped when the platform denies link
 * creation).
 */
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  ResolveExecutableDeniedError,
  RuntimeHook,
  type RuntimeHookSessionContext,
} from '../src/intervention/RuntimeHook.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import { normalizeConfig } from '../src/config.js'
import { validateEvent } from '../src/utils/schema.js'
import type { InterventionContext, SecurityDecision, SecurityEvent } from '../src/types/index.js'
import type { SubprocessRuntimeLike } from '../src/types/external.js'

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

/** Stub engine that records the InterventionContext it was asked to evaluate. */
function makeRecordingEngine(decision: SecurityDecision): {
  engine: InterventionEngine
  seen: InterventionContext[]
} {
  const seen: InterventionContext[] = []
  const engine = {
    evaluate: async (ctx: InterventionContext) => {
      seen.push(ctx)
      return decision
    },
  } as unknown as InterventionEngine
  return { engine, seen }
}

function makeConfig(overrides: Record<string, unknown> = {}) {
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
  } as Parameters<typeof RuntimeHook>[0]['runtimeHookConfig']
}

function makeAllowDecision(): SecurityDecision {
  return { decision: 'allow', mode: 'audit', latency_ms: 1 }
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

interface ResolveCall {
  command: string
  env?: Record<string, string>
}

/** Subprocess runtime stub whose resolveExecutable returns `resolvedPath`. */
function makeResolveRuntime(resolvedPath: string): SubprocessRuntimeLike & { resolveCalls: ResolveCall[] } {
  const resolveCalls: ResolveCall[] = []
  const rt: SubprocessRuntimeLike = {
    spawn() {
      return { handle: null, pid: 1234 }
    },
    async spawnTerminal() {
      return { handle: null, pid: 5678 }
    },
    async resolveExecutable(command: string, env?: Record<string, string>) {
      resolveCalls.push({ command, env })
      return resolvedPath
    },
  }
  return Object.assign(rt, { resolveCalls })
}

function makeHook(opts: {
  collector: StubEventCollector
  engine: InterventionEngine
  config?: ReturnType<typeof makeConfig>
  mode?: 'audit' | 'enforce'
  sessionResolve?: () => RuntimeHookSessionContext | undefined
  realpathFn?: (path: string) => string
}): RuntimeHook {
  return new RuntimeHook({
    eventCollector: opts.collector as unknown as Parameters<typeof RuntimeHook>[0]['eventCollector'],
    interventionEngine: opts.engine,
    runtimeHookConfig: opts.config ?? makeConfig(),
    mode: opts.mode ?? 'audit',
    sessionResolve: opts.sessionResolve ?? (() => undefined),
    ...(opts.realpathFn ? { realpathFn: opts.realpathFn } : {}),
  })
}

const SESSION: RuntimeHookSessionContext = {
  sessionId: 'sess-1',
  runId: 'run-1',
  agentId: 'agent-1',
}

describe('RuntimeHook resolveExecutable seam', () => {
  let collector: StubEventCollector
  beforeEach(() => {
    collector = new StubEventCollector()
  })

  it('install wraps resolveExecutable and uninstall restores the original', async () => {
    const target = makeResolveRuntime('/usr/bin/tool')
    const orig = target.resolveExecutable
    const hook = makeHook({ collector, engine: makeEngine(makeAllowDecision()) })
    hook.install(target)
    expect(target.resolveExecutable).not.toBe(orig)
    await target.resolveExecutable!('tool')
    expect(hook.stats.resolved).toBe(1)
    hook.uninstall()
    expect(target.resolveExecutable).toBe(orig)
    // Restored original must keep working without the wrapper.
    await expect(target.resolveExecutable!('tool')).resolves.toBe('/usr/bin/tool')
    expect(hook.stats.resolved).toBe(1)
  })

  it('runtime without resolveExecutable stays inert (install does not throw)', () => {
    const rt: SubprocessRuntimeLike = {
      spawn() {
        return { handle: null, pid: 1 }
      },
    }
    const hook = makeHook({ collector, engine: makeEngine(makeAllowDecision()) })
    expect(() => hook.install(rt)).not.toThrow()
    expect(hook.stats.installed).toBe(true)
    expect(() => hook.uninstall()).not.toThrow()
  })

  it('allow: returns resolved path, emits runtime_resolve_intent only, event validates', async () => {
    const target = makeResolveRuntime('/usr/bin/node')
    const hook = makeHook({
      collector,
      engine: makeEngine(makeAllowDecision()),
      sessionResolve: () => SESSION,
      realpathFn: (p) => p,
    })
    hook.install(target)
    const result = await target.resolveExecutable!('node')
    expect(result).toBe('/usr/bin/node')
    expect(target.resolveCalls).toHaveLength(1)

    const intents = collector.events.filter((e) => e.event_type === 'runtime_resolve_intent')
    expect(intents).toHaveLength(1)
    expect(collector.events.filter((e) => e.event_type === 'runtime_resolve_denied')).toHaveLength(0)
    const event = intents[0]
    expect(event.exe).toBe('/usr/bin/node')
    expect(event.cmdline).toBe('/usr/bin/node')
    expect(event.session_id).toBe('sess-1')
    expect(event.source_layer).toBe('runtime')
    expect((event.metadata as Record<string, unknown>).symlink_diverged).toBe(false)
    expect(validateEvent(event)).toEqual([])
  })

  it('audit-mode block: records runtime_resolve_denied but still returns the resolved path', async () => {
    const target = makeResolveRuntime('/proj/node_modules/.bin/safe-name')
    const hook = makeHook({
      collector,
      engine: makeEngine(makeBlockDecision('malicious resolved executable', 'EVIL_001')),
      realpathFn: () => '/proj/node_modules/.evil/payload.sh',
    })
    hook.install(target)
    const result = await target.resolveExecutable!('safe-name')
    // Audit-only (mode=audit): the resolution is NOT interrupted.
    expect(result).toBe('/proj/node_modules/.bin/safe-name')

    const denied = collector.events.filter((e) => e.event_type === 'runtime_resolve_denied')
    expect(denied).toHaveLength(1)
    const event = denied[0]
    expect(event.blocked).toBe(true)
    expect(event.block_reason).toBe('malicious resolved executable')
    // exe carries the realpath'd target — the deny-list match target.
    expect(event.exe).toBe('/proj/node_modules/.evil/payload.sh')
    expect(event.cmdline).toBe('/proj/node_modules/.bin/safe-name -> /proj/node_modules/.evil/payload.sh')
    expect((event.metadata as Record<string, unknown>).symlink_diverged).toBe(true)
    expect(event.intervention?.block_code).toBe('EVIL_001')
    expect(validateEvent(event)).toEqual([])
    expect(hook.stats.resolveBlocked).toBe(1)
  })

  it('enforce + blockAtSubprocess: throws ResolveExecutableDeniedError', async () => {
    const target = makeResolveRuntime('/proj/node_modules/.bin/safe-name')
    const hook = makeHook({
      collector,
      engine: makeEngine(makeBlockDecision('malicious resolved executable', 'EVIL_001')),
      config: makeConfig({ blockAtSubprocess: true }),
      mode: 'enforce',
      realpathFn: () => '/proj/node_modules/.evil/payload.sh',
    })
    hook.install(target)
    await expect(target.resolveExecutable!('safe-name')).rejects.toBeInstanceOf(ResolveExecutableDeniedError)
    await expect(target.resolveExecutable!('safe-name')).rejects.toMatchObject({
      blockCode: 'EVIL_001',
      resolvedPath: '/proj/node_modules/.bin/safe-name',
      realPath: '/proj/node_modules/.evil/payload.sh',
    })
    // Intent + denied pair was recorded for the blocked call.
    expect(collector.events.filter((e) => e.event_type === 'runtime_resolve_denied').length).toBeGreaterThanOrEqual(1)
  })

  it('enforce + blockAtSubprocess:false stays audit-only (returns path)', async () => {
    const target = makeResolveRuntime('/proj/node_modules/.bin/safe-name')
    const hook = makeHook({
      collector,
      engine: makeEngine(makeBlockDecision()),
      config: makeConfig({ blockAtSubprocess: false }),
      mode: 'enforce',
      realpathFn: () => '/proj/node_modules/.evil/payload.sh',
    })
    hook.install(target)
    await expect(target.resolveExecutable!('safe-name')).resolves.toBe('/proj/node_modules/.bin/safe-name')
    expect(collector.events.filter((e) => e.event_type === 'runtime_resolve_denied')).toHaveLength(1)
  })

  it('feeds the realpath target (not the argv-safe name) to the SPL matcher', async () => {
    const target = makeResolveRuntime('/proj/node_modules/.bin/safe-name')
    const { engine, seen } = makeRecordingEngine(makeAllowDecision())
    const hook = makeHook({
      collector,
      engine,
      realpathFn: () => '/proj/node_modules/.evil/payload.sh',
    })
    hook.install(target)
    await target.resolveExecutable!('safe-name', { FOO: 'bar' })

    expect(seen).toHaveLength(1)
    const ctx = seen[0]
    // toolName is the real target's basename — deny-list sees through the symlink.
    expect(ctx.toolName).toBe('payload.sh')
    // Matcher-visible command text carries BOTH resolved and realpath.
    expect(ctx.params.command).toBe('/proj/node_modules/.bin/safe-name -> /proj/node_modules/.evil/payload.sh')
    expect(ctx.body).toBe(ctx.params.command)
    expect(ctx.params.requested_command).toBe('safe-name')
    expect(ctx.params.env).toEqual({ FOO: 'bar' })
    expect(ctx.actionType).toBe('process_start')
  })

  it('normalises Windows separators in matcher-visible text', async () => {
    const target = makeResolveRuntime('C:\\proj\\node_modules\\.bin\\safe-name')
    const { engine, seen } = makeRecordingEngine(makeAllowDecision())
    const hook = makeHook({
      collector,
      engine,
      realpathFn: () => 'C:\\proj\\node_modules\\.evil\\payload.sh',
    })
    hook.install(target)
    await target.resolveExecutable!('safe-name')
    const ctx = seen[0]
    expect(ctx.params.command).toBe('C:/proj/node_modules/.bin/safe-name -> C:/proj/node_modules/.evil/payload.sh')
    // Raw paths stay un-normalised under the metadata-style params.
    expect(ctx.params.resolved_path).toBe('C:\\proj\\node_modules\\.bin\\safe-name')
  })

  it('realpath failure degrades to the resolved path (never throws, invariant #3)', async () => {
    const target = makeResolveRuntime('/usr/bin/tool')
    const { engine, seen } = makeRecordingEngine(makeAllowDecision())
    const hook = makeHook({
      collector,
      engine,
      realpathFn: () => {
        throw new Error('ENOENT')
      },
    })
    hook.install(target)
    await expect(target.resolveExecutable!('tool')).resolves.toBe('/usr/bin/tool')
    expect(seen[0].params.command).toBe('/usr/bin/tool')
    expect(seen[0].params.realpath).toBeUndefined()
  })

  it('eval error + failOpenOnError: returns resolved path and emits runtime_hook_error', async () => {
    const target = makeResolveRuntime('/usr/bin/tool')
    const engine = {
      evaluate: async () => {
        throw new Error('engine exploded')
      },
    } as unknown as InterventionEngine
    const hook = makeHook({ collector, engine })
    hook.install(target)
    await expect(target.resolveExecutable!('tool')).resolves.toBe('/usr/bin/tool')
    expect(hook.stats.errors).toBe(1)
    const errors = collector.events.filter((e) => e.event_type === 'runtime_hook_error')
    expect(errors).toHaveLength(1)
    expect(errors[0].cmdline).toBe('tool')
    expect(validateEvent(errors[0])).toEqual([])
  })

  it('eval error + failOpenOnError:false rethrows the eval error', async () => {
    const target = makeResolveRuntime('/usr/bin/tool')
    const engine = {
      evaluate: async () => {
        throw new Error('engine exploded')
      },
    } as unknown as InterventionEngine
    const hook = makeHook({ collector, engine, config: makeConfig({ failOpenOnError: false }) })
    hook.install(target)
    await expect(target.resolveExecutable!('tool')).rejects.toThrow('engine exploded')
  })

  it('original resolver rejection propagates untouched (no events recorded)', async () => {
    const resolveCalls: string[] = []
    const rt: SubprocessRuntimeLike = {
      spawn() {
        return { handle: null, pid: 1 }
      },
      async resolveExecutable(command: string) {
        resolveCalls.push(command)
        throw new Error('command not found: ' + command)
      },
    }
    const hook = makeHook({ collector, engine: makeEngine(makeAllowDecision()) })
    hook.install(rt)
    await expect(rt.resolveExecutable!('missing-cmd')).rejects.toThrow('command not found: missing-cmd')
    expect(collector.events).toHaveLength(0)
    expect(hook.stats.errors).toBe(0)
  })

  it('disabled seam (enabledAtSubprocess:false) passes through without eval or events', async () => {
    const target = makeResolveRuntime('/usr/bin/tool')
    const { engine, seen } = makeRecordingEngine(makeAllowDecision())
    const hook = makeHook({ collector, engine, config: makeConfig({ enabledAtSubprocess: false }) })
    hook.install(target)
    await expect(target.resolveExecutable!('tool')).resolves.toBe('/usr/bin/tool')
    expect(seen).toHaveLength(0)
    expect(collector.events).toHaveLength(0)
  })
})

describe('resolveExecutable seam × default SPL policy (integration)', () => {
  let tmpDir: string
  let collector: StubEventCollector

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-resolve-seam-'))
    collector = new StubEventCollector()
  })

  afterEach(() => {
    if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true })
  })

  function withDefaultPolicy(): InterventionEngine {
    const defaultPolicyPath = fileURLToPath(new URL('../policies/default-policy.spl.yaml', import.meta.url))
    const cfg = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPath: defaultPolicyPath, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
    })
    const engine = new InterventionEngine(cfg)
    engine.initialize()
    return engine
  }

  it('acceptance : node_modules/.bin/<safe-name> resolving to a malicious target is downgraded to warn ( severity=medium)', async () => {
    const engine = withDefaultPolicy()
    try {
      const resolvedPath = join(tmpDir, 'node_modules', '.bin', 'safe-name')
      const evilTarget = join(tmpDir, 'node_modules', '.evil', '.ssh', 'id_dropper')
      const target = makeResolveRuntime(resolvedPath)
      const hook = makeHook({
        collector,
        engine,
        config: makeConfig({ blockAtSubprocess: true }),
        mode: 'enforce',
        // Model the symlink: resolver returns the .bin name, realpath
        // reveals the malicious target (matches block-credential-in-command-critical
        // via the `.ssh/id_` literal in the realpath'd path).
        realpathFn: () => evilTarget,
      })
      hook.install(target)
      // severity=medium on block-credential-in-command-critical
      // downgrades the authored `block` to runtime `warn` — the hook no
      // longer rejects, it emits an audit-only intent event with the
      // matched rule + audit trail preserved.
      await expect(target.resolveExecutable!('safe-name')).resolves.toBe(resolvedPath)
      const intents = collector.events.filter((e) => e.event_type === 'runtime_resolve_intent')
      expect(intents.length).toBeGreaterThanOrEqual(1)
      const warnIntent = intents.find((e) => e.intervention?.severity_downgraded === true)
      expect(warnIntent).toBeDefined()
      expect(warnIntent?.intervention?.severity_rule_id).toBe('block-credential-in-command-critical')
      expect(warnIntent?.intervention?.block_code).toBe('DATA_LEAK_MONITORING_CREDENTIAL_CMD_001')
      // No `runtime_resolve_denied` event — the hook did not throw.
      const denied = collector.events.filter((e) => e.event_type === 'runtime_resolve_denied')
      expect(denied).toHaveLength(0)
      expect(validateEvent(intents[0])).toEqual([])
    } finally {
      engine.shutdown()
    }
  })

  it('acceptance : benign resolution is not blocked (no symlink divergence)', async () => {
    const engine = withDefaultPolicy()
    try {
      const resolvedPath = join(tmpDir, 'node_modules', '.bin', 'rg')
      const target = makeResolveRuntime(resolvedPath)
      const hook = makeHook({
        collector,
        engine,
        config: makeConfig({ blockAtSubprocess: true }),
        mode: 'enforce',
        realpathFn: (p) => p, // realpath == resolved → no divergence
      })
      hook.install(target)
      await expect(target.resolveExecutable!('rg')).resolves.toBe(resolvedPath)
      expect(collector.events.filter((e) => e.event_type === 'runtime_resolve_denied')).toHaveLength(0)
      const intents = collector.events.filter((e) => e.event_type === 'runtime_resolve_intent')
      expect(intents).toHaveLength(1)
      expect(intents[0].blocked).toBe(false)
      expect(validateEvent(intents[0])).toEqual([])
    } finally {
      engine.shutdown()
    }
  })

  it('real filesystem symlink/junction: resolver path realpaths to the deny-list target ( severity=medium → warn)', async (ctx) => {
    // Real end-to-end realpath through an actual symlink. Junction on
    // Windows (no admin needed for directory junctions); dir symlink on POSIX.
    const evilDir = join(tmpDir, 'node_modules', '.evil', '.ssh', 'id_dropper')
    const binDir = join(tmpDir, 'node_modules', '.bin')
    mkdirSync(evilDir, { recursive: true })
    mkdirSync(binDir, { recursive: true })
    writeFileSync(join(evilDir, 'index.js'), '// malicious bin\n')
    try {
      symlinkSync(evilDir, join(binDir, 'safe-link'), process.platform === 'win32' ? 'junction' : 'dir')
    } catch {
      // Platform denies link creation (non-dev Windows / restricted FS) —
      // the injected-realpath tests above already cover the seam logic.
      ctx.skip()
    }
    const engine = withDefaultPolicy()
    try {
      const resolvedPath = join(binDir, 'safe-link')
      const target = makeResolveRuntime(resolvedPath)
      const hook = makeHook({
        collector,
        engine,
        config: makeConfig({ blockAtSubprocess: true }),
        mode: 'enforce',
        // Use the REAL realpath implementation (no realpathFn override).
      })
      hook.install(target)
      // severity=medium downgrade → no throw, audit-only.
      await expect(target.resolveExecutable!('safe-link')).resolves.toContain('safe-link')
      const intents = collector.events.filter((e) => e.event_type === 'runtime_resolve_intent')
      const warnIntent = intents.find((e) => e.intervention?.severity_downgraded === true)
      expect(warnIntent).toBeDefined()
      expect(warnIntent?.intervention?.severity_rule_id).toBe('block-credential-in-command-critical')
      // exe carries the realpath'd target (case may differ on Windows).
      expect(warnIntent?.exe?.toLowerCase().replace(/\\/g, '/')).toContain('.ssh/id_dropper')
      expect(warnIntent?.intervention?.block_code).toBe('DATA_LEAK_MONITORING_CREDENTIAL_CMD_001')
      // No `runtime_resolve_denied` event — the hook did not throw.
      const denied = collector.events.filter((e) => e.event_type === 'runtime_resolve_denied')
      expect(denied).toHaveLength(0)
    } finally {
      engine.shutdown()
    }
  })
})
