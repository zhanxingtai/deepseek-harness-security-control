/**
 * Tests for the server-side Typert contribution
 * Config tab snapshot + livePatch.
 *
 * Coverage:
 *  - registration: `ctx.typert.register(contribution)` is called with
 *    the expected host-side TypertContribution (`{package,
 *    face:'host', schemas, model, invocations[]}` — the rich registry
 *    contract, the typert registry) and a Cordis
 *    Service named 'securityMonitor' is registered via
 *    `ctx.reflect.provide('securityMonitor', service)` carrying the
 *    `typertRemote` binding the gateway's `validateBinding` demands
 *    (the host gateway). Handlers live as
 *    instance methods on the registered service, not on the
 *    descriptors.
 *  - graceful degradation: missing `ctx.typert` → no-op disposer +
 *    single warn line
 *  - `register` returns `TypertDisposer` synchronously; the disposer
 *    itself is async (`Promise<void>`)
 *  - `overview()` returns the expected snapshot shape
 *  - `recentBlocks()` accepts a limit and returns BlockRow[] in
 *    newest-first order; missing sink path returns []
 *  - `rules()` lists enabled rules with declared severity + decision
 *  - `reload()` delegates to InterventionEngine.requestReload()
 *  - `getConfig()` returns a 16-group snapshot mirroring every key on
 * the normalised Config ( read-only contract)
 *  - disposer is idempotent and safe to call multiple times
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  registerSecurityMonitorRemote,
  type TypertContribution,
  type TypertDisposer,
  type TypertRegistryContract,
} from '../../src/typert/host.js'
import { SECURITY_MONITOR_INVOCATIONS } from '../../src/typert/descriptors.js'
import { OverviewCache } from '../../src/status/overviewCache.js'
import { InterventionEngine } from '../../src/intervention/InterventionEngine.js'
import { DebugLog } from '../../src/utils/debugLog.js'
import type { Context, Logger } from '../../src/types/external.js'
import { normalizeConfig, type Config } from '../../src/config.js'

interface FakeSink {
  getStats: () => { queued: number; flushed: number; dropped: number; errors: number }
  getLocalOutputPath: () => string | undefined
}

interface ProvideCapture {
  name: string
  value: unknown
  disposer: () => Promise<void>
}

function buildContext(
  typert: TypertRegistryContract | undefined,
  provide: (name: string, value: unknown) => () => Promise<void>,
): { ctx: Context; warns: string[] } {
  const warns: string[] = []
  const logger: Logger = {
    debug() {
      /* noop */
    },
    info() {
      /* noop */
    },
    warn(message) {
      warns.push(message)
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
    // the host-side mount API
    // migrated off `ctx.typert.remotes.register(...)` (wrong layer —
    // the consumer-side view used by `ctx.remote.$mount` on the
    // browser cordis ctx) onto `ctx.typert.register(contribution)`
    // (canonical host-side strict registry,
    // the typert registry) plus a
    // separately-registered Cordis Service via
    // `ctx.reflect.provide('securityMonitor', service)`. 'typert' is
    // reached via `ctx.reflect.get(name)` (safe-access shim). The
    // shim returns the test-supplied `typert` mock when present;
    // `provide` captures the Service registration.
    reflect: {
      get(name: string) {
        if (name === 'typert') return typert
        return undefined
      },
      _getImpl: () => undefined,
      store: {},
      props: {},
      provide,
    },
  } as unknown as Context
  return { ctx, warns }
}

function captureMount(): {
  typert: TypertRegistryContract
  provide: (name: string, value: unknown) => () => Promise<void>
  state: {
    contribution: TypertContribution | null
    provides: ProvideCapture[]
    disposed: number
    throwOnMount?: Error
    throwOnDispose?: Error
  }
} {
  const state: {
    contribution: TypertContribution | null
    provides: ProvideCapture[]
    disposed: number
    throwOnMount?: Error
    throwOnDispose?: Error
  } = { contribution: null, provides: [], disposed: 0 }
  const typert: TypertRegistryContract = {
    register(contribution) {
      state.contribution = contribution
      if (state.throwOnMount) throw state.throwOnMount
      const disposer: TypertDisposer = async () => {
        state.disposed += 1
        if (state.throwOnDispose) throw state.throwOnDispose
      }
      return disposer
    },
  }
  const provide = (name: string, value: unknown): (() => Promise<void>) => {
    const disposer = async (): Promise<void> => {
      /* noop */
    }
    state.provides.push({ name, value, disposer })
    return disposer
  }
  return { typert, provide, state }
}

/**
 * helper to invoke a method on the registered
 * `securityMonitor` Cordis Service. Pre- the test read
 * `state.contribution.descriptors[*].handler` (the legacy
 * descriptor-attached shape); the harness actually looks up the
 * receiver via `receiverContext.get('securityMonitor')` and calls
 * `Reflect.get(receiver, method)`, so we look up the service method
 * on the captured provide value.
 */
function getHandler(
  state: { provides: ProvideCapture[] },
  name: string,
): (...args: unknown[]) => Promise<unknown> {
  const capture = state.provides.find((p) => p.name === 'securityMonitor')
  if (!capture) {
    throw new Error("'securityMonitor' service was not provided on ctx")
  }
  const service = capture.value as Record<string, unknown>
  const method = service[name]
  if (typeof method !== 'function') {
    throw new Error(`method '${name}' not found on 'securityMonitor' service`)
  }
  return method.bind(service) as (...args: unknown[]) => Promise<unknown>
}

let dir: string
let policyPath: string
let engine: InterventionEngine
let config: Config

beforeEach(() => {
  // synthetic TY_A fixture — canonical SPL v2 shape: per-rule risk tier
  // lives in the top-level `severity:`, and decision=block carries a
  // category-aligned blockCode so the rule survives spec §7.4 validation.
  // The typert rules() surface surfaces that declared severity.
  dir = mkdtempSync(join(tmpdir(), 'sec-mgr-typert-'))
  policyPath = join(dir, 'policy.json')
  writeFileSync(
    policyPath,
    JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'typert-test', version: '1' },
      rules: [
        {
          id: 'TY_A',
          name: 'a',
          enabled: true,
          priority: 200,
          category: 'intrusion_defense',
          severity: 'critical',
          match: { toolName: ['t1'] },
          action: {
            decision: 'block',
            blockReason: 'reason-a',
            blockCode: 'INTRUSION_DEFENSE_TY_A_001',
          },
        },
        {
          id: 'TY_B_DISABLED',
          name: 'b',
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
  engine = new InterventionEngine({
    intervention: {
      mode: 'audit',
      failStrategy: 'fail_open',
      decisionTimeoutMs: 50,
      policyPath,
      policyPaths: [],
      reloadIntervalMs: 0,
    },
    inlineGuards: { enabled: false },
  } as unknown as Parameters<typeof InterventionEngine.prototype.constructor>[0])
  engine.initialize()
  // construct a real normalised Config so the
  // getConfig() handler has the full shape to snapshot. Slight overlay
  // on top of the marketplace defaults makes the assertions below
  // specific without coupling to every default.
  config = normalizeConfig({
    mode: 'enforce',
    hostId: 'host-A',
    containerId: 'host',
    collector: {
      localOutputPath: '/var/log/sec.jsonl',
      batchSize: 50,
      flushIntervalMs: 250,
      maxFileBytes: 1_000_000,
      debugLogPath: '',
    },
    application: { toolResultMaxChars: 200_000, sessionTtlMs: 900_000 },
    intervention: { mode: 'enforce', policyPath, reloadIntervalMs: 15_000 },
    runtimeHooks: { hookPath: '/var/run/sec.hook' },
  })
})

afterEach(() => {
  engine.shutdown()
  rmSync(dir, { recursive: true, force: true })
})

/**
 * The descriptor shape captured from the fake registry — mirrors the
 * harness `InvocationDescriptor` fields the gateway + registry
 * actually read (the typert protocol).
 */
interface CapturedDescriptor {
  id: string
  service: string
  namespace: string
  method: string
  invocation: { kind: string }
  parameters: Array<{
    name: string
    wire: string
    codec: { mode: string }
    acceptsUndefined?: true
  }>
  result: { mode: string }
}

function capturedDescriptors(state: { contribution: TypertContribution | null }): CapturedDescriptor[] {
  return (state.contribution?.invocations ?? []) as CapturedDescriptor[]
}

describe('registerSecurityMonitorRemote', () => {
  it('mounts the securityMonitor package with invocations[] matching SECURITY_MONITOR_INVOCATIONS', () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    expect(state.contribution).not.toBeNull()
    // Host-side contract: the rich `TypertContribution` shape
    // `{package, face:'host', schemas, model, invocations[]}` consumed
    // by `TypertRegistry.register` (the typert registry service —
    // commits `invocations` into `ctx.typert.local`).
    // NOTE: the slim `{package, descriptors}` shape belongs to the
    // CLIENT-side `ctx.remote.$mount` (the typert protocol types) —
    // the two register paths are NOT the same.
    expect(state.contribution?.package).toBe('sst-security-control-dsh')
    expect(state.contribution?.face).toBe('host')
    const descriptors = capturedDescriptors(state)
    const methods = descriptors.map((d) => d.method).sort()
    expect(methods).toEqual(
      [...SECURITY_MONITOR_INVOCATIONS.map((i) => i.method)].sort(),
    )
    // Each descriptor points at the registered Cordis Service via
    // `service: 'securityMonitor'` (the harness's TypertGateway
    // dispatches through this field at
    // the host gateway).
    for (const desc of descriptors) {
      expect(desc.service).toBe('securityMonitor')
    }
    // The actual handlers live on the registered Cordis Service,
    // not on the descriptors. Verify every documented method is
    // present on the captured service.
    const providedService = state.provides.find((p) => p.name === 'securityMonitor')
    expect(providedService).toBeDefined()
    const service = providedService?.value as Record<string, unknown>
    for (const name of methods) {
      expect(typeof service[name]).toBe('function')
    }
  })

  it('attaches a consistent typertRemote binding to the registered service (validateBinding contract)', () => {
    // The gateway calls `validateBinding(receiver, ...)` on EVERY
    // invocation (the host gateway): the
    // receiver must carry a frozen `typertRemote` whose `service`
    // is the receiver itself and whose serviceKey/namespace match
    // (`readBinding`, same file :1036-1058). A plain class without
    // this property lands on `gateway/binding-invalid` for every RPC.
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const providedService = state.provides.find((p) => p.name === 'securityMonitor')
    const service = providedService?.value as Record<string, unknown>
    const binding = service['typertRemote'] as
      | { service: unknown; serviceKey: string; namespace: string }
      | undefined
    expect(binding).toBeDefined()
    expect(binding?.service).toBe(service)
    expect(binding?.serviceKey).toBe('securityMonitor')
    expect(binding?.namespace).toBe('securityMonitor')
    expect(Object.isFrozen(binding)).toBe(true)
  })

  it('declares strict codecs on payload parameters (client $mount contract)', () => {
    // The browser-side `ctx.remote.$mount` rejects descriptors whose
    // input parameters lack a strict codec
    // (the host gateway client requireStrictCodec)
    // — a src-json parameter codec makes the namespace unmountable.
    // Payload parameters also carry `acceptsUndefined` so a client
    // may omit the payload (e.g. `recentBlocks()`).
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const descriptors = capturedDescriptors(state)
    const withPayload = descriptors.filter((d) => d.parameters.length > 0)
    expect(withPayload.length).toBeGreaterThan(0)
    for (const d of withPayload) {
      for (const p of d.parameters) {
        expect(p.codec.mode).toBe('strict')
        expect(p.acceptsUndefined).toBe(true)
      }
    }
    for (const d of descriptors) {
      expect(d.result.mode).toBe('src-json')
    }
  })

  it('accepts the real Typert 0.1.6-alpha.2 host contribution shape', async () => {
    // The host-side `TypertContribution` contract from
    // the typert registry — re-assert it here so a
    // future shape drift (e.g. someone swapping to the CLIENT-side
    // slim `{package, descriptors}` shape, which `ctx.typert.register`
    // does NOT accept) fails loudly at the test layer instead of
    // silently at runtime.
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const c = state.contribution as TypertContribution
    expect(typeof c.package).toBe('string')
    expect(c.face).toBe('host')
    expect(Array.isArray(c.invocations)).toBe(true)
    const descriptors = capturedDescriptors(state)
    for (const d of descriptors) {
      expect(typeof d.method).toBe('string')
      expect(d.service).toBe('securityMonitor')
    }
    // Invoke every documented method on the registered Cordis
    // Service to confirm the handler dispatch surface is callable
    // the way TypertGateway will call it
    // (the host gateway).
    const providedService = state.provides.find((p) => p.name === 'securityMonitor')
    const service = providedService?.value as Record<string, (...args: unknown[]) => Promise<unknown>>
    for (const d of descriptors) {
      const method = service[d.method]
      expect(typeof method).toBe('function')
      // Bind `this` to the service — the harness TypertGateway uses
      // `Reflect.apply(method, receiver, args)`, so without binding,
      // the dispatched method would not see `this.sink` / `this.engine`.
      const result = await method.call(service, {})
      expect(result).toBeDefined()
    }
  })

  it('awaits the TypertDisposer (Promise<void>) instead of sync-disposing', async () => {
    // Pre- the wrapper did `dispose ` synchronously; the harness
    // returns `Promise<TypertDisposer>` (a Promise resolving to an
    // async disposer), so the sync call raised TypeError silently
    // (caught here as warn). The new path awaits both. We exercise
    // the full lifecycle and assert the underlying state flipped.
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    const dispose = registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    expect(state.disposed).toBe(0)
    dispose()
    // The disposer returns immediately (fire-and-forget); wait one
    // microtask for the async chain to settle.
    await Promise.resolve()
    await Promise.resolve()
    expect(state.disposed).toBe(1)
    // Idempotent — second call is a no-op (the `disposed` once-guard
    // prevents the TypertDisposer from firing twice).
    dispose()
    await Promise.resolve()
    await Promise.resolve()
    expect(state.disposed).toBe(1)
  })

  it('swallows TypertDisposer errors as warn (invariant #3: never throw to host)', async () => {
    // If the harness rejects during dispose (network teardown, race
    // with shutdown), the plugin must degrade silently with a warn —
    // never propagate to the host.
    const { typert, provide, state } = captureMount()
    state.throwOnDispose = new Error('harness teardown failed')
    const { ctx, warns } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    const dispose = registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    expect(() => {
      dispose()
    }).not.toThrow()
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    // Invariant : never throw to the host — the warn line is the
    // only observable signal.
    expect(warns.some((w) => /typert dispose failed/.test(w))).toBe(true)
  })

  it('returns a no-op disposer + warn when ctx.typert is missing and the host has no inject', () => {
    const { ctx, warns } = buildContext(undefined)
    // Terminal unavailable path requires a host WITHOUT `ctx.inject`
    // (when inject exists the registration defers instead — covered
    // by the deferred-registration test below).
    ;(ctx as unknown as Record<string, unknown>).inject = undefined
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    const dispose = registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    expect(typeof dispose).toBe('function')
    expect(warns.length).toBe(1)
    expect(warns[0]).toMatch(/typert bridge not registered/)
    expect(() => {
      dispose()
      dispose()
    }).not.toThrow()
  })

  it('defers registration via ctx.inject when the typert registry loads after the plugin', () => {
    // Runtime-verified behaviour (2026-09-23): in the web profile the
    // `typert` registry fiber loads AFTER this plugin, so the
    // immediate probe misses and registration must defer. Simulate:
    // inject captures the callback; typert appears when it fires.
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(undefined, provide)
    let injectCallback: (() => unknown) | undefined
    ;(ctx as unknown as Record<string, unknown>).inject = (
      _deps: string[],
      cb: () => unknown,
    ) => {
      injectCallback = cb
    }
    const states: Array<{ registered: boolean; note: string }> = []
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
      undefined,
      undefined,
      undefined,
      (registered, note) => states.push({ registered, note }),
    )
    // Immediate probe missed → deferred; nothing registered yet.
    expect(injectCallback).toBeDefined()
    expect(state.contribution).toBeNull()
    expect(states).toEqual([
      { registered: false, note: 'deferred: waiting for the typert registry service' },
    ])
    // The registry lands → the inject callback registers for real.
    ;(ctx as unknown as { reflect: { get: (n: string) => unknown } }).reflect.get = (
      name: string,
    ) => (name === 'typert' ? typert : undefined)
    injectCallback!()
    expect(state.contribution).not.toBeNull()
    expect(states[1]).toEqual({ registered: true, note: 'deferred' })
    expect(state.provides.some((p) => p.name === 'securityMonitor')).toBe(true)
  })

  it('BUG-5 : writes a surface_unavailable breadcrumb to the debug log when the remote bridge is missing', () => {
    const { ctx } = buildContext(undefined)
    // Terminal unavailable path: no inject on this host.
    ;(ctx as unknown as Record<string, unknown>).inject = undefined
    const debugLogPath = join(dir, 'security-monitor-debug.log')
    const debugLog = new DebugLog({ path: debugLogPath, logger: ctx.logger })
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    const dispose = registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
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
    expect(unavailable[0]!.surface).toBe('remote')
    expect(unavailable[0]!.reason).toMatch(/ctx\.typert\.register is unavailable/)
    expect(unavailable[0]!.peer).toMatch(/@deepseek-ai\/dsh-typert-protocol/)
  })

  it('BUG-5 : does not write surface_unavailable when the remote bridge mounts successfully', () => {
    const { typert, provide } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const debugLogPath = join(dir, 'security-monitor-debug.log')
    const debugLog = new DebugLog({ path: debugLogPath, logger: ctx.logger })
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
      debugLog,
    )
    // Successful mount writes no breadcrumb at all — the file is never
    // created (DebugLog is append-only-on-write).
    expect(existsSync(debugLogPath)).toBe(false)
  })

  it('overview() returns a snapshot with all expected fields', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 42, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => '/tmp/sec.jsonl',
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = await getHandler(state, 'overview')({})
    // overview reads live config.mode (was hardcoded
    // 'audit' regardless of plugin startup config). The test config
    // (line 140) sets mode: 'enforce' — assert against that.
    expect(snap.mode).toBe('enforce')
    // 2026-10-12: totalEvents is the file-scan count, not `flushed`
    // (42). '/tmp/sec.jsonl' does not exist on disk, so the scan sees
    // zero events — flushed is now only a cache-invalidation sentinel.
    expect(snap.totalEvents).toBe(0)
    expect(snap.loadedRuleCount).toBe(1)
    expect(snap.localOutputPath).toBe('/tmp/sec.jsonl')
    expect(typeof snap.uptimeSec).toBe('number')
    expect(snap.uptimeSec).toBeGreaterThanOrEqual(0)
    // the Metrics-page fields exist on the snapshot.
    // '/tmp/sec.jsonl' is not a deterministic fixture — only assert
    // types here; the counting contract is pinned by the fixture test
    // below.
    expect(typeof (snap as Record<string, unknown>).last24hTotalCount).toBe('number')
    expect(typeof (snap as Record<string, unknown>).byLayer).toBe('object')
  })

  it('overview counts last-24h totals and by-layer buckets from the NDJSON log', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const ndjson = join(dir, 'events.jsonl')
    const now = Date.now()
    const H = 60 * 60 * 1000
    const lines: string[] = [
      // in-window block (application layer)
      JSON.stringify({
        ts: now - 1 * H,
        layer: 'application',
        event_type: 'agent_tool_call',
        intervention: { decision: 'block', decision_internal: 'block' },
      }),
      // in-window allow (application layer)
      JSON.stringify({
        ts: now - 2 * H,
        layer: 'application',
        event_type: 'agent_tool_call',
        intervention: { decision: 'allow' },
      }),
      // in-window network capture
      JSON.stringify({ ts: now - 3 * H, layer: 'network', event_type: 'network_http' }),
      // OLD block — outside the 24h window: all-time only
      JSON.stringify({
        ts: now - 50 * H,
        layer: 'application',
        event_type: 'agent_tool_call',
        intervention: { decision: 'block', decision_internal: 'block' },
      }),
      // in-window audit WITHOUT a layer field → 'unknown' bucket
      JSON.stringify({ ts: now - 4 * H, event_type: 'security_audit' }),
      // 2026-10-12 — high-severity policy audit must NOT count as a
      // threat (决策口径):it has no intervention decision.
      JSON.stringify({
        ts: now - 5 * H,
        layer: 'application',
        event_type: 'security_audit',
        audit_category: 'policy',
        audit_action: 'tamper',
        severity: 'high',
      }),
      // malformed line is skipped by the streaming parser
      'not-json{',
    ]
    writeFileSync(ndjson, lines.join('\n') + '\n', 'utf8')
    const sink: FakeSink = {
      // flushed (5) deliberately disagrees with the on-disk count (6):
      // totalEvents must come from the file scan, not this counter.
      getStats: () => ({ queued: 0, flushed: 5, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = (await getHandler(state, 'overview')({})) as Record<string, unknown> & {
      totalEvents: number
      blockCount: number
      last24hBlockCount: number
      threatCount: number
      last24hThreatCount: number
      last24hTotalCount: number
      byLayer: Record<string, number>
    }
    // 2026-10-12 — total is the full-file parseable count (6), NOT the
    // process-local `flushed` counter (5): the counter resets on restart
    // while the NDJSON file persists.
    expect(snap.totalEvents).toBe(6)
    // 2 blocks total (one in-window, one 50h old), 1 block in window.
    expect(snap.blockCount).toBe(2)
    expect(snap.last24hBlockCount).toBe(1)
    // 2026-09-28 — 威胁事件口径:当前 fixture 无 warn 命中,威胁=拦截;
    // 窗口外旧命中仍计入全时间威胁计数。2026-10-12 (rev 2) — 审计发现
    // 档:severity=high 的 tamper 审计事件计入威胁(tamper/high 在窗口内)。
    expect(snap.threatCount).toBe(3)
    expect(snap.last24hThreatCount).toBe(2)
    // 5 of the 6 parseable events carry a ts inside the last 24h.
    expect(snap.last24hTotalCount).toBe(5)
    // Full-log bucket counts; the layerless audit lands in 'unknown'.
    expect(snap.byLayer).toEqual({ application: 4, network: 1, unknown: 1 })
  })

  it('overview returns 0 totals and an empty byLayer map for an empty log file', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const ndjson = join(dir, 'events-empty.jsonl')
    writeFileSync(ndjson, '', 'utf8')
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = (await getHandler(state, 'overview')({})) as Record<string, unknown>
    expect(snap.totalEvents).toBe(0)
    expect(snap.blockCount).toBe(0)
    expect(snap.last24hBlockCount).toBe(0)
    expect(snap.last24hTotalCount).toBe(0)
    expect(snap.byLayer).toEqual({})
  })

  it('overview serves last24hTotalCount / byLayer from the cache on repeat reads', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const ndjson = join(dir, 'events.jsonl')
    const now = Date.now()
    writeFileSync(
      ndjson,
      [
        JSON.stringify({
          ts: now - 1000,
          layer: 'application',
          event_type: 'agent_tool_call',
          intervention: { decision: 'block', decision_internal: 'block' },
        }),
        JSON.stringify({ ts: now - 2000, layer: 'network', event_type: 'network_http' }),
      ].join('\n') + '\n',
      'utf8',
    )
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 2, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    // Wire a real OverviewCache like bootstrap.ts does in production.
    const cache = new OverviewCache()
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
      undefined,
      undefined,
      cache,
    )
    const first = (await getHandler(state, 'overview')({})) as {
      totalEvents: number
      last24hTotalCount: number
      byLayer: Record<string, number>
    }
    expect(first.totalEvents).toBe(2)
    expect(first.last24hTotalCount).toBe(2)
    expect(first.byLayer).toEqual({ application: 1, network: 1 })
    // Second read rides the cache — same numbers, no re-scan.
    const second = (await getHandler(state, 'overview')({})) as {
      totalEvents: number
      last24hTotalCount: number
      byLayer: Record<string, number>
    }
    expect(second.totalEvents).toBe(2)
    expect(second.last24hTotalCount).toBe(2)
    expect(second.byLayer).toEqual({ application: 1, network: 1 })
  })

  it('overview() degrades to 0 counts when sink is not initialized', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = await getHandler(state, 'overview')({})
    expect(snap.localOutputPath).toBe('')
    expect(snap.totalEvents).toBe(0)
    expect(snap.last24hBlockCount).toBe(0)
    expect((snap as Record<string, unknown>).last24hTotalCount).toBe(0)
    expect((snap as Record<string, unknown>).byLayer).toEqual({})
  })

  it('rules() lists enabled rules with declared severity + decision', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const rules = (await getHandler(state, 'rules')({})) as Array<Record<string, unknown>>
    expect(rules.length).toBe(1) // disabled rule excluded
    const a = rules[0]!
    expect(a.id).toBe('TY_A')
    expect(a.enabled).toBe(true)
    expect(a.priority).toBe(200)
    expect(a.risk_level).toBe('critical')
    expect(a.decision).toBe('block')
    expect(a.block_reason).toBe('reason-a')
  })

  it('recentBlocks() reads NDJSON tail and returns BlockRow[]', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const ndjson = join(dir, 'events.jsonl')
    const lines: string[] = []
    for (let i = 0; i < 4; i++) {
      lines.push(
        JSON.stringify({
          event_type: 'agent_tool_call',
          ts: 1_000 + i,
          session_id: `s-${i}`,
          tool_name: `tool-${i}`,
          intervention: { decision: i % 2 === 0 ? 'block' : 'allow' },
        }),
      )
    }
    writeFileSync(ndjson, lines.join('\n') + '\n', 'utf8')
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 4, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const rows = (await getHandler(state, 'recentBlocks')({ limit: 10 })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(rows.rows.length).toBeGreaterThan(0)
    for (const r of rows.rows) {
      expect(r.decision).toMatch(/block|deny/)
    }
  })

  // 2026-09-28 — scope=all-hits:Policy Hits 列表列出全部规则命中(含
  // warn 级标记未拦截与 runtime 子进程层),scope 缺省保持 blocked 口径。
  it('recentBlocks({scope:"all-hits"}) includes warn-marked and runtime-layer hits', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const ndjson = join(dir, 'events.jsonl')
    const lines: string[] = [
      // block (both scopes)
      JSON.stringify({ event_type: 'agent_tool_call', ts: 1, tool_name: 'bash', intervention: { decision: 'deny', decision_internal: 'block', block_code: 'POLICY_X' } }),
      // warn 标记未拦截(仅 all-hits)
      JSON.stringify({ event_type: 'agent_tool_call', ts: 2, tool_name: 'read', intervention: { decision: 'ask', decision_internal: 'warn', policy_id: 'block-sensitive-system-files-warn' } }),
      // runtime 层 warn 命中(仅 all-hits),无 tool_name → exe 回填
      JSON.stringify({ event_type: 'runtime_spawn_intent', ts: 3, exe: '/usr/bin/bwrap', intervention: { decision: 'ask', decision_internal: 'warn' } }),
      // allow — 两个口径都不含
      JSON.stringify({ event_type: 'agent_tool_call', ts: 4, intervention: { decision: 'allow' } }),
    ]
    writeFileSync(ndjson, lines.join('\n') + '\n', 'utf8')
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 4, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const blocked = (await getHandler(state, 'recentBlocks')({ limit: 10 })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(blocked.rows.length).toBe(1)
    const hits = (await getHandler(state, 'recentBlocks')({ limit: 10, scope: 'all-hits' })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(hits.rows.length).toBe(3)
    const internals = hits.rows.map((r) => r.decision_internal).sort()
    expect(internals).toEqual(['block', 'warn', 'warn'])
    // runtime 行带 exe 回填字段,TOOL 列渲染 `spawn: <exe>` 的数据源。
    const spawnRow = hits.rows.find((r) => r.exe !== undefined)
    expect(spawnRow).toBeDefined()
    expect(spawnRow?.tool_name).toBeUndefined()
  })

  // 2026-09-29 — B2 惰性明细:includeRaw=true 时每行额外携带截断的完整
  // 原始事件(raw_json),供 Policy Hits 详情展开;缺省摘要不带。
  it('recentBlocks({includeRaw:true}) caps and attaches the raw event per row', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const ndjson = join(dir, 'events.jsonl')
    const fatParams = 'x'.repeat(20 * 1024)
    const lines: string[] = [
      JSON.stringify({
        event_type: 'agent_tool_call',
        ts: 1,
        tool_name: 'bash',
        tool_call_id: 'call-1',
        tool_params: '{"command":"cat /etc/shadow"}',
        intervention: { decision: 'deny', decision_internal: 'block', policy_id: 'rule-fat' },
      }),
      JSON.stringify({
        event_type: 'agent_tool_call',
        ts: 2,
        tool_name: 'bash',
        tool_params: fatParams,
        intervention: { decision: 'deny', decision_internal: 'block', policy_id: 'rule-fat' },
      }),
    ]
    writeFileSync(ndjson, lines.join('\n') + '\n', 'utf8')
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 2, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    // 摘要模式(3 s 轮询口径)不带 raw_json。
    const summary = (await getHandler(state, 'recentBlocks')({ limit: 10, scope: 'all-hits' })) as {
      rows: Array<Record<string, unknown>>
      total: number
    }
    expect(summary.rows.length).toBe(2)
    for (const r of summary.rows) expect(r['raw_json']).toBeUndefined()
    // includeRaw 模式:小行给完整 JSON,超大行截断 + 面包屑。
    const rows = (await getHandler(state, 'recentBlocks')({ limit: 10, scope: 'all-hits', includeRaw: true })) as {
      rows: Array<Record<string, unknown>>
      total: number
    }
    expect(rows.rows.length).toBe(2)
    const small = rows.rows.find((r) => typeof r['raw_json'] === 'string' && !(r['raw_json'] as string).endsWith('...[truncated]'))
    expect(small).toBeDefined()
    expect(small?.['raw_json']).toContain('cat /etc/shadow')
    const fat = rows.rows.find((r) => typeof r['raw_json'] === 'string' && (r['raw_json'] as string).endsWith('...[truncated]'))
    expect(fat).toBeDefined()
  })

  it('recentBlocks() returns [] when sink is not initialized', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const rows = (await getHandler(state, 'recentBlocks')({ limit: 10 })) as { rows: Array<unknown>; total: number }
    expect(rows).toEqual({ rows: [], total: 0 })
  })

  it('reload() delegates to engine.requestReload', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const result = (await getHandler(state, 'reload')({})) as { ok: boolean; ruleCount?: number }
    expect(result.ok).toBe(true)
    expect(typeof result.ruleCount).toBe('number')
  })

  it('getConfig() returns 7-group snapshot with all top-level keys present', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = (await getHandler(state, 'getConfig')({})) as Record<string, unknown>
    // Top-level shape — every key the Config tab groups.
    //
    // extended with the 7 §6.2 sub-block
    // mirrors (sensitivePathGuard / inlinePromptInjection /
    // stdioMirror / envPassthroughGuard / sensitiveHeaderGuard /
    // loopedToolDetector / tokenUsageDetector / sinkDiskLow). Pre-
    // the host test hardcoded the 10-key list and silently accepted a
    // snapshot that dropped the 7 inline-guard / detector / mirror
    // blocks. E2-3 adds sensitiveHeaderGuard.
    expect(Object.keys(snap).sort()).toEqual(
      [
        'application',
        'collector',
        'containerId',
        'enabled',
        'envPassthroughGuard',
        'hostId',
        'inlineGuards',
        'inlinePromptInjection',
        'intervention',
        'loopedToolDetector',
        'mode',
        'networkCapture',
        'runtimeHooks',
        'sensitiveHeaderGuard',
        'sensitivePathGuard',
        'sinkDiskLow',
        'stdioMirror',
        'tokenUsageDetector',
      ].sort(),
    )
  })

  it('getConfig() propagates top-level mode + enabled + ids', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = (await getHandler(state, 'getConfig')({})) as Record<string, unknown>
    expect(snap.mode).toBe('enforce') // top-level overlay was 'enforce'
    expect(snap.enabled).toBe(true)
    expect(snap.hostId).toBe('host-A')
    expect(snap.containerId).toBe('host')
  })

  it('getConfig() collector sub-block mirrors normalised CollectorConfig', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = (await getHandler(state, 'getConfig')({})) as Record<string, any>
    const collector = snap.collector as Record<string, unknown>
    expect(collector.localOutputPath).toBe('/var/log/sec.jsonl')
    expect(collector.batchSize).toBe(50)
    expect(collector.flushIntervalMs).toBe(250)
    expect(collector.maxFileBytes).toBe(1_000_000)
    // Defaults that we did not override should fall through to the
    // marketplace defaults — the snapshot must reflect the LIVE
    // normalised Config, not the input overlay.
    expect(collector.validateEvents).toBe(true)
    expect(collector.redactRawParams).toBe(true)
    expect(typeof collector.diskWarnWatermarkBytes).toBe('number')
    expect(typeof collector.diskLowWatermarkBytes).toBe('number')
  })

  it('getConfig() intervention sub-block carries mode + policyPath + reloadIntervalMs', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = (await getHandler(state, 'getConfig')({})) as Record<string, any>
    const intervention = snap.intervention as Record<string, unknown>
    expect(intervention.mode).toBe('enforce')
    expect(intervention.policyPath).toBe(policyPath)
    expect(intervention.reloadIntervalMs).toBe(15_000)
    expect(intervention.failStrategy).toBe('fail_open')
    expect(Array.isArray(intervention.policyPaths)).toBe(true)
  })

  it('getConfig inlineGuards sub-block mirrors the actual shape (no enabled flag)', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap = (await getHandler(state, 'getConfig')({})) as Record<string, any>
    const inline = snap.inlineGuards as Record<string, unknown>
    // design: the snapshot carries the actual inlineGuards keys
    // not a boolean 'enabled'. The UI shows a lock icon on every
    // field to convey "immutable by design".
    expect(Object.keys(inline).sort()).toEqual(
      ['engineLaunchers', 'patchMarkers', 'pluginPackageName'].sort(),
    )
    expect(inline.pluginPackageName).toBe('sst-security-control-dsh')
    expect(Array.isArray(inline.engineLaunchers)).toBe(true)
    expect(Array.isArray(inline.patchMarkers)).toBe(true)
    expect((inline.engineLaunchers as string[]).length).toBeGreaterThan(0)
  })

  it('getConfig() spread-copies array fields so the snapshot is detached from the live Config', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const snap1 = (await getHandler(state, 'getConfig')({})) as Record<string, any>
    const snap2 = (await getHandler(state, 'getConfig')({})) as Record<string, any>
    // Two distinct snapshot objects — each call rebuilds. Same content
    // (immutable contract) but the array references are NOT shared.
    const a = snap1.inlineGuards.engineLaunchers as string[]
    const b = snap2.inlineGuards.engineLaunchers as string[]
    expect(a).not.toBe(b)
    expect([...a]).toEqual([...b])
  })

  it('disposer is safe to call', () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    const dispose = registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    expect(() => {
      dispose()
      dispose()
    }).not.toThrow()
    // Contribution is still present for inspection even after dispose —
    // the runtime's own teardown owns the actual unmount.
    expect(state.contribution).not.toBeNull()
  })

  /* ---------------------------------------------------------------- *
   * Config form + draft persistence.        *
   *                                                                    *
   * The settings-page Config tab is upgraded from a read-only mirror   *
   * to a controlled form. The wire contract gains 3 new methods       *
   * (`validateConfigPatch`, `saveConfigDraft`, `getConfigDraftStatus`)*
   * — the cases below exercise every documented rejection + warning  *
   * path so the host side cannot silently drift from the validator's
   * documented behaviour.
   * ---------------------------------------------------------------- */

  it('validateConfigPatch rejects unknown top-level keys with an actionable message', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const result = (await getHandler(state, 'validateConfigPatch')({
      unknownField: 'foo',
    })) as { ok: boolean; errors: string[] }
    expect(result.ok).toBe(false)
    expect(result.errors.some((e) => e.includes('unknownField'))).toBe(true)
    // The error message names the allowed set so the operator can
    // self-correct without reading the source.
    expect(result.errors.some((e) => e.includes('not a recognized Config top-level key'))).toBe(true)
  })

  it('validateConfigPatch rejects illegal mode enum values', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const result = (await getHandler(state, 'validateConfigPatch')({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mode: 'rainbow' as any,
    })) as { ok: boolean; errors: string[] }
    expect(result.ok).toBe(false)
    // The Schemastery validator emits the field path + a list of
    // accepted values. The exact wording is the validator's
    // concern — we just assert the call was rejected.
    expect(result.errors.length).toBeGreaterThan(0)
  })

  it('validateConfigPatch warns on inlineGuards.engineLaunchers=[] ( safety net)', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const result = (await getHandler(state, 'validateConfigPatch')({
      inlineGuards: { engineLaunchers: [] },
    })) as { ok: boolean; errors: string[]; warnings: string[] }
    // The validator accepts the patch ( is enforced at apply time
    // by `defaultInlineGuardsConfig`, not by hard-rejecting the
    // patch) but emits a warning that names the invariant.
    expect(result.ok).toBe(true)
    expect(result.warnings.some((w) => w.includes('engineLaunchers'))).toBe(true)
    expect(result.warnings.some((w) => w.toLowerCase().includes('safety net'))).toBe(true)
  })

  it('validateConfigPatch rejects marketplace-stripped top-level keys (endpoint / auth)', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const result = (await getHandler(state, 'validateConfigPatch')({
      endpoint: 'http://malicious.example/collect',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      auth: { token: 'leak' } as any,
    })) as { ok: boolean; errors: string[] }
    expect(result.ok).toBe(false)
    expect(result.errors.some((e) => e.includes('endpoint'))).toBe(true)
    expect(result.errors.some((e) => e.includes('auth'))).toBe(true)
    // The rejection message names the marketplace stripping so an
    // operator can tell it is policy, not a typo.
    expect(result.errors.some((e) => e.includes('marketplace'))).toBe(true)
  })

  it('validateConfigPatch warns on mode=enforce + missing policyPath', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    // Override the input overlay so intervention.policyPaths is
    // empty for this case.
    const isolatedConfig = normalizeConfig({
      mode: 'enforce',
      intervention: { policyPath: '' },
    })
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      isolatedConfig,
    )
    const result = (await getHandler(state, 'validateConfigPatch')({
      mode: 'enforce',
    })) as { ok: boolean; errors: string[]; warnings: string[] }
    // The validator does NOT block — a missing operator policy
    // means "load the marketplace default", which is correct for
    // a fresh install. It does warn so the operator knows.
    expect(result.ok).toBe(true)
    expect(result.warnings.some((w) => w.toLowerCase().includes('enforce'))).toBe(true)
    expect(result.warnings.some((w) => w.includes('policy'))).toBe(true)
  })

  it('saveConfigDraft writes the envelope to ~/.dsh/security-monitor-config.draft.json', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const result = (await getHandler(state, 'saveConfigDraft')({
      mode: 'enforce',
      hostId: 'l2-host',
    })) as { ok: boolean; path: string; restartRequired: true; error?: string }
    expect(result.ok).toBe(true)
    expect(result.restartRequired).toBe(true)
    expect(result.path).toMatch(/security-monitor-config\.draft\.json$/)
    // The path is absolute — the operator can `cat` it.
    expect(result.path.length).toBeGreaterThan(0)
  })

  it('saveConfigDraft envelope includes schemaVersion=1 + ISO patchedAt + operator', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const result = (await getHandler(state, 'saveConfigDraft')({
      mode: 'audit',
      hostId: 'l2-host',
    })) as { ok: boolean; path: string; restartRequired: true }
    expect(result.ok).toBe(true)
    // Read the envelope back from disk to verify the on-disk shape.
    const { readDraftFile } = (await import('../../src/config/draft.js')) as {
      readDraftFile: () => {
        schemaVersion: number
        patchedAt: string
        operator: string
        patch: Record<string, unknown>
      } | null
    }
    const env = readDraftFile()
    expect(env).not.toBeNull()
    expect(env?.schemaVersion).toBe(1)
    expect(env?.patchedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)
    expect(typeof env?.operator).toBe('string')
    expect(env?.patch).toMatchObject({ mode: 'audit', hostId: 'l2-host' })
  })

  /* ---------------------------------------------------------------- *
   * Events tab wire contract.                *
   *                                                                  *
   * `events()` is the raw event-stream view exposed to the settings  *
   * page. The handler re-uses tailNdjson with a custom filter        *
   * predicate assembled from the (whitelisted) client-supplied       *
   * event_type / outcome / search triple. The cases below exercise   *
   * every documented normalisation + filter path so the host side    *
   * cannot silently drift from the wire contract.                    *
   * ---------------------------------------------------------------- */

  /** Helper — register a bridge against a populated NDJSON fixture. */
  async function registerWithFixture(
    lines: ReadonlyArray<Record<string, unknown>>,
  ): Promise<{ contribution: TypertContribution | null; provides: ProvideCapture[] }> {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const ndjson = join(dir, `events-${Math.random().toString(36).slice(2)}.jsonl`)
    const body = lines.map((o) => JSON.stringify(o)).join('\n') + '\n'
    writeFileSync(ndjson, body, 'utf8')
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: lines.length, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => ndjson,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    // Wait for the dynamic import to resolve (loadNdjsonTail uses a
    // dynamic import that resolves on first call).
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    return { contribution: state.contribution, provides: state.provides }
  }

  it('events() returns [] when the sink has no output path', async () => {
    const { typert, provide, state } = captureMount()
    const { ctx } = buildContext(typert, provide)
    const sink: FakeSink = {
      getStats: () => ({ queued: 0, flushed: 0, dropped: 0, errors: 0 }),
      getLocalOutputPath: () => undefined,
    }
    registerSecurityMonitorRemote(
      ctx,
      sink as unknown as Parameters<typeof registerSecurityMonitorRemote>[1],
      engine,
      config,
    )
    const rows = (await getHandler({ provides: state.provides }, 'events')({})) as { rows: Array<unknown>; total: number }
    expect(rows).toEqual({ rows: [], total: 0 })
  })

  it('events() returns RawEventRow[] with summary fields + raw_json for known types', async () => {
    const { provides } = await registerWithFixture([
      {
        ts: 1_700_000_000_000,
        event_id: 'e1',
        event_type: 'agent_tool_call',
        session_id: 's1',
        tool_name: 'bash',
        intervention: {
          decision: 'block',
          block_code: 'INLINE_SELF_PROTECTION_001',
          block_reason: 'uninstall attempt',
          policy_id: 'inline-self-protection',
        },
        outcome: 'blocked',
      },
      {
        ts: 1_700_000_001_000,
        event_id: 'e2',
        event_type: 'network_http',
        session_id: 's2',
        outcome: 'allow',
      },
    ])
    const rows = (await getHandler({ provides }, 'events')({})) as { rows: Array<Record<string, unknown>>; total: number }
    expect(rows.rows.length).toBe(2)
    // Newest-first: e2 first.
    expect(rows.rows[0]?.event_id).toBe('e2')
    expect(rows.rows[1]?.event_id).toBe('e1')
    // Summary fields + raw_json populated on the first row.
    const r1 = rows.rows[1] as Record<string, unknown>
    expect(r1.ts).toBe(1_700_000_000_000)
    expect(r1.event_type).toBe('agent_tool_call')
    expect(r1.session_id).toBe('s1')
    expect(r1.tool_name).toBe('bash')
    expect(r1.block_code).toBe('INLINE_SELF_PROTECTION_001')
    expect(r1.block_reason).toBe('uninstall attempt')
    expect(r1.policy_id).toBe('inline-self-protection')
    expect(r1.outcome).toBe('blocked')
    expect(typeof r1.raw_json).toBe('string')
    expect((r1.raw_json as string).length).toBeGreaterThan(0)
  })

  it('events() clamps limit to [1, 1000]', async () => {
    const lines: Array<Record<string, unknown>> = []
    for (let i = 0; i < 5; i++) {
      lines.push({ ts: 1_700_000_000_000 + i, event_type: 'network_http', outcome: 'allow' })
    }
    const { provides } = await registerWithFixture(lines)
    // limit=0 → clamp to 1
    const rows0 = (await getHandler({ provides }, 'events')({ limit: 0 })) as { rows: Array<unknown>; total: number }
    expect(rows0.rows.length).toBe(1)
    // limit=2000 → clamp to 1000 (we only have 5 rows so all 5 land)
    const rows2000 = (await getHandler({ provides }, 'events')({ limit: 2000 })) as { rows: Array<unknown>; total: number }
    expect(rows2000.rows.length).toBe(5)
  })

  it('events() filter.event_type drops unknown values silently (no throw)', async () => {
    const { provides } = await registerWithFixture([
      { ts: 1, event_type: 'agent_tool_call', session_id: 's', outcome: 'blocked' },
      { ts: 2, event_type: 'network_http', session_id: 's', outcome: 'allow' },
    ])
    // Mix a known + an unknown event_type — the handler drops the
    // unknown silently (invariant #3) and applies the known one.
    const rows = (await getHandler({ provides }, 'events')({
      filter: { event_type: ['agent_tool_call', '__bogus__'] },
    })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(rows.rows.length).toBe(1)
    expect(rows.rows[0]?.event_type).toBe('agent_tool_call')
  })

  it('events() filter.outcome is lower-cased + allow-listed', async () => {
    const { provides } = await registerWithFixture([
      { ts: 1, event_type: 'a', outcome: 'blocked' },
      { ts: 2, event_type: 'b', outcome: 'denied' },
      { ts: 3, event_type: 'c', outcome: 'allow' },
    ])
    const blocked = (await getHandler({ provides }, 'events')({
      filter: { outcome: 'BLOCKED' }, // upper-case → lower-cased server-side
    })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(blocked.rows.length).toBe(1)
    expect(blocked.rows[0]?.outcome).toBe('blocked')
    // Unknown outcome → no filter (silently ignored).
    const noFilter = (await getHandler({ provides }, 'events')({
      filter: { outcome: '__bogus__' },
    })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(noFilter.rows.length).toBe(3)
  })

  it('events() filter.search is trimmed + capped at 64 chars + case-insensitive substring', async () => {
    const { provides } = await registerWithFixture([
      { ts: 1, event_type: 'agent_tool_call', session_id: 's', tool_name: 'curl-api-example' },
      { ts: 2, event_type: 'agent_tool_call', session_id: 's', tool_name: 'curl-other-data' },
      { ts: 3, event_type: 'agent_tool_call', session_id: 's', tool_name: 'curl-api-example-posts' },
    ])
    // Substring match on the JSON-serialised row.
    const rows = (await getHandler({ provides }, 'events')({
      filter: { search: 'API-EXAMPLE' },
    })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(rows.rows.length).toBe(2)
    // Trim and case-fold are applied server-side.
    const trimmed = (await getHandler({ provides }, 'events')({
      filter: { search: '   other-data   ' },
    })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(trimmed.rows.length).toBe(1)
    expect((trimmed.rows[0] as Record<string, unknown>).tool_name).toBe('curl-other-data')
    // 64-char cap — a 200-char string with no match returns the
    // unfiltered slice (the cap is on what we send to includes()).
    const long = (await getHandler({ provides }, 'events')({
      filter: { search: 'x'.repeat(200) },
    })) as { rows: Array<Record<string, unknown>>; total: number }
    expect(long.rows.length).toBe(0)
  })

  it('events() truncates raw_json to MAX_RAW_JSON_BYTES with breadcrumb when over the cap', async () => {
    const bigBody = 'x'.repeat(40 * 1024) // 40 KiB > 16 KiB cap
    const { provides } = await registerWithFixture([
      {
        ts: 1,
        event_type: 'agent_tool_call',
        session_id: 's',
        tool_name: 'bash',
        raw_params: bigBody,
      },
    ])
    const rows = (await getHandler({ provides }, 'events')({})) as { rows: Array<Record<string, unknown>>; total: number }
    expect(rows.rows.length).toBe(1)
    const rawJson = rows.rows[0]?.raw_json as string
    expect(rawJson.endsWith('...[truncated]')).toBe(true)
    // Cap: MAX_RAW_JSON_BYTES + breadcrumb
    expect(rawJson.length).toBeLessThanOrEqual(16 * 1024 + '...[truncated]'.length)
  })
})