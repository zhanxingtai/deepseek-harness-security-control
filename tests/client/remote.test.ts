/**
 * Tests for the browser-side bridge bootstrap (`src/client/remote.ts`)
 * — 2026-09-23 typert-bridge fix.
 *
 * Coverage:
 *  - `mountSecurityMonitorRemote`: missing `remote` service → false +
 *    single warn; successful `$mount` → true and the contribution is
 *    `{package, descriptors[]}` (the real `TypertRemoteContribution`
 *    shape, the typert protocol);
 *    `$mount` rejection (e.g. duplicate mount under HMR) → falls back
 *    to probing an already-mounted namespace.
 *  - `resolveSecurityMonitorBridge`: absent namespace → undefined;
 *    mounted namespace → adapted `SecurityMonitorBridge` whose methods
 *    unwrap the `RemoteResult<T>` envelope; `rules` stays host-only;
 *    payload vs no-payload call convention matches the host contract.
 */
import { describe, expect, it } from 'vitest'
import {
  mountSecurityMonitorRemote,
  resolveSecurityMonitorBridge,
} from '../../src/client/remote.js'
import { SECURITY_MONITOR_INVOCATIONS } from '../../src/typert/descriptors.js'
import type { SecurityMonitorBridge } from '../../src/client/wire.js'

interface FakeCtx {
  get(service: string): unknown
  logger: { warn(message: string): void }
}

function makeCtx(services: Record<string, unknown>): { ctx: FakeCtx; warns: string[] } {
  const warns: string[] = []
  return {
    ctx: {
      get: (name: string) => services[name],
      logger: { warn: (m: string) => warns.push(m) },
    },
    warns,
  }
}

/** A fake mounted namespace service: methods resolve RemoteResult envelopes. */
function makeNamespace(overrides: Record<string, unknown> = {}) {
  const calls: Array<{ method: string; args: unknown[] }> = []
  const ns: Record<string, unknown> = { __calls: calls }
  for (const inv of SECURITY_MONITOR_INVOCATIONS) {
    ns[inv.method] = async (...args: unknown[]) => {
      calls.push({ method: inv.method, args })
      const override = overrides[inv.method]
      if (override !== undefined) return override
      return { ok: true, value: { method: inv.method } }
    }
  }
  return ns
}

describe('mountSecurityMonitorRemote', () => {
  it('returns false + warns once when ctx.remote is unavailable', async () => {
    const { ctx, warns } = makeCtx({})
    const ok = await mountSecurityMonitorRemote(ctx)
    expect(ok).toBe(false)
    expect(warns.length).toBe(1)
    expect(warns[0]).toContain('$mount')
  })

  it('mounts the namespace with the real {package, descriptors} contribution shape', async () => {
    let captured: { package: string; descriptors: readonly unknown[] } | undefined
    const remote = {
      $mount: async (contribution: { package: string; descriptors: readonly unknown[] }) => {
        captured = contribution
        return async () => {}
      },
    }
    const { ctx, warns } = makeCtx({ remote })
    const ok = await mountSecurityMonitorRemote(ctx)
    expect(ok).toBe(true)
    expect(warns.length).toBe(0)
    expect(captured?.package).toBe('sst-security-control-dsh')
    expect(Array.isArray(captured?.descriptors)).toBe(true)
    // The client contribution carries the SAME descriptor list the
    // host registers — one builder, no host/client drift.
    expect(captured?.descriptors.length).toBe(SECURITY_MONITOR_INVOCATIONS.length)
    // Client $mount requires strict codecs on every input parameter
    // (`requireStrictCodec` in the host gateway client).
    for (const d of captured?.descriptors ?? []) {
      const desc = d as { parameters: Array<{ codec: { mode: string } }> }
      for (const p of desc.parameters) {
        expect(p.codec.mode).toBe('strict')
      }
    }
  })

  it('tolerates a duplicate mount (HMR) when the namespace already exists', async () => {
    const remote = {
      $mount: async () => {
        throw new Error('typert: Remote package "sst-security-control-dsh" is already registered')
      },
    }
    const { ctx } = makeCtx({ remote, 'remote.securityMonitor': makeNamespace() })
    const ok = await mountSecurityMonitorRemote(ctx)
    expect(ok).toBe(true)
  })

  it('returns false when $mount fails and no namespace exists', async () => {
    const remote = {
      $mount: async () => {
        throw new Error('carrier down')
      },
    }
    const { ctx } = makeCtx({ remote })
    const ok = await mountSecurityMonitorRemote(ctx)
    expect(ok).toBe(false)
  })
})

describe('resolveSecurityMonitorBridge', () => {
  it('returns undefined when the namespace service is absent', () => {
    const { ctx } = makeCtx({})
    expect(resolveSecurityMonitorBridge(ctx)).toBeUndefined()
  })

  it('returns undefined for a half-mounted namespace (service without methods)', () => {
    const { ctx } = makeCtx({ 'remote.securityMonitor': {} })
    expect(resolveSecurityMonitorBridge(ctx)).toBeUndefined()
  })

  it('adapts every bridge method and unwraps RemoteResult envelopes', async () => {
    const ns = makeNamespace()
    const { ctx } = makeCtx({ 'remote.securityMonitor': ns })
    const bridge = resolveSecurityMonitorBridge(ctx) as SecurityMonitorBridge
    expect(bridge).toBeDefined()

    const overview = await bridge.overview()
    expect(overview).toEqual({ method: 'overview' })

    // Payload method: the payload rides as the single positional arg.
    await bridge.recentBlocks({ limit: 5 })
    const calls = ns['__calls'] as Array<{ method: string; args: unknown[] }>
    const recent = calls.find((c) => c.method === 'recentBlocks')
    expect(recent?.args).toEqual([{ limit: 5 }])

    // No-payload method: called with zero args (no undefined payload).
    const ov = calls.find((c) => c.method === 'overview')
    expect(ov?.args).toEqual([])

    // rules stays host-only (CLI surface) — not on the client bridge.
    expect('rules' in bridge).toBe(false)
  })

  it('throws a descriptive error when the host returns ok:false', async () => {
    const ns = makeNamespace({
      reload: { ok: false, error: { code: 'gateway/internal', message: 'boom' } },
    })
    const { ctx } = makeCtx({ 'remote.securityMonitor': ns })
    const bridge = resolveSecurityMonitorBridge(ctx) as SecurityMonitorBridge
    await expect(bridge.reload()).rejects.toThrow('boom')
  })
})
