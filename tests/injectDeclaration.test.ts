/**
 * Regression test for the Cordis `inject` declaration drift.
 *
 * Background: the plugin reads `ctx.subprocess`, `ctx.tools`,
 * `ctx.commands`, and `ctx.typert` from four host-side places
 * (`src/bootstrap.ts` surface probe, `src/intervention/RuntimeHook.ts`
 * seam, `src/intervention/SelfProtectionGuard.ts` deny guard
 * `src/commands/security.ts:107` /security CLI registration
 * `src/typert/host.ts:340` typert RPC bridge).
 * The browser-only `ctx.remote` gateway-client service was historically
 * probed via `ctx.reflect.get('remote')` (typert-bridge earlier) but
 * was replaced by the typert-namespace `onState` callback in the
 * 2026-09-23 typert-bridge fix — see `src/bootstrap.ts:297-303` and
 * `src/index.ts:59` for the post-fix rationale.
 *
 * The Cordis 4 ReflectService proxy (cordis)
 * enforces inject declaration on every read of `ctx.X`: an undeclared
 * optional service throws `cannot get property "X" without inject`,
 * which would propagate to host crash and leave the operator with
 * "等待依赖". Tests below pin the entries to the **minimal correct
 * set** — four host-side services in `inject`, one client-side
 * service accessed via `ctx.reflect.get`.
 *
 * Earlier versions of this file pinned `'remote'` to `inject` as well,
 * but that's wrong: `remote` is registered ONLY on the client (browser)
 * cordis context by `@deepseek-ai/dsh-cordis-client-runner` at
 * the cordis client runner.
 * Including it would hang the host plugin fiber in
 * `FIBER_PENDING` forever (Cordis waits for a service the host never
 * provides) — surfaced to operators as `rowPhasePending: '等待依赖'`
 * via the plugin inventory service →
 * the plugin manager UI.
 *
 * The fix is asymmetric:
 *   - HOST-side services (`subprocess` / `tools` / `commands` / `typert`)
 *     — declare in `inject`; the proxy returns the live service, or
 *     throws once the implementation is missing (caught by `if (!X)`
 *     graceful paths).
 *   - CLIENT-only services (`remote`) — DO NOT declare; reach via
 *     `ctx.reflect.get('remote')`, which is the safe accessor that
 *     returns `undefined` without throwing and does not gate fiber
 *     activation (see cordis).
 *
 * The five reads corresponding to:
 * `subprocess` — RuntimeHook seam (`src/intervention/RuntimeHook.ts`)
 * `tools` — synchronous monotonic-deny guard
 *                    (`src/intervention/SelfProtectionGuard.ts`)
 * `commands` — `/security` CLI
 *                    (`src/commands/security.ts:107`) + BUG-5 surface
 *                    probe (`src/bootstrap.ts:295`)
 * `typert` — settings/status/reload RPC bridge
 *                    (`src/typert/host.ts:340`, deferred registration via
 *                    `ctx.inject(['typert'], …)` after immediate
 *                    `ctx.reflect.get('typert')` probe).
 *   - `remote`     — historically probed via `ctx.reflect.get('remote')`
 * in earlier typert-bridge; replaced 2026-09-23 by the
 *                    typert-namespace `onState` callback. No longer read
 *                    via `ctx.reflect.get` from production code.
 */
import { describe, expect, it } from 'vitest'
import { name, inject } from '../src/index.js'
import type { Context } from '../src/types/external.js'

describe('Cordis inject declaration (current Windows marketplace fix)', () => {
  it('exports the marketplace plugin short name `security-monitor`', () => {
    expect(name).toBe('security-monitor')
  })

  it('declares every HOST-side Cordis service the plugin reads from `ctx`', () => {
    // The order does not matter — Cordis resolves deps by name. Sort
    // before comparing so the assertion is stable across refactors.
    expect([...inject].sort()).toEqual(
      ['commands', 'subprocess', 'tools', 'typert'],
    )
  })

  it('does NOT silently lose `commands` (the first regression)', () => {
    // Catches a future refactor that thinks "commands is only used by
    // the optional CLI surface, remove it from inject to make the
    // bundle lighter". Without this entry the marketplace `web`
    // profile crashes on activation with the Cordis-observed error
    // `cannot get property "commands" without inject`.
    expect(inject).toContain('commands')
  })

  it('does NOT include `remote` in inject (would hang host fiber in FIBER_PENDING)', () => {
    // The earlier fix added `remote` here. That broke the host
    // plugin: `remote` is a client-only service registered by
    // `@deepseek-ai/dsh-cordis-client-runner` on the BROWSER cordis ctx,
    // never on the host ctx. Cordis 4's loader waits for every entry
    // in `inject` to be registered on the host ctx before activating
    // the fiber ((host source)), so the host plugin
    // stayed in FIBER_PENDING forever → marketplace UI shows
    // `rowPhasePending: '等待依赖'`. The corrected access pattern
    // (`ctx.reflect.get('remote')` instead of `ctx.remote`) returns
    // `undefined` cleanly without gating fiber activation.
    expect(inject).not.toContain('remote')
  })
})

/**
 * Cordis-proxy stub — minimal `Proxy` that mirrors the runtime
 * behaviour of `ReflectService`: any **optional service** property
 * access on `ctx` whose name is NOT in the declared `inject` list
 * throws with the same error string Cordis emits
 * (`cannot get property "X" without inject`). Framework fields that
 * are inherent to every Cordis Context (`logger` / `on` / `effect` /
 * `inject` / `reflect`) are always allowed — Cordis's real proxy does
 * not enforce inject on them either; inject enforcement applies to
 * the *optional services* a plugin opts into.
 */
const CORDIS_FRAMEWORK_FIELDS = new Set([
  'logger',
  'on',
  'effect',
  'inject',
  'reflect',
])
function makeCordisProxyStub(
  declared: readonly string[],
  services: Record<string, unknown> = {},
): Context {
  const target = {
    logger: { debug() {}, info() {}, warn() {}, error() {} },
    on() {},
    effect() {},
    inject() {},
    // The safe accessor that the plugin's bootstrap probe uses for
    // service names NOT declared in `inject` (e.g. `remote`). Returns
    // the registered service when present, undefined otherwise —
    // matches `ReflectService.get(name, strict = true)`
    // (cordis).
    reflect: {
      get(name: string) {
        return (services as Record<string, unknown>)[name]
      },
    },
    ...services,
  } as Record<string, unknown>
  const proxy = new Proxy(target, {
    get(obj, prop) {
      if (typeof prop !== 'string') return Reflect.get(obj, prop)
      // Cordis's ReflectService only enforces the inject declaration
      // on OPTIONAL services. Framework fields are part of the base
      // Context interface and pass through unconditionally.
      if (CORDIS_FRAMEWORK_FIELDS.has(prop)) return obj[prop]
      if (declared.includes(prop)) return obj[prop]
      throw new Error(`cannot get property "${prop}" without inject`)
    },
  })
  return proxy as unknown as Context
}

describe('Cordis-proxy behaviour — `inject` declaration enables runtime access', () => {
  it('throws on undeclared-property access (Cordis `ReflectService` semantics)', () => {
    const ctx = makeCordisProxyStub(['subprocess', 'tools'])
    expect(() => (ctx as unknown as { commands?: unknown }).commands).toThrow(
      /cannot get property "commands" without inject/,
    )
  })

  it('allows access to declared host-side deps', () => {
    const sentinel = { register() { return () => {} } }
    const ctx = makeCordisProxyStub(
      ['subprocess', 'tools', 'commands'],
      { commands: sentinel, subprocess: {}, tools: {} },
    )
    // Three declarations in `inject` → three reads succeed
    expect((ctx as unknown as { commands: unknown }).commands).toBe(sentinel)
    expect((ctx as unknown as { subprocess: unknown }).subprocess).toBeDefined()
    expect((ctx as unknown as { tools: unknown }).tools).toBeDefined()
  })

  it('"remote" is reached via ctx.reflect.get, NOT via ctx.remote (would throw on a Cordis-proxied ctx)', () => {
    // Pre--follow-up: declaring `remote` in `inject` looked correct
    // on the surface but pinned the host fiber to FIBER_PENDING. The
    // corrected contract reads `remote` through the safe accessor
    // `ctx.reflect.get(name)`. The proxy stub returns whatever the
    // service registry carries (the real harness has no `remote`
    // provider on the host, so this returns undefined).
    const ctx = makeCordisProxyStub(
      ['subprocess', 'tools', 'commands'], // no 'remote'
      { commands: { register() { return () => {} } }, remote: { $mount() {} } },
    )
    // `ctx.remote` would throw "without inject" — go through reflect.
    expect(() => (ctx as unknown as { remote?: unknown }).remote).toThrow(
      /cannot get property "remote" without inject/,
    )
    // The plugin's actual access path: ctx.reflect.get('remote')
    const remote = ctx.reflect.get('remote') as { $mount?: unknown } | undefined
    expect(remote?.$mount).toBeTypeOf('function')
  })
})
