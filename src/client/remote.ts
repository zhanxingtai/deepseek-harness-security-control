/**
 * Browser-side bridge bootstrap.
 *
 * Closes the client half of the settings-page data path.
 *
 * The two harness seams used here are both PUBLIC runtime APIs (no
 * harness change required):
 *
 *   1. `ctx.remote.$mount(contribution)` — mounts a Remote namespace
 *      on the browser cordis root at runtime
 *      (the host gateway client +
 *      `mountContribution` :237-264). The first-party assembly
 *      (the host remotes API) is a compile-time
 *      hardcoded import list; `$mount` is the third-party path around
 *      it. The contribution shape is `TypertRemoteContribution` =
 *      `{ package, descriptors }` — the SAME builder output the host
 *      registers (`src/typert/descriptors.ts`), so host and client
 *      can never drift apart on the method list.
 *   2. `ctx.get('remote.securityMonitor')` — after a successful mount
 *      the namespace service exists under the key
 *      `remote.<namespace>` (`remoteServiceKey`,
 *      the host gateway client). Its methods
 *      resolve to `RemoteResult<T>` envelopes
 *      (`{ ok: true, value } | { ok: false, error }` — see
 *      the typert protocol), which the adapter
 *      below unwraps into the plain `SecurityMonitorBridge` contract
 *      the tab components already consume.
 *
 * Graceful degradation: when
 * the browser ctx has no `remote` service, or `$mount` rejects, the
 * bridge stays `undefined` and the section renders its fallback
 * banner. Nothing here throws to the host.
 */
import {
  buildSecurityMonitorDescriptors,
  SECURITY_MONITOR_INVOCATIONS,
} from '../typert/descriptors.js'
import type { SecurityMonitorBridge } from './wire.js'

/** npm package name — mirrors the host registration byte-for-byte. */
const PKG_NAME = 'sst-security-control-dsh'
/** Cordis service key the mounted namespace lands under. */
const BRIDGE_SERVICE_KEY = 'remote.securityMonitor'

/** Methods that take a single `payload` argument (host-side contract). */
const METHODS_WITH_PAYLOAD = new Set<string>([
  'recentBlocks',
  'validateConfigPatch',
  'saveConfigDraft',
  'previewLivePatch',
  'applyLivePatch',
  'events',
])

/** `RemoteResult<T>` envelope — see dsh-typert-protocol types. */
type RemoteResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: { readonly code?: string; readonly message?: string } }

/** Minimal shape of the harness browser-side `remote` service. */
interface RemoteServiceLike {
  $mount(contribution: {
    package: string
    descriptors: readonly unknown[]
  }): Promise<unknown>
}

/** Minimal slice of the client cordis Context this module reads. */
interface BridgeContext {
  get(service: string): unknown
  logger: { warn(message: string): void }
}

type NamespaceProxy = Record<string, (...args: unknown[]) => Promise<unknown>>

/**
 * Mount the `securityMonitor` Remote namespace on the browser's
 * gateway client. Idempotent-by-tolerance: a duplicate mount (HMR /
 * double apply) rejects with "already registered" — we warn and fall
 * through to `resolveSecurityMonitorBridge`, which succeeds anyway
 * because the namespace service already exists.
 *
 * Returns true when the namespace is usable after the call (whether
 * this call mounted it or it was already mounted).
 */
export async function mountSecurityMonitorRemote(ctx: BridgeContext): Promise<boolean> {
  const remote = ctx.get('remote') as RemoteServiceLike | undefined
  if (!remote || typeof remote.$mount !== 'function') {
    ctx.logger.warn(
'[SecurityMonitor] ctx.remote.$mount is unavailable on this host; '+
        'the settings page will render its fallback banner.',
    )
    return false
  }
  try {
    await remote.$mount({
      package: PKG_NAME,
      descriptors: buildSecurityMonitorDescriptors(PKG_NAME),
    })
    return true
  } catch (err: unknown) {
    // Duplicate mount (HMR re-apply) is benign — the namespace persists.
    ctx.logger.warn(
      `[SecurityMonitor] remote.$mount(${PKG_NAME}) reported: ${String(err)} — ` +
        'probing for an already-mounted namespace before giving up.',
    )
    return resolveSecurityMonitorBridge(ctx) !== undefined
  }
}

/**
 * Resolve the mounted `remote.securityMonitor` namespace into the
 * `SecurityMonitorBridge` the tab components consume. Returns
 * `undefined` when the namespace is not mounted (yet) — callers keep
 * the fallback-banner behavior in that branch.
 */
export function resolveSecurityMonitorBridge(ctx: BridgeContext): SecurityMonitorBridge | undefined {
  const ns = ctx.get(BRIDGE_SERVICE_KEY) as NamespaceProxy | undefined
  if (!ns || typeof ns !== 'object') return undefined
  // Smoke-check one no-payload method so a half-mounted namespace
  // (service exists, methods not yet installed) is treated as absent.
  if (typeof ns['overview'] !== 'function') return undefined

  const call = async <T>(method: string, payload?: unknown): Promise<T> => {
    const fn = ns[method]
    if (typeof fn !== 'function') {
      throw new Error(`securityMonitor/${method} is not mounted on the remote namespace`)
    }
    const raw: unknown = await (METHODS_WITH_PAYLOAD.has(method) ? fn(payload) : fn())
    // Generated Remote methods resolve to a RemoteResult envelope;
    // tolerate a hypothetical direct-value host for forward-compat.
    if (raw && typeof raw === 'object' && 'ok' in (raw as Record<string, unknown>)) {
      const result = raw as RemoteResult<T>
      if (result.ok) return result.value
      const detail = result.error?.message ?? result.error?.code ?? 'unknown error'
      throw new Error(`securityMonitor/${method} failed: ${detail}`)
    }
    return raw as T
  }

  // The bridge surface is derived from the SAME invocation list the
  // host exposes — `rules` stays host-only (CLI), per wire.ts:48-52.
  const bridge: Record<string, unknown> = {}
  for (const inv of SECURITY_MONITOR_INVOCATIONS) {
    if (inv.method === 'rules') continue
    bridge[inv.method] = (payload?: unknown) => call(inv.method, payload)
  }
  return bridge as unknown as SecurityMonitorBridge
}
