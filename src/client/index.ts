/**
 * `sst-security-control-dsh` browser half — settings page.
 *
 * The full client implementation. The bundle exposes:
 *
 *   - `apply(ctx)` — the Cordis entry point. Synchronous, returns void.
 *     Registers the Security Monitor surface in two slots so the
 *     operator can reach it from one entry point:
 *       1. `sidebar.panellist` id `security-monitor` — the top-level
 *          left-rail nav icon. The
 *          marketplace node carries the icon at the same id so a
 *          single click on it routes the operator to the page.
 *       2. `main` keyed-slot entry `key: 'security-monitor'` — the
 *          central page occupant rendered when
 *          `ctx.layout.selectPanel('security-monitor')` is dispatched
 *          from the sidebar click
 *          ((host source)x:42`).
 *   - `name` — the plugin name; matches the package name.
 *   - `inject` — the Cordis services the entry depends on. Hard
 *     requirements are `slots` (the slot registry) and `locale`
 *     (the locale bind / register). The optional bridge
 *     (`remote.securityMonitor`) is intentionally NOT listed — host
 *     cordis contexts never provide it, and declaring it
 *     would pin the fiber to PENDING — an unmet hard requirement stalls
 *     it silently rather than surfacing an error.
 *     The bridge is mounted via `ctx.remote.$mount` at apply time and
 *     resolved lazily at render time (see `src/client/remote.ts`);
 *     when the gateway client is absent the page falls back to a
 *     load-error banner.
 *
 * The runtime contract is intentionally defensive: any missing
 * service yields a single `ctx.logger.warn` line and a no-op apply.
 * The plugin's host side (`src/index.ts`) keeps running its audit
 * / enforce pipeline regardless of whether the client half can
 * surface a page.
 *
 * Discovery is the sidebar icon alone: a marketplace install shows
 * up once (left rail), not twice. The `SecurityMonitorSection`
 * component still ships (rendered via `SecurityMonitorPage` for the
 * `main` keyed-slot).
 *
 * Why minimal type surface: `@deepseek-ai/cordis` is an optional peer
 * dependency, so the client cannot import from it at build time. The
 * `ClientContext` interface below mirrors the slice of the Cordis
 * Context API the client actually uses, and the `apply()` function
 * casts the input to that interface. When the marketplace node
 * resolves the real `@deepseek-ai/cordis` Context, the cast is
 * trivially correct.
 */
import { SecurityMonitorIcon } from './components/SecurityMonitorIcon.js'
import { SecurityMonitorPage } from './components/SecurityMonitorPage.js'
import { locales, type LocaleKey } from './locales.js'
import { mountSecurityMonitorRemote, resolveSecurityMonitorBridge } from './remote.js'
import { injectSecurityMonitorStyles } from './styles.js'

export const name = 'sst-security-control-dsh'

/**
 * The Cordis services `apply()` reads. `slots` and `locale` are
 * hard requirements — without them, no slot can be registered.
 * The `remote` service is resolved lazily via `ctx.get('remote')`
 * inside `apply()` and NOT listed here — on hosts without the
 * gateway client (headless CLI), declaring it would pin the fiber
 * to PENDING — an unmet requirement stalls it silently. When present, apply()
 * mounts the `securityMonitor` namespace via `ctx.remote.$mount`
 * (see `src/client/remote.ts`).
 */
export const inject = ['slots', 'locale'] as const

/* ---------------------------------------------------------------- *
 * Local mirror of the Cordis Context slice we use.                  *
 * The interfaces are intentionally permissive (`get` returns         *
 * `unknown`) — we narrow with `as` casts at the use site so the     *
 * type checker is happy without dragging in the full Cordis API.   *
 * ---------------------------------------------------------------- */

interface LocaleService {
  register(namespace: string, dict: { en: unknown; zh: unknown }): void
  bind(namespace: string): (key: string, params?: Record<string, string | number>) => string
}

interface SlotsService {
  /**
   * Aligned with the harness reference impl
   * (the host settings UI)
   * and the host registry semantics (ui-renderer SlotInjectionEffect):
   * the callback MUST return a disposer (or iterable of disposers) —
   * returning a bare spec is a silent no-op on the current host.
   */
  inject(slot: string, callback: () => SlotDisposer | Iterable<SlotDisposer>): void
  /** Returns the disposer for the registered contribution. */
  register(spec: SlotSpec, component: unknown): SlotDisposer
}

/** A slot disposer — returned by `register` and returned by `inject`. */
type SlotDisposer = () => void

/**
 * The union spec accepted by `slots.register` across both slots this
 * bundle registers (`sidebar.panellist` + `main`). Fields are loose
 * (`id` is required for list slots, `key` for keyed slots; the
 * runtime SlotCore validates per slot kind and throws on mismatch).
 */
interface SlotSpec {
  name: string
  /** Required by `sidebar.panellist` (list kind). */
  id?: string
  /** Required by `main` (keyed kind). */
  key?: string
  /** Optional on list slots; ignored by keyed. */
  order?: number
  /** Optional on list slots; ignored by keyed. */
  label?: () => string
  locale?: string
  inject?: () => Record<string, unknown>
  children?: Record<string, { kind: 'list' | 'single' | 'keyed' | 'chain'; scope: 'root' | 'session' }>
}

interface LoggerService {
  warn(message: string): void
  info?(message: string): void
}

interface ClientContext {
  get(service: string): unknown
  logger: LoggerService
}

const NS = 'settings.securityMonitor'
const PANEL_ID = 'security-monitor'
// The sidebar panellist slot sorts ascending; the
// reference impl `ui-plugin-manager` uses order=0 for the Plugins
// icon. We pick 10 to sit just below Plugins so the order reads
// "会话 / 插件 / 安全监控 / …" top-to-bottom — matches the operator's
// mental model that security monitoring belongs alongside the other
// maintenance surfaces.
const PANELIST_ORDER = 10

/**
 * Cordis entry point. Idempotent — safe to call multiple times in
 * a single session.
 *
 * Registration form (mirrors the harness reference impl
 * `ui-settings-unarchive-sessions`): ONE step —
 * `slots.inject(SLOT, () => slots.register(spec, Component))` where
 * the inject callback returns the register disposer.
 *
 * Two slots are registered — `sidebar.panellist` for the
 * top-level left-rail icon row, and `main` (keyed-slot) for the
 * central page occupant. Both share
 * `id / key = 'security-monitor'` so a sidebar click
 * (`ctx.layout.selectPanel('security-monitor')`) lands on the right
 * page.
 *
 * `apply()` mounts the `securityMonitor` namespace via
 * `ctx.remote.$mount`
 * (best-effort; see `src/client/remote.ts`) and the slot inject thunk
 * resolves it lazily through `resolveSecurityMonitorBridge`. When the
 * host lacks the gateway client the bridge stays `undefined` and the
 * React components render the load-error banner in that branch.
 */
// Idempotency guard: `apply()` may be called twice when the host
// materializes the same module via two separate paths (e.g. the
// plugins/ concatenation bundle AND the standalone client.js).
// Subsequent calls after the first are no-ops.
let _applied = false

/**
 * Test-only escape hatch so multiple
 * vitest `it()` blocks in the same file can each re-exercise `apply()`.
 * Production code MUST NOT call this — the idempotency guard is a
 * real correctness property against double-bundle hosts (see header).
 * The guard's module-level state is a feature, not a bug, for the
 * marketplace runtime.
 * @internal
 */
export function __resetAppliedForTests(): void {
  _applied = false
}

export function apply(ctx: unknown): void {
  if (_applied) return
  _applied = true

  const c = ctx as ClientContext
  // Inject the plugin stylesheet first
  // (idempotent, no-op outside a DOM) so even a half-broken surface
  // renders themed instead of falling back to browser defaults.
  injectSecurityMonitorStyles()
  const slots = c.get('slots') as SlotsService | undefined
  const locale = c.get('locale') as LocaleService | undefined
  if (!slots || !locale) {
    c.logger.warn(
'[SecurityMonitor] ctx.slots or ctx.locale is unavailable; '+
        'no Security Monitor surface will be registered.',
    )
    return
  }

  // 1. Register the locale dictionaries. Cordis locale.register is
  //    synchronous and idempotent for the same namespace.
  try {
    locale.register(NS, { en: locales.en, zh: locales.zh })
  } catch (err: unknown) {
    c.logger.warn?.(
      `[SecurityMonitor] locale.register(${NS}) failed: ${String(err)}`,
    )
  }

  const t = locale.bind(NS) as (key: LocaleKey, params?: Record<string, string | number>) => string

  // Mount the `securityMonitor` Remote
  // namespace on the browser's gateway client (public runtime API;
  // see src/client/remote.ts for the harness citations). Fire-and-
  // forget: the slot inject thunk resolves the bridge lazily at
  // render time, and the section retries briefly via `resolveBridge`
  // so a slow mount does not pin the page to the fallback banner.
  void mountSecurityMonitorRemote(c)

  // 2a. sidebar.panellist — the top-level left-rail icon.
  //     Mirror of `ui-plugin-manager/src/client/index.ts:94`. The
  //     icon component receives `{ size, active }` from the shell's
  //     PanelRow renderer; today `IconShieldOutline16` does not
  //     recolor by selected state, but the props are kept for
  //     parity so a future themed icon can flip without re-registration.
  try {
    slots.inject('sidebar.panellist', () =>
      slots.register(
        {
          name: 'sidebar.panellist',
          id: PANEL_ID,
          order: PANELIST_ORDER,
          label: () => t('nav'),
          locale: NS,
          inject: () => ({ t }),
        },
        SecurityMonitorIcon,
      ),
    )
  } catch (err: unknown) {
    c.logger.warn(
      `[SecurityMonitor] sidebar.panellist registration failed: ${String(err)}`,
    )
  }

  // 2b. main — the central page occupant rendered by AppFrame when
  //     `ctx.layout.selectPanel('security-monitor')` is dispatched.
  //     Mirror of `ui-plugin-manager/src/client/index.ts:83`.
  //
  //     The inject thunk resolves the REAL bridge via
  //     `remote.securityMonitor` (mounted above). `resolveBridge`
  //     is passed alongside so the section can re-resolve after the
  //     async `$mount` settles (mount-vs-render race).
  try {
    slots.inject('main', () =>
      slots.register(
        {
          name: 'main',
          key: PANEL_ID,
          locale: NS,
          inject: () => ({
            bridge: resolveSecurityMonitorBridge(c),
            resolveBridge: () => resolveSecurityMonitorBridge(c),
            t,
          }),
        },
        SecurityMonitorPage,
      ),
    )
  } catch (err: unknown) {
    c.logger.warn(
      `[SecurityMonitor] main registration failed: ${String(err)}`,
    )
  }
}

/* ---------------------------------------------------------------- *
 * Host module-loader registration is generated by build-client.mjs  *
 * at build time.                                                    *
 *                                                                   *
 * Build to `--format=cjs` and wrap the CJS body inside              *
 *   window.__ModuleLoader__.load({                                 *
 *     id, factory: (require) => {                                  *
 *       var module = { exports: {} };                              *
 *       <CJS body — require() calls now resolve to the             *
 *        factory's `require` parameter via lexical scoping,        *
 *        evaluated only when the host calls materialize(id)>       *
 *       return module.exports;                                     *
 *     }                                                            *
 *   });                                                            *
 * so React / ReactDOM / peer deps are NOT bundled and the host's    *
 * `seed` table resolves them lazily.                               *
 * ---------------------------------------------------------------- */
