/**
 * Server-side Typert contribution.
 *
 * Mounts the `securityMonitor` namespace on the host's Typert runtime
 * (`ctx.typert.register(contribution)` + a Cordis Service registered
 * via `ctx.reflect.provide('securityMonitor', service)`). The browser
 * settings page (the client half of this, shipped separately)
 * consumes these methods through the `ctx.remote.securityMonitor.*`
 * bridge — it never touches the filesystem directly because the
 * marketplace sandbox forbids browser-side fs reads.
 *
 * The host process running this plugin does NOT carry `ctx.remote`
 * (that is the GATEWAY-CLIENT* stream API — `ctx.remote` is registered
 * only on the browser cordis ctx via
 * the host gateway client), so host-side mounts use
 * the canonical two-step API:
 *     a. `ctx.reflect.provide('securityMonitor', service)` — registers
 *        a Cordis Service whose methods the harness's TypertGateway
 *        can dispatch against (the host gateway).
 *     b. `ctx.typert.register(contribution)` — populates
 *        `ctx.typert.local` with the strict descriptors (`id`,
 *        `service`, `namespace`, `method`, `invocation`, `parameters`,
 *        `result`) the gateway uses to look up the receiver per
 *        endpoint (the typert registry).
 *
 * The namespace methods:
 *   - `overview()`         → mode / event counts / uptime / rule count
 *   - `recentBlocks()`     → last N SPL block decisions, newest first
 *   - `rules()`            → list enabled SPL rules
 *   - `reload()`           → force a policy reload
 *   - `getConfig()`        → current effective Config snapshot
 *   - `validateConfigPatch` / `saveConfigDraft` / `getConfigDraftStatus`
 *     → draft persistence (restart-scoped)
 *   - `previewLivePatch` / `applyLivePatch` → config livePatch
 *     (hot-applies 🟢 keys, refuses 🔴 self-protection keys)
 *
 * Graceful degradation: when `ctx.typert` is unavailable (the
 * marketplace node does not have `@deepseek-ai/dsh-typert-protocol`
 * installed), `registerSecurityMonitorRemote` logs a single warning
 * and returns a no-op disposer — and, when a `DebugLog` handle is
 * passed, writes a `surface_unavailable`
 * breadcrumb to the operator-visible debug log. The plugin's audit /
 * enforce surface continues to work without the settings page.
 *
 * The five low-level helpers (`STARTUP_TS`,
 * `clampLimit`, `countAllBlocks`, `countLast24hBlocks`, `toBlockRow`)
 * live in `src/status/overview.ts` so the CLI side
 * (`src/commands/security.ts`) and the host side render from one
 * source of truth. The wire-level type definitions stay on
 * `./descriptors.ts`.
 *
 * Concurrency note: the `recentBlocks` reader uses a dynamic import
 * of `src/utils/ndjsonTail.ts` (the shared util). The import
 * resolves to the bundled copy in production; in development the
 * dynamic import survives a missing file (returns null + warn) so the
 * server side stays shippable independently of the client half. When
 * both halves land, the dynamic import resolves naturally and
 * `recentBlocks` works end-to-end.
 */
import type { Context, Logger } from '../types/external.js'
import { LocalNdjsonSink } from '../collectors/LocalNdjsonSink.js'
import { InterventionEngine } from '../intervention/InterventionEngine.js'
import type { Config } from '../config.js'
import type { DebugLog } from '../utils/debugLog.js'
import {
  resolveDraftPath,
  readDraftFile,
  writeDraftFile,
} from '../config/draft.js'
import { validateConfigPatch } from '../config/validate.js'
import type { LivePatchManager } from '../config/livePatch.js'
import { buildSecurityMonitorDescriptors } from './descriptors.js'
import {
  STARTUP_TS,
  clampLimit,
  scanOverviewAggregates,
  toBlockRow,
} from '../status/overview.js'
import { OverviewCache } from '../status/overviewCache.js'
import {
  ALLOWED_EVENT_TYPES,
  ALLOWED_OUTCOMES,
  MAX_SEARCH_CHARS,
  truncateRawJson,
} from './descriptors.js'
import type {
  BlockRow,
  ConfigDraftResult,
  ConfigDraftStatus,
  ConfigPatch,
  ConfigSnapshot,
  ConfigSnapshotCollector,
  ConfigSnapshotApplication,
  ConfigSnapshotNetworkCapture,
  ConfigSnapshotRuntimeHooks,
  ConfigSnapshotIntervention,
  ConfigSnapshotInlineGuards,
  // The 7 §6.2 sub-block snapshot types.
  ConfigSnapshotSensitivePathGuard,
  ConfigSnapshotInlinePromptInjection,
  ConfigSnapshotStdioMirror,
  ConfigSnapshotEnvPassthroughGuard,
  ConfigSnapshotSensitiveHeaderGuard,
  ConfigSnapshotLoopedToolDetector,
  ConfigSnapshotTokenUsageDetector,
  ConfigSnapshotSinkDiskLow,
  ConfigValidationResult,
  EventsArgs,
  LivePatchApplyResult,
  LivePatchPatch,
  LivePatchPreview,
  OverviewSnapshot,
  RawEventRow,
  ReloadResult,
  RuleSummary,
} from './descriptors.js'

/**
 * Local stub of the dsh-typert-registry host-side surface.
 *
 * TWO DIFFERENT register paths exist in the harness — do not
 * conflate them:
 *
 *   - HOST side: `ctx.typert.register(contribution)` takes the rich
 *     `TypertContribution` = `{ package, face, schemas, model,
 *     invocations }` (the typert registry +
 *     `TypertRegistry.register`). It commits
 *     `invocations` into `ctx.typert.local` — the strict-descriptor
 *     store the gateway reads FIRST.
 *   - CLIENT side: `ctx.remote.$mount({ package, descriptors })`
 *     takes `TypertRemoteContribution` (the typert protocol types)
 *     — a different, slimmer shape used only on the browser.
 *
 * Gateway invocation contract (same file :597-624):
 *   - each `InvocationDescriptor` carries `id`, `service`,
 *     `namespace`, `method`, `invocation`, `parameters`, `result` —
 *     NO handler on the descriptor itself; the gateway resolves the
 *     receiver via `receiverContext.get(descriptor.service)` and
 *     calls `Reflect.get(receiver, descriptor.method)`;
 *   - the receiver MUST carry a `typertRemote` binding —
 *     `validateBinding` at :610 is unconditional (see the attach
 *     site below).
 *
 * Handlers therefore live on the Cordis Service we register via
 * `ctx.reflect.provide('securityMonitor', service)` — see
 * `SecurityMonitorService` below.
 */
export interface TypertContribution {
  readonly package: string
  readonly face: 'host' | 'client'
  readonly schemas: readonly unknown[]
  readonly model: {
    readonly services: readonly unknown[]
    readonly events: readonly unknown[]
    readonly objects: readonly unknown[]
  }
  readonly invocations: readonly unknown[]
}
export interface TypertDisposer {
  (): Promise<void>
}
export interface TypertRegistryContract {
  register(contribution: TypertContribution): TypertDisposer
}

/**
 * `SecurityMonitorService` is the Cordis Service
 * whose methods the harness's `TypertGateway` dispatches against.
 *
 * The class is intentionally a plain class (no `extends Cordis
 * Service`) so the host plugin can pass dependencies through the
 * constructor without Cordis's `static inject` machinery (the deps
 * are constructed by `bootstrap.ts` and need direct ctor injection).
 * The Cordis-side `Service` semantics — auto-register on
 * `ctx.reflect.provide(name, this)` — are obtained by manually
 * calling `ctx.reflect.provide('securityMonitor', service)` from
 * `registerSecurityMonitorRemote`.
 *
 * Note: a plain class alone is NOT
 * dispatchable — the gateway's `validateBinding` demands a
 * `typertRemote` binding on the receiver (see the attach site in
 * `registerSecurityMonitorRemote`). We attach the frozen
 * `{service, serviceKey, namespace}` binding manually (the exact
 * shape `bindTypertRemote` produces in
 * the typert protocol) instead of
 * extending `TypertRemoteService`, so the plugin keeps zero runtime
 * imports of `@deepseek-ai/dsh-typert-protocol`.
 */
class SecurityMonitorService {
  constructor(
    private readonly sink: LocalNdjsonSink,
    private readonly engine: InterventionEngine,
    private readonly config: Config,
    private readonly logger: Logger,
    private readonly livePatch: LivePatchManager | undefined,
    private readonly overviewCache: OverviewCache,
  ) {}

  async overview(): Promise<OverviewSnapshot> {
    return overviewHandler(this.sink, this.engine, this.config, this.overviewCache)
  }

  async recentBlocks(
    payload: {
      limit?: number
      offset?: number
      scope?: 'blocked' | 'all-hits'
      includeRaw?: boolean
    } = {},
  ): Promise<{ rows: BlockRow[]; total: number }> {
    return recentBlocksHandler(
      this.sink,
      payload.limit,
      this.logger,
      payload.scope,
      payload.includeRaw,
      payload.offset ?? 0,
    )
  }

  async rules(): Promise<RuleSummary[]> {
    return rulesHandler(this.engine)
  }

  async reload(): Promise<ReloadResult> {
    return this.engine.requestReload()
  }

  async getConfig(): Promise<ConfigSnapshot> {
    return getConfigHandler(this.config)
  }

  // Config form + draft persistence.
  async validateConfigPatch(patch: ConfigPatch): Promise<ConfigValidationResult> {
    return validateConfigPatchHandler(patch, this.config, this.logger)
  }

  async saveConfigDraft(patch: ConfigPatch): Promise<ConfigDraftResult> {
    return saveConfigDraftHandler(patch, this.config, this.logger)
  }

  async getConfigDraftStatus(): Promise<ConfigDraftStatus> {
    return getConfigDraftStatusHandler(this.logger)
  }

  // Config livePatch: preview is pure
  // classification; apply hot-applies the 🟢 subset through the
  // LivePatchManager (shared-config in-place mutation + component
  // timer/watcher rebuilds). When the manager was not wired (older
  // embeddings / unit tests), both methods degrade to an error
  // result instead of throwing (invariant #3).
  async previewLivePatch(patch: LivePatchPatch): Promise<LivePatchPreview> {
    return previewLivePatchHandler(patch, this.livePatch, this.logger)
  }

  async applyLivePatch(patch: LivePatchPatch): Promise<LivePatchApplyResult> {
    return applyLivePatchHandler(patch, this.livePatch, this.logger)
  }

  // Events: raw event-stream view. The handler
  // reuses the tailNdjson utility, but with a custom filter
  // predicate assembled from the (whitelisted) client-supplied
  // event_type / outcome / search triple. See eventsHandler() +
  // normaliseEventsFilter() for the wire-level invariants.
  //
  // Returns `{ rows, total }` so the
  // Events tab footer can render "Showing N of M events" (the
  // "of N" total). `total` is the filter-aware
  // count of all matching events in the file, not the page size.
  async events(args: EventsArgs = {}): Promise<{ rows: RawEventRow[]; total: number }> {
    return eventsHandler(this.sink, args, this.logger)
  }
}

/** Empty Typert model — no reflection metadata the registry inspects. */
const EMPTY_TYPERT_MODEL: TypertContribution['model'] = {
  services: [],
  events: [],
  objects: [],
}

/**
 * Register the `securityMonitor` namespace on the host's Typert
 * runtime. Returns a disposer for the plugin's shutdown path. If the
 * runtime is unavailable the disposer is a no-op and a single warn
 * line is logged.
 */
export function registerSecurityMonitorRemote(
  ctx: Context,
  sink: LocalNdjsonSink,
  engine: InterventionEngine,
  config: Config,
  debugLog?: DebugLog,
  livePatch?: LivePatchManager,
  // shared cache instance constructed by
  // bootstrap.ts and reused across the `overview` handler. When
  // omitted (older embeddings / unit tests), the handler falls
  // back to direct full-file scans. Bootstrap wires the same
  // instance to the sink's `onRotate` callback so a rotation
  // invalidates the cache.
  overviewCache?: OverviewCache,
  // Outcome callback for the startup
  // surfaces metadata + tests. Fired on every terminal or deferred
  // outcome of a registration attempt.
  onState?: (registered: boolean, note: string) => void,
): () => void {
  let activeDisposer: TypertDisposer | null = null
  let disposed = false
  const dispose = (): void => {
    if (disposed) return
    disposed = true
    const d = activeDisposer
    activeDisposer = null
    if (!d) return
    void (async () => {
      // TypertDisposer is async (`Promise<void>`) per
      // the typert protocol,315`. Surface real
      // failures as warn, never throw to host (invariant #3).
      try {
        await d()
      } catch (error: unknown) {
        ctx.logger.warn(
          `[SecurityMonitor] typert dispose failed: ${String(error)}`,
        )
      }
    })()
  }

  const attempt = (origin: 'immediate' | 'deferred'): boolean => {
    const typert = ctx.reflect.get('typert') as TypertRegistryContract | undefined
    if (!typert || typeof typert.register !== 'function') return false
    activeDisposer = doRegistration(
      ctx, sink, engine, config, debugLog, livePatch, overviewCache, typert, origin, onState,
    )
    return activeDisposer !== null
  }

  // The `typert`
  // registry service is guaranteed present in compositions that carry
  // the gateway (`dsh-api-gateway` has `static inject = ['typert']`),
  // but the registry fiber may load AFTER this plugin — a one-shot
  // `ctx.reflect.get('typert')` probe at apply time races the bundle
  // load order and can pin the surface to unavailable forever. Run
  // immediately when possible, otherwise defer via
  // `ctx.inject(['typert'], …)` (the Cordis-idiomatic pattern the
  // RuntimeHook uses for `subprocess`).
  if (attempt('immediate')) return dispose

  if (typeof ctx.inject === 'function') {
    try {
      ctx.inject(['typert'], () => {
        attempt('deferred')
        return dispose
      })
    } catch (error: unknown) {
      ctx.logger.warn(
        `[SecurityMonitor] typert deferred registration failed: ${String(error)}`,
      )
      debugLog?.write('surface_unavailable', {
        surface: 'remote',
        reason: 'ctx.inject deferred registration threw',
        error: String(error),
      })
      onState?.(false, `error: ${String(error)}`)
      return dispose
    }
    // A host without the registry (headless CLI) never fires the
    // callback — this breadcrumb is the persistent trace for that case.
    debugLog?.write('surface_unavailable', {
      surface: 'remote',
      reason: 'deferred: waiting for the typert registry service',
    })
    onState?.(false, 'deferred: waiting for the typert registry service')
    return dispose
  }

  // No inject on this host (legacy embedding / unit tests): terminal
  // unavailable path — single warn + breadcrumb.
  ctx.logger.warn(
'[SecurityMonitor] typert bridge not registered: ctx.typert.register is unavailable. '+
      'Install @deepseek-ai/dsh-typert-protocol@0.1.6-alpha.2 on the marketplace node to enable the settings page.',
  )
  debugLog?.write('surface_unavailable', {
    surface: 'remote',
    reason: 'ctx.typert.register is unavailable',
    peer: '@deepseek-ai/dsh-typert-protocol@0.1.6-alpha.2',
  })
  onState?.(false, 'ctx.typert.register is unavailable')
  return dispose
}

/**
 * The registration body, extracted so both the immediate and the
 * deferred (`ctx.inject(['typert'])`) path run the identical steps.
 * Returns the registry disposer on success, null on failure (the
 * failure is already warned + breadcrumbed here).
 */
function doRegistration(
  ctx: Context,
  sink: LocalNdjsonSink,
  engine: InterventionEngine,
  config: Config,
  debugLog: DebugLog | undefined,
  livePatch: LivePatchManager | undefined,
  overviewCache: OverviewCache | undefined,
  typert: TypertRegistryContract,
  origin: 'immediate' | 'deferred',
  onState?: (registered: boolean, note: string) => void,
): TypertDisposer | null {
  // use the shared cache instance when wired
  // by bootstrap.ts, or build a transient local one for older
  // embedding paths. Both paths produce the same in-bridge
  // behaviour; the difference is whether the cache survives across
  // bridge remounts.
  const _overviewCache = overviewCache ?? new OverviewCache()

  // Two-step registration: (1) install the SecurityMonitorService
  // Cordis service whose instance methods the harness TypertGateway
  // dispatches against; (2) populate `ctx.typert.local` with the
  // strict descriptors so the gateway can route endpoints to the
  // right receiver + method. The service is plain (no `extends
  // Cordis Service`) so deps flow through the constructor —
  // bootstrap.ts constructs the deps and this function wires them.
  const service = new SecurityMonitorService(
    sink,
    engine,
    config,
    ctx.logger,
    livePatch,
    _overviewCache,
  )
  // The gateway's invocation path
  // (the host gateway) unconditionally calls
  // `validateBinding(receiver, ...)`, which requires a
  // `typertRemote` binding on the service that is
  // identity-consistent with the registered serviceKey/namespace
  // (`readBinding`, same file :1036-1058). First-party services get
  // this from `TypertRemoteService`'s ctor
  // (the typert protocol); we attach the
  // equivalent frozen binding manually so the plugin keeps its
  // zero-runtime-dep contract (no static import of
  // `@deepseek-ai/dsh-typert-protocol`). Without this property every
  // RPC lands on `gateway/binding-invalid`.
  Object.defineProperty(service, 'typertRemote', {
    value: Object.freeze({
      service,
      serviceKey: 'securityMonitor',
      namespace: 'securityMonitor',
    }),
    enumerable: true,
  })

  try {
    // Cordis-side Service registration: `ctx.reflect.provide(name, value)`
    // is the public API the harness Cordis Service ctor calls into
    // ((host source):Service`). It records the
    // service under `name` in the reflect store so `ctx.<name>` and
    // `receiverContext.get(name)` both resolve to this instance.
    ctx.reflect.provide('securityMonitor', service)

    // Host-side registration: the rich `TypertContribution` shape
    // (`{package, face:'host', schemas, model, invocations}`) consumed by
    // `TypertRegistry.register` — it commits `invocations` into
    // `ctx.typert.local`, the strict-descriptor store the gateway reads
    // first (see the contract block above). The `package` field mirrors
    // `package.json#name` byte-for-byte (the marketplace contract
    // verified by `scripts/verify-artifacts.mjs`).
    const PKG_NAME = 'sst-security-control-dsh'
    const contribution: TypertContribution = {
      package: PKG_NAME,
      face: 'host',
      schemas: [],
      model: EMPTY_TYPERT_MODEL,
      invocations: buildSecurityMonitorDescriptors(PKG_NAME),
    }
    const disposer = typert.register(contribution)
    onState?.(true, origin)
    return disposer
  } catch (error: unknown) {
    // invariant #3: a registration failure (e.g. duplicate package
    // under HMR) must warn, not throw to the host.
    ctx.logger.warn(
      `[SecurityMonitor] typert bridge registration failed (${origin}): ${String(error)}`,
    )
    debugLog?.write('surface_unavailable', {
      surface: 'remote',
      reason: 'typert.register threw',
      error: String(error),
    })
    onState?.(false, `error: ${String(error)}`)
    return null
  }
}

async function overviewHandler(
  sink: LocalNdjsonSink,
  engine: InterventionEngine,
  config: Config,
  // optional cache injection. When undefined
  // (older embeddings / unit tests), the handler falls back to the
  // direct full-file scans — back-compat with the pre-cache tests.
  cache?: OverviewCache,
): Promise<OverviewSnapshot> {
  const loaded = engine.getLoadedPolicy()
  const path = sink.getLocalOutputPath() ?? ''
  // Pull the scan aggregates through the cache when available. On the
  // first call this performs the (relatively expensive) full-file pass;
  // every subsequent call within the TTL hits the O(1) cache path.
  // The cached bundle also carries
  // `last24hTotalCount` / `byLayer` for the Metrics page, so a cache
  // hit stays O(1) for the whole snapshot.
  let totalCount: number
  let blockCount: number
  let last24hBlockCount: number
  let threatCount: number
  let last24hThreatCount: number
  let last24hTotalCount: number
  let byLayer: Record<string, number>
  if (cache) {
    const cached = await cache.read(sink)
    totalCount = cached.totalCount
    blockCount = cached.blockCount
    last24hBlockCount = cached.last24hBlockCount
    threatCount = cached.threatCount
    last24hThreatCount = cached.last24hThreatCount
    last24hTotalCount = cached.last24hTotalCount
    // Shallow-copy so the snapshot cannot alias the cache entry's
    // bucket object across wire marshalling.
    byLayer = { ...cached.byLayer }
  } else {
    const agg = path ? await scanOverviewAggregates(sink) : null
    totalCount = agg?.totalCount ?? 0
    blockCount = agg?.blockCount ?? 0
    last24hBlockCount = agg?.last24hBlockCount ?? 0
    threatCount = agg?.threatCount ?? 0
    last24hThreatCount = agg?.last24hThreatCount ?? 0
    last24hTotalCount = agg?.last24hTotalCount ?? 0
    byLayer = agg?.byLayer ?? {}
  }
  return {
    // Read the live mode from `config.intervention.mode`,
    // which is the engine's authoritative enforcement switch. The
    // top-level `Config.mode` field is still in the type for backward
    // compatibility (old patch YAMLs may set `mode: enforce` at the
    // top level) but normalizeConfig already propagates it down to
    // `intervention.mode` when the nested field is unset
    // (`src/config/normalize.ts:151-153`). Reading from
    // `config.intervention.mode` directly gives the operator a
    // truthful view of the runtime posture regardless of which
    // surface they used to set it; reading the top-level `Config.mode`
    // here would be a no-op alias once `normalizeConfig` has run.
    mode: config.intervention.mode,
    // `total` comes from the full-file scan (cross-restart
    // persistent), not the process-local `stats.flushed` counter —
    // on restart the counter zeroes while last24h keeps counting the
    // retained NDJSON, which produced "total < last 24h" on the
    // Metrics page.
    totalEvents: totalCount,
    blockCount,
    last24hBlockCount,
    threatCount,
    last24hThreatCount,
    last24hTotalCount,
    byLayer,
    uptimeSec: Math.max(0, Math.floor((Date.now() - STARTUP_TS) / 1000)),
    loadedRuleCount: loaded.rules.filter((r) => r.enabled).length,
    localOutputPath: path,
  }
}

async function recentBlocksHandler(
  sink: LocalNdjsonSink,
  rawLimit: number | undefined,
  logger: Logger,
  /** `blocked`(默认,原行为)只列被拦截的工具调用;
   *  `all-hits` 列出全部规则命中(含 warn 级"标记但未拦截"与
   *  runtime 子进程层命中),谓词 `isRuleHit`。 */
  scope: 'blocked' | 'all-hits' = 'blocked',
  /** 惰性明细:true 时每行额外携带截断的完整原始事件
   *  (`raw_json`),供详情展开;缺省摘要不带,3 s 轮询载荷不变。 */
  includeRaw = false,
  /** Load more cursor; mirrors the Events tab. Pages
   *  into older history; clamped to `[0, ∞)`; an out-of-range
   *  offset returns `[]`. */
  offset: number = 0,
): Promise<{ rows: BlockRow[]; total: number }> {
  const path = sink.getLocalOutputPath()
  if (!path) return { rows: [], total: 0 }
  const limit = clampLimit(rawLimit, 20, 1, 500)
  const ndjsonTail = await loadNdjsonTail(logger)
  if (!ndjsonTail) return { rows: [], total: 0 }
  const filter = scope === 'all-hits' ? ndjsonTail.isRuleHit : ndjsonTail.isBlockDecision
  const [raw, total] = await Promise.all([
    ndjsonTail.tailNdjson(path, limit, { filter, offset }),
    ndjsonTail.countNdjson(path, filter),
  ])
  return {
    rows: raw.map((row) => toBlockRow(row, { includeRaw })),
    total,
  }
}

function rulesHandler(engine: InterventionEngine): RuleSummary[] {
  const loaded = engine.getLoadedPolicy()
  return loaded.rules.map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    priority: r.priority,
    // spec §3: the per-rule risk tier is the top-level `severity:`.
    // The v1 `evaluate.risk_level` shape no longer survives the loader —
    // rules carrying an `evaluate:` section are dropped at compile time.
    risk_level: r.severity ?? null,
    decision: r.action?.decision ?? 'allow',
    block_reason: r.action?.blockReason,
  }))
}

async function loadNdjsonTail(
  logger: Logger,
): Promise<typeof import('../utils/ndjsonTail.js') | null> {
  try {
    return await import('../utils/ndjsonTail.js')
  } catch (error: unknown) {
    logger.warn?.(`[SecurityMonitor] ndjsonTail util not available: ${String(error)}`)
    return null
  }
}

/**
 * A read-only mirror of the normalised
 * Config for the Config tab.
 *
 * The snapshot is computed on every call (no caching) so an operator
 * who just patched the YAML and restarted DSH sees the new values
 * after clicking `<Reload Config>`. The snapshot is a plain object
 * literal — the host-side TS compiler strips the type annotations at
 * build, leaving a wire-level JSON shape the browser-side bridge
 * consumes verbatim.
 *
 * Field parity contract: every key on the matching Config sub-block
 * MUST appear on the snapshot. The dedicated test
 * `tests/typert/host.test.ts` > 'getConfig() returns 9-group
 * snapshot with all 7 group keys present' walks each sub-block via
 * `Object.keys` and asserts the key set matches.
 */
function getConfigHandler(config: Config): ConfigSnapshot {
  return {
    // Surface the *effective* runtime mode (always
    // `config.intervention.mode` after normalizeConfig), not the
    // top-level `Config.mode` field. The Config tab edits
    // `intervention.mode` only; the snapshot reflects what the
    // engine actually reads.
    mode: config.intervention.mode,
    enabled: config.enabled !== false,
    hostId: config.hostId ?? '',
    containerId: config.containerId ?? '',
    collector: snapshotCollector(config),
    application: snapshotApplication(config),
    networkCapture: snapshotNetworkCapture(config),
    runtimeHooks: snapshotRuntimeHooks(config),
    intervention: snapshotIntervention(config),
    inlineGuards: snapshotInlineGuards(config),
    // The 7 §6.2 sub-block mirrors.
    // The UI iterates these keys for the Config tab section
    // headers; missing keys would silently drop sections.
    sensitivePathGuard: snapshotSensitivePathGuard(config),
    inlinePromptInjection: snapshotInlinePromptInjection(config),
    stdioMirror: snapshotStdioMirror(config),
    envPassthroughGuard: snapshotEnvPassthroughGuard(config),
    sensitiveHeaderGuard: snapshotSensitiveHeaderGuard(config),
    loopedToolDetector: snapshotLoopedToolDetector(config),
    tokenUsageDetector: snapshotTokenUsageDetector(config),
    sinkDiskLow: snapshotSinkDiskLow(config),
  }
}

function snapshotCollector(config: Config): ConfigSnapshotCollector {
  return {
    localOutputPath: config.collector.localOutputPath,
    batchSize: config.collector.batchSize,
    flushIntervalMs: config.collector.flushIntervalMs,
    validateEvents: config.collector.validateEvents,
    maxFileBytes: config.collector.maxFileBytes,
    diskWarnWatermarkBytes: config.collector.diskWarnWatermarkBytes,
    diskLowWatermarkBytes: config.collector.diskLowWatermarkBytes,
    redactRawParams: config.collector.redactRawParams,
    debugLogPath: config.collector.debugLogPath ?? '',
  }
}

function snapshotApplication(config: Config): ConfigSnapshotApplication {
  return {
    captureUserPrompt: config.application.captureUserPrompt,
    captureSystemPrompt: config.application.captureSystemPrompt,
    captureAgentPlan: config.application.captureAgentPlan,
    captureReasoning: config.application.captureReasoning,
    toolResultMaxChars: config.application.toolResultMaxChars,
    sessionTtlMs: config.application.sessionTtlMs,
  }
}

function snapshotNetworkCapture(config: Config): ConfigSnapshotNetworkCapture {
  return {
    enabled: config.networkCapture.enabled,
    redactBodies: config.networkCapture.redactBodies,
    captureResponseBody: config.networkCapture.captureResponseBody,
    maxBodyBytes: config.networkCapture.maxBodyBytes,
    sseSummaryChunks: config.networkCapture.sseSummaryChunks,
    sseSummaryLastChunks: config.networkCapture.sseSummaryLastChunks,
    includeHosts: [...config.networkCapture.includeHosts],
    excludeHosts: [...config.networkCapture.excludeHosts],
    excludeUrls: [...config.networkCapture.excludeUrls],
    sensitiveKeyPatterns: [...config.networkCapture.sensitiveKeyPatterns],
    captureDns: config.networkCapture.captureDns,
  }
}

function snapshotRuntimeHooks(config: Config): ConfigSnapshotRuntimeHooks {
  return {
    enabled: config.runtimeHooks.enabled,
    networkEnabled: config.runtimeHooks.networkEnabled,
    logPath: config.runtimeHooks.logPath,
    hookPath: config.runtimeHooks.hookPath ?? '',
    excludeCommandLines: [...config.runtimeHooks.excludeCommandLines],
    enabledAtSubprocess: config.runtimeHooks.enabledAtSubprocess,
    blockAtSubprocess: config.runtimeHooks.blockAtSubprocess,
    failOpenOnError: config.runtimeHooks.failOpenOnError,
  }
}

function snapshotIntervention(config: Config): ConfigSnapshotIntervention {
  return {
    enabled: config.intervention.enabled,
    mode: config.intervention.mode,
    policyPath: config.intervention.policyPath,
    policyPaths: [...config.intervention.policyPaths],
    reloadIntervalMs: config.intervention.reloadIntervalMs,
    decisionTimeoutMs: config.intervention.decisionTimeoutMs,
    failStrategy: config.intervention.failStrategy,
  }
}

function snapshotInlineGuards(config: Config): ConfigSnapshotInlineGuards {
  return {
    engineLaunchers: [...config.inlineGuards.engineLaunchers],
    pluginPackageName: config.inlineGuards.pluginPackageName,
    patchMarkers: [...config.inlineGuards.patchMarkers],
  }
}

// The 7 §6.2 sub-block snapshot helpers.
// Each helper is a shallow clone of its sub-block; arrays are
// spread so the snapshot owns its copies (mutating the snapshot
// cannot reach back into the live Config).
function snapshotSensitivePathGuard(config: Config): ConfigSnapshotSensitivePathGuard {
  return {
    enabled: config.sensitivePathGuard.enabled,
    paths: [...config.sensitivePathGuard.paths],
    watchEnabled: config.sensitivePathGuard.watchEnabled,
    watchDebounceMs: config.sensitivePathGuard.watchDebounceMs,
  }
}

function snapshotInlinePromptInjection(config: Config): ConfigSnapshotInlinePromptInjection {
  return {
    enabled: config.inlinePromptInjection.enabled,
    patterns: [...config.inlinePromptInjection.patterns],
    excerptMaxChars: config.inlinePromptInjection.excerptMaxChars,
  }
}

function snapshotStdioMirror(config: Config): ConfigSnapshotStdioMirror {
  return {
    enabled: config.stdioMirror.enabled,
    payloadLimitBytes: config.stdioMirror.payloadLimitBytes,
    outputPath: config.stdioMirror.outputPath,
  }
}

function snapshotEnvPassthroughGuard(config: Config): ConfigSnapshotEnvPassthroughGuard {
  return {
    enabled: config.envPassthroughGuard.enabled,
    keys: [...config.envPassthroughGuard.keys],
  }
}

function snapshotSensitiveHeaderGuard(config: Config): ConfigSnapshotSensitiveHeaderGuard {
  return {
    enabled: config.sensitiveHeaderGuard.enabled,
    keys: [...config.sensitiveHeaderGuard.keys],
    // Both fields must stay in the snapshot —
    // see the comment on ConfigSnapshotSensitiveHeaderGuard in
    // src/typert/descriptors.ts. If the host's getConfig() payload
    // drops them, the Config tab UI renders controls for values the
    // baseline does not carry, and validateConfigPatch sees a
    // malformed baseline and rejects any patch touching these fields.
    harnessPlaneHosts: [...config.sensitiveHeaderGuard.harnessPlaneHosts],
    enforceOutOfFrame: config.sensitiveHeaderGuard.enforceOutOfFrame,
  }
}

function snapshotLoopedToolDetector(config: Config): ConfigSnapshotLoopedToolDetector {
  return {
    enabled: config.loopedToolDetector.enabled,
    windowMs: config.loopedToolDetector.windowMs,
    thresholdPerWindow: config.loopedToolDetector.thresholdPerWindow,
  }
}

function snapshotTokenUsageDetector(config: Config): ConfigSnapshotTokenUsageDetector {
  return {
    enabled: config.tokenUsageDetector.enabled,
    windowMs: config.tokenUsageDetector.windowMs,
    burstFactor: config.tokenUsageDetector.burstFactor,
    minBaselineSamples: config.tokenUsageDetector.minBaselineSamples,
  }
}

function snapshotSinkDiskLow(config: Config): ConfigSnapshotSinkDiskLow {
  return {
    recoverMarginBytes: config.sinkDiskLow.recoverMarginBytes,
  }
}

/* ---------------------------------------------------------------- *
 * Config patch validation + draft.        *
 *                                                                    *
 * The marketplace contract:                                            *
 *   - `validateConfigPatch` runs the patch through the Schemastery    *
 *     Config schema + a small policy-guard layer (inlineGuards      *
 *     immutability, mode/policyPath consistency). Returns errors     *
 *     and warnings separately so the UI can colour them differently.  *
 *   - `saveConfigDraft` writes the patch envelope (schemaVersion +    *
 *     patchedAt + operator + patch) to                                *
 *     `~/.dsh/security-monitor-config.draft.json`. The next           *
 *     `apply()` deep-merges it on top of the patch YAML.              *
 *   - `getConfigDraftStatus` is the passive read that powers the     *
 *     "Config draft pending" banner on first render.                  *
 *                                                                    *
 * Draft file format is `schemaVersion: 1` with an ISO-8601            *
 * `patchedAt` and an optional `operator` tag (from the runtime auth   *
 * context if available, else the env var `USER` / `USERNAME`, else   *
 * empty). The path is expanded at write time so the operator can `cat`*
 * the file directly.                                                 *
 * ---------------------------------------------------------------- */

/**
 * `validateConfigPatch` — thin Remote wrapper around
 * `src/config/validate.ts#validateConfigPatch`. The dedicated
 * validator owns the Schemastery schema + policyPath logic so the
 * host has one source of truth and the test suite exercises the
 * same path the runtime uses.
 *
 * The handler runs the validator against a fresh ConfigSnapshot
 * derived from the live `Config` (which may have a draft merged
 * in already on a subsequent boot) so the warnings / errors are
 * computed against the same base the next `apply()` would see.
 */
function validateConfigPatchHandler(
  patch: ConfigPatch,
  currentConfig: Config,
  logger: Logger,
): ConfigValidationResult {
  const snapshot: ConfigSnapshot = {
    mode: currentConfig.mode,
    enabled: currentConfig.enabled !== false,
    hostId: currentConfig.hostId ?? '',
    containerId: currentConfig.containerId ?? '',
    collector: snapshotCollector(currentConfig),
    application: snapshotApplication(currentConfig),
    networkCapture: snapshotNetworkCapture(currentConfig),
    runtimeHooks: snapshotRuntimeHooks(currentConfig),
    intervention: snapshotIntervention(currentConfig),
    inlineGuards: snapshotInlineGuards(currentConfig),
    // Mirror the 7 §6.2 sub-blocks
    // so the validator's mergeSnapshots() can shallow-merge an
    // operator patch that touches any of them.
    sensitivePathGuard: snapshotSensitivePathGuard(currentConfig),
    inlinePromptInjection: snapshotInlinePromptInjection(currentConfig),
    stdioMirror: snapshotStdioMirror(currentConfig),
    envPassthroughGuard: snapshotEnvPassthroughGuard(currentConfig),
    sensitiveHeaderGuard: snapshotSensitiveHeaderGuard(currentConfig),
    loopedToolDetector: snapshotLoopedToolDetector(currentConfig),
    tokenUsageDetector: snapshotTokenUsageDetector(currentConfig),
    sinkDiskLow: snapshotSinkDiskLow(currentConfig),
  }
  const result = validateConfigPatch(patch as ConfigPatch, snapshot)
  if (!result.ok) {
    logger.warn?.(
      `[SecurityMonitor] validateConfigPatch rejected: ${result.errors.length} error(s) — ${result.errors.join(';')}`,
    )
  } else if (result.warnings.length > 0) {
    logger.info?.(
      `[SecurityMonitor] validateConfigPatch accepted with ${result.warnings.length} warning(s) — ${result.warnings.join(';')}`,
    )
  }
  return result
}

/**
 * `saveConfigDraft` — write the patch envelope to disk and return
 * the absolute path. The shape is `schemaVersion: 1` + `patchedAt`
 * ISO + optional `operator` + the patch body verbatim. The next
 * `apply()` deep-merges the patch on top of the patch YAML.
 *
 * A saved draft never hot-applies: the `restartRequired: true` literal in the
 * return type is the wire-level contract the client relies on to
 * show the "restart to apply" banner without branching.
 */
async function saveConfigDraftHandler(
  patch: ConfigPatch,
  currentConfig: Config,
  logger: Logger,
): Promise<ConfigDraftResult> {
  try {
    // Re-validate before write so a saveConfigDraft call with
    // errors never reaches disk — the client may not have awaited
    // its own validateConfigPatch result yet.
    const validation = validateConfigPatchHandler(patch, currentConfig, logger)
    if (!validation.ok) {
      return {
        ok: false,
        path: '',
        restartRequired: true,
        error: validation.errors.join('; '),
      }
    }
    const operator = readOperatorTag()
    const patchRecord = patch as unknown as Record<string, unknown>
    const result = writeDraftFile(patchRecord, operator)
    if (!result.ok) {
      return { ok: false, path: '', restartRequired: true, error: result.error }
    }
    logger.info?.(
      `[SecurityMonitor] saveConfigDraft: persisted to ${result.path} (operator=${operator ||'anonymous'})`,
    )
    return { ok: true, path: result.path, restartRequired: true }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err)
    logger.error?.(`[SecurityMonitor] saveConfigDraft failed: ${message}`)
    return { ok: false, path: '', restartRequired: true, error: message }
  }
}

/**
 * `getConfigDraftStatus` — passive read for the "Config draft
 * pending" banner. Returns the file's path + envelope timestamp
 * + operator tag when a draft exists; empty strings when none.
 *
 * Failures (missing file, corrupt JSON) are reported as an empty
 * status — the client renders the same banner for "no draft" and
 * "draft unreadable" so the operator never sees a stray error from
 * a stale file.
 */
async function getConfigDraftStatusHandler(
  logger: Logger,
): Promise<ConfigDraftStatus> {
  try {
    const path = resolveDraftPath()
    const envelope = readDraftFile()
    if (!envelope) {
      return { path: '', patchedAt: '', operator: '' }
    }
    return {
      path,
      patchedAt: envelope.patchedAt,
      operator: envelope.operator,
    }
  } catch (err: unknown) {
    logger.warn?.(`[SecurityMonitor] getConfigDraftStatus failed: ${String(err)}`)
    return { path: '', patchedAt: '', operator: '' }
  }
}

/**
 * `previewLivePatch` / `applyLivePatch` Remote
 * wrappers around the LivePatchManager. Both are fail-soft: a missing
 * manager (older embedding that did not wire one) returns
 * `{ ok: false, error }` rather than throwing across the wire, and any
 * manager-internal failure is already folded into its return value.
 */
function previewLivePatchHandler(
  patch: LivePatchPatch,
  livePatch: LivePatchManager | undefined,
  logger: Logger,
): LivePatchPreview {
  try {
    if (!livePatch) {
      return {
        ok: false,
        safeKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
        errors: ['livePatch manager is not wired on this embedding'],
      }
    }
    return livePatch.preview(patch)
  } catch (error: unknown) {
    logger.warn?.(`[SecurityMonitor] previewLivePatch failed: ${String(error)}`)
    return {
      ok: false,
      safeKeys: [],
      needsRestartKeys: [],
      rejectedKeys: [],
      warnings: [],
      errors: [error instanceof Error ? error.message : String(error)],
    }
  }
}

async function applyLivePatchHandler(
  patch: LivePatchPatch,
  livePatch: LivePatchManager | undefined,
  logger: Logger,
): Promise<LivePatchApplyResult> {
  try {
    if (!livePatch) {
      return {
        ok: false,
        appliedKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
        error: 'livePatch manager is not wired on this embedding',
      }
    }
    const result = await livePatch.apply(patch)
    if (!result.ok) {
      logger.warn?.(
        `[SecurityMonitor] applyLivePatch rejected/failed: ${result.error ??'unknown'}`,
      )
    } else if (result.appliedKeys.length > 0) {
      logger.info?.(
        `[SecurityMonitor] applyLivePatch applied ${result.appliedKeys.length} key(s): ${result.appliedKeys.join(',')}`,
      )
    }
    return result
  } catch (error: unknown) {
    logger.warn?.(`[SecurityMonitor] applyLivePatch failed: ${String(error)}`)
    return {
      ok: false,
      appliedKeys: [],
      needsRestartKeys: [],
      rejectedKeys: [],
      warnings: [],
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/**
 * `readOperatorTag` — best-effort operator identifier for the
 * draft envelope. The runtime's auth context is the authoritative
 * source (when the marketplace node has the @deepseek-ai/sso
 * surface installed), but for the ship we fall back to the
 * `USER` / `USERNAME` env var so a draft is never anonymous on
 * developer machines.
 */
function readOperatorTag(): string {
  // Process env is the portable path — no harness-side coupling.
  const fromEnv = process.env['USER'] ?? process.env['USERNAME'] ?? ''
  return fromEnv.trim()
}

/* ---------------------------------------------------------------- *
 * `events` RPC for the Events tab.        *
 *                                                                  *
 * The Events tab exposes the raw NDJSON stream to the operator so *
 * they can browse / filter what the plugin actually collected —   *
 * not just the aggregated block counts in the Overview tab or the  *
 * recent-block decisions in the Recent blocks tab. The wire       *
 * contract is `EventsArgs` (clampable limit + filter object); the  *
 * return is `RawEventRow[]` (summary fields + full raw JSON       *
 * string for `<details>` expansion in the UI).                    *
 *                                                                  *
 * Three filtering primitives:                                      *
 *   - `event_type` — allow-list of known platform event types;    *
 *     unknown values are dropped server-side (never throws —       *
 *     invariant #3 holds even for malformed RPC bodies).          *
 *   - `outcome`    — lower-cased; only 'blocked' / 'denied' /     *
 *     'allow' are accepted (other values silently ignored).       *
 *   - `search`     — trimmed + capped at MAX_SEARCH_CHARS; matched *
 *     as a case-insensitive substring on the JSON-serialised row. *
 *     Never compiled as a regex (no ReDoS exposure).               *
 *                                                                  *
 * The filter predicate is assembled as a single pure function     *
 * over `Record<string, unknown>` so the existing tailNdjson path   *
 * does the byte-level tail read; we just hand it the predicate.   *
 * Limit is clamped to [1, 1000] (default 100) so a fat-fingered   *
 * client cannot request 10M rows.                                  *
 *                                                                  *
 * Per-row `raw_json` is truncated to MAX_RAW_JSON_BYTES (16 KiB)  *
 * with a `...[truncated]` breadcrumb so a single 4 KiB body +     *
 * 50 KiB `raw_params` does not blow up the marketplace bundle.    *
 * The UI surfaces a "raw truncated" hint when the breadcrumb is   *
 * present so the operator knows the full record is on disk.       *
 * ---------------------------------------------------------------- */

function normaliseEventsFilter(raw: unknown): {
  eventType: ReadonlySet<string> | null
  outcome: string | null
  search: string | null
} {
  if (!raw || typeof raw !== 'object') {
    return { eventType: null, outcome: null, search: null }
  }
  const filter = raw as { event_type?: unknown; outcome?: unknown; search?: unknown }
  // event_type: keep only known values (allow-list). Unknown entries
  // are dropped silently — the marketplace never throws at the wire
  // boundary (invariant #3). An empty allow-list is treated as "no
  // filter" so the client UI can send `[]` without breaking.
  let eventType: ReadonlySet<string> | null = null
  if (Array.isArray(filter.event_type)) {
    const known: string[] = []
    for (const entry of filter.event_type) {
      if (typeof entry === 'string' && ALLOWED_EVENT_TYPES.has(entry)) {
        known.push(entry)
      }
    }
    if (known.length > 0) eventType = new Set(known)
  }
  // outcome: lowercase + allow-list. Anything else (including the
  // empty string / non-strings) becomes 'no filter'.
  let outcome: string | null = null
  if (typeof filter.outcome === 'string') {
    const lc = filter.outcome.toLowerCase()
    if (ALLOWED_OUTCOMES.has(lc)) outcome = lc
  }
  // search: trim + cap. Never regex-compiled — substring on the
  // serialised row. Empty / whitespace-only → no filter.
  let search: string | null = null
  if (typeof filter.search === 'string') {
    const trimmed = filter.search.trim().slice(0, MAX_SEARCH_CHARS)
    if (trimmed.length > 0) search = trimmed.toLowerCase()
  }
  return { eventType, outcome, search }
}

function makeEventsPredicate(filter: {
  eventType: ReadonlySet<string> | null
  outcome: string | null
  search: string | null
}): (obj: Record<string, unknown>) => boolean {
  // Fast-path: no filter at all → accept everything. The tail reader
  // will still cap at `limit` rows.
  if (!filter.eventType && !filter.outcome && !filter.search) {
    return () => true
  }
  // Cache the lower-cased search bytes so we don't re-trim on every
  // row. The per-row JSON.stringify is unavoidable (the UI needs the
  // string back) but it lives outside this predicate — see
  // toRawEventRow. The predicate only does the cheap shallow scans.
  return (obj: Record<string, unknown>): boolean => {
    const et = obj['event_type']
    if (filter.eventType) {
      if (typeof et !== 'string' || !filter.eventType.has(et)) return false
    }
    if (filter.outcome) {
      const oc = obj['outcome']
      if (typeof oc !== 'string' || oc.toLowerCase() !== filter.outcome) return false
    }
    if (filter.search) {
      // Serialise the row once per match attempt — tailNdjson walks
      // the file from the END, so for a typical 50-row page the cost
      // is bounded. The same string is later re-used by
      // toRawEventRow(); we re-serialise there to keep the
      // predicate cache-free (the predicate may be invoked by the
      // tail reader in arbitrary order).
      const raw = JSON.stringify(obj)
      if (!raw.toLowerCase().includes(filter.search)) return false
    }
    return true
  }
}

function toRawEventRow(raw: Record<string, unknown>): RawEventRow {
  // The full event as JSON — truncated to MAX_RAW_JSON_BYTES with a
  // breadcrumb so a single row cannot blow up the marketplace bundle.
  // We re-serialise from the parsed object (rather than reusing the
  // tail reader's raw line) to normalise key ordering — operators
  // expect `ts` first. Truncation lives in the shared
  // `truncateRawJson` (descriptors) so Events tab and Policy Hits
  // cap byte-identically.
  const truncated = truncateRawJson(JSON.stringify(raw))
  // The summary fields ride alongside the raw_json. We tolerate
  // non-string fields (runtime may emit numbers / objects / nulls);
  // only string fields are surfaced, others become undefined.
  const tsRaw = raw['ts']
  const ts = typeof tsRaw === 'number' && Number.isFinite(tsRaw) ? tsRaw : 0
  const eventId = typeof raw['event_id'] === 'string' ? raw['event_id'] : undefined
  const eventType = typeof raw['event_type'] === 'string' ? raw['event_type'] : ''
  const sessionId = typeof raw['session_id'] === 'string' ? raw['session_id'] : undefined
  const agentId = typeof raw['agent_id'] === 'string' ? raw['agent_id'] : undefined
  const toolName = typeof raw['tool_name'] === 'string' ? raw['tool_name'] : undefined
  // block_code / block_reason can live at the top level (runtime seam
  // events) or inside intervention.* (SPL tool-layer blocks). Look in
  // both so the UI shows a uniform field.
  const intervention = raw['intervention'] as
    | { block_code?: unknown; block_reason?: unknown; policy_id?: unknown }
    | undefined
  const blockCode =
    (typeof intervention?.block_code === 'string' && intervention.block_code) ||
    (typeof raw['block_code'] === 'string' && raw['block_code']) ||
    undefined
  const blockReason =
    (typeof intervention?.block_reason === 'string' && intervention.block_reason) ||
    (typeof raw['block_reason'] === 'string' && raw['block_reason']) ||
    undefined
  const policyId =
    (typeof intervention?.policy_id === 'string' && intervention.policy_id) ||
    (typeof raw['policy_id'] === 'string' && raw['policy_id']) ||
    undefined
  const outcome = typeof raw['outcome'] === 'string' ? raw['outcome'] : undefined
  return {
    ts,
    event_id: eventId,
    event_type: eventType,
    session_id: sessionId,
    agent_id: agentId,
    tool_name: toolName,
    block_code: blockCode,
    block_reason: blockReason,
    policy_id: policyId,
    outcome,
    raw_json: truncated,
  }
}

async function eventsHandler(
  sink: LocalNdjsonSink,
  rawArgs: EventsArgs,
  logger: Logger,
): Promise<{ rows: RawEventRow[]; total: number }> {
  const path = sink.getLocalOutputPath()
  if (!path) return { rows: [], total: 0 }
  // Limit: clamp to [1, 1000] (default 100). Using the shared
  // clampLimit helper (from src/status/overview.ts) keeps the
  // bounds handling identical to recentBlocks / overview.
  const limit = clampLimit(rawArgs?.limit, 100, 1, 1000)
  // Offset: load-more cursor. The Events tab pages into
  // older history by `offset: <rows-already-shown>`. The host passes
  // it through to tailNdjson which skips the newest `offset` matches
  // before returning the next `limit`. A negative / out-of-range
  // offset returns `[]` (clamped at the utility layer).
  const offset = Math.max(0, rawArgs?.offset ?? 0)
  // Filter: whitelist event_type + lowercase outcome + trim/cap
  // search. Failures are silently dropped (invariant #3).
  const filter = normaliseEventsFilter(rawArgs?.filter)
  const predicate = makeEventsPredicate(filter)
  const ndjsonTail = await loadNdjsonTail(logger)
  if (!ndjsonTail) return { rows: [], total: 0 }
  // Fan out the page tail + filter-aware count so the
  // footer can render "Showing N of M events". `countNdjson` walks
  // the whole file; for the local audit sink the file is small
  // enough (1–2 MiB) that the second pass is cheap and parallel
  // with the first.
  const [raw, total] = await Promise.all([
    ndjsonTail.tailNdjson(path, limit, {
      filter: predicate,
      offset,
    }),
    ndjsonTail.countNdjson(path, predicate),
  ])
  return {
    rows: raw.map(toRawEventRow),
    total,
  }
}
