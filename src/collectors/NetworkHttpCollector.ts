/**
 * NetworkHttpCollector — application-layer HTTP/HTTPS request capture.
 *
 * This collector monkey-patches Node's built-in `http.request`, `https.request`
 * and `global.fetch` inside the harness process to emit `network_http` security
 * events. It sees plaintext before TLS and can capture method, URL, headers,
 * request body, response status and response body.
 *
 * Design constraints:
 *   - Non-intrusive: only runtime patches, no harness source changes.
 * Audit by default: requests are observed, not blocked (enforce is).
 *   - Self-protecting: the plugin's own HTTP sink endpoint is excluded.
 *   - Transparent: callbacks, streams and promises are preserved.
 */

import http from 'node:http'
import https from 'node:https'
import dns from 'node:dns'
import type { ClientRequest, IncomingMessage, RequestOptions } from 'node:http'
import type { Config } from '../config.js'
import type { LocalNdjsonSink } from './LocalNdjsonSink.js'
import type { InterventionEngine } from '../intervention/InterventionEngine.js'
import type { InterventionContext, SecurityEvent } from '../types/index.js'
import { DEFAULT_PLATFORM_ID } from '../types/index.js'
import { generateEventId } from '../utils/eventId.js'
import { nowMs } from '../utils/time.js'
import { toMarketplaceDecision } from '../utils/decisionVocabulary.js'
import { buildHostMeta } from './LocalNdjsonSink.js'
import { redactSensitiveBody, limitPayloadSize, DEFAULT_SENSITIVE_KEYS, summarizeMultipartBody } from '../utils/redact.js'
import { redactUrlQueryString, redactHttpBody } from '../utils/contentRedactor.js'
import { getHttpRequestSessionContext, type HttpRequestSessionContext } from '../utils/httpContext.js'
import {
  evaluateSensitiveHeaderGuard,
  flattenHeadersForGuard,
  SensitiveHeaderDeniedError,
  type SensitiveHeaderGuardConfig,
} from '../intervention/SensitiveHeaderGuard.js'
import {
  defaultSettingsPath,
  matchesAnyHostPattern,
  readProviderHosts,
  watchProviderHosts,
} from './providerHostDiscovery.js'

export interface NetworkHttpCollectorDeps {
  eventCollector: LocalNdjsonSink
  interventionEngine?: InterventionEngine
  /** Fallback session resolver when AsyncLocalStorage has no context. */
  sessionResolve?: () => HttpRequestSessionContext | undefined
}

interface RequestMeta {
  protocol: 'http:' | 'https:'
  method: string
  host: string
  port?: number
  path: string
  requestUrl: string
  headers: Record<string, string | string[]>
}

interface EmitArgs {
  meta: RequestMeta
  requestId: string
  startTs: number
  code?: number
  responseBody?: string
  responseError?: string
  requestBodyText?: string
  responseTruncated?: boolean
  responseOriginalLength?: number
  responseContentType?: string
  session?: HttpRequestSessionContext
}

class BodyAccumulator {
  private chunks: Buffer[] = []
  private capturedLength = 0
  private originalLength = 0

  constructor(private readonly maxBytes: number) {}

  append(chunk: unknown, encoding?: BufferEncoding): void {
    if (chunk === undefined || chunk === null) return
    let buf: Buffer | undefined
    if (Buffer.isBuffer(chunk)) {
      buf = chunk
    } else if (typeof chunk === 'string') {
      buf = Buffer.from(chunk, encoding ?? 'utf8')
    }
    if (!buf) return

    this.originalLength += buf.length
    if (this.capturedLength >= this.maxBytes) {
      // Already at cap; just keep counting original size.
      return
    }
    const remaining = this.maxBytes - this.capturedLength
    if (buf.length > remaining) {
      this.chunks.push(buf.subarray(0, remaining))
      this.capturedLength = this.maxBytes
    } else {
      this.chunks.push(buf)
      this.capturedLength += buf.length
    }
  }

  string(): string {
    return Buffer.concat(this.chunks).toString('utf8')
  }

  original(): number {
    return this.originalLength
  }

  truncated(): boolean {
    return this.originalLength > this.maxBytes
  }
}

export class NetworkHttpCollector {
  private readonly config: Config['networkCapture']
  private readonly eventCollector: LocalNdjsonSink
  private readonly interventionEngine?: InterventionEngine
  private readonly sessionResolve: () => HttpRequestSessionContext | undefined
  /**
   * Inline sensitive-header guard config. Owns the
   * `Authorization` / `Cookie` / `Proxy-Authorization` / `X-API-Key` deny-list
   * that gates ALL outbound HTTP — both `global.fetch` and the http(s) modules.
   * `normalizeConfig` force-asserts `enabled: true` and UNION-merges the
   * operator's `keys` with `SENSITIVE_HEADER_FALLBACK`, so the safety net
   * cannot be downgraded by `cordis.patch.yml`.
   */
  private readonly sensitiveHeaderGuard: SensitiveHeaderGuardConfig
  /**
   * derived matcher state — rebuilt by
   * `rebuildDerivedMatcherState()` on livePatch of the corresponding
   * config arrays (constructor + livePatch share one code path).
   */
  private excludeHosts: Set<string>
  private includeHosts: Set<string>
  private excludeUrlRegexps: RegExp[]
  private sensitiveKeyPatterns: string[]
  // Lowercased host Set of the sensitive-header guard's
  // `harnessPlaneHosts` allow-list. Out-of-frame requests to these hosts
  // skip the guard; everything else out-of-frame is guard-evaluated.
  private harnessPlaneHosts: Set<string>
  /**
   * Lowercased host Set of the AUTO exemption layer, config half —
   * `sensitiveHeaderGuard.seedHosts` (marketplace seeds UNION operator
   * entries). Rebuilt by `rebuildDerivedMatcherState()`; supports `*.`
   * wildcard entries like the manual list.
   */
  private seedExemptHosts: Set<string>
  /**
   * Lowercased host Set of the AUTO exemption layer, discovery half —
   * provider hosts read from the host settings document. Owned by the
   * discovery watcher (constructor seeds the initial read); plain
   * hostnames, no wildcards.
   */
  private discoveredHosts: Set<string>
  /** Discovery watcher handle; undefined when discovery is disabled. */
  private providerDiscoveryStop?: { stop: () => void }
  private installed = false

  private originalHttpRequest?: typeof http.request
  private originalHttpsRequest?: typeof https.request
  // capture module.get alongside module.request
  // at install so uninstall() can restore it. Previously only request was
  // captured, leaving module.get wrapped after every plugin reload — a
  // double-wrap on every http(s).get call (functionally benign but a latent
  // resource leak + doubled per-request allocation cost).
  private originalHttpGet?: typeof http.get
  private originalHttpsGet?: typeof https.get
  private originalFetch?: typeof fetch
  private originalDnsLookup?: typeof dns.lookup
  private originalDnsResolve?: typeof dns.resolve
  private originalDnsResolve4?: typeof dns.resolve4
  private originalDnsResolve6?: typeof dns.resolve6

  constructor(config: Config, deps: NetworkHttpCollectorDeps) {
    this.config = config.networkCapture
    this.eventCollector = deps.eventCollector
    this.interventionEngine = deps.interventionEngine
    this.sessionResolve = deps.sessionResolve ?? (() => undefined)
    // Pass the inline sensitive-header guard config
    // through. `normalizeConfig` already force-asserted `enabled: true` and
    // UNION-merged the operator's keys with `SENSITIVE_HEADER_FALLBACK`, so
    // the guard runs in enforce posture by default and cannot be downgraded.
    this.sensitiveHeaderGuard = config.sensitiveHeaderGuard

    this.excludeHosts = new Set()
    this.includeHosts = new Set()
    this.excludeUrlRegexps = []
    this.sensitiveKeyPatterns = []
    this.harnessPlaneHosts = new Set()
    this.seedExemptHosts = new Set()
    this.discoveredHosts = new Set()
    this.rebuildDerivedMatcherState()

    // Provider host auto-discovery starts in install() — a constructed
    // but disabled (networkCapture.enabled false) collector must not keep
    // polling the settings document. The discovery module degrades all
    // failures to "no hosts" and uses a `persistent: false` watcher plus
    // an unref'd poll, so it never holds the host process open.

    // marketplace drops the HTTP sink endpoint
    // (`collector.endpoint` is gone). Recursion protection now relies
    // entirely on the operator's `excludeHosts` list.
  }

  /**
   * rebuild the host Sets / URL regexps /
   * sensitive-key list from the (possibly live-patched) config arrays.
   * Shared by the constructor and `livePatch()` so the derivation cannot
   * drift.
   */
  private rebuildDerivedMatcherState(): void {
    this.excludeHosts = new Set(this.config.excludeHosts.map((h) => h.toLowerCase()))
    this.includeHosts = new Set(this.config.includeHosts.map((h) => h.toLowerCase()))
    this.excludeUrlRegexps = this.config.excludeUrls.map((p) => new RegExp(p))
    this.sensitiveKeyPatterns = [...DEFAULT_SENSITIVE_KEYS, ...this.config.sensitiveKeyPatterns]
    // Keep the guard's exemption Sets in the same
    // rebuild path so constructor and livePatch cannot drift. The
    // discovery half (discoveredHosts) is owned by the watcher and is
    // deliberately NOT rebuilt here.
    this.harnessPlaneHosts = new Set((this.sensitiveHeaderGuard.harnessPlaneHosts ?? []).map((h) => h.toLowerCase()))
    this.seedExemptHosts = new Set((this.sensitiveHeaderGuard.seedHosts ?? []).map((h) => h.toLowerCase()))
  }

  /**
   * apply 🟢 networkCapture keys in place. Scalar
   * thresholds (maxBodyBytes / sseSummary* / redactBodies /
   * captureResponseBody / captureDns) are read per-request off the shared
   * config reference; the array fields additionally rebuild the derived
   * matcher state so the next request matches against the new lists.
   * `enabled` is 🔴 at the classifier level (master switch) and never
   * reaches this method from LivePatchManager.
   */
  livePatch(patch: Record<string, unknown>): {
    ok: boolean
    appliedKeys: string[]
    needsRestartKeys: string[]
    error?: string
  } {
    const appliedKeys: string[] = []
    const needsRestartKeys: string[] = []
    try {
      const cfg = patch['networkCapture']
      if (cfg && typeof cfg === 'object' && !Array.isArray(cfg)) {
        const c = cfg as Record<string, unknown>
        const assignNumber = (field: 'maxBodyBytes' | 'sseSummaryChunks' | 'sseSummaryLastChunks'): void => {
          if (typeof c[field] === 'number' && Number.isFinite(c[field])) {
            this.config[field] = c[field]
            appliedKeys.push(`networkCapture.${field}`)
          }
        }
        const assignBool = (field: 'redactBodies' | 'captureResponseBody' | 'captureDns'): void => {
          if (typeof c[field] === 'boolean') {
            this.config[field] = c[field]
            appliedKeys.push(`networkCapture.${field}`)
          }
        }
        assignNumber('maxBodyBytes')
        assignNumber('sseSummaryChunks')
        assignNumber('sseSummaryLastChunks')
        assignBool('redactBodies')
        assignBool('captureResponseBody')
        assignBool('captureDns')
        const assignStrList = (field: 'includeHosts' | 'excludeHosts' | 'excludeUrls' | 'sensitiveKeyPatterns'): void => {
          if (Array.isArray(c[field])) {
            this.config[field] = [
              ...(c[field] as unknown[]).filter((x): x is string => typeof x === 'string'),
            ]
            appliedKeys.push(`networkCapture.${field}`)
          }
        }
        assignStrList('includeHosts')
        assignStrList('excludeHosts')
        assignStrList('excludeUrls')
        assignStrList('sensitiveKeyPatterns')
        if (
          appliedKeys.some(
            (k) =>
              k === 'networkCapture.includeHosts' ||
              k === 'networkCapture.excludeHosts' ||
              k === 'networkCapture.excludeUrls' ||
              k === 'networkCapture.sensitiveKeyPatterns',
          )
        ) {
          this.rebuildDerivedMatcherState()
        }
      }
      // sensitiveHeaderGuard.keys is a livePatch key (see
      // src/config/livePatch.ts SAFE_FIELDS) — without this branch the
      // classifier accepts the key but no component ever applies it, so
      // operator edits silently no-op.
      const shg = patch['sensitiveHeaderGuard']
      if (shg && typeof shg === 'object' && !Array.isArray(shg)) {
        const s = shg as Record<string, unknown>
        if (Array.isArray(s['keys'])) {
          this.sensitiveHeaderGuard.keys = [
            ...(s['keys'] as unknown[]).filter((x): x is string => typeof x === 'string'),
          ]
          appliedKeys.push('sensitiveHeaderGuard.keys')
        }
        // Seed exemption hosts are 🟢 livePatch-able (noise-reduction
        // list, same hygiene as keys). Union semantics are owned by
        // `normalizeConfig` at restart; a livePatch REPLACES the seed
        // half wholesale (operator intent), so rebuild the derived Set.
        if (Array.isArray(s['seedHosts'])) {
          this.sensitiveHeaderGuard.seedHosts = [
            ...(s['seedHosts'] as unknown[]).filter(
              (x): x is string => typeof x === 'string' && x.trim().length > 0,
            ),
          ].map((h) => h.toLowerCase())
          this.rebuildDerivedMatcherState()
          appliedKeys.push('sensitiveHeaderGuard.seedHosts')
        }
      }
      appliedKeys.sort()
      needsRestartKeys.sort()
      return { ok: true, appliedKeys, needsRestartKeys }
    } catch (error: unknown) {
      return {
        ok: false,
        appliedKeys,
        needsRestartKeys,
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }

  install(): void {
    if (this.installed || !this.config.enabled) return
    this.installed = true
    // Provider host auto-discovery: seed the initial read and subscribe
    // to settings document changes. `persistent: false` watcher + unref'd
    // poll — never holds the host process open; failures degrade to "no
    // hosts" (current behaviour), never to a throw.
    if (this.sensitiveHeaderGuard.providerDiscovery && !this.providerDiscoveryStop) {
      const overridePath = this.sensitiveHeaderGuard.providerDiscoveryPath
      const settingsPath =
        typeof overridePath === 'string' && overridePath.trim().length > 0
          ? overridePath
          : defaultSettingsPath()
      this.discoveredHosts = new Set(readProviderHosts(settingsPath))
      this.providerDiscoveryStop = watchProviderHosts(settingsPath, (hosts) => {
        this.discoveredHosts = new Set(hosts)
      })
    }
    this.patchHttpModule(http, 'http:')
    this.patchHttpModule(https, 'https:')
    this.patchFetch()
    this.patchDns()
  }

  uninstall(): void {
    if (!this.installed) return
    if (this.originalHttpRequest) http.request = this.originalHttpRequest
    if (this.originalHttpsRequest) https.request = this.originalHttpsRequest
    if (this.originalHttpGet) http.get = this.originalHttpGet
    if (this.originalHttpsGet) https.get = this.originalHttpsGet
    if (this.originalFetch) globalThis.fetch = this.originalFetch
    if (this.originalDnsLookup) dns.lookup = this.originalDnsLookup
    if (this.originalDnsResolve) dns.resolve = this.originalDnsResolve
    if (this.originalDnsResolve4) dns.resolve4 = this.originalDnsResolve4
    if (this.originalDnsResolve6) dns.resolve6 = this.originalDnsResolve6
    // Stop the provider-discovery watcher — an uninstalled collector must
    // not keep polling the settings document (plugin reload would otherwise
    // stack one watcher per generation).
    try {
      this.providerDiscoveryStop?.stop()
    } catch {
      // watcher teardown is best-effort
    }
    this.providerDiscoveryStop = undefined
    this.installed = false
  }

  private callOrigRequest(
    orig: (...args: unknown[]) => ClientRequest,
    target: string | URL | RequestOptions,
    requestOptions: RequestOptions | undefined,
    callback: (res: IncomingMessage) => void,
  ): ClientRequest {
    if (typeof target === 'string' || target instanceof URL) {
      if (requestOptions) return orig(target, requestOptions, callback)
      return orig(target, callback)
    }
    return orig(target, callback)
  }

  private patchHttpModule(
    module: typeof http | typeof https,
    defaultProtocol: 'http:' | 'https:',
  ): void {
    const orig = module.request.bind(module) as (...args: unknown[]) => ClientRequest

    const parseArgs = (
      args: unknown[],
    ): {
      target: string | URL | RequestOptions
      requestOptions: RequestOptions | undefined
      callback: ((res: IncomingMessage) => void) | undefined
    } => {
      const target = args[0] as string | URL | RequestOptions
      if (typeof target === 'string' || target instanceof URL) {
        if (typeof args[1] === 'function') {
          return { target, requestOptions: undefined, callback: args[1] as (res: IncomingMessage) => void }
        }
        if (args[1] && typeof args[1] === 'object') {
          return {
            target,
            requestOptions: args[1] as RequestOptions,
            callback: typeof args[2] === 'function' ? (args[2] as (res: IncomingMessage) => void) : undefined,
          }
        }
        return { target, requestOptions: undefined, callback: undefined }
      }
      return {
        target,
        requestOptions: target as RequestOptions,
        callback: typeof args[1] === 'function' ? (args[1] as (res: IncomingMessage) => void) : undefined,
      }
    }

    const wrapped = (...args: unknown[]): ClientRequest => {
      const { target, requestOptions, callback } = parseArgs(args)

      const meta = this.extractRequestMeta(target, requestOptions, defaultProtocol)
      if (this.shouldSkip(meta.host, meta.path, meta.requestUrl)) {
        return orig(...args)
      }

      // Inline sensitive-header guard. Run BEFORE the
      // original http(s).request fires (so the outbound socket never opens)
      // and BEFORE any SPL evaluation (the rail is hardcoded and cannot be
      // downgraded by policy-file edits). On hit we throw
      // SensitiveHeaderDeniedError synchronously, which the calling tool
      // layer surfaces as a tool error; we also emit one audit row carrying
      // the matched key + truncated value preview.
      this.guardSensitiveHeadersOrThrow(
        flattenHeadersForGuard(meta.headers as unknown as Parameters<typeof flattenHeadersForGuard>[0]),
        meta.requestUrl,
      )

      const startTs = nowMs()
      const requestId = generateEventId()
      const bodyAcc = new BodyAccumulator(this.config.maxBodyBytes)
      const session = getHttpRequestSessionContext() ?? this.sessionResolve()

      const wrappedResponse = (res: IncomingMessage): void => {
        const respAcc = new BodyAccumulator(this.config.maxBodyBytes)
        const responseContentType = getHeaderValue(
          flattenHeaders(res.headers),
          'content-type',
        )
        res.on('data', (chunk: unknown) => respAcc.append(chunk))
        res.on('end', () => {
          void this.emitEvent({
            meta,
            requestId,
            startTs,
            code: res.statusCode,
            responseBody: respAcc.string(),
            responseTruncated: respAcc.truncated(),
            responseOriginalLength: respAcc.original(),
            responseContentType,
            requestBodyText: bodyAcc.string(),
            session,
          })
        })
        res.on('error', (err: Error) => {
          void this.emitEvent({
            meta,
            requestId,
            startTs,
            responseError: err.message,
            requestBodyText: bodyAcc.string(),
            session,
          })
        })
        if (callback) callback(res)
      }

      const req = this.callOrigRequest(orig, target, requestOptions, wrappedResponse)

      // Intercept req.write / req.end to capture outgoing body chunks.
      const origWrite = req.write.bind(req) as (...args: unknown[]) => boolean
      const origEnd = req.end.bind(req) as (...args: unknown[]) => ClientRequest

      req.write = function write(_chunk: unknown, _encoding?: unknown, _cb?: unknown): boolean {
        bodyAcc.append(_chunk, _encoding as BufferEncoding)
        return origWrite(_chunk, _encoding, _cb)
      }

      req.end = function end(_chunk?: unknown, _encoding?: unknown, _cb?: unknown): ClientRequest {
        if (_chunk !== undefined && typeof _chunk !== 'function') bodyAcc.append(_chunk, _encoding as BufferEncoding)
        return origEnd(_chunk, _encoding, _cb)
      }

      req.on('error', (err: Error) => {
        void this.emitEvent({
          meta,
          requestId,
          startTs,
          responseError: err.message,
          requestBodyText: bodyAcc.string(),
          session,
        })
      })

      return req
    }

    const wrappedGet = (...args: unknown[]): ClientRequest => {
      const req = wrapped(...args)
      // Node's http.get is request() + end(). Our wrapped request returns a
      // patched ClientRequest whose end() still needs to be called, so we mimic
      // the native shortcut here.
      req.end()
      return req
    }

    if (defaultProtocol === 'http:') {
      this.originalHttpRequest = module.request as typeof http.request
      this.originalHttpGet = module.get as typeof http.get
      module.request = wrapped as unknown as typeof http.request
      module.get = wrappedGet as unknown as typeof http.get
    } else {
      this.originalHttpsRequest = module.request as typeof https.request
      this.originalHttpsGet = module.get as typeof https.get
      module.request = wrapped as unknown as typeof https.request
      module.get = wrappedGet as unknown as typeof https.get
    }
  }

  private patchFetch(): void {
    if (typeof globalThis.fetch !== 'function') return
    const origFetch = globalThis.fetch.bind(globalThis) as (...args: unknown[]) => Promise<Response>
    this.originalFetch = globalThis.fetch

    globalThis.fetch = async (input: unknown, init?: RequestInit): Promise<Response> => {
      const meta = this.extractFetchMeta(input, init)
      if (this.shouldSkip(meta.host, meta.path, meta.requestUrl)) {
        return origFetch(input, init)
      }

      // Inline sensitive-header guard. Same posture
      // as the http(s).request wrapper — runs BEFORE the original fetch
      // fires (no outbound socket opens) and BEFORE any SPL evaluation.
      // The `Request.headers` carrier is forwarded as-is; the
      // `init.headers` carrier is normalised through
      // `flattenHeadersForGuard` (Headers / Record / Array all reduce to
      // HeaderEntry[]). Both then flow into the guard's denylist match.
      const carrierHeaders: unknown[] = []
      if (input instanceof Request) carrierHeaders.push(input.headers)
      if (init?.headers) carrierHeaders.push(init.headers)
      const flat: Array<{ name: string; value: string }> = []
      for (const h of carrierHeaders) {
        for (const entry of flattenHeadersForGuard(h as Parameters<typeof flattenHeadersForGuard>[0])) flat.push(entry)
      }
      this.guardSensitiveHeadersOrThrow(flat, meta.requestUrl)

      const startTs = nowMs()
      const requestId = generateEventId()
      const session = getHttpRequestSessionContext() ?? this.sessionResolve()
      const requestBodyText = await this.captureFetchBody(init?.body)

      let response: Response
      try {
        response = await origFetch(input, init)
      } catch (err) {
        void this.emitEvent({
          meta,
          requestId,
          startTs,
          responseError: err instanceof Error ? err.message : String(err),
          requestBodyText,
          session,
        })
        throw err
      }

      let responseBody: string | undefined
      let responseTruncated = false
      let responseOriginalLength: number | undefined
      if (this.config.captureResponseBody) {
        try {
          const cloned = response.clone()
          const text = await cloned.text()
          const limited = limitPayloadSize(text, this.config.maxBodyBytes)
          responseBody = limited.value as string
          responseTruncated = limited.truncated
          responseOriginalLength = limited.originalLength
        } catch {
          responseBody = undefined
        }
      }

      const responseContentType = response.headers.get('content-type') ?? undefined
      void this.emitEvent({
        meta,
        requestId,
        startTs,
        code: response.status,
        responseBody,
        responseTruncated,
        responseOriginalLength,
        responseContentType,
        requestBodyText,
        session,
      })
      return response
    }
  }

  private extractRequestMeta(
    options: string | URL | RequestOptions,
    requestOptions: RequestOptions | undefined,
    defaultProtocol: 'http:' | 'https:',
  ): RequestMeta {
    let url: URL
    if (typeof options === 'string') {
      url = new URL(options)
    } else if (options instanceof URL) {
      url = options
    } else {
      const protocol = (options.protocol as string) || defaultProtocol
      const hostname = (options.hostname as string) || (options.host as string) || 'localhost'
      const port = options.port ? String(options.port) : protocol === 'https:' ? '443' : '80'
      const path = (options.path as string) || '/'
      url = new URL(`${protocol}//${hostname}:${port}${path}`)
    }

    let method = 'GET'
    let headers: Record<string, string | string[]> = {}
    const explicitOptions =
      typeof options === 'object' && !(options instanceof URL) ? (options as RequestOptions) : requestOptions
    if (explicitOptions) {
      if (explicitOptions.method) method = explicitOptions.method.toUpperCase()
      if (explicitOptions.headers) headers = flattenHeaders(explicitOptions.headers)
    }

    return {
      protocol: url.protocol === 'https:' ? 'https:' : 'http:',
      method,
      host: url.hostname.toLowerCase(),
      port: url.port ? Number(url.port) : undefined,
      path: url.pathname + url.search,
      requestUrl: url.href,
      headers,
    }
  }

  private extractFetchMeta(input: unknown, init?: RequestInit): RequestMeta {
    let url: URL
    let method = 'GET'
    let headers: Record<string, string | string[]> = {}

    if (input instanceof Request) {
      url = new URL(input.url)
      method = (input.method || 'GET').toUpperCase()
      headers = flattenHeaders(input.headers)
    } else if (input instanceof URL) {
      url = input
    } else if (typeof input === 'string') {
      url = new URL(input)
    } else {
      url = new URL(String(input))
    }

    if (init) {
      if (init.method) method = init.method.toUpperCase()
      if (init.headers) headers = flattenHeaders(init.headers)
    }

    return {
      protocol: url.protocol === 'https:' ? 'https:' : 'http:',
      method,
      host: url.hostname.toLowerCase(),
      port: url.port ? Number(url.port) : undefined,
      path: url.pathname + url.search,
      requestUrl: url.href,
      headers,
    }
  }

  /**
   * opt-in DNS query capture. We patch Node's callback-style
   * `dns.lookup` / `dns.resolve*` so every name resolution emits a
   * `network_dns` event. The patch is lightweight and only installed when
   * `httpCapture.captureDns` is true.
   */
  private patchDns(): void {
    if (!this.config.captureDns) return

    if (!this.originalDnsLookup) {
      this.originalDnsLookup = dns.lookup
      dns.lookup = ((hostname: string, ...args: unknown[]): ReturnType<typeof dns.lookup> => {
        const cbIndex = args.findIndex((a) => typeof a === 'function')
        const cb = cbIndex >= 0 ? (args[cbIndex] as (err: NodeJS.ErrnoException | null, address: string, family: number) => void) : undefined
        const rest = cbIndex >= 0 ? args.slice(0, cbIndex).concat(args.slice(cbIndex + 1)) : args
        const wrapped = (err: NodeJS.ErrnoException | null, address: string, family: number) => {
          if (!err) this.emitDnsEvent(String(hostname), address)
          if (cb) cb(err, address, family)
        }
        return (this.originalDnsLookup as unknown as (...args: unknown[]) => ReturnType<typeof dns.lookup>).call(
          dns,
          hostname,
          ...rest,
          wrapped,
        )
      }) as typeof dns.lookup
    }

    const patchResolve = (
      key: 'resolve' | 'resolve4' | 'resolve6',
      storeRef: { value?: typeof dns.resolve },
    ) => {
      if (storeRef.value) return
      const orig = dns[key] as typeof dns.resolve
      storeRef.value = orig
      ;(dns[key] as unknown) = ((hostname: string, ...args: unknown[]): void => {
        // resolve() optionally accepts an rrtype string before the callback.
        const cbIndex = args.findIndex((a) => typeof a === 'function')
        const cb = cbIndex >= 0 ? (args[cbIndex] as (err: NodeJS.ErrnoException | null, records: unknown) => void) : undefined
        const rest = cbIndex >= 0 ? args.slice(0, cbIndex).concat(args.slice(cbIndex + 1)) : args
        const wrapped = (err: NodeJS.ErrnoException | null, records: unknown) => {
          if (!err) this.emitDnsEvent(String(hostname), this.extractDnsAddress(records))
          if (cb) cb(err, records)
        }
        return (orig as unknown as (...args: unknown[]) => void).call(dns, hostname, ...rest, wrapped)
      })
    }

    const resolveStores: { resolve?: typeof dns.resolve; resolve4?: typeof dns.resolve4; resolve6?: typeof dns.resolve6 } = {}
    patchResolve('resolve', resolveStores as { value?: typeof dns.resolve })
    this.originalDnsResolve = resolveStores.resolve
    patchResolve('resolve4', resolveStores as { value?: typeof dns.resolve })
    this.originalDnsResolve4 = resolveStores.resolve4 as typeof dns.resolve4
    patchResolve('resolve6', resolveStores as { value?: typeof dns.resolve })
    this.originalDnsResolve6 = resolveStores.resolve6 as typeof dns.resolve6
  }

  private extractDnsAddress(records: unknown): string | undefined {
    if (typeof records === 'string') return records
    if (Array.isArray(records)) {
      const first = records[0]
      if (typeof first === 'string') return first
      if (first && typeof first === 'object') {
        const o = first as Record<string, unknown>
        if (typeof o.address === 'string') return o.address
      }
    }
    return undefined
  }

  private emitDnsEvent(query: string, remoteIp?: string): void {
    const session = getHttpRequestSessionContext() ?? this.sessionResolve()
    const now = nowMs()
    const event: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: 'network_dns',
      layer: 'application',
      source_layer: 'network',
      ts: now,
      timestamp: now,
      pid: process.pid,
      collection_method: 'hook',
      protocol: 'udp',
      remote_port: 53,
      service: 'dns',
      query,
      ...(remoteIp ? { remote_ip: remoteIp } : {}),
      blocked: false,
      ...buildHostMeta(),
      session_id: session?.sessionId,
      run_id: session?.runId,
      agent_id: session?.agentId,
      tool_call_id: session?.toolCallId,
      source: 'sst-security-control-dsh.network-http-collector.0.4.0',
      collector: {
        hook_name: 'dns_lookup',
        middleware_name: DEFAULT_PLATFORM_ID,
        collector_name: 'network-http-collector',
      },
    }
    this.eventCollector.report(event)
  }

  private async captureFetchBody(body: unknown): Promise<string | undefined> {
    if (body === undefined || body === null) return undefined
    if (typeof body === 'string') return body
    if (Buffer.isBuffer(body)) return body.toString('utf8')
    if (body instanceof Uint8Array) return Buffer.from(body).toString('utf8')
    if (body instanceof Blob) {
      try {
        const text = await body.text()
        const limited = limitPayloadSize(text, this.config.maxBodyBytes)
        return limited.value as string
      } catch {
        return '[unreadable Blob body]'
      }
    }
    if (body instanceof URLSearchParams) return body.toString()
    if (body instanceof FormData) {
      // Progressive multipart summary — see
      // summarizeMultipartBody in src/utils/events/redact.ts. An opaque
      // `'[FormData body]'` placeholder would either write
      // 50 MiB to NDJSON (no cap) or 13 bytes (audit gap). The summary
      // walks FormData.entries() with bounded Blob reads and returns a
      // JSON-serialisable structure; captureFetchBody is the one async
      // call site so the await chains naturally.
      try {
        const summary = await summarizeMultipartBody(body)
        const serialised = JSON.stringify(summary)
        const limited = limitPayloadSize(serialised, this.config.maxBodyBytes)
        return limited.value as string
      } catch {
        return '[FormData body]'
      }
    }
    if (typeof (body as ReadableStream<unknown>).getReader === 'function') {
      return '[ReadableStream body]'
    }
    return '[unreadable body]'
  }

  private shouldSkip(host: string, path: string, requestUrl: string): boolean {
    const hostLower = host.toLowerCase()

    // Self-capture gap (forward-looking): this build ships no uploader, so
    // there is no reporting traffic to exclude yet. If an uploader is ever
    // wired in — a governance SDK batch upload, or anything else that tags
    // its requests with the `x-aise-protocol-version` header — that request
    // would be captured here as ordinary business traffic, and every batch
    // would re-enter the event stream and grow the next batch without bound.
    // Before enabling any upload path, port the guard: skip requests
    // carrying the protocol header (config `networkCapture.excludeInternalUploads`)
    // and exclude the upload host(s) through an internal exclusion set that
    // operator `excludeHosts` edits cannot wipe.
    if (this.includeHosts.size > 0 && !this.includeHosts.has(hostLower)) return true
    if (this.excludeHosts.has(hostLower)) return true
    for (const re of this.excludeUrlRegexps) {
      if (re.test(path) || re.test(requestUrl)) return true
    }
    return false
  }

  /**
   * Inline sensitive-header guard gate. Accepts the
   * already-normalised header entries (Headers / Record / Array → `HeaderEntry[]`)
   * and the outbound request URL, calls `evaluateSensitiveHeaderGuard()`,
   * and on a non-null `SecurityDecision`:
   *
   *   1. Recovers the matched key + value via `findMatchedHeaderKey` (the
   *      `SecurityDecision` shape intentionally does NOT carry those —
   *      `buildInlineGuardDecision` keeps the four inline-guard shapes
   *      identical by design, and the audit row needs both fields for
   *      forensic replay).
   *   2. Emits one `security_audit/inline_sensitive_header_detect` event
   *      (matched key, 80-char value preview, request URL) via
   *      `emitSensitiveHeaderAudit`.
   *   3. Throws `SensitiveHeaderDeniedError` synchronously so the calling
   *      tool layer surfaces the denial as a tool error. The throw happens
   *      for in-frame (agent plane) requests, and for out-of-frame requests
   *      only when `sensitiveHeaderGuard.enforceOutOfFrame` is true (see the
   *      exemption note inside the method).
   *
   * On a non-match the call is a no-op (the guard is pure + synchronous).
   * Errors inside the guard are swallowed and the request proceeds — the
   * safety net must never block all outbound HTTP because of an internal
   * glitch (matches the invariant #3"never throw to the host").
   */
  private guardSensitiveHeadersOrThrow(
    headers: ReadonlyArray<{ name: string; value: string }>,
    requestUrl: string,
  ): void {
    if (!this.sensitiveHeaderGuard.enabled) return

    // Harness-plane exemption: the guard's scope is the
    // AGENT's outbound HTTP layer — fetches issued while a tool executes.
    // Harness-internal planes run OUTSIDE the agent/tool AsyncLocalStorage
    // frame: the llm-pi-ai adapter's own provider calls, plugin telemetry,
    // bootstrap helpers. Without this exemption the guard 100%-blocked every
    // LLM request, because each provider call legitimately carries
    // `Authorization: Bearer <key>` — the denial fired before the socket
    // opened, which the provider layer reports as a generic transport error
    // rather than as a guard denial, so the real cause is invisible to the
    // operator.
    //
    // An earlier exemption skipped EVERY out-of-frame
    // request, which also silently exempted all agent traffic scheduled
    // outside the tool frame (`setImmediate`/`queueMicrotask` fetches,
    // worker threads) — self-contradictory with the guard's documented
    // purpose ("agent outbound
    // layer must not carry user credentials"). The exemption is an explicit
    // operator allow-list (`sensitiveHeaderGuard.harnessPlaneHosts`): out-of-frame
    // requests to any OTHER host are guard-evaluated; on a hit they emit an
    // audit row (`outcome: 'detected'`) and are hard-blocked only when
    // `enforceOutOfFrame` is true. In-frame requests (the agent plane) keep
    // full deny-list coverage and are hard-blocked.
    const httpContext = getHttpRequestSessionContext()
    if (httpContext === undefined && this.isHarnessPlaneUrl(requestUrl)) return

    let decision
    try {
      decision = evaluateSensitiveHeaderGuard(headers, this.sensitiveHeaderGuard)
    } catch {
      return
    }
    if (!decision) return

    const outOfFrame = httpContext === undefined
    if (outOfFrame && !this.sensitiveHeaderGuard.enforceOutOfFrame) {
      // Audit-only path for out-of-frame non-exempt hits: the attempt is on
      // disk even though the request proceeds. Deliberately NOT thrown —
      // the default must never brick the product's own LLM traffic before
      // the operator has populated `harnessPlaneHosts`. Operators who have
      // listed their provider hosts should set `enforceOutOfFrame: true`
      // to upgrade this to a hard block. `outcome: 'success'` follows the
      // existing audit-only detector vocabulary (ApplicationCollector's
      // `reason: 'detect'` rows): the HOST was not affected. The
      // `out_of_frame` / `guard_seam` audit_details fields carry the fact
      // that this was a detection, not a denial.
      this.emitSensitiveHeaderAudit(headers, requestUrl, decision, undefined, 'success')
      return
    }

    // In-frame (agent plane) hard-block, or out-of-frame with
    // `enforceOutOfFrame: true`. Audit row first, then throw.
    this.emitSensitiveHeaderAudit(headers, requestUrl, decision, httpContext, 'blocked')
    const matchedKey = this.findMatchedHeaderKey(headers)
    throw new SensitiveHeaderDeniedError(
      decision.block_reason ?? 'inline sensitive-header guard denied the request',
      matchedKey,
      requestUrl,
    )
  }

  /**
   * True when the URL's host is exempt from out-of-frame guard
   * evaluation. Three layers, first match wins: the operator-maintained
   * `harnessPlaneHosts` (manual, highest priority), the `seedHosts`
   * config layer (marketplace + operator seeds, `*.` wildcard entries
   * supported), and the discovery layer (provider hosts read from the
   * host settings document). Parsing failure returns false — an
   * unparsable URL falls TOWARD the guard (protection) rather than
   * toward exemption.
   */
  private isHarnessPlaneUrl(requestUrl: string): boolean {
    if (
      this.harnessPlaneHosts.size === 0 &&
      this.seedExemptHosts.size === 0 &&
      this.discoveredHosts.size === 0
    ) {
      return false
    }
    try {
      const host = new URL(requestUrl).hostname.toLowerCase()
      if (matchesAnyHostPattern(host, this.harnessPlaneHosts)) return true
      if (matchesAnyHostPattern(host, this.seedExemptHosts)) return true
      return this.discoveredHosts.has(host)
    } catch {
      return false
    }
  }

  /**
   * Recover the matched header name for the deny-list. Mirrors the
   * case-insensitive match in `SensitiveHeaderGuard.findHeaderHit`.
   */
  private findMatchedHeaderKey(headers: ReadonlyArray<{ name: string; value: string }>): string {
    const patterns = this.sensitiveHeaderGuard.keys
    const patternUpper = new Set<string>()
    for (const p of patterns) patternUpper.add(p.toUpperCase())
    for (const entry of headers) {
      if (patternUpper.has(entry.name.toUpperCase())) return entry.name
    }
    return ''
  }

  /**
   * Emit one `security_audit/inline_sensitive_header_detect` row. Shared by
   * the in-frame hard-block path and the out-of-frame audit-only path so the
   * two cannot drift. `sessionContext === undefined` (out-of-frame) falls
   * back to `sessionResolve()` for best-effort attribution.
   */
  private emitSensitiveHeaderAudit(
    headers: ReadonlyArray<{ name: string; value: string }>,
    requestUrl: string,
    decision: NonNullable<ReturnType<typeof evaluateSensitiveHeaderGuard>>,
    sessionContext: HttpRequestSessionContext | undefined,
    outcome: 'blocked' | 'success',
  ): void {
    const matchedKey = this.findMatchedHeaderKey(headers)
    let matchedValue = ''
    for (const entry of headers) {
      if (entry.name.toUpperCase() === matchedKey.toUpperCase()) {
        matchedValue = entry.value
        break
      }
    }
    const valuePreview = matchedValue.length > 80 ? matchedValue.slice(0, 80) + '…' : matchedValue
    const outOfFrame = sessionContext === undefined
    const session = sessionContext ?? this.sessionResolve()
    const now = nowMs()
    const auditEvent: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: 'security_audit',
      layer: 'application',
      source_layer: 'network',
      ts: now,
      timestamp: now,
      pid: process.pid,
      // The sink validator requires host_id/container_id;
      // without buildHostMeta() every block audit would be silently DROPPED
      // ("host_id: missing required field"), making guard hits invisible.
      ...buildHostMeta(),
      collection_method: 'inline-guard',
      audit_category: 'integrity',
      audit_action: 'detect',
      severity: 'high',
      // `summary` keeps the audit human-readable. The matched header VALUE
      // stays out of it (sensitive); value_preview is already in
      // audit_details.
      summary:
        `sensitive header '${matchedKey}' ${outcome === 'blocked' ? 'blocked on outbound request' : 'allowed under audit-only posture'}`,
      outcome,
      blocked: outcome === 'blocked',
      block_reason: decision.block_reason,
      audit_details: {
        event_type_alias: 'inline_sensitive_header_detect',
        policy_id: decision.intervention?.policy_id ?? 'inline-sensitive-header-guard',
        matched_key: matchedKey,
        value_preview: valuePreview,
        request_url: requestUrl,
        guard_seam: outOfFrame ? 'network.http.out-of-frame' : 'network.http.fetch+https.request',
        // Distinguishes "request was denied" from "request proceeded
        // under audit-only posture (out-of-frame, enforceOutOfFrame false)".
        out_of_frame: outOfFrame,
        // Ops hook: an out-of-frame audit-only hit on this host usually
        // means a provider route the discovery layers do not cover yet
        // — operators filter on this field to find pending exemptions.
        ...(outOfFrame && outcome === 'success'
          ? (() => {
              try {
                return { suggested_provider_exemption: new URL(requestUrl).hostname.toLowerCase() }
              } catch {
                return {}
              }
            })()
          : {}),
      },
      session_id: session?.sessionId,
      run_id: session?.runId,
      agent_id: session?.agentId,
      tool_call_id: session?.toolCallId,
      source: 'sst-security-control-dsh.network-http-collector.0.4.0',
      collector: {
        hook_name: 'sensitive_header_guard',
        middleware_name: DEFAULT_PLATFORM_ID,
        collector_name: 'network-http-collector',
      },
    }
    try {
      this.eventCollector.report(auditEvent)
    } catch {
      // Sink failure must not break the denial — the caller-side throw is
      // the operator-visible signal even if the audit row did not land.
    }
  }

  private async emitEvent(args: EmitArgs): Promise<void> {
    const { meta, requestId, startTs, code, responseBody, responseError, responseTruncated, responseOriginalLength, responseContentType, requestBodyText, session } = args

    const originalRequestBody = requestBodyText ?? ''
    const headersForEvent = redactSensitiveBody(meta.headers, this.sensitiveKeyPatterns)
    // D4 — the previous `redactHttpBody` only handled
    // JSON bodies. Form-urlencoded (`token=xxx&user=alice`) and raw
    // bytes (Bearer / AKIA / PEM) were passing through unmasked —
    // the last invariant #6 leak in the HTTP body path. The helper
    // returns the structured `{ body, redactedKeys }` so we can
    // surface `body_redacted_keys` on the audit row.
    const requestBodyRedaction = redactHttpBody(originalRequestBody)
    const requestBodyForEvent = requestBodyRedaction.body
    const limitedRequestBody = limitPayloadSize(requestBodyForEvent, this.config.maxBodyBytes)

    // invariant #6 leak: `meta.path` and
    // `meta.requestUrl` were written verbatim, so a fetch to
    // `https://api.example.com/v1?token=xxx` wrote the token to
    // NDJSON unmasked while the same Bearer header on the same
    // request was masked. Both fields are redacted here, and the
    // aggregated redactedKeys surface on `url_redacted_keys` for
    // operator diff. Mirrors the D1 stdio-mirror / D2 user_prompt
    // pattern: VALUE-level scanning supplements the existing KEY-
    // based pass on `params` / `headers`.
    const pathRedaction = redactUrlQueryString(meta.path)
    const requestUrlRedaction = redactUrlQueryString(meta.requestUrl)
    const urlRedactedKeys = [...new Set([...pathRedaction.redactedKeys, ...requestUrlRedaction.redactedKeys])].sort()
    // D4 — HTTP body redaction keys land on
    // `body_redacted_keys` (see also D3 `url_redacted_keys`). The
    // audit row union on `redacted_keys` includes both, prefixed
    // with `body.` / `query.` / `argv.` so the operator can tell
    // which seam fired without diffing the carrier.
    const bodyRedactedKeys = requestBodyRedaction.redactedKeys

    const rawResponseBody = responseError ? `[error: ${responseError}]` : (responseBody ?? '')

    // fold verbose SSE streams (LLM chat.completion.chunk)
    // so a single network_http event doesn't carry thousands of repetitive
    // `data: {...}` envelopes. The raw byte count is still preserved in
    // content_original_length for audit replay.
    const sseSummary =
      this.config.sseSummaryChunks > 0 && isEventStreamContentType(responseContentType ?? '')
        ? foldSseStream(rawResponseBody, this.config.sseSummaryChunks, this.config.sseSummaryLastChunks)
        : { body: rawResponseBody, chunksTotal: undefined, chunksKept: undefined, folded: false }

    const foldedResponseBody = sseSummary.body
    const limitedResponse = limitPayloadSize(foldedResponseBody, this.config.maxBodyBytes)
    const finalResponseBody = limitedResponse.value as string
    const contentTruncated = responseTruncated || limitedResponse.truncated || sseSummary.folded
    const contentOriginalLength = responseOriginalLength ?? limitedResponse.originalLength

    const now = nowMs()
    const latencyMs = startTs ? now - startTs : undefined
    const baseEvent: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: 'network_http',
      //'layer'is now the 3-tier spec enum; the
      // fine-grain 'network' tag moves to `source_layer` so dashboards
      // that key on the seam (e.g. filtering all network_http
      // captures) can still find them via `source_layer === 'network'`.
      layer: 'application',
      source_layer: 'network',
      ts: now,
      timestamp: now,
      pid: process.pid,
      collection_method: 'hook',
      request_id: requestId,
      session_id: session?.sessionId,
      run_id: session?.runId,
      agent_id: session?.agentId,
      tool_call_id: session?.toolCallId,
      service: meta.protocol === 'https:' ? 'https' : 'http',
      method: meta.method,
      url: pathRedaction.value,
      host: meta.host,
      request_url: requestUrlRedaction.value,
      domain_name: meta.host,
      blocked: false,
      // per-event URL-redaction audit surface. Empty array
      // when nothing matched; platform-compatible with the
      // `redacted_keys` shape used by the tool_params side-channel.
      url_redacted_keys: urlRedactedKeys.length > 0 ? urlRedactedKeys : undefined,
      // See the header comment above. Empty array when the body
      // passed through unchanged (no JSON / form-urlencoded keys hit,
      // no value-pattern matches).
      body_redacted_keys: bodyRedactedKeys.length > 0 ? bodyRedactedKeys : undefined,
      ...buildHostMeta(),
      source: 'sst-security-control-dsh.network-http-collector.0.4.0',
      collector: {
        hook_name: 'http_request',
        middleware_name: DEFAULT_PLATFORM_ID,
        collector_name: 'network-http-collector',
      },
    }

    // The platform event schema requires both `send` and `recv`
    // directions. The `send` event captures the request plus a mirrored copy
    // of the response summary (preserves existing consumer expectations); the
    // `recv` event captures the response. They share `request_id` for correlation.
    //
    // `headers` is the structured object required by the
    // platform per-type validator (`event-schema/network.json` anyOf branch);
    // emit only `headers` here.
    const sendEvent: SecurityEvent = {
      ...baseEvent,
      event_id: generateEventId(),
      direction: 'send',
      code,
      latency_ms: latencyMs,
      headers: headersForEvent,
      body: limitedRequestBody.value,
      response_body: finalResponseBody,
      content_length: Buffer.byteLength(finalResponseBody, 'utf8'),
      content_truncated: contentTruncated || undefined,
      content_original_length: contentTruncated ? contentOriginalLength : undefined,
      response_body_chunks_total: sseSummary.chunksTotal,
      response_body_chunks_kept: sseSummary.chunksKept,
    }

    const recvEvent: SecurityEvent = {
      ...baseEvent,
      event_id: generateEventId(),
      direction: 'recv',
      code,
      latency_ms: latencyMs,
      headers: headersForEvent,
      body: finalResponseBody,
      response_body: finalResponseBody,
      content_length: Buffer.byteLength(finalResponseBody, 'utf8'),
      content_truncated: contentTruncated || undefined,
      content_original_length: contentTruncated ? contentOriginalLength : undefined,
      response_body_chunks_total: sseSummary.chunksTotal,
      response_body_chunks_kept: sseSummary.chunksKept,
    }

    if (this.interventionEngine) {
      try {
        // gate rule evaluation to the active
        // tool-call window. The session
        // context only carries a toolCallId when the request runs inside
        // a Cordis tool handler (AsyncLocalStorage); the most-recent
        // session fallback deliberately has none, so background traffic —
        // including the harness's own LLM API round-trips — is collected
        // but not evaluated. In-window evaluations go through the engine's
        // TTL decision cache (evaluateHttp), which preserves the 50ms
        // cooperative deadline and failStrategy semantics.
        const decision = await this.interventionEngine.evaluateHttp(
          this.buildInterventionContext(meta, originalRequestBody, session),
          { toolActive: typeof session?.toolCallId === 'string' && session.toolCallId.length > 0 },
        )
        if (decision && decision.decision !== 'allow') {
          sendEvent.blocked = decision.decision === 'block'
          sendEvent.block_reason = decision.block_reason
          sendEvent.intervention = decision.intervention
            ? {
                ...withoutFailStrategy(decision.intervention),
                decision: toMarketplaceDecision(decision.decision),
                decision_internal: decision.decision,
              }
            : {
                decision: toMarketplaceDecision(decision.decision),
                decision_internal: decision.decision,
                mode: decision.mode,
                block_reason: decision.block_reason,
                block_code: decision.block_code,
                appealable: decision.appealable,
              }
          if (decision.risk_signal) sendEvent.risk_assessment = decision.risk_signal
        }
      } catch (err) {
        // Policy evaluation must never break the host request. Log is best-effort
        // because we do not have a logger handle here; swallow and continue.
        void err
      }
    }

    // Mirror the request-side decision onto the response-side event so audits
    // can read a single recv event for the final verdict.
    recvEvent.blocked = sendEvent.blocked
    recvEvent.block_reason = sendEvent.block_reason
    recvEvent.intervention = sendEvent.intervention
    recvEvent.risk_assessment = sendEvent.risk_assessment

    this.eventCollector.report(sendEvent)
    this.eventCollector.report(recvEvent)
  }

  private buildInterventionContext(
    meta: RequestMeta,
    body: string,
    session?: HttpRequestSessionContext,
  ): InterventionContext {
    // SPL rules see the REDACTED form of the URL
    // — same invariant #6 boundary as `params` / `headers`. A rule
    // matching `url contains "token="` would otherwise never fire on
    // a token-bearing URL (the secret leaks via `params.url` /
    // `params.path` to the rule evaluator). Redacting pre-SPL keeps
    // the rule surface and the persisted surface consistent.
    //
    // D4 : same boundary on `body` — form-urlencoded
    // `token=xxx` and raw `Bearer yyy` payloads reach the rule
    // evaluator pre-masked so a `bodyRegex` rule with a credential
    // pattern cannot fire on the secret (it would still record the
    // attempt, but the secret value never crosses the SPL seam).
    const pathRedaction = redactUrlQueryString(meta.path)
    const requestUrlRedaction = redactUrlQueryString(meta.requestUrl)
    const bodyRedaction = redactHttpBody(body)
    return {
      actionType: 'http_request',
      params: {
        service: meta.protocol === 'https:' ? 'https' : 'http',
        method: meta.method,
        host: meta.host,
        url: requestUrlRedaction.value,
        path: pathRedaction.value,
      },
      body: bodyRedaction.body,
      headers: redactSensitiveBody(meta.headers, this.sensitiveKeyPatterns),
      sessionId: session?.sessionId,
      runId: session?.runId,
      agentId: session?.agentId,
    }
  }

  // Body redaction now lives in `redactHttpBody` ( D4) —
  // JSON / form-urlencoded / raw text are handled in
  // `src/utils/events/contentRedactor.ts`. The collector just calls the
  // helper for both the persisted event body and the SPL-visible
  // InterventionContext body.
}

function flattenHeaders(headers: unknown): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {}
  if (!headers) return result
  if (headers instanceof Headers) {
    headers.forEach((value, key) => {
      result[key] = value
    })
    return result
  }
  if (Array.isArray(headers)) {
    for (let i = 0; i < headers.length; i += 2) {
      const key = headers[i]
      const value = headers[i + 1]
      if (typeof key === 'string') result[key] = value as string
    }
    return result
  }
  for (const [key, value] of Object.entries(headers as Record<string, unknown>)) {
    if (value === undefined) continue
    if (typeof value === 'string' || Array.isArray(value)) {
      result[key] = value
    } else {
      result[key] = String(value)
    }
  }
  return result
}

function withoutFailStrategy(intervention: NonNullable<SecurityEvent['intervention']>): NonNullable<SecurityEvent['intervention']> {
  const { fail_strategy: _fs, ...rest } = intervention as Record<string, unknown>
  void _fs
  return rest as NonNullable<SecurityEvent['intervention']>
}

function getHeaderValue(headers: Record<string, string | string[]>, key: string): string | undefined {
  const lowerKey = key.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lowerKey) {
      return Array.isArray(v) ? v.join(', ') : v
    }
  }
  return undefined
}

function isEventStreamContentType(contentType: string): boolean {
  return /\btext\/event-stream\b/i.test(contentType)
}

interface SseSummary {
  body: string
  chunksTotal?: number
  chunksKept?: number
  folded: boolean
}

function foldSseStream(body: string, keepHead: number, keepTail: number): SseSummary {
  // SSE messages are separated by blank lines. We preserve the raw text of
  // each chunk so that any `event:`, `id:`, or `retry:` lines are not lost.
  const chunks = body.split(/(?:\r?\n){2,}/).filter((c) => c.trim().length > 0)
  const total = chunks.length
  if (total <= keepHead + keepTail || keepHead < 0 || keepTail < 0) {
    return { body, chunksTotal: total, chunksKept: total, folded: false }
  }
  const head = chunks.slice(0, keepHead)
  const tail = chunks.slice(-keepTail)
  const omitted = total - keepHead - keepTail
  const summary = `data: {"type":"__dsh_sse_summary","omitted_chunks":${omitted},"total_chunks":${total}}`
  const kept = [...head, summary, ...tail]
  return { body: kept.join('\n\n') + '\n\n', chunksTotal: total, chunksKept: kept.length, folded: true }
}
