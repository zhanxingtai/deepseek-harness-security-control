/**
 * Inline Sensitive-Header Guard.
 *
 * Hardcoded, non-overridable safety net: blocks outbound HTTP requests that
 * attempt to propagate a known-dangerous authentication / authorization
 * header. Coverage:
 *
 *   - `Authorization`         — Bearer / Basic / OAuth / API tokens. The
 *                               standard for credential-bearing requests;
 *                               any agent-side usage is suspect (the
 *                               agent's outbound HTTP layer should not be
 *                               carrying the user's bearer tokens).
 *   - `Cookie`                — session cookies. Cookies are stateful and
 *                               domain-scoped; smuggling them out of the
 *                               intended context is a session-hijack vector.
 *   - `Proxy-Authorization`   — proxy credentials. Same rationale as
 *                           Authorization.
 *   - `X-API-Key`             — common (non-standard) API-key header.
 *                               Many SaaS APIs use this; flagging it
 *                               forces operators to add an explicit
 *                               allow-list override rather than relying
 *                               on incidental leakage.
 *
 * Mirrors the InlineSelfProtection / SensitivePathGuard /
 * InlinePromptInjection / EnvPassthroughGuard pattern: deny-list is
 * hardcoded and non-overridable — `keys: []` in `normalizeConfig` is
 * silently re-asserted to the marketplace fallback list. `evaluateSensitiveHeaderGuard()`
 * is invoked synchronously from `NetworkHttpCollector.patchFetch` /
 * `patchHttps` BEFORE the original fetch / https.request fires, BEFORE
 * any SPL rule. Returns a `block` SecurityDecision on first hit; the
 * caller throws `SensitiveHeaderDeniedError` so the agent's tool layer
 * catches and reports the denial.
 *
 * Field scope:
 *   - `init.headers` (HeadersInit) — the structured headers payload the
 *     fetch / XHR / https.request API accepts. Normalised via
 *     `flattenHeaders` so a `Headers` instance, a `Record<string,string>`,
 *     and a `[string,string][]` array all reduce to the same scan.
 *   - Case-insensitive key match (HTTP headers are case-insensitive per
 *     RFC 7230 §3.2; we follow sibling inline guards' stance so a
 *     `authorization` lowercase spelling still trips the rail).
 *
 * What this guard deliberately does NOT do:
 *   - URL query-string / body credential scan. Those are covered by
 *     `redactUrlQueryString` and `redactHttpBody` — layering
 *     another substring pass here would duplicate work and inflate
 *     false-positive risk.
 *   - Response-header inspection. We only gate OUTBOUND headers; an
 *     outbound response carries the SERVER's set-cookie, which we want
 *     to record for forensic review (NetworkHttpCollector already
 *     emits `response_headers_redacted_keys` on the audit row).
 *   - Value-content inspection. The presence of the header alone is
 *     the deny signal — we don't peek at the bearer prefix / token
 *     shape. A legitimate outbound fetch should not be carrying any
 *     Authorization / Cookie / X-API-Key at all.
 */
import { buildInlineGuardDecision } from '../utils/inlineGuardDecision.js'

/**
 * Hardcoded deny-list — non-overridable. The keys are matched
 * case-insensitively against the request headers.
 *
 * Order is preserved for the audit `matched_key` field — the wire
 * payload reports the FIRST key that hits, in catalogue order.
 */
export const DEFAULT_DANGEROUS_HEADER_KEYS: readonly string[] = [
  // Standard credential-bearing headers (RFC 7235 / 6265)
  'Authorization',
  'Cookie',
  'Proxy-Authorization',
  // Non-standard but ubiquitous API-key header
  'X-API-Key',
]

/** Block code for the inline sensitive-header guard. Distinct from the
 *  SPL `SELF_PROTECTION_*` codes and the existing inline
 *  `INLINE_SELF_PROTECTION_*` / `INLINE_SENSITIVE_PATH_001` /
 *  `INLINE_PROMPT_INJECTION_001` / `INLINE_ENV_PASSTHROUGH_001` codes
 *  so audit consumers can filter on the deny reason without colliding
 *  with sibling rules. */
export const INLINE_SENSITIVE_HEADER_CODE = 'INLINE_SENSITIVE_HEADER_001' as const

export interface SensitiveHeaderGuardConfig {
  /** Master switch — defaults to true. The marketplace rejects
   *  `enabled: false` in `normalizeConfig` (mirrors sibling guards). */
  enabled: boolean
  /** Operator-added header keys. Empty array → fallback to
   *  `DEFAULT_DANGEROUS_HEADER_KEYS` (the safety net cannot be downgraded
   *  to an empty list — same pattern as
   *  `SensitivePathGuardConfig.paths` /
   *  `EnvPassthroughGuardConfig.keys` /
   *  `InlinePromptInjectionConfig.patterns`). */
  keys: string[]
  /**
   * Hosts whose OUT-OF-FRAME requests (no ALS tool frame)
   *  are exempt from the guard. The harness plane — llm-pi-ai provider
   *  calls, plugin telemetry — legitimately carries `Authorization: Bearer
   *  <key>`; list those endpoints here. Out-of-frame requests to any other
   *  host are guard-evaluated (audit-only, or hard-blocked when
   *  `enforceOutOfFrame` is true). See
   *  `NetworkHttpCollector.guardSensitiveHeadersOrThrow`. Structural
   *  duplicate of the field on `Config`'s block in src/config/types.ts —
   *  this module must stay importable without the config package.
   */
  harnessPlaneHosts?: string[]
  /**
   * Upgrade out-of-frame non-exempt hits from audit-only
   *  to hard-block. Defaults to false (audit-only) so the guard can never
   *  brick the product's own LLM traffic before `harnessPlaneHosts` is
   *  populated.
   */
  enforceOutOfFrame?: boolean
  /**
   * Auto-discover LLM provider hosts from the host settings document
   *  and exempt them (same semantics as `harnessPlaneHosts`). Defaults
   *  to true. Structural duplicate of the field on `Config`'s block in
   *  src/config/types.ts — this module must stay importable without the
   *  config package.
   */
  providerDiscovery?: boolean
  /** Explicit settings document path for discovery; empty → harness
   *  home resolution. Structural duplicate (see above). */
  providerDiscoveryPath?: string
  /** Seed exemption hosts (catalog-route endpoints + operator seeds),
   *  `*.` wildcard entries supported. Structural duplicate (see above). */
  seedHosts?: string[]
}

/** Normalised header entry. Mirrors the `RequestMeta.headers` shape used
 *  by `NetworkHttpCollector.extractRequestMeta` so the guard sits in
 *  the same scan site as the existing `redactSensitiveBody` pass. */
export interface HeaderEntry {
  /** Header name as it appeared in the carrier (preserves case for
   *  the audit trail). */
  readonly name: string
  /** Header value. Truncated in the audit message but kept full in
   *  the decision `audit_details` field. */
  readonly value: string
}

interface HeaderHit {
  /** The exact header name as it appeared in the carrier (preserves case
   *  for the audit trail). */
  readonly name: string
  /** The associated value. Truncated in the audit message. */
  readonly value: string
}

function findHeaderHit(
  headers: ReadonlyArray<HeaderEntry>,
  patterns: readonly string[],
): HeaderHit | null {
  const patternUpper = new Set<string>()
  for (const p of patterns) patternUpper.add(p.toUpperCase())
  for (const entry of headers) {
    if (patternUpper.has(entry.name.toUpperCase())) {
      return { name: entry.name, value: entry.value }
    }
  }
  return null
}

function truncateValue(v: string, max = 80): string {
  if (v.length <= max) return v
  return v.slice(0, max) + '…'
}

/**
 * Normalise a `HeadersInit`-shaped carrier (Headers / Record / Array) into
 * the `HeaderEntry[]` shape this guard scans. Mirrors `flattenHeaders` in
 * `NetworkHttpCollector.ts` so the carrier variants converge to a single
 * iterable.
 */
export function flattenHeadersForGuard(
  headers: unknown,
): HeaderEntry[] {
  if (!headers || typeof headers !== 'object') return []
  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    const out: HeaderEntry[] = []
    headers.forEach((v, k) => out.push({ name: k, value: v }))
    return out
  }
  if (Array.isArray(headers)) {
    const out: HeaderEntry[] = []
    for (const tuple of headers) {
      if (Array.isArray(tuple) && tuple.length >= 2) {
        const [k, v] = tuple as unknown as [string, string]
        out.push({ name: k, value: v })
      }
    }
    return out
  }
  const rec = headers as Record<string, unknown>
  const out: HeaderEntry[] = []
  for (const [k, v] of Object.entries(rec)) {
    if (Array.isArray(v)) {
      for (const item of v) {
        if (typeof item === 'string') out.push({ name: k, value: item })
      }
    } else if (typeof v === 'string') {
      out.push({ name: k, value: v })
    }
  }
  return out
}

function buildSensitiveHeaderBlock(hit: HeaderHit): import('../types/index.js').SecurityDecision {
  const reason =
    '敏感请求头透传命中：请求头 `' + hit.name + '` 的值 `' + truncateValue(hit.value) +
    '` 试图被 agent 端 fetch / https.request 转发到外网。该键属于内嵌敏感请求头黑名单（不可被策略文件改写关闭）'
  return buildInlineGuardDecision(
    {
      policyId: 'inline-sensitive-header-guard',
      policyName: 'Inline Sensitive-Header Guard (hardcoded, non-overridable)',
      blockCode: INLINE_SENSITIVE_HEADER_CODE,
    },
    reason,
  )
}

/** Specialised error thrown when the inline sensitive-header guard trips.
 *  Caught by the agent's tool layer (`tools/pre-execute` wrapper) and
 *  surfaced as a tool error; the audit row is the `security_audit` event
 *  the caller emits before throwing. Mirrors `SpawnDeniedError` from
 *  `RuntimeHook`. */
export class SensitiveHeaderDeniedError extends Error {
  readonly block_code = INLINE_SENSITIVE_HEADER_CODE
  constructor(
    message: string,
    readonly matchedKey: string,
    readonly requestUrl: string,
  ) {
    super(message)
    this.name = 'SensitiveHeaderDeniedError'
  }
}

/**
 * Evaluate the inline sensitive-header guard against the supplied
 * carrier-normalised headers. Returns a `block` SecurityDecision on
 * first match, or `null` when no deny-list pattern matched.
 *
 * The function is synchronous and never throws — a malformed
 * `headers` (non-object / undefined / null) is treated as "no match".
 *
 * **Caller integration contract**: on a non-null return the caller
 * MUST emit a `security_audit/inline_sensitive_header_detect` event
 * (carrying the matched_key / url / value_preview) and MUST throw
 * `SensitiveHeaderDeniedError` to abort the outbound fetch. The audit
 * row is the operator-visible record; the throw surfaces the denial
 * back to the agent's tool layer.
 */
export function evaluateSensitiveHeaderGuard(
  headers: ReadonlyArray<HeaderEntry>,
  cfg: SensitiveHeaderGuardConfig,
): import('../types/index.js').SecurityDecision | null {
  if (!cfg.enabled) return null
  try {
    const patterns = cfg.keys.length > 0 ? cfg.keys : DEFAULT_DANGEROUS_HEADER_KEYS
    if (patterns.length === 0) return null

    const hit = findHeaderHit(headers, patterns)
    if (!hit) return null
    return buildSensitiveHeaderBlock(hit)
  } catch {
    // Defensive — inline module failure must never block all outbound HTTP.
    return null
  }
}