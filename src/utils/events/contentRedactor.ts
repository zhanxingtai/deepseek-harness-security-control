/**
 * Stream content + argv-entry redactors for the stdio pipe mirror
 *
 *
 * ## Scope: unstructured text only
 *
 * This module handles **bytes / text** that arrive at the plugin from
 * untrusted sources — a child process's stderr, an argv string from
 * `cmdline`, a URL query string, a raw HTTP body — and applies
 * **value-pattern matching** to redact credential-shaped substrings.
 *
 * The KEY-based masking in `./redact.ts` is **not** sufficient for this
 * surface: the stdio mirror writes to NDJSON outside the
 * `LocalNdjsonSink` validation path (the wrapper is a separate Node.js
 * process; brought the path back to the host's NDJSON file, but
 * the wrapper still cannot share the sink's in-memory validator).
 * Neither `redactSensitiveBody` (object keys) nor `redactRawParams`
 * (tool_params) ever runs on the per-chunk `content` or the joined
 * `cmdline`. A child process printing `Authorization: Bearer xxx` to
 * stderr would land on disk verbatim without this layer.
 *
 * Three sub-redactors close the gap:
 *
 * 1. **JSON-parse + KEY-based** (`redactStreamContent`) — when the
 *    content happens to be a JSON document (e.g. a child's debug log
 *    line `{"token":"...","user":"..."}`), parse it and walk the tree
 *    with the same masking rules the host plugin uses for `params` /
 *    `tool_params`. Flat-keyed `redacted_keys` (`headers.Authorization`)
 *    land on the audit row in the same shape as the platform spec.
 *
 * 2. **Value-pattern scanner** (also `redactStreamContent`) — for raw
 *    text (HTTP headers, shell output, etc.) the KEY-based pass is
 *    blind. A tightly-scoped value-pattern scanner handles the
 *    documented credential formats: Bearer tokens, Basic auth, AWS
 *    access / session keys, GitHub PAT / OAuth / server / refresh
 *    tokens, Slack tokens, PEM private-key blocks, URL query-string
 *    secrets. Each match produces a `redactedKeys` entry keyed by the
 *    credential family (`bearer_token`, `aws_access_key`,
 *    `query.token`, …) so the audit row tells the operator exactly
 *    which class was redacted without leaking the value. Scope is
 *    conservative on purpose: false positives are accepted because
 *    invariant #6 mandates "unconditional" — better to mask a benign
 *    credential-shaped substring than to ship a known leak.
 *
 * 3. **Argv-entry redactor** (`redactArgvEntries`) — `cmdline` is
 *    `argv.join(' ')` on every event. Each entry is walked for
 *    `--key=value` / `Key: Value` (env-var / HTTP-header) shapes and
 *    KEY-redacted; raw entries without a key/value shape fall through
 *    to the value-pattern scanner.
 *
 * ## Boundary with `./redact.ts`
 *
 * `redact.ts` handles **structured data** — parsed JavaScript values,
 * JSON strings, typed payloads — via KEY-based masking. This module
 * handles **unstructured text** — bytes / strings / argv — via
 * VALUE-based masking. The two are deliberately separate: this module
 * does **not** import the recursive walker from `redact.ts` because
 * that walker requires a parsed value and the stdio mirror stream is
 * untrusted bytes (parsing could throw / be DoS'd). They share the
 * `DEFAULT_SENSITIVE_KEYS` catalogue via re-export.
 *
 * ## Exports at a glance
 *
 * - `redactStreamContent(text)` — combined JSON-parse + value-pattern
 *   pass on a single text chunk. Returns `{ value, redactedKeys }`.
 * - `redactUrlQueryString(urlOrPath)` — query-string-only redaction.
 *   Used by `NetworkHttpCollector` for URL fields.
 * - `redactHttpBody(body)` — HTTP body redaction (handles
 *   `application/json`, `application/x-www-form-urlencoded`,
 *   `text/plain`). Used by the body capture path.
 * - `redactArgvEntries(argv)` — argv walker; returns `{ argv,
 *   redactedKeys }` so the host can stamp `redactedKeys` onto the
 *   audit row.
 *
 * ## Safety contract
 *
 * - Never throws on malformed input (input is untrusted child output).
 * - Always returns `{ value, redactedKeys }` — empty `redactedKeys`
 *   for inputs with no matches.
 * - `redactedKeys` is sorted alphabetically + deduplicated so audit
 *   consumers can diff across events deterministically.
 *
 * Note on scope: the wrapper self-runs as a separate Node.js process;
 * `src/runtime/stdio-mirror.ts` imports this module via the standard
 * build pipeline (the bundler pulls `src/` into `lib/`), so no extra
 * wiring is needed for marketplace deployment.
 */

import { redactSensitiveBody } from './redact.js'

// Re-export the patterns so callers that want to extend the catalogue
// (e.g. a per-operator override list) can compose against the same set.
export { DEFAULT_SENSITIVE_KEYS } from './redact.js'

export interface StreamRedaction {
  /** Redacted string. Identical to input when no matches. */
  value: string
  /** Sorted, deduplicated list of redaction classes that fired. */
  redactedKeys: string[]
}

// ---------------------------------------------------------------------------
// Catalogue — value-pattern regexes for the documented credential formats.
// Each entry maps to a `redactedKeys` slug so audit rows name the family
// without exposing the value. Keep this list aligned with the inline
// `InlinePromptInjection` secret redaction (it also redacts these).
// ---------------------------------------------------------------------------

interface ValuePattern {
  /** Slug surfaced in `redactedKeys`. */
  name: string
  /** Global regex; the replacement preserves the leading literal prefix
   *  (e.g. "Bearer ", "Basic ") where present so the masked text is still
   *  recognisable to a human auditor. */
  re: RegExp
}

const BEARER_RE = /\bBearer\s+[A-Za-z0-9._\-+/=]{8,}/g
const BASIC_RE = /\bBasic\s+[A-Za-z0-9+/=]{4,}/g
// AWS access key (long-lived) + session key (short-lived STS).
const AWS_ACCESS_RE = /\bAKIA[0-9A-Z]{16}\b/g
const AWS_SESSION_RE = /\bASIA[0-9A-Z]{16}\b/g
// GitHub PAT (fine-grained `ghp_` + classic `gho_`/`ghu_`/`ghs_`/`ghr_`).
const GH_PAT_RE = /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g
// Slack tokens (`xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-`).
const SLACK_RE = /\bxox[bpars]-[A-Za-z0-9-]{10,}\b/g
// PEM-encoded private key blocks (RSA / EC / OPENSSH / DSA / PGP).
// Multi-line; the body is replaced wholesale — the audit row carries
// `pem_private_key` in redactedKeys and the line count in originalLength
// but no key material.
const PEM_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/g

const VALUE_PATTERNS: readonly ValuePattern[] = [
  { name: 'bearer_token', re: BEARER_RE },
  { name: 'basic_auth', re: BASIC_RE },
  { name: 'aws_access_key', re: AWS_ACCESS_RE },
  { name: 'aws_session_key', re: AWS_SESSION_RE },
  { name: 'github_pat', re: GH_PAT_RE },
  { name: 'slack_token', re: SLACK_RE },
  { name: 'pem_private_key', re: PEM_RE },
]

// URL query-string secret keys. Conservative on purpose: only the keys
// the project actually treats as sensitive (mirrors DEFAULT_SENSITIVE_KEYS
// + access_token / sid / signature / auth). The scanner is a regex pass
// over the whole text rather than URL-parse-and-rebuild, because the
// mirror content is rarely a well-formed URL on its own — it's usually
// mixed into a log line like `curl ... https://api.example.com/?token=xxx`
// where URL-parse would fail.
const QUERY_SECRET_KEYS = new Set([
  'token', 'api_key', 'apikey', 'secret', 'password', 'credential',
  'authorization', 'access_token', 'sid', 'signature', 'auth', 'key',
])
const QUERY_SECRET_RE =
  /([?&])(token|api_?key|apikey|secret|password|credential|authorization|access_?token|sid|signature|auth|key)=([^&\s#]+)/gi

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// ---------------------------------------------------------------------------
// JSON-structure KEY-based pass. Used when the stream content happens to be
// a JSON document (e.g. structured log lines). Mirrors `redactAndCollectKeys`
// but works on any value (including arrays) and emits the same dot-path
// `redacted_keys` shape the platform spec uses for `tool_params`.
// ---------------------------------------------------------------------------

function isSensitiveKeyLocal(key: string): boolean {
  // Mirror the segmentation rules from `events/redact.ts isSensitiveKey`
  // — exact match OR per-segment match (split on . _ - + camelCase).
  // Duplicated locally to avoid a circular import; the helper in redact.ts
  // is not exported (kept internal for the existing callers), so we
  // re-implement the same predicate. If the upstream helper ever moves,
  // update both copies — the test suite (`redact.test.ts`) keeps the
  // canonical contract stable.
  const lower = key.toLowerCase()
  const segments: string[] = []
  for (const rawSeg of lower.split(/[._\-]+/)) {
    if (!rawSeg) continue
    segments.push(rawSeg)
    // camelCase split on the ORIGINAL mixed-case key
    const origSeg = key.split(/[._\-]+/).find((s) => s.toLowerCase() === rawSeg) ?? rawSeg
    const camelParts: string[] = []
    let buf = ''
    for (let i = 0; i < origSeg.length; i++) {
      const ch = origSeg[i]!
      if (i > 0 && /[A-Z]/.test(ch) && /[a-z]/.test(origSeg[i - 1]!)) {
        if (buf) camelParts.push(buf.toLowerCase())
        buf = ch
      } else {
        buf += ch
      }
    }
    if (buf) camelParts.push(buf.toLowerCase())
    if (camelParts.length > 1) {
      for (const p of camelParts) segments.push(p)
    }
  }
  // Match any segment against the default set.
  const DEFAULTS = new Set([
    'token', 'key', 'secret', 'password', 'credential', 'authorization',
    'api_key', 'apikey',
  ])
  return segments.some((s) => DEFAULTS.has(s))
}

function redactJsonValue(value: unknown, prefix: string): { result: unknown; redactedKeys: string[] } {
  const keys: string[] = []
  if (Array.isArray(value)) {
    // Include the array index in the path so audit rows can pinpoint
    // which array slot fired (e.g. `headers.0.Authorization`). The top-
    // level array has no parent prefix, so the index becomes the whole
    // path (`0.value`).
    const result = value.map((v, i) => {
      const childPrefix = prefix ? `${prefix}.${i}` : String(i)
      const r = redactJsonValue(v, childPrefix)
      keys.push(...r.redactedKeys)
      return r.result
    })
    return { result, redactedKeys: keys }
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const fullKey = prefix ? `${prefix}.${k}` : k
      if (isSensitiveKeyLocal(k)) {
        out[k] = '***'
        keys.push(fullKey)
      } else {
        const r = redactJsonValue(v, fullKey)
        out[k] = r.result
        keys.push(...r.redactedKeys)
      }
    }
    return { result: out, redactedKeys: keys }
  }
  if (typeof value === 'string') {
    const r = redactStreamContent(value)
    // Tag the nested redaction with the parent path so audit rows show
    // `root.body.bearer_token` rather than the bare `bearer_token`.
    for (const k of r.redactedKeys) keys.push(prefix ? `${prefix}.${k}` : k)
    return { result: r.value, redactedKeys: keys }
  }
  return { result: value, redactedKeys: keys }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Redact `text` using both JSON-parse + KEY-based pass and the
 * value-pattern scanner. Order is JSON-first because JSON content
 * pre-empts raw-text scanning — JSON's key/value boundary is more
 * reliable than value-pattern heuristics (a string value containing
 * `Bearer xxx` inside a JSON object gets the value-pattern hit with
 * a path-prefixed redactedKeys entry).
 *
 * @param text  Stream chunk or any untrusted string.
 */
export function redactStreamContent(text: string): StreamRedaction {
  if (typeof text !== 'string' || text.length === 0) {
    return { value: text ?? '', redactedKeys: [] }
  }
  const keys = new Set<string>()
  let value = text

  // 1. JSON-parse attempt → walk with KEY-based + value-pattern per leaf.
  try {
    const parsed = JSON.parse(value)
    if (parsed && typeof parsed === 'object') {
      const r = redactJsonValue(parsed, '')
      for (const k of r.redactedKeys) keys.add(k)
      value = JSON.stringify(r.result)
    }
  } catch {
    // Not JSON — fall through to value-pattern only.
  }

  // 2. Value-pattern pass over the (possibly JSON-rewritten) text.
  for (const { name, re } of VALUE_PATTERNS) {
    re.lastIndex = 0
    if (re.test(value)) {
      keys.add(name)
      re.lastIndex = 0
      value = value.replace(re, (m) => {
        const prefixMatch = /^(Bearer|Basic)\s+/i.exec(m)
        return prefixMatch ? `${prefixMatch[0]}***` : '***'
      })
    }
  }

  // 3. URL query-string secret pass.
  QUERY_SECRET_RE.lastIndex = 0
  const queryHits = new Set<string>()
  value = value.replace(QUERY_SECRET_RE, (_m, prefix, key) => {
    queryHits.add(`query.${key.toLowerCase()}`)
    return `${prefix}${key}=***`
  })
  for (const k of queryHits) keys.add(k)

  return { value, redactedKeys: [...keys].sort() }
}

/**
 * Redact query-string secrets in a URL or URL-path string.
 *
 * Used by `NetworkHttpCollector` to mask `?token=xxx` / `?api_key=xxx`
 * before the URL lands on `network_http.url` / `network_http.request_url`
 * (invariant #6 leak: NetworkHttpCollector was
 * emitting `url.href` and `url.path+search` verbatim, so a fetch to
 * `https://api.example.com/v1?token=xxx` wrote the token to NDJSON
 * unmasked while the same Bearer header on the same request was masked).
 *
 * Two-pass design:
 *  1. URL parse (when the input is parseable): walk `searchParams`,
 *     redact sensitive keys, rebuild via `url.toString()`. This is the
 *     canonical path and preserves URL encoding semantics.
 *  2. Regex fallback: when `new URL()` throws (the input is a bare
 *     path, a relative URL, or has invalid percent-encoding), fall
 *     through to `QUERY_SECRET_RE` which handles the literal
 *     `?key=value` shape.
 *
 * Returns `{ url, redactedKeys }` where `redactedKeys` carries
 * `query.<key>` entries — the same shape `redactStreamContent` uses
 * for inline URL hits — so audit rows can merge the two sources
 * without ambiguity.
 */
export function redactUrlQueryString(urlOrPath: string): StreamRedaction {
  if (typeof urlOrPath !== 'string' || urlOrPath.length === 0) {
    return { value: urlOrPath ?? '', redactedKeys: [] }
  }
  const keys = new Set<string>()

  // 1. URL-parse pass — identify sensitive keys via searchParams, then
  //    do an in-place regex replacement on the RAW query string so
  //    URL-encoded values (`%20`, `+`, `%2F`) round-trip without
  //    URLSearchParams re-encoding (`URLSearchParams.toString()` would
  //    normalise `%20` → `+` and lose the original shape).
  let parsed: URL | undefined
  try {
    parsed = new URL(urlOrPath, 'http://__dsh_redact_placeholder__/')
  } catch {
    parsed = undefined
  }

  if (parsed && parsed.search.length > 0) {
    const sensitiveKeys: string[] = []
    for (const k of Array.from(parsed.searchParams.keys())) {
      if (QUERY_SECRET_KEYS.has(k.toLowerCase())) sensitiveKeys.push(k)
    }
    if (sensitiveKeys.length === 0) {
      return { value: urlOrPath, redactedKeys: [] }
    }
    const keyAlt = sensitiveKeys.map(escapeRegex).join('|')
    const KEY_VALUE_RE = new RegExp(`([?&])(${keyAlt})=([^&]*)`, 'gi')
    const newSearch = parsed.search.replace(KEY_VALUE_RE, (_m, prefix, key) => {
      keys.add(`query.${key.toLowerCase()}`)
      return `${prefix}${key}=***`
    })
    // Strip placeholder origin if input was relative.
    const placeholder = 'http://__dsh_redact_placeholder__'
    const beforeOrigin = parsed.origin === placeholder ? '' : parsed.origin
    const out = `${beforeOrigin}${parsed.pathname}${newSearch}${parsed.hash}`
    return { value: out, redactedKeys: [...keys].sort() }
  }

  // 2. Regex fallback (invalid URL or bare `?key=value` strings —
  //    covers the stdio-mirror's "log line contains a URL fragment"
  //    case where URL.parse fails on surrounding text).
  let value = urlOrPath
  QUERY_SECRET_RE.lastIndex = 0
  const queryHits = new Set<string>()
  value = value.replace(QUERY_SECRET_RE, (_m, prefix, key) => {
    queryHits.add(`query.${key.toLowerCase()}`)
    return `${prefix}${key}=***`
  })
  for (const k of queryHits) keys.add(k)
  return { value, redactedKeys: [...keys].sort() }
}

/**
 * Redact an HTTP request body across the three documented formats:
 *
 *   1. **JSON** — `{ ... }` / `[ ... ]`. Walk with KEY-based
 *      `redactJsonValue` (covers nested objects + arrays).
 *   2. **Form-urlencoded** — `key=value&key2=value2`. Parse via
 *      `URLSearchParams`, redact sensitive keys via the broader
 *      `QUERY_SECRET_KEYS` set, rebuild. Detection is a heuristic:
 *      every segment must be `non-empty-key=non-empty-value` (no
 *      JSON braces, no XML tags, no raw whitespace). A bare
 *      `application/x-www-form-urlencoded` with no sensitive keys
 *      passes through unchanged (nothing to mask).
 *   3. **Raw text** — anything else. Run `redactStreamContent`
 *      (which itself tries JSON-parse again as a last-ditch pass,
 *      then value-pattern + URL query) so Bearer / AKIA / GitHub
 *      PAT / PEM / URL query-string leaks in raw bodies are masked.
 *
 * D4 : previously the JSON path was the only branch
 * (`startsWith('{')` / `[`), so `application/x-www-form-urlencoded`
 * POSTs (`token=xxx&user=alice`) and raw bytes landed on disk
 * unmasked — the same invariant #6 leak class as D1/D2/D3. The
 * old code's comment "Non-JSON bodies do not carry recognisable
 * keys and pass through unchanged" is now obsolete: form-urlencoded
 * keys are recognisable, and raw bytes carry value patterns.
 *
 * Each redacted key is prefixed with `body.` so the audit row's
 * union `redacted_keys` list tells the operator whether the hit
 * came from the body vs. the URL vs. the headers (matching the
 * `query.` / `argv.` convention established by D1 / D3).
 *
 * Returns `{ body, redactedKeys }` — `body` is the masked string,
 * `redactedKeys` is the sorted, deduplicated dot-path list.
 */
export interface HttpBodyRedaction {
  body: string
  redactedKeys: string[]
}

// Conservative form-urlencoded detector: every segment is a
// `non-empty-key=non-empty-value` with no JSON / XML / shell
// punctuation. False positives on odd inputs (e.g. an English
// sentence containing `?` or `=`) are acceptable — the URLSearchParams
// parse will simply produce zero entries and we'd fall through to
// the raw-text pass, which still catches value-pattern leaks.
const FORM_URLENCODED_RE = /^[A-Za-z0-9._\-+%]+=[^&]*(&[A-Za-z0-9._\-+%]+=[^&]*)*$/

export function redactHttpBody(body: string): HttpBodyRedaction {
  if (typeof body !== 'string' || body.length === 0) {
    return { body: body ?? '', redactedKeys: [] }
  }
  const keys = new Set<string>()
  const trimmed = body.trim()

  // 1. JSON path — strict shape check (starts with `{` / `[`).
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(body) as Record<string, unknown> | unknown[]
      const r = redactJsonValue(parsed, '')
      for (const k of r.redactedKeys) keys.add(`body.${k}`)
      return { body: JSON.stringify(r.result), redactedKeys: [...keys].sort() }
    } catch {
      // Not valid JSON — fall through to form / raw.
    }
  }

  // 2. Form-urlencoded path — heuristic shape check, then URLSearchParams.
  if (FORM_URLENCODED_RE.test(trimmed)) {
    const params = new URLSearchParams(trimmed)
    let touched = false
    for (const k of Array.from(params.keys())) {
      if (QUERY_SECRET_KEYS.has(k.toLowerCase())) {
        params.set(k, '***')
        keys.add(`body.${k.toLowerCase()}`)
        touched = true
      }
    }
    if (touched) {
      return { body: params.toString(), redactedKeys: [...keys].sort() }
    }
    // Heuristic matched but no sensitive keys — pass through verbatim
    // (avoids unnecessary URL-encoding re-rounds on benign bodies).
    return { body, redactedKeys: [] }
  }

  // 3. Raw text — value-pattern + URL query-string secret pass.
  //    `redactStreamContent` already retries JSON-parse internally as a
  //    last-ditch safety net for malformed JSON; we get Bearer / AKIA
  //    / GitHub PAT / PEM / URL-query masking for free here.
  const r = redactStreamContent(body)
  for (const k of r.redactedKeys) keys.add(`body.${k}`)
  return { body: r.value, redactedKeys: [...keys].sort() }
}

/**
 * Walk `argv` and redact each entry. Three shapes handled per entry:
 *  - `--key=value` / `-k=value` → split on first `=`, KEY-redact value
 *    if the key matches the sensitive set; else fall through to value
 *    pattern on the value side.
 *  - `KEY=value` (env-var form, ALL_CAPS key) → same as above without
 *    the leading dashes.
 *  - `Key: Value` (HTTP-header / INI / YAML form, Title-Case key) →
 *    same as above.
 *  - Raw entry (no recognised shape) → value-pattern only.
 *
 * Returns the redacted array (preserves order + length) and the
 * aggregated `redactedKeys` list, with `argv.<key>` prefixed entries
 * so an operator can tell which argv position fired.
 */
const ARGV_KV_DASHED = /^--?([^=]+)=(.*)$/
const ARGV_KV_BARE = /^([A-Z][A-Z0-9_]+)=(.*)$/
const ARGV_HEADER = /^([A-Z][A-Za-z0-9-]*):\s+(.*)$/

export function redactArgvEntries(argv: readonly string[]): { argv: string[]; redactedKeys: string[] } {
  if (!Array.isArray(argv)) return { argv: [], redactedKeys: [] }
  const keys = new Set<string>()
  const out = argv.map((entry) => {
    if (typeof entry !== 'string') return entry

    // 1. --key=value or -k=value
    let m = ARGV_KV_DASHED.exec(entry)
    if (m) {
      const key = m[1]!.replace(/^-+/, '')
      const value = m[2] ?? ''
      if (isSensitiveKeyLocal(key)) {
        keys.add(`argv.${key}`)
        return `--${key}=***`
      }
      const r = redactStreamContent(value)
      if (r.redactedKeys.length > 0) {
        for (const k of r.redactedKeys) keys.add(`argv.${key}.${k}`)
        return `--${key}=${r.value}`
      }
      return entry
    }

    // 2. KEY=value (env-var form, ALL_CAPS key)
    m = ARGV_KV_BARE.exec(entry)
    if (m) {
      const key = m[1]!
      const value = m[2] ?? ''
      if (isSensitiveKeyLocal(key)) {
        keys.add(`argv.${key}`)
        return `${key}=***`
      }
      const r = redactStreamContent(value)
      if (r.redactedKeys.length > 0) {
        for (const k of r.redactedKeys) keys.add(`argv.${key}.${k}`)
        return `${key}=${r.value}`
      }
      return entry
    }

    // 3. Key: Value (header / INI)
    m = ARGV_HEADER.exec(entry)
    if (m && m[1]!.length > 1) {
      const key = m[1]!
      const value = m[2] ?? ''
      if (isSensitiveKeyLocal(key)) {
        keys.add(`argv.${key}`)
        return `${key}: ***`
      }
      const r = redactStreamContent(value)
      if (r.redactedKeys.length > 0) {
        for (const k of r.redactedKeys) keys.add(`argv.${key}.${k}`)
        return `${key}: ${r.value}`
      }
      return entry
    }

    // 4. Raw entry — value-pattern only.
    const r = redactStreamContent(entry)
    if (r.redactedKeys.length > 0) {
      for (const k of r.redactedKeys) keys.add(`argv.${k}`)
      return r.value
    }
    return entry
  })
  return { argv: out, redactedKeys: [...keys].sort() }
}

// Re-export so callers that already use `redactSensitiveBody` from the
// existing barrel can compose without importing a second module.
export { redactSensitiveBody }
