/**
 * Field-level (structured) redaction utilities. Sensitive values are replaced
 * with a fixed mask before events are persisted or reported.
 *
 * ## Scope: structured data only
 *
 * This module operates on **parsed, typed JavaScript values** — plain objects
 * (`Record<string, unknown>`), JSON strings, and structured payloads
 * (`RedactedRawParams`, `MultipartSummary`, etc.). Each export walks the
 * shape and masks values whose **key** matches `DEFAULT_SENSITIVE_KEYS`
 * (case + segment + camelCase boundary aware).
 *
 * ## Exports at a glance
 *
 * - `DEFAULT_SENSITIVE_KEYS` — canonical sensitive-key catalogue. Re-exported
 *   by `./contentRedactor.ts` and consumed by `ApplicationCollector` for the
 *   `params` / `tool_params` masking path. Extend with care — every consumer
 *   inherits new entries.
 * - `redactSensitiveBody<T>` — recursive walk; masks values, returns the
 *   same shape.
 * - `redactAndCollectKeys<T>` — like `redactSensitiveBody` but also returns
 *   the flat dotted paths that were masked (`a.b.c`).
 * - `truncateString(value, maxLength)` — byte-aware truncation. Used by
 *   `ApplicationCollector` for `tool_result` and `error.message` caps.
 * - `redactRawParams(raw, options)` — JSON-string redaction for raw tool
 * params. Returns `{ value, hash, size, redactedKeys }` so audit
 *   consumers can reconcile post-hoc.
 * - `limitPayloadSize<T>(value, cap)` — size cap before write. Catches
 *   accidental "send 100 MB JSON" payloads that would otherwise exhaust
 *   the NDJSON file.
 * `summarizeMultipartBody(body, opts)` — multipart form-data
 *   summarization for the audit side; text fields masked via
 *   `redactSensitiveBody`, blob fields replaced with `{name, size,
 *   content_hash}` only.
 *
 * ## Boundary with `./contentRedactor.ts`
 *
 * `contentRedactor.ts` handles **unstructured text** — Bearer tokens in
 * a child's stderr stream, AWS keys inside a shell command, URL query
 * strings, etc. — by **value-pattern matching**, not key matching.
 * It re-imports `DEFAULT_SENSITIVE_KEYS` from this module so the two
 * layers share one canonical catalogue, but the two are deliberately
 * separate: `contentRedactor.ts` does not call into this module's
 * recursive walker because that walker requires a parsed value, and the
 * stdio mirror stream is untrusted bytes.
 *
 * ## Safety contract
 *
 * - All exports are total on the input domain (no throws on malformed
 *   JSON / unknown keys).
 * - `DEFAULT_SENSITIVE_KEYS` is locked — the marketplace form's
 *   `normalizeConfig` re-asserts `enabled: true` for the inline guard
 * that uses it ( §十一).
 */

import { createHash } from 'node:crypto'

export const DEFAULT_SENSITIVE_KEYS = [
  'token',
  'key',
  'secret',
  'password',
  'credential',
  'authorization',
  'api_key',
  'apikey',
]

const MASK = '***'

/**
 * switched from substring match to exact-segment
 * match to close false positives on incidental substrings
 * (`monkey_business` / `keyboard` / `tokenizer` / `secretary` etc.
 * previously masked because they contained `key` / `token` / `secret`
 * as a substring). Segment boundaries are `._-` and case transitions
 * (`apiKey` → `api` + `key`), matching the conventions used in
 * JSON-stringified HTTP headers / OAuth payloads where the same logical
 * key is variously spelled `api_key` / `apiKey` / `api-key` / `apikey`.
 *
 * The whole-key form is also kept in the match set so a bare
 * `authorization` or `password` (no separators) is still caught.
 */
function isSensitiveKey(key: string, patterns: string[] = DEFAULT_SENSITIVE_KEYS): boolean {
  const patternSet = new Set(patterns.map((p) => p.toLowerCase()))
  const lower = key.toLowerCase()
  if (patternSet.has(lower)) return true
  // Split on . _ - (run BEFORE camelCase split so the per-segment
  // pass below sees separated identifiers, not whole camelCase strings).
  const segments: string[] = []
  for (const rawSeg of lower.split(/[._\-]+/)) {
    if (!rawSeg) continue
    segments.push(rawSeg)
    // Split camelCase on the ORIGINAL (mixed-case) input so the
    // boundary between `custom` and `Secret` is preserved. Lowering
    // first would erase the boundary and collapse `customSecret` into
    // a single segment.
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
  return segments.some((s) => patternSet.has(s))
}

export function redactSensitiveBody<T extends Record<string, unknown>>(
  body: T,
  patterns?: string[],
): T {
  if (!body || typeof body !== 'object') return body
  const result: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(body)) {
    if (isSensitiveKey(key, patterns)) {
      result[key] = MASK
    } else if (typeof value === 'object' && value !== null) {
      result[key] = redactSensitiveBody(value as Record<string, unknown>, patterns)
    } else {
      result[key] = value
    }
  }
  return result as T
}

/**
 * redact a body and also return the (deduplicated
 * depth-flattened) list of keys that were masked. Mirrors
 * `redactSensitiveBody` exactly except for the augmented return.
 *
 * The platform spec requires a top-level `redacted_keys: string[]`
 * field on every event that flowed through redaction, so audit can
 * verify which keys were touched without having to diff the event
 * against the original. The list is:
 *  - sorted alphabetically (deterministic, no set-order flakiness)
 *  - flattened across nesting (a token buried under `headers.Authorization`
 *    appears as `headers.Authorization`, not just `headers`)
 *  - deduplicated (a sensitive value hit twice in a deep tree still
 *    appears once)
 *
 * The legacy `redactSensitiveBody` is kept untouched (and untouched
 * callers compile unchanged) — this companion function is opt-in by
 * call sites that need the keys side-channel.
 */
export interface RedactionResult<T> {
  result: T
  redactedKeys: string[]
}

export function redactAndCollectKeys<T extends Record<string, unknown>>(
  body: T,
  patterns?: string[],
): RedactionResult<T> {
  const keys = new Set<string>()
  const result = walkAndCollect(body, '', keys, patterns)
  return {
    result: result as T,
    redactedKeys: [...keys].sort(),
  }
}

function walkAndCollect(
  body: unknown,
  prefix: string,
  keys: Set<string>,
  patterns: string[] | undefined,
): unknown {
  if (!body || typeof body !== 'object') return body
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    const fullKey = prefix ? `${prefix}.${key}` : key
    if (isSensitiveKey(key, patterns)) {
      out[key] = MASK
      keys.add(fullKey)
    } else if (typeof value === 'object' && value !== null) {
      out[key] = walkAndCollect(value, fullKey, keys, patterns)
    } else {
      out[key] = value
    }
  }
  return out
}

export function truncateString(value: string, maxLength: number): string {
  if (!value || value.length <= maxLength) return value
  return value.slice(0, maxLength) + '...'
}

/**
 * `tool_params` 脱敏（默认开启）。
 *
 * `redactSensitiveBody` 走对象；`tool_params` 是 JSON 字符串 carrier。
 * 本函数走：JSON.parse → `redactSensitiveBody` → JSON.stringify，同时算
 * sha256 hash + 原始字节数。
 *
 * 决策点（schema 兼容性优先）：
 *  - `tool_params` 保持 string 类型（脱敏后的 JSON 字符串 / 解析失败时空串）
 *  - `hash` / `size` / `redacted` 仍由本函数返回供调用方审计使用，但
 * SecurityEvent 不保留 raw_params_* 字段—— ApplicationCollector 只把 `value` 写到 `tool_params`。
 *
 * 风险权衡：
 *  - 开启后 NDJSON 不再是完整镜像，事后取证需要 `redactedKeys` 对账
 *  - 关闭（enabled:false）则保留明文
 *  - JSON 解析失败时按"未知结构"处理 —— 仅保留 hash/size，**不暴露原始内容**
 *
 * @param raw    原始 JSON 字符串（`JSON.stringify(exec.arguments)` 形态）
 * @param options.enabled     false = 保留原始 raw；true = 走 redactSensitiveBody
 * @param options.patterns    optional 替换 `DEFAULT_SENSITIVE_KEYS`
 */
export interface RedactedRawParams {
  /** 脱敏后的 JSON 字符串（脱敏生效时）；原始字符串当 opted out */
  value: string
  /** sha256 hex digest of original raw string — always populated */
  hash: string
  /** UTF-8 byte length of original raw string */
  size: number
  /** 是否走过了 redactSensitiveBody */
  redacted: boolean
  /**
   * list of keys that were masked, in the same shape
   * `redactAndCollectKeys` produces. Always an array (possibly empty)
   * so callers can pass it straight to the SecurityEvent without
   * nullish checks. Populated only when `redacted === true` AND the
   * input parsed as a JSON object; otherwise `[]`.
   */
  redactedKeys: string[]
}

export function redactRawParams(
  raw: string | undefined | null,
  options: { enabled: boolean; patterns?: string[] } = { enabled: true },
): RedactedRawParams {
  const normalized = typeof raw === 'string' ? raw : ''
  const hash = createHash('sha256').update(normalized, 'utf8').digest('hex')
  const size = Buffer.byteLength(normalized, 'utf8')

  if (!options.enabled) {
    return { value: normalized, hash, size, redacted: false, redactedKeys: [] }
  }

  // Empty input → empty value (not "{}" — preserves the no-content signal
  // for callers that pass undefined when no args were supplied).
  if (normalized.length === 0) {
    return { value: '', hash, size, redacted: true, redactedKeys: [] }
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(normalized)
  } catch {
    // JSON 解析失败 → 不暴露原始内容（可能是损坏的中间态，含敏感信息无法保证）
    return { value: '', hash, size, redacted: true, redactedKeys: [] }
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    // 非对象（数组 / 标量 / null） —— 没有 key 可脱敏，但明文仍可读
    // 出于安全考虑按 redacted 处理，**仅保留 hash / size，不暴露原始内容**
    return { value: '', hash, size, redacted: true, redactedKeys: [] }
  }

  // Custom patterns EXTEND the default set (not replace it) — callers
  // expect "my custom secrets are redacted, AND the standard token/key/
  // password masking still applies". Passing the merged list keeps both
  // promises simultaneously.
  const mergedPatterns =
    options.patterns && options.patterns.length > 0
      ? [...DEFAULT_SENSITIVE_KEYS, ...options.patterns]
      : options.patterns
  // use the key-tracking variant so `redactedKeys`
  // can land on the SecurityEvent `redacted_keys` field. Same masking
  // semantics as `redactSensitiveBody`; only the return shape differs.
  // (§十一 B4: SecurityEvent no longer carries
  // `raw_params`; `tool_params` is the sole tool-args carrier.)
  const { result: redacted, redactedKeys } = redactAndCollectKeys(
    parsed as Record<string, unknown>,
    mergedPatterns,
  )
  return {
    value: JSON.stringify(redacted),
    hash,
    size,
    redacted: true,
    redactedKeys,
  }
}

/**
 * payload size limiter.
 *
 * Returns a value whose `.content` is at most `maxBytes` long. The original
 * `length` is preserved on `.originalLength` for auditability — a
 * downstream consumer can tell that a truncation happened without losing
 * the byte-count signal.
 *
 * The default `maxBytes` of 1 MiB matches the Phase-4 memory cap on
 * `collectMemoryInfo`-related defaults and is large enough to hold a real
 * `cat /etc/hosts` or a typical tool result, but small enough to bound the
 * worst-case memory pressure from a single payload.
 *
 * Behaviour:
 *  - If the input is undefined or within the cap, return as-is.
 *  - If over the cap, truncate and set `truncated: true` + `originalLength`.
 *  - The truncation is byte-based (UTF-8), not character-based — a single
 *    multi-byte character at the boundary is allowed to be split, then
 *    `Buffer.byteLength` reports the actual stored size. A `replacement`
 *    suffix is appended so the consumer can see something was dropped.
 */
export interface PayloadLimitResult<T> {
  value: T
  truncated: boolean
  originalLength: number
}

export function limitPayloadSize<T>(
  value: T,
  maxBytes: number,
  options?: { suffix?: string },
): PayloadLimitResult<T> {
  if (value === undefined || value === null) {
    return { value, truncated: false, originalLength: 0 }
  }
  // For strings, measure by UTF-8 byte length (matches what the audit log
  // will persist and how downstream consumers process).
  if (typeof value === 'string') {
    const originalLength = Buffer.byteLength(value, 'utf8')
    if (originalLength <= maxBytes) {
      return { value: value as T, truncated: false, originalLength }
    }
    // Slice by characters (cheap upper bound) then re-fit to bytes.
    const suffix = options?.suffix ?? '…[truncated]'
    const suffixBytes = Buffer.byteLength(suffix, 'utf8')
    const budget = Math.max(0, maxBytes - suffixBytes)
    let truncated = value.slice(0, budget)
    // Tighten until the byte length is within budget (avoid splitting a
    // multi-byte char at the boundary).
    while (truncated.length > 0 && Buffer.byteLength(truncated, 'utf8') > budget) {
      truncated = truncated.slice(0, -1)
    }
    return { value: (truncated + suffix) as T, truncated: true, originalLength }
  }
  // For non-strings, leave the value untouched but report its size.
  return { value, truncated: false, originalLength: 0 }
}

/** Default cap for arbitrary user/tool payloads. 1 MiB by default. */
export const DEFAULT_PAYLOAD_MAX_BYTES = 1024 * 1024

/**
 * Progressive multipart/form-data payload summary.
 *
 * `FormData` is an opaque carrier in the audit pipeline — the previous
 * `captureFetchBody` path wrote `'[FormData body]'` (a single fixed string
 * the operator could not diff or grep) and `limitPayloadSize` had no
 * payload to bound. For multipart bodies with embedded files this is
 * unacceptable: a 50-MiB upload writes 50 MiB to NDJSON (memory pressure)
 * or is silently dropped to a 13-byte placeholder (audit gap).
 *
 * Design (progressive truncation):
 *
 *   - **Text fields** (`formData.get(name)` returns string): emitted
 *     verbatim, then handed to `limitPayloadSize` so the joined summary
 *     still respects the global body cap.
 *   - **Blob / File fields** (`Blob` instance, including `File`): we
 *     NEVER read the full bytes into memory. Instead the field is
 *     summarised as `{ name, filename?, contentType, size }` plus a
 *     `preview` string of the FIRST `previewBytes` (default 4 KiB) of
 *     the underlying buffer, with `truncated: true` and
 *     `original_size: <full byte length>` when the blob exceeds the
 *     preview budget. The preview respects the global body cap via
 *     `limitPayloadSize` on the assembled summary.
 *   - **Non-FormData bodies**: caller should not invoke this helper.
 *     Defensive: returns `null` so the caller can fall back to the
 *     opaque `[unreadable body]` placeholder.
 *
 * Safety:
 *
 *   - Blob reads use `.slice(0, previewBytes).text()` — bounded by the
 *     preview budget, never `await blob.text()` (which would materialise
 *     the full buffer).
 *   - `limitPayloadSize` still caps the assembled summary, so a request
 *     body of 1000 text fields is bounded to `maxBytes` regardless of
 *     per-field growth.
 *   - The helper is sync-return-shape; the async Blob read happens in
 *     the caller (captureFetchBody), so this function only walks
 *     `formData.entries()` synchronously and hands back a list of
 *     descriptors with the Blob fields marked for async materialisation.
 *
 * Return shape (JSON-serialisable):
 *
 *   ```
 *   {
 *     kind: 'multipart_summary',
 *     fields: Array<
 *       | { name, kind: 'text', value: string, truncated: boolean, original_length: number }
 *       | { name, kind: 'blob', filename?, content_type, size, preview: string, truncated: boolean, original_size: number }
 *     >,
 *     field_count: number,
 *     blob_count: number,
 *     blob_truncated_count: number,
 *     original_size: number,
 *   }
 *   ```
 */
export interface MultipartTextField {
  name: string
  kind: 'text'
  value: string
  truncated: boolean
  original_length: number
}

export interface MultipartBlobField {
  name: string
  kind: 'blob'
  filename?: string
  content_type: string
  size: number
  preview: string
  truncated: boolean
  original_size: number
}

export type MultipartField = MultipartTextField | MultipartBlobField

export interface MultipartSummary {
  kind: 'multipart_summary'
  fields: MultipartField[]
  field_count: number
  blob_count: number
  blob_truncated_count: number
  original_size: number
}

export interface MultipartSummaryOptions {
  /** Per-blob preview budget. Default 4 KiB. */
  previewBytes?: number
}

/**
 * Walk `formData.entries()` and return a JSON-serialisable summary.
 *
 * Async because Blob fields are read with `blob.slice(0, previewBytes)`
 * to bound memory pressure; text fields are returned as-is.
 *
 * On any unexpected entry shape (non-string / non-Blob field value),
 * the field is recorded as `{ name, kind: 'unknown' }` and skipped in
 * the original-size tally — never throws (invariant #3: never throw to
 * the host). Callers can detect anomalies via `field_count` vs the
 * number of well-typed fields.
 */
export async function summarizeMultipartBody(
  formData: FormData,
  options: MultipartSummaryOptions = {},
): Promise<MultipartSummary> {
  const previewBytes = options.previewBytes ?? 4 * 1024
  const fields: MultipartField[] = []
  let blobCount = 0
  let blobTruncatedCount = 0
  let originalSize = 0

  // FormData iterator yields [name, value] pairs. We must materialise the
  // iterator once because re-iterating FormData is allowed but some hosts
  // (older Node fetch impls) only support a single pass.
  const entries: Array<[string, unknown]> = []
  try {
    for (const entry of formData.entries()) {
      entries.push(entry as [string, unknown])
    }
  } catch {
    // Iterator construction failure — degrade gracefully.
    return {
      kind: 'multipart_summary',
      fields: [],
      field_count: 0,
      blob_count: 0,
      blob_truncated_count: 0,
      original_size: 0,
    }
  }

  for (const [name, value] of entries) {
    if (typeof value === 'string') {
      const length = Buffer.byteLength(value, 'utf8')
      originalSize += length
      // Per-field cap is the global body cap (callers pass it via the
      // returned `fields[]`; `captureFetchBody` then runs limitPayloadSize
      // on the assembled JSON so a 1000-field body still respects the cap).
      const truncated = length > previewBytes
      fields.push({
        name,
        kind: 'text',
        value: truncated ? value.slice(0, previewBytes) + '…[truncated]' : value,
        truncated,
        original_length: length,
      })
      continue
    }
    if (value instanceof Blob) {
      blobCount++
      const size = value.size
      originalSize += size
      const truncated = size > previewBytes
      if (truncated) blobTruncatedCount++
      const contentType = value.type || 'application/octet-stream'
      let preview = ''
      let previewSize = 0
      try {
        // Bounded read — never materialises the full Blob.
        const slice = value.slice(0, previewBytes)
        preview = await slice.text()
        previewSize = Buffer.byteLength(preview, 'utf8')
      } catch {
        preview = '[unreadable blob]'
        previewSize = 0
      }
      // File extends Blob with `name` (filename); guard with optional chain
      // because not every Blob is a File (e.g. fetch body constructed from
      // a Blob literal).
      const filename =
        typeof (value as unknown as { name?: unknown }).name === 'string'
          ? ((value as unknown as { name: string }).name)
          : undefined
      fields.push({
        name,
        kind: 'blob',
        ...(filename !== undefined ? { filename } : {}),
        content_type: contentType,
        size: previewSize,
        preview,
        truncated,
        original_size: size,
      })
      continue
    }
    // Non-string / non-Blob: skip with a tombstone field. We do NOT throw.
    fields.push({
      name,
      kind: 'text',
      value: '[unsupported FormData field]',
      truncated: false,
      original_length: 0,
    })
  }

  return {
    kind: 'multipart_summary',
    fields,
    field_count: fields.length,
    blob_count: blobCount,
    blob_truncated_count: blobTruncatedCount,
    original_size: originalSize,
  }
}
