/**
 * ndjsonTail — read-only NDJSON reader for the local audit sink.
 *
 * shared utility. The local
 * `LocalNdjsonSink` writes one JSON object per line via `appendFileSync`.
 * This module exposes two readers that never throw to the host:
 *
 *   - `tailNdjson(path, n, opts?)` — read the LAST `n` parseable JSON
 *     objects from the file, applying an optional filter. Suitable for
 * `/security recent N` and the settings page's"Recent Blocks"
 *     tab. Returns most-recent-first.
 *
 *   - `streamNdjson(path, opts?)` — an AsyncIterable that yields parsed
 *     objects oldest-first. Useful for full scans; supports an optional
 *     `fromLastBytes` so a follow-up scan can resume from the previous
 *     EOF without re-reading the file.
 *
 * Concurrency contract (per the design notes):
 *
 *   - The plugin's `appendFileSync` write of one NDJSON line is atomic at
 *     the POSIX write(2) layer for line sizes below `PIPE_BUF` (4096 B
 *     on Linux). For larger lines (deeply nested tool params, big
 *     assistant messages) the reader may observe a partial line at the
 *     tail. We tolerate this by passing the readline stream through
 *     `tryParseLine` — a partial / malformed line is silently skipped
 *     rather than aborting the read.
 *
 *   - The reader does not hold any lock. The plugin's writer uses
 *     `appendFileSync` which does not require coordination, and our
 *     `readline` interface reads in 64 KiB chunks via the underlying
 *     `createReadStream`. There is no guarantee of seeing the very last
 *     line if a write is in flight at the moment of EOF — call again
 *     with the next request.
 *
 *   - On any stream error (file missing, permission denied, malformed
 *     JSON on every line) we return whatever we have parsed so far. The
 *     caller decides whether to surface an empty result or a degraded
 *     status.
 */
import { createReadStream } from 'node:fs'
import { existsSync, statSync } from 'node:fs'
import { createInterface, type Interface as RLInterface } from 'node:readline'

/** Maximum size of a single line read into memory (1 MiB). Tool args with
 *  deeply nested payloads or large assistant messages may approach this
 *  in practice; anything larger is treated as malformed and skipped. */
const MAX_LINE_BYTES = 1 * 1024 * 1024

/** Default read chunk size — Node's readline default. */
const READ_CHUNK_BYTES = 64 * 1024

export interface TailNdjsonOptions {
  /** Predicate applied AFTER parsing. Use to keep only events of interest
   *  (e.g. only `agent_tool_call` events with a `block` decision). */
  filter?: (obj: Record<string, unknown>) => boolean
  /** Hint for how many bytes to read from the tail of the file before
   *  scanning. Defaults to `Math.max(n * 4096, 64 KiB)` so the typical
   *  case (find the last few hundred events in a multi-MB log) does
   *  not require the caller to tune this. Pass an explicit number to
   *  trade off I/O vs completeness on huge logs. */
  fromLastBytes?: number
  /** Skip the newest `offset` matches (newest-first), then return the
   *  next `n`. Combined with a stable page size this paginates into
   *  older history without re-reading the file. Defaults to 0
   *  (no skip). Used by the Load more cursor on the Events and
   *  Policy Hits tabs. */
  offset?: number
}

export interface StreamNdjsonOptions {
  /** Predicate applied AFTER parsing. */
  filter?: (obj: Record<string, unknown>) => boolean
  /** Start scanning from `fromLastBytes` bytes before EOF instead of
   *  the start of the file. Useful for incremental follow-up scans
   *  (e.g. a tail-follow mode that catches new events between polls). */
  fromLastBytes?: number
}

function tryParseLine(line: string): Record<string, unknown> | null {
  if (line.length === 0) return null
  try {
    const obj = JSON.parse(line) as unknown
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      return obj as Record<string, unknown>
    }
    return null
  } catch {
    return null
  }
}

/**
 * Read the LAST `n` parseable JSON objects from a NDJSON file, most
 * recent first.
 *
 * Implementation note: rather than buffer the entire file, we read the
 * tail byte-window (`fromLastBytes`), split into lines, parse from the
 * END backwards, and stop once we have `n` matches. For files smaller
 * than the window we read the whole file. The reverse-scan avoids the
 * "read 50 MiB to find the last 20 lines" pathology of the naive
 * forward scan.
 *
 * With a `filter` set (and no explicit `fromLastBytes`),
 * the byte window DOUBLES and re-scans until `n` filtered matches are
 * collected or the whole file is covered — the n*4096 heuristic assumes
 * ~4KB/event while real security events average ~7KB (network_http SSE
 * bodies run to tens of KB), and an under-covering window silently
 * dropped older rule hits (Policy Hits showed 2 of 6 threat events).
 */
export async function tailNdjson(
  path: string,
  n: number,
  opts: TailNdjsonOptions = {},
): Promise<Array<Record<string, unknown>>> {
  if (n <= 0) return []
  // Load more cursor: skip the newest `offset` matches
  // (newest-first), then return the next `n`. We over-collect
  // `offset + n` so scanTailWindow can apply its `n*4` over-scan cap
  // naturally, and slice the final window to the requested page.
  // Without this a `Load more` click re-returns the same first page
  // (the file's newest `n` rows), and dedup swallows the lot — the
  // visible list never grows.
  const offset = Math.max(0, opts.offset ?? 0)
  const total = offset + n
  let totalBytes: number
  try {
    totalBytes = statSync(path).size
  } catch {
    // File missing or unreadable — return empty rather than throw.
    return []
  }
  if (totalBytes === 0) return []

  // 带 filter 时字节窗口
  // 可能欠覆盖——窗口启发值 n*4096 按 4KB/事件标定,而安全事件平均
  // ~7KB(network_http 的 SSE 响应体单条可达数十 KB)。例如 84 事件、619KB
  // 的日志里 n=50 的窗口只覆盖末尾 ~1/3,较早的规则命中被漏采,页面
  // 显示 2 条而全量扫描统计 6 条。窗口不足时成倍扩展重扫,直到凑满 n
  // 条命中或覆盖到文件头;显式 fromLastBytes 的调用方维持单次扫描。
  let windowBytes = opts.fromLastBytes ?? Math.max(total * 4096, READ_CHUNK_BYTES)

  for (;;) {
    const result = await scanTailWindow(path, total, windowBytes, opts.filter)
    if (opts.fromLastBytes !== undefined) {
      return result.slice(offset, offset + n)
    }
    if (result.length >= total || windowBytes >= totalBytes) {
      return result.slice(offset, offset + n)
    }
    windowBytes = Math.min(totalBytes, windowBytes * 2)
  }
}

/** Scan the last `windowBytes` bytes of the file, return up to `n`
 *  filter-passing objects (newest-first). Used by the window-growth
 *  loop to re-scan with a larger window. */
async function scanTailWindow(
  path: string,
  n: number,
  windowBytes: number,
  filter: ((obj: Record<string, unknown>) => boolean) | undefined,
): Promise<Array<Record<string, unknown>>> {
  const totalBytes = statSync(path).size
  const startByte = Math.max(0, totalBytes - windowBytes)
  const stream = createReadStream(path, {
    start: startByte,
    end: totalBytes - 1,
    encoding: 'utf8',
  })
  const rl = createInterface({ input: stream, crlfDelay: Infinity })

  // We scan backwards; collect in an array then reverse. Most-recent-first
  // means: the LAST parsed line is index 0.
  const matched: Array<Record<string, unknown>> = []
  try {
    for await (const rawLine of rl) {
      const obj = tryParseLine(rawLine)
      if (!obj) continue
      if (filter && !filter(obj)) continue
      matched.push(obj)
      // Keep at most `n` items (we're scanning backwards, so the OLDEST
      // items drop off). Slight over-scan is fine — final reverse handles it.
      if (matched.length > n * 4) {
        matched.splice(0, matched.length - n * 4)
      }
    }
  } catch {
    // Read error mid-stream — return what we have.
  } finally {
    rl.close()
    stream.destroy()
  }
  // matched is in file order (oldest -> newest). Return the LAST n in
  // reverse so the caller gets newest-first.
  const tail = matched.length > n ? matched.slice(matched.length - n) : matched
  return tail.reverse()
}

/**
 * Stream parseable JSON objects from a NDJSON file in file order
 * (oldest first). Use for full scans where the file is small or the
 * caller wants every event (e.g. a one-shot analytics run).
 */
export async function* streamNdjson(
  path: string,
  opts: StreamNdjsonOptions = {},
): AsyncIterable<Record<string, unknown>> {
  const stream = (() => {
    if (opts.fromLastBytes && opts.fromLastBytes > 0) {
      let total: number
      try {
        total = statSync(path).size
      } catch {
        return null
      }
      return createReadStream(path, {
        start: Math.max(0, total - opts.fromLastBytes),
        end: total - 1,
        encoding: 'utf8',
      })
    }
    return createReadStream(path, { encoding: 'utf8' })
  })()

  if (!stream) return

  const rl: RLInterface = createInterface({
    input: stream,
    crlfDelay: Infinity,
  })
  // Cap individual line size so a runaway line cannot exhaust memory.
  rl.on('line', (line) => {
    if (line.length > MAX_LINE_BYTES) {
      // Drop silently — the parser would JSON.parse-throw anyway, but
      // not before allocating the string in memory.
      return
    }
  })
  try {
    for await (const rawLine of rl) {
      const obj = tryParseLine(rawLine)
      if (!obj) continue
      if (opts.filter && !opts.filter(obj)) continue
      yield obj
    }
  } catch {
    // Swallow mid-stream errors — the iterable just ends.
  } finally {
    rl.close()
    stream.destroy()
  }
}

/**
 * Count filter-passing objects in a NDJSON file. Streams the file
 * end-to-end (no window) and tallies lines that pass the optional
 * filter predicate. Returns 0 for a missing / empty file.
 *
 * The Events / Policy Hits
 * footer shows "Showing X of N events" — N is the filter-aware
 * total in the file, not the page count. Doing a full scan here
 * is fine for the local sink (small to medium log files); the
 * host caches nothing, so the count is always current.
 */
export async function countNdjson(
  path: string,
  filter?: (obj: Record<string, unknown>) => boolean,
): Promise<number> {
  if (!existsSync(path)) return 0
  let total = 0
  try {
    for await (const obj of streamNdjson(path, { filter })) {
      // We only need the count; avoid materialising the body.
      void obj
      total += 1
    }
  } catch {
    // Mid-stream errors: return the count we accumulated so far.
  }
  return total
}

/**
 * Cheap predicate: was the event an SPL-blocked tool call (or any
 * non-allow decision the operator cares to surface)? 纯决策谓词,与
 * event_type 解耦:只看 `intervention.decision`,不再按
 * 事件类型白名单过滤。原因:拦截发生在多个层面,事件类型各不相同——
 * `agent_tool_call`(工具层)、`runtime_spawn_denied`(子进程层)、
 * `agent_message`(消息层,blocked:true 但消息仍送达,仅审计标记)。
 * 旧的 `event_type === 'agent_tool_call'` 白名单把消息层/子进程层的
 * 拦截决策全部漏出统计,造成事件列表"已拦截"徽标与 Metrics/Policy
 * Hits 数字分裂。
 *
 * 安全性:security_audit 事件(含 SelfProtectionGuard 的
 * `blocked:true` 审计行)没有 intervention 字段,仍被排除——与
 * 威胁口径(isRuleHit)保持一致。
 */
export function isBlockDecision(obj: Record<string, unknown>): boolean {
  const intervention = obj['intervention'] as
    | { decision?: string; decision_internal?: string }
    | undefined
  if (!intervention) return false
  const d = intervention.decision_internal ?? intervention.decision
  return d === 'block' || d === 'deny'
}

/**
 * 威胁事件口径(规则命中,含 warn 标记未拦截):
 * 任何带 intervention 且最终决策不是 allow 的受评事件。
 *
 * 与 `isBlockDecision` 的关系:拦截 ⊂ 威胁——block/deny 命中同时计入
 * 两个口径;warn/ask(命中 warn 级规则,enforce/audit 下都只记录不拦)
 * 只计入威胁。用 `intervention` 判断而不是
 * `policy_evaluation.status === 'matched'`:runtime 层 allow 事件带
 * `unknown-rule` 占位命中,会误计。
 *
 * 同一动作可能产生 tool_call + spawn_intent 两条命中事件,按事件计数
 * 不去重(与 blockCount 口径一致)。
 *
 * 口径与 event_type 解耦,分两档:
 *   1. 决策命中档:任何带 intervention 且决策为 warn/block/deny 的事件
 *      (工具层 / 消息层 / 子进程层,不看事件类型);
 *   2. 审计发现档:severity ∈ {medium, high, critical} 的 security_audit
 *      事件(tamper / integrity detect / 行为检测等前端"风险"档发现)。
 *      info/low(policy reload committed / heartbeat 等生命周期审计)
 *      不计入——避免重载噪音淹没威胁统计。
 *   两档并集 = 威胁事件;block/deny 同时计入已拦截(拦截 ⊂ 威胁)。
 *   与前端 Events 徽标分层对齐:已拦截 / 威胁(决策命中) / 风险(审计发现
 *   ≥ medium)在 Metrics 与 Policy Hits 中都有归宿。
 */
export function isRuleHit(obj: Record<string, unknown>): boolean {
  const intervention = obj['intervention'] as
    | { decision?: string; decision_internal?: string }
    | undefined
  if (intervention) {
    const d = intervention.decision_internal ?? intervention.decision
    if (d === 'warn' || d === 'block' || d === 'deny') return true
  }
  // 审计发现档:无 intervention 的 security_audit 按顶层 severity 分档。
  if (obj['event_type'] === 'security_audit') {
    const sev = obj['severity']
    return sev === 'medium' || sev === 'high' || sev === 'critical'
  }
  return false
}
