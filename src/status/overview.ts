/**
 * Shared overview helpers —.
 *
 * Both `commands/security.ts` (the `/security` CLI surface) and
 * `typert/host.ts` (the DSH Web settings RPC bridge) need the
 * same handful of helpers to render their respective status / overview
 * payloads:
 *
 *   - `STARTUP_TS`            — process-uptime anchor (single instance)
 *   - `countAllBlocks`        — full NDJSON scan, filtered to block decisions
 *   - `countLast24hBlocks`    — same, restricted to a sliding window
 *   - `countLast24hTotal`     — ALL events (not just blocks) in the window
 *   - `scanOverviewAggregates`— single-pass superset of the four counters
 *   - `clampLimit`            — coerce a string|number to a clamped int
 *   - `toBlockRow`            — normalize a raw NDJSON event into `BlockRow`
 *
 * Before these were duplicated verbatim (with two near-identical
 * `clampLimit` signatures) across the two carrier modules, so any change
 * to the format had to be applied twice and the types (`SecurityStatus`
 * vs `OverviewSnapshot`, two `BlockRow` definitions) had drifted. This
 * file is the single source of truth; both carriers import from here.
 *
 * Wire-level type definitions still live on `src/typert/descriptors.ts`
 * (they are the Typert method contract; the CLI side re-exports the
 * same names as a stable public API).
 */
import type { LocalNdjsonSink } from '../collectors/LocalNdjsonSink.js'
import { streamNdjson, isBlockDecision, isRuleHit } from '../utils/ndjsonTail.js'
import { truncateRawJson, type BlockRow } from '../typert/descriptors.js'

/** Process start anchor for `uptimeSec` calculations. Set at module
 * load so both carrier sides see the same reference value (pre-
 *  each file declared its own `const STARTUP_TS = Date.now()`, which
 *  could differ by a few ms if the modules loaded out of order). */
export const STARTUP_TS = Date.now()

/** Coerce `raw` (a string from the CLI parser or a number from the
 *  RPC payload) to a clamped integer in `[min, max]`. Returns
 *  `fallback` on `undefined`, empty string, NaN, or non-finite. */
export function clampLimit(
  raw: unknown,
  fallback: number,
  min: number,
  max: number,
): number {
  if (raw === undefined || raw === null) return fallback
  const n = typeof raw === 'number' ? raw : Number.parseInt(String(raw), 10)
  if (!Number.isFinite(n)) return fallback
  return Math.max(min, Math.min(max, Math.floor(n)))
}

/** Count all block decisions in the local NDJSON log. Walks the full
 *  file via `streamNdjson` so the count is correct regardless of log
 *  size (the `tailNdjson` shortcut would only see the tail window). */
export async function countAllBlocks(sink: LocalNdjsonSink): Promise<number> {
  const path = sink.getLocalOutputPath()
  if (!path) return 0
  let count = 0
  for await (const _obj of streamNdjson(path, { filter: isBlockDecision })) {
    count += 1
  }
  return count
}

/** Count block decisions whose event timestamp falls within the last
 *  `hours` hours (default 24). Same scanner as `countAllBlocks` with
 *  an added `ts >= cutoff` gate. */
export async function countLast24hBlocks(
  sink: LocalNdjsonSink,
  hours = 24,
): Promise<number> {
  const path = sink.getLocalOutputPath()
  if (!path) return 0
  const cutoff = Date.now() - hours * 60 * 60 * 1000
  let count = 0
  for await (const obj of streamNdjson(path, { filter: isBlockDecision })) {
    const ts = obj['ts']
    if (typeof ts === 'number' && ts >= cutoff) count += 1
  }
  return count
}

/** Count ALL events (any event_type / decision) whose timestamp falls
 *  within the last `hours` hours (default 24). Thin wrapper over
 *  `scanOverviewAggregates` — operators asking for the 24h total do not
 *  pay for a second pass when the caller already scans for the other
 *  aggregates. */
export async function countLast24hTotal(
  sink: LocalNdjsonSink,
  hours = 24,
): Promise<number> {
  const agg = await scanOverviewAggregates(sink, hours)
  return agg.last24hTotalCount
}

/** Aggregate counter bundle for the overview surface: block
 *  counts plus the Metrics-page additions (`last24hTotalCount`,
 *  `byLayer`). Computed in ONE streaming pass — the alternative
 *  (chaining the individual counters) would re-read the log once per
 *  aggregate, and the UI polls `overview()` on a 5 s interval. */
export interface OverviewAggregates {
  /** ALL parsed events in the file, regardless of type/decision. Same
   *  source and predicate as `last24hTotalCount` minus the time gate —
   *  a process-local counter (e.g. `stats.flushed`) resets on restart
   *  while the NDJSON file persists, which is why "total < last 24h"
   *  inversions kept showing up on the Metrics page. */
  totalCount: number
  /** All-time block decisions (same semantics as `countAllBlocks`). */
  blockCount: number
  /** Block decisions with `ts >= now - hours` (semantics of
   *  `countLast24hBlocks`). */
  last24hBlockCount: number
  /** 威胁事件(规则命中,含 warn 级"标记但未拦截";
   *  拦截是其子集)。全时间计数,谓词 `isRuleHit`。 */
  threatCount: number
  /** 威胁事件在近 `hours` 窗口内的计数。 */
  last24hThreatCount: number
  /** ALL parsed events with `ts >= now - hours` — blocks, allows,
   *  audits, network captures. */
  last24hTotalCount: number
  /** Per-`layer` counts over the whole file; layerless rows bucket
   *  under `'unknown'`. */
  byLayer: Record<string, number>
}

/** Single-pass full-log scan producing every overview aggregate. Falls
 *  back to zero/empty aggregates when the sink has no local output
 *  path (or the file is missing — `streamNdjson` yields nothing). */
export async function scanOverviewAggregates(
  sink: LocalNdjsonSink,
  hours = 24,
): Promise<OverviewAggregates> {
  const empty: OverviewAggregates = {
    totalCount: 0,
    blockCount: 0,
    last24hBlockCount: 0,
    threatCount: 0,
    last24hThreatCount: 0,
    last24hTotalCount: 0,
    byLayer: {},
  }
  const path = sink.getLocalOutputPath()
  if (!path) return empty
  const cutoff = Date.now() - hours * 60 * 60 * 1000
  const agg: OverviewAggregates = { ...empty, byLayer: {} }
  for await (const obj of streamNdjson(path)) {
    agg.totalCount += 1
    const ts = obj['ts']
    const inWindow = typeof ts === 'number' && ts >= cutoff
    if (inWindow) agg.last24hTotalCount += 1
    if (isBlockDecision(obj)) {
      agg.blockCount += 1
      if (inWindow) agg.last24hBlockCount += 1
    }
    // 威胁事件口径:warn 标记未拦截也计入,block/deny 命中同时推进
    // 两个计数器(threat ⊇ blocked)。
    if (isRuleHit(obj)) {
      agg.threatCount += 1
      if (inWindow) agg.last24hThreatCount += 1
    }
    const layer = obj['layer']
    const key = typeof layer === 'string' && layer.length > 0 ? layer : 'unknown'
    agg.byLayer[key] = (agg.byLayer[key] ?? 0) + 1
  }
  return agg
}

/** Normalize a raw NDJSON event record into the wire-level `BlockRow`
 * shape. The CLI imports `BlockRow` from
 *  `descriptors.ts` and reaches this
 *  normalizer when needed — a single shared rendering so the CLI and
 *  host views cannot drift apart.
 *
 * 惰性明细:`opts.includeRaw` 为 true 时额外携带
 * `raw_json`(完整原始事件,`truncateRawJson` 截断),供 Policy Hits
 * 详情展开使用;缺省摘要不带,3 s 轮询载荷不变。 */
export function toBlockRow(
  raw: Record<string, unknown>,
  opts: { includeRaw?: boolean } = {},
): BlockRow {
  const intervention = raw['intervention'] as
    | {
        decision?: string
        decision_internal?: string
        block_reason?: string
        block_code?: string
        policy_id?: string
        // severity trace fields copied by
        // `RuntimeHook.emitResolveEvent` / `DecisionComposer` so the UI
        // can render the SEVERITY column + the ↓warn downgrade marker.
        severity?: 'critical' | 'extreme' | 'high' | 'medium' | 'low'
        severity_downgraded?: boolean
        severity_rule_id?: string
      }
    | undefined
  const auditDetails = raw['audit_details'] as { policy_id?: string } | undefined
  const isAuditRow = raw['event_type'] === 'security_audit'
  // 审计行(security_audit)没有 intervention 块,语义全部靠顶层
  // 字段承载: audit_action(tamper/detect/modify/...) 进决策侧的
  // 旁路列, severity 进等级列, block_reason / reason 进原因列。
  // decision 列保持 'unknown' —— 审计发现不是一次干预,不该被渲染
  // 成 block 徽章。
  const auditAction = typeof raw['audit_action'] === 'string' ? raw['audit_action'] : undefined
  return {
    ts: typeof raw['ts'] === 'number' ? raw['ts'] : 0,
    session_id: typeof raw['session_id'] === 'string' ? raw['session_id'] : undefined,
    agent_id: typeof raw['agent_id'] === 'string' ? raw['agent_id'] : undefined,
    // 审计行无 tool_name,回退取顶层 target(如插件名),工具
    // 列不再只有 '—'。对敏感头检测类行,再回退到
    // audit_details.matched_key,前端可显示 'header:authorization'
    // 这种带语义的标签。
    tool_name:
      typeof raw['tool_name'] === 'string'
        ? raw['tool_name']
        : isAuditRow && typeof raw['target'] === 'string'
          ? raw['target']
          : isAuditRow &&
              typeof auditDetails === 'object' &&
              auditDetails !== null &&
              typeof (auditDetails as { matched_key?: unknown }).matched_key === 'string'
            ? `header:${(auditDetails as { matched_key: string }).matched_key}`
            : undefined,
    // runtime 层命中行(spawn_intent / spawn_denied)没有
    // tool_name,客户端 TOOL 列回退显示 `spawn: <exe>`。
    exe: typeof raw['exe'] === 'string' ? raw['exe'] : undefined,
    tool_call_id: typeof raw['tool_call_id'] === 'string' ? raw['tool_call_id'] : undefined,
    // 审计发现档(security_audit)行无 intervention,回退取
    // 顶层 severity / audit_action,Policy Hits 的等级列与决策列才有值。
    audit_action: auditAction,
    // 决策列:审计发现档(security_audit)不参与干预流水线,
    // 没有 intervention.decision 可用,恒为 'unknown';审计语义
    // (tamper/detect/modify/...)由 audit_action 列单独承载 ——
    // 2026-10-12 定的"双轨",避免把审计发现伪装成一次 block,
    // 让 Policy Hits 的 badge 配色按真实干预来源区分。
    decision: intervention?.decision ?? 'unknown',
    decision_internal: intervention?.decision_internal ?? (isAuditRow ? auditAction : undefined),
    // 审计行的原因列:回退取 顶层 block_reason(security_audit
    // 事件直接落盘该字段,比 reason 更精炼) / reason
    // (security_audit 规范字段,一句话描述),否则前端只能显示
    // 'unknown'。策略列回退 audit_details.policy_id。
    block_reason:
      intervention?.block_reason ??
      (typeof raw['block_reason'] === 'string'
        ? raw['block_reason']
        : typeof raw['reason'] === 'string'
          ? raw['reason']
          : undefined),
    block_code: intervention?.block_code,
    policy_id:
      intervention?.policy_id ??
      (typeof auditDetails?.policy_id === 'string' ? auditDetails.policy_id : undefined),
    // severity trace propagated to the wire-level BlockRow;审计行回退顶层
    // severity(info/low 已被 isRuleHit 挡在威胁口径外,能进 Policy Hits
    // 的审计行必然带 medium+ 等级)。
    severity:
      intervention?.severity ??
      (typeof raw['severity'] === 'string'
        ? (raw['severity'] as 'critical' | 'extreme' | 'high' | 'medium' | 'low')
        : undefined),
    severity_downgraded: intervention?.severity_downgraded,
    ...(opts.includeRaw ? { raw_json: truncateRawJson(JSON.stringify(raw)) } : {}),
  }
}