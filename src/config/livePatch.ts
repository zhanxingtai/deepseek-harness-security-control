/**
 * Config 热应用 (`livePatch`).
 *
 * 字段清单按现状分类：
 *   - httpCatchup/endpoint/auth 等块已删除，不参与分类；
 *   - loopedToolDetector / tokenUsageDetector / sinkDiskLow / sensitivePathGuard /
 *     inlinePromptInjection / stdioMirror / envPassthroughGuard 等块为分类成员。
 *
 * 三分类原则（设计稿 §2，按现状落地）：
 *   🟢 safe-apply      — 纯数值/布尔/字符串数组阈值，原地突变共享 config
 *                        子对象引用即生效；timer 间隔字段做 timer 重建。
 *   🟡 restart-required — 持有 fd / 路径 / watcher / 启动期快照的字段；
 *                        返回 needsRestart，绝不原地改值。
 *   🔴 rejected        — 自保护开关面：任何块的 `enabled`、`inlineGuards.*`
 *                        （参数化自保护网）。一个 rejected 键都不可混入：
 *                        整体拒绝并 emit high severity security_audit 留痕。
 *
 * 实现机制：bootstrap 装配时各组件拿到的是归一化 Config 的子对象引用
 * （如 `deps.runtimeHookConfig = config.runtimeHooks`）。livePatch 对共享
 * config 对象**原地突变字段**（引用不变 → 运行时读到新值）；对启动时按值
 * 快照的标量（`RuntimeHook.deps.mode`）由各组件 livePatch() 同步。派生结构
 * （NetworkHttpCollector 的 host Set / URL 正则、timer 句柄）由组件在
 * livePatch() 内重建。
 *
 * 审计面（自保护敏感）：applyLivePatch 成功 emit 一条
 * `security_audit`（audit_category='config', audit_action='modify'）；
 * 含 rejected 键的尝试额外 emit 一条 high severity 告警（audit_action='deny'）。
 * 事件过 validateEvent()（security_audit 必填 audit_category + audit_action，
 * 与 FEAT 加 'sink' 枚举先例一致——validateEvent 对取值不做 enum 限制）。
 *
 * 持久化边界（设计稿 §3.4）：applyLivePatch 只改运行时，不回写
 * cordis.patch.yml / 草稿文件；UI 随后自行调 saveConfigDraft，两者正交。
 *
 * 范围外（设计稿 §8）：mode grace period（mode 保持 🟡 restart-required）。
 */

import { hostname } from 'node:os'
import { normalizeConfig, type Config } from '../config.js'
import { validateConfig as validateConfigSchema } from '../config.schema.js'
import { validateEvent } from '../utils/schema.js'
import { generateEventId } from '../utils/eventId.js'
import { DEFAULT_PLATFORM_ID, type SecurityEvent } from '../types/index.js'

/**
 * 每个组件 livePatch() 的返回形状。`appliedKeys` 为实际生效的 dotted key；
 * `needsRestartKeys` 为组件认得的 🟡 键（值未被修改）。不认识其他块的
 * 键——那些属于别的组件。
 */
export interface ComponentLivePatchResult {
  ok: boolean
  appliedKeys: string[]
  needsRestartKeys: string[]
  error?: string
}

/** 参与 livePatch 委派的组件接口。 */
export interface LivePatchableComponent {
  livePatch(patch: Record<string, unknown>): ComponentLivePatchResult
}

export interface LivePatchPreview {
  ok: boolean
  /** 🟢 可立即应用的 dotted key（已按当前 config 归一化校验）。 */
  safeKeys: string[]
  /** 🟡 需重启的 dotted key（值不会被修改）。 */
  needsRestartKeys: string[]
  /** 🔴 永远不可的 dotted key（出现即整体拒绝）。 */
  rejectedKeys: string[]
  /** 非阻断提示（如 blockAtSubprocess 在 audit 模式下不生效）。 */
  warnings: string[]
  /** 校验失败时的错误列表（ok=false 时非空）。 */
  errors: string[]
  /** Caller-supplied client_id echoed back so the
   *  UI can correlate the preview with the eventual apply emit. */
  clientId?: string
}

export interface LivePatchApplyResult {
  ok: boolean
  appliedKeys: string[]
  needsRestartKeys: string[]
  rejectedKeys: string[]
  warnings: string[]
  error?: string
}

/** 三分类表：block → { safe 字段集, restart 字段集 }。未列出的字段
 *  （各块 enabled、inlineGuards.*、未知键）一律 🔴 rejected。 */
const SAFE_FIELDS: Readonly<Record<string, ReadonlySet<string>>> = {
  collector: new Set([
    'batchSize',
    'flushIntervalMs',
    'validateEvents',
    'maxFileBytes',
    'diskWarnWatermarkBytes',
    'diskLowWatermarkBytes',
    'auditDedupWindowMs',
    // `redactRawParams` removed from safe-apply
    // — the marketplace forces it to true (see Config type literal +
    // normalizeConfig override). livePatch cannot toggle it off.
  ]),
  application: new Set([
    'captureUserPrompt',
    'captureSystemPrompt',
    'captureAgentPlan',
    'captureReasoning',
    'toolResultMaxChars',
    'sessionTtlMs',
  ]),
  networkCapture: new Set([
    'redactBodies',
    'captureResponseBody',
    'maxBodyBytes',
    'maxRequestBodyBytes',
    'sseSummaryChunks',
    'sseSummaryLastChunks',
    'includeHosts',
    'excludeHosts',
    'excludeUrls',
    'ignoreUrls',
    'ignoreHosts',
    'sensitiveKeyPatterns',
    'captureDns',
  ]),
  intervention: new Set([
    'reloadIntervalMs',
    'decisionTimeoutMs',
    'failStrategy',
  ]),
  runtimeHooks: new Set([
    'networkEnabled',
    'excludeCommandLines',
    'enabledAtSubprocess',
    'blockAtSubprocess',
    'failOpenOnError',
  ]),
  sensitivePathGuard: new Set(['paths']),
  inlinePromptInjection: new Set(['patterns', 'excerptMaxChars']),
  stdioMirror: new Set(['payloadLimitBytes']),
  envPassthroughGuard: new Set(['keys']),
  // Without this entry classifyPatchKeys treats sensitiveHeaderGuard.* as
  // unknown keys and rejects the whole patch, so operator edits to `keys`
  // could never apply at runtime.
  sensitiveHeaderGuard: new Set(['keys', 'seedHosts']),
  loopedToolDetector: new Set(['windowMs', 'thresholdPerWindow']),
  tokenUsageDetector: new Set(['windowMs', 'burstFactor', 'minBaselineSamples']),
  sinkDiskLow: new Set(['recoverMarginBytes']),
}

const RESTART_FIELDS: Readonly<Record<string, ReadonlySet<string>>> = {
  collector: new Set(['localOutputPath', 'debugLogPath']),
  application: new Set([]),
  networkCapture: new Set([]),
  intervention: new Set(['mode', 'policyPath', 'policyPaths']),
  runtimeHooks: new Set(['logPath', 'hookPath']),
  sensitivePathGuard: new Set(['watchEnabled', 'watchDebounceMs']),
  inlinePromptInjection: new Set([]),
  stdioMirror: new Set(['outputPath']),
  envPassthroughGuard: new Set([]),
  // harnessPlaneHosts / enforceOutOfFrame are
  // 🔴 restart-required per the schema docstring on
  // SensitiveHeaderGuardConfigSchema (`src/config.schema.ts:271-276`).
  // Without this entry classifyPatchKeys falls through to the
  // 🔴 rejected branch and applyLivePatch emits a
  // `security_audit/deny` for what the schema documents as a
  // restart-required change.
  sensitiveHeaderGuard: new Set(['harnessPlaneHosts', 'enforceOutOfFrame']),
  loopedToolDetector: new Set([]),
  tokenUsageDetector: new Set([]),
  sinkDiskLow: new Set([]),
}

const TOP_LEVEL_SAFE: ReadonlySet<string> = new Set([])
const TOP_LEVEL_RESTART: ReadonlySet<string> = new Set(['mode', 'hostId', 'containerId'])

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v)
}

/**
 * 分类一个 operator patch（无副作用）。dotted key 形如
 * `collector.batchSize`。任何 🔴 键（含未知键）落入 rejectedKeys——
 * preview 阶段可见，apply 阶段整体拒绝。
 */
export function classifyPatchKeys(patch: unknown, currentConfig: Config): LivePatchPreview {
  const safeKeys: string[] = []
  const needsRestartKeys: string[] = []
  const rejectedKeys: string[] = []
  const warnings: string[] = []
  const errors: string[] = []
  const record = isPlainObject(patch) ? patch : {}

  for (const [topKey, value] of Object.entries(record)) {
    if (topKey in SAFE_FIELDS) {
      if (!isPlainObject(value)) {
        errors.push(`${topKey}: expected an object sub-block`)
        continue
      }
      for (const field of Object.keys(value)) {
        const dotted = `${topKey}.${field}`
        if (SAFE_FIELDS[topKey]!.has(field)) {
          safeKeys.push(dotted)
        } else if (RESTART_FIELDS[topKey]!.has(field)) {
          needsRestartKeys.push(dotted)
        } else {
          // 各块 enabled + 未列出的键 → 🔴。
          rejectedKeys.push(dotted)
        }
      }
      continue
    }
    if (topKey === 'inlineGuards') {
      // 自保护参数化：engineLaunchers / pluginPackageName / patchMarkers
      // 任何在线修改都可能削弱 001/015 自保护网 → 整体 🔴。
      const fields = isPlainObject(value) ? Object.keys(value) : ['(non-object)']
      for (const field of fields) rejectedKeys.push(`inlineGuards.${field}`)
      continue
    }
    if (TOP_LEVEL_SAFE.has(topKey)) {
      safeKeys.push(topKey)
    } else if (TOP_LEVEL_RESTART.has(topKey)) {
      needsRestartKeys.push(topKey)
    } else {
      // top-level enabled / 未知 top-level 键 → 🔴。
      rejectedKeys.push(topKey)
    }
  }

  safeKeys.sort()
  needsRestartKeys.sort()
  rejectedKeys.sort()

  if (rejectedKeys.length > 0) {
    warnings.push(
      `patch carries rejected key(s): ${rejectedKeys.join(', ')}; applyLivePatch will refuse the whole patch`,
    )
  }
  if (
    safeKeys.includes('runtimeHooks.blockAtSubprocess') &&
    currentConfig.mode !== 'enforce' &&
    isPlainObject(record['runtimeHooks']) &&
    record['runtimeHooks']['blockAtSubprocess'] === true
  ) {
    warnings.push(
      'runtimeHooks.blockAtSubprocess=true has no effect while mode=audit; fork blocking requires mode=enforce',
    )
  }
  if (
    safeKeys.includes('intervention.failStrategy') &&
    isPlainObject(record['intervention']) &&
    record['intervention']['failStrategy'] === 'fail_closed'
  ) {
    warnings.push('intervention.failStrategy=fail_closed blocks tool calls on evaluation timeout; confirm intent')
  }

  return { ok: errors.length === 0, safeKeys, needsRestartKeys, rejectedKeys, warnings, errors }
}

/**
 * 把 operator patch 深合并到当前 Config 的克隆上（block 级浅合并：
 * patch 的数组整体替换、标量覆盖），再过 normalizeConfig 复用现有
 * 校验/回退管道（ 空列表重断言、sinkDiskLow 负值回退等语义与
 * 启动路径完全一致）。纯函数——不改 currentConfig。
 */
export function mergePatchForValidation(currentConfig: Config, patch: unknown): Config {
  const record = isPlainObject(patch) ? patch : {}
  const merged: Record<string, unknown> = { ...currentConfig }
  for (const [key, value] of Object.entries(record)) {
    const base = merged[key]
    if (isPlainObject(base) && isPlainObject(value)) {
      merged[key] = { ...base, ...value }
    } else {
      merged[key] = value
    }
  }
  return normalizeConfig(merged)
}

/** 从归一化后的 merged Config 提取 safe key 的有效值，组装成组件
 *  消费的 safe patch（只含 🟢 键，值已经过 normalize 回退语义）。 */
function buildSafePatch(preview: LivePatchPreview, merged: Config): Record<string, unknown> {
  const safePatch: Record<string, unknown> = {}
  const mergedRecord = merged as unknown as Record<string, unknown>
  for (const dotted of preview.safeKeys) {
    const dot = dotted.indexOf('.')
    if (dot === -1) {
      safePatch[dotted] = mergedRecord[dotted]
      continue
    }
    const block = dotted.slice(0, dot)
    const field = dotted.slice(dot + 1)
    const blockValue = isPlainObject(safePatch[block]) ? safePatch[block] as Record<string, unknown> : {}
    blockValue[field] = (mergedRecord[block] as Record<string, unknown>)[field]
    safePatch[block] = blockValue
  }
  return safePatch
}

export interface LivePatchManagerDeps {
  /** 共享的归一化 Config（组件持有其子对象引用，原地突变即生效）。 */
  config: Config
  sink: { report: (event: SecurityEvent) => void }
  components: LivePatchableComponent[]
  /** Operator 标识（缺省读 USER / USERNAME 环境变量）。 */
  operator?: string
}

/**
 * LivePatchManager — previewLivePatch / applyLivePatch 的服务端实现。
 * applyLivePatch 串行化（简单 promise 链互斥），永不向 host 抛异常
 * （不变式)：任何内部失败都折进 { ok:false, error } 返回值。
 */
export class LivePatchManager {
  private readonly deps: LivePatchManagerDeps
  private chain: Promise<unknown> = Promise.resolve()

  constructor(deps: LivePatchManagerDeps) {
    this.deps = deps
  }

  preview(patch: unknown, clientId?: string): LivePatchPreview {
    if (!isPlainObject(patch)) {
      return {
        ok: false,
        safeKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
        errors: ['livePatch patch must be an object'],
      }
    }
    try {
      const preview = classifyPatchKeys(patch, this.deps.config)
      // preview 也跑 schema 校验，让 UI 在 apply 前就能看到类型错误。
      if (preview.rejectedKeys.length === 0 && preview.errors.length === 0) {
        if (!validateConfigSchema(patch)) {
          preview.errors.push('schema validation failed: patch is not a valid Config sub-shape')
          preview.ok = false
        }
      } else {
        preview.ok = false
      }
      // Surface the caller-supplied client_id on the
      // preview path too (carried through to the eventual apply emit
      // via the audit_details.client_id field). Lets an operator UI
      // correlate multiple preview calls with the apply that follows.
      if (clientId) {
        preview.clientId = clientId
      }
      return preview
    } catch (error: unknown) {
      return {
        ok: false,
        safeKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
        errors: [`previewLivePatch failed: ${error instanceof Error ? error.message : String(error)}`],
      }
    }
  }

  apply(patch: unknown, clientId?: string): Promise<LivePatchApplyResult> {
    // Serialize preview + apply through the same
    // chain so two near-simultaneous RPC calls cannot interleave
    // classify → mutate. Both share `this.chain`; otherwise only
    // apply is serialized and preview stays a
    // free-running window where another caller could mutate the
    // shared config under the live-patch's feet.
    const run = this.chain.then(() => this.applySerialized(patch, clientId))
    // 链上挂一个吞错尾巴，保证下一次 apply 不被上一次 rejection 污染。
    this.chain = run.catch(() => undefined)
    return run
  }

  private async applySerialized(patch: unknown, clientId?: string): Promise<LivePatchApplyResult> {
    const operator = this.deps.operator ?? readOperatorTag()
    if (!isPlainObject(patch)) {
      return {
        ok: false,
        appliedKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
        error: 'livePatch patch must be an object',
      }
    }
    try {
      const preview = classifyPatchKeys(patch, this.deps.config)
      if (preview.errors.length > 0) {
        return {
          ok: false,
          appliedKeys: [],
          needsRestartKeys: preview.needsRestartKeys,
          rejectedKeys: preview.rejectedKeys,
          warnings: preview.warnings,
          error: preview.errors.join('; '),
        }
      }
      if (preview.rejectedKeys.length > 0) {
        // 自保护敏感面：rejected 键尝试必须留痕（high severity）。
        // Include `client_id` so two operators
        // clicking "Apply" near-simultaneously produce disjoint audit
        // events. Without this, a second apply that races the first
        // could end up emitting an audit row that's attributed to the
        // first caller's session.
        this.emitAudit('deny', 'high', {
          operator,
          ...(clientId ? { client_id: clientId } : {}),
          request_keys: flattenPatchKeys(patch),
          rejected_keys: preview.rejectedKeys,
          detail: `applyLivePatch rejected: patch carries self-protection-class key(s): ${preview.rejectedKeys.join(', ')}`,
        })
        return {
          ok: false,
          appliedKeys: [],
          needsRestartKeys: preview.needsRestartKeys,
          rejectedKeys: preview.rejectedKeys,
          warnings: preview.warnings,
          error:
            `patch rejected: self-protection-class key(s) cannot be modified at runtime: ` +
            preview.rejectedKeys.join(', '),
        }
      }
      if (!validateConfigSchema(patch)) {
        return {
          ok: false,
          appliedKeys: [],
          needsRestartKeys: preview.needsRestartKeys,
          rejectedKeys: [],
          warnings: preview.warnings,
          error: 'schema validation failed: patch is not a valid Config sub-shape',
        }
      }
      const merged = mergePatchForValidation(this.deps.config, patch)
      const safePatch = buildSafePatch(preview, merged)

      const appliedKeys: string[] = []
      const needsRestartKeys = [...preview.needsRestartKeys]
      for (const component of this.deps.components) {
        let result: ComponentLivePatchResult
        try {
          result = component.livePatch(safePatch)
        } catch (error: unknown) {
          result = {
            ok: false,
            appliedKeys: [],
            needsRestartKeys: [],
            error: error instanceof Error ? error.message : String(error),
          }
        }
        if (!result.ok) {
          return {
            ok: false,
            appliedKeys,
            needsRestartKeys,
            rejectedKeys: [],
            warnings: preview.warnings,
            error: result.error ?? 'component livePatch failed',
          }
        }
        appliedKeys.push(...result.appliedKeys)
        needsRestartKeys.push(...result.needsRestartKeys)
      }
      appliedKeys.sort()
      needsRestartKeys.sort()

      // Include `client_id` on the success path too so
      // audit consumers can correlate "operator clicked Apply at 12:34"
      // with the eventual audit row.
      this.emitAudit('modify', preview.needsRestartKeys.length > 0 ? 'medium' : 'low', {
        operator,
        ...(clientId ? { client_id: clientId } : {}),
        applied_keys: appliedKeys,
        needs_restart_keys: needsRestartKeys,
        request_keys: flattenPatchKeys(patch),
        detail:
          `applyLivePatch: ${appliedKeys.length} key(s) applied live` +
          (needsRestartKeys.length > 0 ? `; ${needsRestartKeys.length} key(s) need restart` : ''),
      })

      return {
        ok: true,
        appliedKeys,
        needsRestartKeys,
        rejectedKeys: [],
        warnings: preview.warnings,
      }
    } catch (error: unknown) {
      return {
        ok: false,
        appliedKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
        error: `applyLivePatch failed: ${error instanceof Error ? error.message : String(error)}`,
      }
    }
  }

  /**
   * config modify 审计事件（成功 modify / 拒绝 deny）。字段口径对齐
   * bootstrap 的 policy_tamper emit：security_audit 必填 audit_category +
   * audit_action，severity/reason/target/outcome 走平台口径（reason 为自由
   * 文本说明，词汇语义由 audit_action 承载）。
   * 事件先过 validateEvent()，有 issue 只 warn 不重试（invariant #3）。
   */
  private emitAudit(
    action: 'modify' | 'deny',
    severity: 'low' | 'medium' | 'high',
    details: Record<string, unknown>,
  ): void {
    try {
      const now = Date.now()
      const rejected = action === 'deny'
      const message = rejected
        ? `config livePatch 被拒绝：patch 携带自保护类键（${String(details['detail'])}）`
        : `config livePatch 已应用：${(details['applied_keys'] as string[] | undefined)?.join(', ') || '(no safe keys)'}`
      const event: SecurityEvent = {
        comm: DEFAULT_PLATFORM_ID,
        event_id: generateEventId(),
        event_type: 'security_audit',
        // this event is validated HERE (before the sink stamps it), so it has
        // to carry the version itself — otherwise the local gate would drop
        // the config-tamper audit record.
        schema_version: 1,
        layer: 'application',
        source_layer: 'application',
        ts: now,
        pid: process.pid,
        collection_method: 'agent_api',
        host_id: hostname(),
        container_id: process.env.CONTAINER_ID || 'host',
        session_id: null,
        run_id: null,
        agent_id: null,
        audit_category: 'config',
        audit_action: action,
        severity,
        reason: message,
        target: 'runtime-config',
        outcome: rejected ? 'blocked' : 'success',
        audit_details: { ...details, detail: message },
      }
      const issues = validateEvent(event)
      if (issues.length > 0) {
        // 审计事件自身不合法时只 warn——绝不能向 host 抛（invariant #3）。
        console.warn(
          `[LivePatchManager] config audit event failed validation: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}`,
        )
        return
      }
      this.deps.sink.report(event)
    } catch (error: unknown) {
      console.warn(`[LivePatchManager] emit config audit failed: ${String(error)}`)
    }
  }
}

function flattenPatchKeys(patch: unknown): string[] {
  const record = isPlainObject(patch) ? patch : {}
  const keys: string[] = []
  for (const [topKey, value] of Object.entries(record)) {
    if (isPlainObject(value) && topKey in SAFE_FIELDS) {
      for (const field of Object.keys(value)) keys.push(`${topKey}.${field}`)
    } else {
      keys.push(topKey)
    }
  }
  return keys.sort()
}

function readOperatorTag(): string {
  const fromEnv = process.env['USER'] ?? process.env['USERNAME'] ?? ''
  return fromEnv.trim()
}
