#!/usr/bin/env node
// scripts/test-rules-interactive.mjs
// FaaS-style SPL rule coverage & accuracy/FP interactive tester.
//
// 设计原则
// ============
//  - **FaaS**：脚本仅 import 一次 InterventionEngine（lib/ 缺失则自动
//    `pnpm run build:host`），之后导出一个 async `eval(ctx)` 函数：
//        eval(ctx) -> { decision, policy_id, block_code, reason, hits[] }
//    不启动 ApplicationCollector / NetworkHttpCollector / RuntimeHook，
//    不装载插件，不读 ~/.dsh 配置——纯内存评估，可被其它脚本 / 单元
//    测试直接 import 调用（见末尾的 `if (import.meta.url === ...)` 段）。
//
//  - **覆盖**：`./rule-corpus.mjs`（独立可复用）为 91 条规则每条生成
//    ≥10 条正例（应被该规则命中）和 ≥10 条反例（不应被任何"对家"规则
//    误命中）。正例保留 `expectRule`、反例保留 `expectRules` 黑名单，
//    通过 evaluate 后的 `policy_id`/`hits` 做精确比对。
//
//  - **OWASP**：rule-corpus.mjs 同时附带 OWASP Top-10 (2021) 的攻击
//    模式库 (~30 样本)，用于校验策略对常见应用层威胁的覆盖面。
//
//  - **交互**：CLI REPL 不仅接受 `--seed`/`:seed` 全量回放，还提供
//    `chat` 模式——把用户输入的中文/自然语言当作对"智能体"的提问，
//    自动封装成 InterventionContext 评估，把策略决策当作"智能体的
//    回答"展示。这是用户指定的"与智能体问答"形态。
//
// 用法
// ============
//  node scripts/test-rules-interactive.mjs                 # 进入交互模式
//  node scripts/test-rules-interactive.mjs --seed           # 全量跑一遍并出报告
//  node scripts/test-rules-interactive.mjs --policy=<path>  # 指定其它策略
//  node scripts/test-rules-interactive.mjs --report=<dir>   # 报告输出目录
//
// 交互命令：
//   help                                  # 帮助
//   list [pattern]                        # 列规则（支持模糊匹配）
//   show <ruleId|#seq>                    # 看某条规则的样本与评估矩阵
//   eval <json>                           # 喂一个 InterventionContext JSON
//   ask                                   # 进入"对话模式"——把你输入的句子
//                                          当作对智能体的提问，回以策略决策；
//                                          该模式可自然标注 o=正常 /
//                                          f=误报 / m=漏报
//   fuzz <ruleId> [N]                     # 用 mutation 对该规则的若干正例
//                                          做轻微变形，验证稳健性
//   attack                                # 跑 OWASP Top-10 攻击库
//   matrix                                # 输出每条规则的 TP/FP/FN/TN +
//                                          precision/recall/FPR/accuracy
//   totals                                # 输出汇总统计
//   :reset                                # 清空当前标注会话
//   :save [path]                          # 写出 JSON / JSONL 报告
//   :quit / :q                            # 退出并出报告

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'
import readline from 'node:readline/promises'

import { ruleCorpus, buildOwaspAttacks, expandYmlTestcases } from './rule-corpus.mjs'
import * as jsyaml from 'js-yaml'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = resolve(__dirname, '..')

// ---------- 参数 ----------
const argv = process.argv.slice(2)
const opts = {
  seed: argv.includes('--seed'),
  chat: false, // 进 REPL 时可手动 `chat`
  policy: join(root, 'policies', 'default-policy.spl.yaml'),
  report: join(root, 'reports', 'test-rules'),
}
for (const a of argv) {
  if (a.startsWith('--policy=')) opts.policy = resolve(a.slice('--policy='.length))
  if (a.startsWith('--report=')) opts.report = resolve(a.slice('--report='.length))
}

// ---------- 确保 lib/ 已构建（缺失则先 build:host） ----------
// Windows 上 pnpm 只有 .cmd shim：shell:false + 'pnpm' → ENOENT；
// Node ≥18.20 因 CVE-2024-27980 的缓解措施又禁止 shell:false 下 spawn .cmd
// （→ EINVAL）。只能走 shell:true；参数是硬编码字面量，无外部输入。
const SPAWN_SHELL = process.platform === 'win32'
const engineEntry = join(root, 'lib', 'intervention', 'InterventionEngine.js')
if (!existsSync(engineEntry)) {
  console.error('lib/ 缺失，先 pnpm run build:host ...')
  const r = spawnSync('pnpm', ['run', 'build:host'], { cwd: root, stdio: 'inherit', shell: SPAWN_SHELL })
  if (r.status !== 0 || !existsSync(engineEntry)) {
    console.error('✗ 编译失败，退出', r.error ?? '')
    process.exit(2)
  }
}
const { normalizeConfig } = await import(pathToFileURL(join(root, 'lib', 'config.js')).href)
const { InterventionEngine } = await import(pathToFileURL(engineEntry).href)

// audit 模式：不短路，一次 evaluate 收集全部命中规则，便于做"哪条规则
// 是真正的命中源头 / 哪些规则仅作旁路命中"审计
const tmpDir = mkdtempSync(join(tmpdir(), 'spl-faas-'))
process.on('exit', () => { try { rmSync(tmpDir, { recursive: true, force: true }) } catch {} })

const engine = new InterventionEngine(
  normalizeConfig({
    mode: 'audit',
    collector: { localOutputPath: join(tmpDir, 'e.jsonl'), flushIntervalMs: 10 },
    intervention: { policyPath: opts.policy, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
  }),
  { logger: { warn() {}, info() {}, debug() {}, error() {} } },
)
engine.initialize()
const loaded = engine.getLoadedPolicy()
if (loaded.error) { console.error('策略加载失败:', loaded.error); process.exit(2) }

// 规则元数据
const ruleMeta = new Map()
for (const r of loaded.rules) {
  ruleMeta.set(r.id, {
    id: r.id, name: r.name, severity: r.severity ?? null,
    category: r.category ?? null, priority: r.priority ?? null,
    decision: r.action?.decision ?? null, blockCode: r.action?.blockCode ?? null,
  })
}

// =============================================================================
// FaaS function
// =============================================================================

let _seq = 0
/**
 * 评估一个 InterventionContext。
 * @param {Record<string,unknown>} ctx
 * @returns {Promise<{
 *   decision: string, policy_id: string|null, block_code: string|null,
 *   reason: string|null, hits: Array<{id:string,name:string,severity:string|null,
 *                                    decision:string|null,priority:number|null}>,
 *   latencyMs: number, sessionId: string }>}
 */
export async function evalCtx(ctx) {
  const sessionId = ctx.sessionId ?? `faas:${++_seq}`
  const t0 = Date.now()
  const d = await engine.evaluate({ ...ctx, sessionId })
  const ids = d.risk_signal?.evaluation_path ?? []
  const names = d.risk_signal?.matched_policies ?? []
  const hits = ids.map((id, i) => {
    const m = ruleMeta.get(id) ?? {}
    return {
      id, name: names[i] ?? m.name ?? id,
      severity: m.severity ?? null, decision: m.decision ?? null,
      priority: m.priority ?? null, blockCode: m.blockCode ?? null,
    }
  })
  return {
    decision: d.decision,
    policy_id: d.policy_id ?? null,
    block_code: d.block_code ?? null,
    reason: d.block_reason ?? d.reason ?? null,
    hits,
    latencyMs: Date.now() - t0,
    sessionId,
  }
}

/**
 * 同步便利封装（内部只是 await 后取最终值）。
 */
export async function classify(ctx) {
  const r = await evalCtx(ctx)
  return { decision: r.decision, rule: r.policy_id, hits: r.hits.map((h) => h.id) }
}

// =============================================================================
// 样本组织：策略内置 testCases + rule-corpus.mjs 生成集 + OWASP 攻击集
// =============================================================================

if (!existsSync(opts.policy)) { console.error('策略缺失:', opts.policy); process.exit(2) }
const policyDoc = jsyaml.load(readFileSync(opts.policy, 'utf8'))

const samples = [] // { id, source, expectDecision, expectRule, expectRules?, label?, ctx, hit?, miss?, fp? }

// 1) 策略 YAML testCases → 已带 expectedDecision 的样本
const ymlCases = expandYmlTestcases(policyDoc)
for (const s of ymlCases) {
  samples.push({
    id: s.id, source: 'yml', ctx: s.ctx,
    expectDecision: s.expectedDecision,
    expectRule: s.expectRule ?? null,
    note: s.note ?? null,
  })
}
// 2) 每条规则的生成集（≥10 + ≥10）
const generated = ruleCorpus(ruleMeta, policyDoc)
for (const s of generated) samples.push(s)
// 3) OWASP Top-10 攻击模式
const owasp = buildOwaspAttacks()
for (const s of owasp) samples.push({ source: 'owasp', ...s })

// =============================================================================
// 一致性 / 矩阵指标
// =============================================================================

function decideGroundTruth(sample) {
  // 三类：
  //   - expectDecision 已知 → 用作 ground truth (TP / FN / FP)
  //   - expectRules 黑名单：反例样本，期望"这些规则都不命中"
  //   - 既无 expectDecision 也无 expectRules：跳过（不在矩阵中计）
  return sample
}

async function evaluateOne(sample) {
  const v = await evalCtx(sample.ctx)
  const matched = new Set(v.hits.map((h) => h.id))
  const expected = sample.expectRule ? new Set([sample.expectRule]) : new Set()
  const blockedSet = new Set(sample.expectRules ?? [])
  const decision = v.decision
  sample._verdict = {
    decision,
    topRule: v.policy_id,
    hitIds: [...matched],
    latencyMs: v.latencyMs,
  }

  // 1. decision-level
  sample._verdict.decisionPass = !sample.expectDecision || sample.expectDecision === decision
  // 2. rule-level (only if expectRule is set)
  if (sample.expectRule) {
    sample._verdict.ruleMatched = matched.has(sample.expectRule)
    sample._verdict.unexpectedHit = [...matched].filter((id) => id !== sample.expectRule)
  }
  // 3. negative black-list (only if expectRules set)
  if (sample.expectRules && sample.expectRules.length) {
    sample._verdict.falseFires = sample.expectRules.filter((id) => matched.has(id))
  }
  return sample
}

// =============================================================================
// 报表
// =============================================================================

function aggregatePerRule(samples) {
  const stats = new Map() // ruleId -> { TP, FP, FN, TN }
  const inc = (k, id) => {
    const s = (stats.get(id) ?? { TP: 0, FP: 0, FN: 0, TN: 0 })
    s[k]++; stats.set(id, s)
  }
  for (const s of samples) {
    if (!s.expectDecision) continue
    if (!s.expectRule) continue // 没有 expectRule 时按"决策是否落入某规则"无法定位
    const matched = s._verdict?.hitIds ?? []
    const hit = matched.includes(s.expectRule)
    // True class = expectDecision ∈ { block, escalate, warn, modify } ⇒ positive
    // (策略意图"应被拦")；allow ⇒ negative
    const positiveClass = s.expectDecision !== 'allow'
    if (positiveClass) {
      if (hit) inc('TP', s.expectRule); else inc('FN', s.expectRule)
    } else {
      // 期望 allow：命中即 FP（误报），未命中即 TN
      if (hit) inc('FP', s.expectRule); else inc('TN', s.expectRule)
    }
  }
  return stats
}

function row(r) {
  const { TP = 0, FP = 0, FN = 0, TN = 0 } = r
  const P = TP + FP, R = TP + FN
  const precision = P ? TP / P : 1
  const recall = R ? TP / R : 1
  const FPR = (FP + TN) ? FP / (FP + TN) : 0
  const accuracy = (TP + TN + FP + FN) ? (TP + TN) / (TP + TN + FP + FN) : 1
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0
  return { TP, FP, FN, TN, precision, recall, FPR, accuracy, f1 }
}

function printPerRule(stats) {
  const lines = []
  lines.push('| 规则 | 类别 | 决策 | TP | FP | FN | TN | precision | recall | FPR | f1 |')
  lines.push('|---|---|---|---|---|---|---|---|---|---|---|')
  const ids = [...stats.keys()].sort()
  for (const id of ids) {
    const r = row(stats.get(id))
    const m = ruleMeta.get(id) ?? {}
    lines.push(
      `| ${id} | ${m.category ?? '?'} | ${m.decision ?? '?'} | ${r.TP} | ${r.FP} | ${r.FN} | ${r.TN} | ${(r.precision * 100).toFixed(0)}% | ${(r.recall * 100).toFixed(0)}% | ${(r.FPR * 100).toFixed(1)}% | ${(r.f1 * 100).toFixed(0)}% |`,
    )
  }
  console.log(lines.join('\n'))
}

function printTotals(samples) {
  let pass = 0, total = 0
  let tp = 0, fp = 0, fn = 0, tn = 0
  for (const s of samples) {
    if (s.expectDecision && s.expectRule) {
      total++
      if (s._verdict?.decisionPass) pass++
      const r = (s._verdict.hitIds ?? []).includes(s.expectRule)
      const pos = s.expectDecision !== 'allow'
      if (pos) { if (r) tp++; else fn++ } else { if (r) fp++; else tn++ }
    }
  }
  const precision = tp + fp ? tp / (tp + fp) : 1
  const recall = tp + fn ? tp / (tp + fn) : 1
  const FPR = fp + tn ? fp / (fp + tn) : 0
  const accuracy = total ? pass / total : 1
  console.log(
    `\n总数 ${total} 决策一致率 ${(accuracy * 100).toFixed(1)}% | TP=${tp} FP=${fp} FN=${fn} TN=${tn}` +
    ` | precision=${(precision * 100).toFixed(1)}% recall=${(recall * 100).toFixed(1)}% FPR=${(FPR * 100).toFixed(2)}%`,
  )
}

// =============================================================================
// runSeed
// =============================================================================

export async function runSeed({ onProgress } = {}) {
  let i = 0
  for (const s of samples) {
    await evaluateOne(s)
    if (onProgress && (++i % 50 === 0 || i === samples.length)) onProgress(i, samples.length)
  }
}

// =============================================================================
// CLI REPL
// =============================================================================

const labelledSessions = [] // { kind, ctx, verdict, label, note }

function fmtVerdict(v) {
  const head = `→ decision=${v.decision}` + (v.block_code ? ` [${v.block_code}]` : '') +
               ` top=${v.policy_id ?? '—'} (${v.latencyMs}ms)`
  const hits = v.hits.map((h) => `   • ${h.id} (${h.name}) sev=${h.severity} dec=${h.decision} prio=${h.priority}`).join('\n')
  return head + (v.hits.length ? '\n 命中规则：\n' + hits : '\n 命中规则：（无，allow）') +
         (v.reason ? `\n reason: ${v.reason}` : '')
}

async function printMatrixCmd() {
  await runSeed()
  const stats = aggregatePerRule(samples)
  console.log(`\n样本 ${samples.length}（yml ${samples.filter((s) => s.source === 'yml').length} + 生成 ${samples.filter((s) => s.source === 'gen').length} + owasp ${samples.filter((s) => s.source === 'owasp').length}）`)
  printPerRule(stats)
  printTotals(samples)
}

async function showRule(idOrSeq) {
  let ruleId = idOrSeq
  if (/^#?\d+$/.test(idOrSeq)) {
    const idx = parseInt(idOrSeq.replace('#', ''), 10) - 1
    ruleId = [...ruleMeta.keys()][idx]
    if (!ruleId) { console.log('no such sequence'); return }
  }
  const m = ruleMeta.get(ruleId)
  if (!m) { console.log('规则不存在'); return }
  console.log(`\n规则 ${m.id}  name=${m.name}  category=${m.category}  severity=${m.severity}  decision=${m.decision}  blockCode=${m.blockCode ?? '—'}  priority=${m.priority}`)
  const own = samples.filter((s) => s.expectRule === ruleId)
  const fired = samples.filter((s) => (s._verdict?.hitIds ?? []).includes(ruleId))
  console.log(`expectRule 样本 ${own.length} 个（positives ${own.filter((x) => x.expectDecision !== 'allow').length} | negatives ${own.filter((x) => x.expectDecision === 'allow').length}）`)
  console.log(`目前实际命中该规则 ${fired.length} 次`)
  // 列前 5 正反例
  const show = (arr, head) => {
    if (!arr.length) return
    console.log(`\n  -- ${head} --`)
    arr.slice(0, 5).forEach((s, i) => {
      const v = s._verdict ?? {}
      console.log(`    ${i + 1}. ${s.id}  expectDecision=${s.expectDecision}  got=${v.decision ?? '(未跑)'}` +
                  (v.topRule ? ` top=${v.topRule}` : ''))
      console.log(`       ctx: ${JSON.stringify(s.ctx).slice(0, 200)}`)
    })
  }
  show(own.filter((x) => x.expectDecision !== 'allow'), '正例 expectRule=top (应拦) — 前 5')
  show(own.filter((x) => x.expectDecision === 'allow'), '反例 expectRule=top & expect=allow (应放过) — 前 5')
}

async function listRulesCmd(pattern) {
  const re = pattern ? new RegExp(pattern, 'i') : null
  const ids = [...ruleMeta.keys()]
  const max = Math.max(...ids.map((x) => x.length))
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i]
    if (re && !re.test(id)) continue
    const m = ruleMeta.get(id)
    console.log(`  ${String(i + 1).padStart(3)}. ${id.padEnd(max)}  ${m.category ?? '?'}  dec=${m.decision} sev=${m.severity}`)
  }
  console.log(`\n共 ${ids.length} 条规则`)
}

async function fuzzRule(ruleId, n = 25) {
  const m = ruleMeta.get(ruleId)
  if (!m) { console.log('规则不存在'); return }
  const own = samples.filter((s) => s.expectRule === ruleId && s.expectDecision !== 'allow' && s._verdict)
  if (!own.length) { console.log('先 :seed 或 matrix 跑一遍以生成基线'); return }
  const victim = own[0]
  const variants = mutateCtx(victim.ctx, n)
  let pass = 0
  for (const v of variants) {
    const r = await evalCtx(v)
    const hit = (r.hits ?? []).some((h) => h.id === ruleId)
    const ok = r.decision !== 'allow'
    if (ok) pass++
    console.log(`  ${hit && ok ? '✓' : '✗'} got=${r.decision} hit=${r.hits.map((h) => h.id).join(',') || '∅'}  ctx=${JSON.stringify(v).slice(0, 120)}`)
  }
  console.log(`稳健性 ${pass}/${variants.length}（期望：发生变形后该规则仍然命中）`)
}

const MUTATORS = [
  (v) => ({ ...v, params: { ...(v.params ?? {}), command: ((v.params && v.params.command) ?? '').replace(/--uninstall|--remove/g, '--install') } }),
  (v) => ({ ...v, params: { ...(v.params ?? {}), command: ((v.params && v.params.command) ?? '').replace(/(sst-security-control-dsh|security-monitor)/g, 'lodash') } }),
  (v) => ({ ...v, params: { ...(v.params ?? {}), command: ((v.params && v.params.command) ?? '').toUpperCase() } }),
  (v) => ({ ...v, toolName: 'pwsh' }),
  (v) => ({ ...v, toolName: 'python3' }),
  (v) => ({ ...v, params: { ...(v.params ?? {}), command: (((v.params && v.params.command) ?? '') + ' # harmless').trim() } }),
  (v) => ({ ...v, toolName: 'cmd' }),
  (v) => ({ ...v, params: { ...(v.params ?? {}), command: ((v.params && v.params.command) ?? '').replace(/\s+/g, '   ') } }),
  (v) => ({ ...v, params: { ...(v.params ?? {}), command: '\t' + ((v.params && v.params.command) ?? '') } }),
  (v) => ({ ...v, params: { ...(v.params ?? {}), command: ((v.params && v.params.command) ?? '').split('').reverse().join('') } }), // 反转
]
function mutateCtx(ctx, n) {
  const out = []
  for (let i = 0; i < n; i++) out.push(MUTATORS[i % MUTATORS.length](ctx))
  return out
}

async function attackCmd() {
  const set = samples.filter((s) => s.source === 'owasp')
  console.log(`OWASP Top-10 攻击 ${set.length} 条`)
  for (const s of set) {
    if (!s._verdict) await evaluateOne(s)
    const v = s._verdict
    const hit = s.expectRule ? (v.hitIds ?? []).includes(s.expectRule) : (v.decision !== 'allow')
    const cover = s.expectRule ? `expectRule=${s.expectRule}` : `expect=${s.expectDecision}`
    console.log(`  ${hit && v.decisionPass ? '✓' : '✗'} ${s.id}  ${cover}  got=${v.decision}` +
                (v.topRule ? ` top=${v.topRule}` : '') +
                `  family=${s.family ?? '?'}` +
                (s.note ? `  // ${s.note}` : ''))
  }
  await runSeed()
  const detected = set.filter((s) => s._verdict?.decisionPass).length
  console.log(`\nOWASP 检出 ${detected}/${set.length}`)
}

async function evalJsonCmd(jsonText) {
  let ctx
  try { ctx = JSON.parse(jsonText) } catch { console.log('JSON 解析失败'); return }
  const v = await evalCtx(ctx)
  console.log(fmtVerdict(v))
}

// "对话模式"：把用户输入当成"对智能体的提问"，回以策略决策 + 询问标注
async function chatLoop(rl) {
  console.log('\n进入 chat 模式 —— 输入中文/自然语言，回以策略决策 + blockCode。空行退出该模式。')
  console.log('提示：在行首加 #tool=NAME 以模拟工具调用（例：#tool=bash npm uninstall lodash）')
  while (true) {
    const line = await rl.question('chat> ')
    if (line == null || line.trim() === '' || line.trim() === ':back') return
    let ctx
    if (line.startsWith('#tool=')) {
      const rest = line.slice(6).trim()
      const sp = rest.indexOf(' ')
      if (sp < 0) { console.log('需要 工具名 + 命令'); continue }
      const toolName = rest.slice(0, sp).trim()
      const command = rest.slice(sp + 1).trim()
      ctx = { actionType: 'agent_tool_call', toolName, params: { command } }
    } else if (line.startsWith('#url=')) {
      ctx = { actionType: 'http_request', toolName: 'fetch', url: line.slice(5).trim() }
    } else if (line.startsWith('#read=')) {
      ctx = { actionType: 'agent_tool_call', toolName: 'read', params: { file_path: line.slice(6).trim() } }
    } else if (line.startsWith('#write=')) {
      const sp = line.indexOf(' ')
      const file = line.slice(7, sp).trim()
      const body = line.slice(sp + 1)
      ctx = { actionType: 'agent_tool_call', toolName: 'write', params: { file_path: file, body } }
    } else {
      ctx = { actionType: 'agent_message', body: line }
    }
    const v = await evalCtx(ctx)
    console.log(fmtVerdict(v))
    const lab = (await rl.question('  标注 [o=正常 / f=误报 / m=漏报 / 回车跳过]: '))?.trim().toLowerCase()
    if (['o', 'f', 'm'].includes(lab)) {
      const note = (await rl.question('  备注（可空）: '))?.trim() ?? ''
      labelledSessions.push({
        kind: 'chat',
        ctx, verdict: v,
        label: { o: 'ok', f: 'fp', m: 'miss' }[lab],
        note,
      })
      console.log('  ✔ 已记录')
    }
  }
}

async function saveReport(file) {
  mkdirSync(dirname(file), { recursive: true })
  const out = {
    generatedAt: new Date().toISOString(),
    policy: relative(root, opts.policy),
    totals: samples.length,
    rules: [...ruleMeta.values()],
    matrix: [...aggregatePerRule(samples).entries()].map(([id, s]) => ({ id, ...row(s) })),
    labelledSessions,
    samples: samples.map((s) => ({
      id: s.id, source: s.source,
      expectDecision: s.expectDecision, expectRule: s.expectRule, note: s.note ?? null,
      ctx: s.ctx,
      v: s._verdict ?? null,
    })),
  }
  writeFileSync(file, JSON.stringify(out, null, 2), 'utf8')
  console.log(`已保存: ${file}`)
}

// ----- main -----
async function main() {
  if (opts.seed) {
    console.log(`正在跑全量评测（共 ${samples.length} 个样本，请稍候）...`)
    await runSeed({ onProgress: (i, t) => process.stdout.write(`\r  ${i}/${t}`) })
    process.stdout.write('\n')
    const stats = aggregatePerRule(samples)
    console.log('=== 每条规则矩阵 ===')
    printPerRule(stats)
    printTotals(samples)
    const reportFile = join(opts.report, `seed-${Date.now()}.json`)
    saveReport(reportFile)
    process.exit(0)
  }

  console.log(`SPL 规则 FaaS 评测器 — 引擎就绪 ${loaded.rules.length} 规则；语料 ${samples.length} 样本（yml ${samples.filter((s) => s.source === 'yml').length} + 生成 ${samples.filter((s) => s.source === 'gen').length} + owasp ${samples.filter((s) => s.source === 'owasp').length}）`)
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false })
  // 自管行队列（与 stress-spl-interactive 同坑）
  const queue = []
  const waiters = []
  let closed = false
  rl.on('line', (l) => { if (waiters.length > 0) waiters.shift()(l); else queue.push(l) })
  rl.on('close', () => { closed = true; while (waiters.length > 0) waiters.shift()(null) })
  const ask = (q) => {
    process.stdout.write(q)
    if (queue.length > 0) return Promise.resolve(queue.shift())
    if (closed) return Promise.resolve(null)
    return new Promise((res) => waiters.push(res))
  }

  console.log('help 看命令；chat 进入与智能体的问答模式；matrix 看每条规则的混淆矩阵；:q 退出。')
  for (;;) {
    const raw = await ask('\n> ')
    if (raw === null) { console.log('\n输入流结束'); break }
    const line = raw.trim()
    if (!line) continue
    if (line === ':q' || line === ':quit' || line === 'quit' || line === 'exit') break
    if (line === 'help' || line === '?') {
      console.log(HELP_TEXT); continue
    }
    if (line === 'list' || line.startsWith('list ')) {
      const pat = line.slice(4).trim() || null
      await listRulesCmd(pat); continue
    }
    if (line === 'totals') {
      await runSeed()
      printTotals(samples); continue
    }
    if (line === 'matrix') {
      await printMatrixCmd(); continue
    }
    if (line === 'attack') { await attackCmd(); continue
    }
    if (line === 'chat') { await chatLoop({ question: (q) => ask(q) }); continue }
    if (line.startsWith('show ')) { await showRule(line.slice(5).trim()); continue }
    if (line.startsWith('fuzz ')) {
      const m = line.match(/^fuzz\s+(\S+)(?:\s+(\d+))?$/)
      if (!m) { console.log('语法: fuzz <ruleId> [N]'); continue }
      await fuzzRule(m[1], parseInt(m[2] ?? '25', 10)); continue
    }
    if (line.startsWith('eval ') || line.startsWith('eval\t')) {
      await evalJsonCmd(line.slice(4).trimStart()); continue
    }
    if (line === ':reset') { labelledSessions.length = 0; console.log('已清空标注'); continue }
    if (line === ':save' || line.startsWith(':save ')) {
      const f = line.startsWith(':save ') ? line.slice(6).trim() : join(opts.report, `interactive-${Date.now()}.json`)
      await runSeed()
      await saveReport(f); continue
    }
    // 否则：默认走 chat（与智能体对话）的便捷行为
    const ctx = { actionType: 'agent_message', body: line }
    const v = await evalCtx(ctx)
    console.log(fmtVerdict(v))
    const lab = (await ask('  标注 [o/f/m/回车]: '))?.trim().toLowerCase()
    if (['o', 'f', 'm'].includes(lab)) {
      labelledSessions.push({
        kind: 'msg', ctx, verdict: v,
        label: { o: 'ok', f: 'fp', m: 'miss' }[lab],
        note: '',
      })
      console.log('  ✔ 已记录')
    }
  }
  await saveReport(join(opts.report, `interactive-${Date.now()}.json`))
  rl.close()
  engine.shutdown()
}

const HELP_TEXT = [
  'help                           显示本帮助',
  'list [pattern]                 列出规则（可模糊匹配）',
  'show <ruleId|#seq>             查看某条规则的样本、当前命中情况',
  'eval <json>                    直接喂一个 InterventionContext JSON（顶层字段：actionType/toolName/params/...）',
  'chat                           进入与"智能体"对话模式（自然语言提问回以策略决策）',
  '       #tool=NAME <命令>       模拟工具调用（agent_tool_call）',
  '       #url=<URL>              模拟 HTTP 出站（http_request）',
  '       #read=<path>            模拟文件读取（read 工具）',
  '       #write=<path> <body>    模拟文件写入（write 工具）',
  '       行末回车会询问你是否标注 ok / fp / miss',
  'fuzz <ruleId> [N]              对该规则的样本做 N 次变异，验证规则稳健性',
  'attack                         跑 OWASP Top-10 攻击库',
  'matrix                         全量评测并打印每条规则 TP/FP/FN/TN + 指标',
  'totals                         全量评测并打印汇总',
  ':reset                         清空对话标注',
  ':save [path]                   写出报告（默认 reports/test-rules/interactive-<ts>.json）',
  ':quit / :q                     退出并自动出报告',
  '对其它任意行，默认会作为智能体消息回以策略决策。',
].join('\n')

// 让该脚本可作为库被其它脚本 import 调用
export const _internal = { samples, policyDoc, loaded, opts }

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main()
}
