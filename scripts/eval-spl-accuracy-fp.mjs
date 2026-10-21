#!/usr/bin/env node
/**
 * eval-spl-accuracy-fp.mjs — SPL 规则准确率/误报率评测器
 *
 * 用真实 InterventionEngine(enforce 模式)跑 scripts/spl-eval-corpus.mjs
 * 语料库(402 个攻击/良性样本),按"策略契约期望"逐条判定,产出:
 *
 *   - 攻击拦截率 / 检出率 / 漏报(FN)
 *   - 良性硬误报(block/escalate)/ 软误报(warn)/ by-design 告警
 *   - 变形绕过(evasion)专项检出率
 *   - 每条规则的命中审计(期望规则 vs 实际规则)
 *   - 从未命中的规则清单(覆盖缺口)
 *   - 交叉验证:project_standards verify-fp-risk.mjs 静态 FP 风险基线
 *     (2026-10-21 起该脚本上收到 project_standards/governance/spl-audit/scripts/,
 *      本仓副本已删；找不到时降级为 { error: 'not found' } 并在报告中标注)
 *
 * 口径说明:
 *   expect = 策略契约意图(来自规则 action/severity 语义与 YAML testCases),
 *   不是当前引擎行为。expect 与实际不一致即缺陷(漏检/误拦/优先级倒挂)。
 *   中危/低危 block 规则经 DecisionComposer 降级为 warn — 这被视为
 *   "契约内降级"(样本 expect 已编码为 warn),不算缺陷。
 *
 * 用法:
 *   node scripts/eval-spl-accuracy-fp.mjs            # 评测 + 打印 + 写报告
 *   node scripts/eval-spl-accuracy-fp.mjs --quiet    # 只写报告文件
 *   node scripts/eval-spl-accuracy-fp.mjs --no-fp-risk  # 跳过 fp-risk 交叉验证
 *
 * 前置: pnpm run build:host(lib/ 为构建产物,gitignored)
 */

import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')

// verify-fp-risk.mjs 自 2026-10-21 起归 project_standards 所有（规则测试能力集中化）。
// 查找顺序：$SPL_AUDIT_DIR → <repo>/../project_standards → <repo>/../project_standards/governance/spl-audit
function resolveFpRiskScript () {
  const rel = join('governance', 'spl-audit', 'scripts', 'verify-fp-risk.mjs')
  const candidates = [
    process.env.SPL_AUDIT_DIR ? join(process.env.SPL_AUDIT_DIR, 'scripts', 'verify-fp-risk.mjs') : null,
    join(root, '..', 'project_standards', rel),
    join(root, '..', 'project_standards', 'scripts', 'verify-fp-risk.mjs'),
  ].filter(Boolean)
  return candidates.find((p) => existsSync(p)) ?? null
}

const args = process.argv.slice(2)
const quiet = args.includes('--quiet')
const withFpRisk = !args.includes('--no-fp-risk')

// ---- 前置检查:lib 构建产物 ----
if (!existsSync(join(root, 'lib', 'intervention', 'InterventionEngine.js'))) {
  console.error('✗ lib/ 未构建。请先运行: pnpm run build:host')
  process.exit(1)
}

const { pathToFileURL } = await import('node:url')
const { normalizeConfig } = await import(pathToFileURL(join(root, 'lib', 'config.js')).href)
const { InterventionEngine } = await import(pathToFileURL(join(root, 'lib', 'intervention', 'InterventionEngine.js')).href)
const corpus = (await import(pathToFileURL(join(root, 'scripts', 'spl-eval-corpus.mjs')).href)).default
const jsyaml = await import('js-yaml')
const { readFileSync } = await import('node:fs')

const POLICY_PATH = join(root, 'policies', 'default-policy.spl.yaml')
const policyDoc = jsyaml.load(readFileSync(POLICY_PATH, 'utf8'))
const policyRuleIds = policyDoc.rules.map((r) => r.id)

// ---- 初始化引擎 ----
const tmpDir = mkdtempSync(join(tmpdir(), 'spl-eval-'))
const config = normalizeConfig({
  mode: 'enforce',
  collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
  intervention: { policyPath: POLICY_PATH, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
})
const engine = new InterventionEngine(config, {
  logger: { warn: () => {}, info: () => {}, debug: () => {}, error: () => {} },
})
engine.initialize()
const loadedPolicy = engine.getLoadedPolicy()
if (loadedPolicy.error) {
  console.error('✗ policy load error:', loadedPolicy.error)
  process.exit(1)
}

// ---- 跑语料 ----
const results = []
let evalMsTotal = 0
for (const sample of corpus) {
  const t0 = Date.now()
  const d = await engine.evaluate(sample.ctx)
  evalMsTotal += Date.now() - t0
  const rec = {
    id: sample.id,
    family: sample.family,
    truth: sample.truth,
    expect: sample.expect,
    expectRule: sample.expectRule ?? null,
    evasion: sample.evasion ?? false,
    note: sample.note ?? null,
    got: d.decision,
    rule: d.policy_id ?? null,
    blockCode: d.block_code ?? null,
    downgraded: d.severity_downgraded ?? false,
    latencyMs: d.latency_ms ?? 0,
    pass: d.decision === sample.expect,
  }
  if (sample.expectRule && d.policy_id && d.policy_id !== sample.expectRule) {
    rec.ruleMismatch = { expected: sample.expectRule, actual: d.policy_id }
  }
  results.push(rec)
}

// ---- 汇总指标 ----
const attacks = results.filter((r) => r.truth === 'attack')
const benigns = results.filter((r) => r.truth === 'benign')
const evasions = attacks.filter((r) => r.evasion)

const blocked = attacks.filter((r) => r.got === 'block')
const detected = attacks.filter((r) => r.got !== 'allow')
const fnAttacks = attacks.filter((r) => r.got === 'allow')
const evasionBlocked = evasions.filter((r) => r.got === 'block')
const evasionDetected = evasions.filter((r) => r.got !== 'allow')

// 良性分层:expect allow 的样本被 block/escalate = 硬误报;被 warn/modify = 意外软误报
const benignExpectAllow = benigns.filter((r) => r.expect === 'allow')
const benignExpectWarn = benigns.filter((r) => r.expect === 'warn')
const hardFp = benignExpectAllow.filter((r) => r.got === 'block' || r.got === 'escalate')
const softFpUnexpected = benignExpectAllow.filter((r) => r.got === 'warn' || r.got === 'modify')
const byDesignFlags = benignExpectWarn.filter((r) => r.got === 'warn' || r.got === 'modify')
const byDesignMissed = benignExpectWarn.filter((r) => r.got === 'allow')
const benignBlockedAnyway = benignExpectWarn.filter((r) => r.got === 'block' || r.got === 'escalate')

// 攻击失败分类
const attackMiss = attacks.filter((r) => !r.pass)
const underBlock = attackMiss.filter((r) => r.expect === 'block' && (r.got === 'warn' || r.got === 'escalate' || r.got === 'modify'))
const fullMiss = attackMiss.filter((r) => r.got === 'allow')
const overAction = attackMiss.filter((r) => r.expect !== 'block' && (r.got === 'block' || r.got === 'escalate'))

// family 表
const families = {}
for (const r of results) {
  const f = (families[r.family] ??= { total: 0, pass: 0, attack: 0, attackBlock: 0, attackDetect: 0, benign: 0, hardFp: 0, softFp: 0 })
  f.total++
  if (r.pass) f.pass++
  if (r.truth === 'attack') {
    f.attack++
    if (r.got === 'block') f.attackBlock++
    if (r.got !== 'allow') f.attackDetect++
  } else {
    f.benign++
    if (r.got === 'block' || r.got === 'escalate') f.hardFp++
    else if (r.got === 'warn' || r.got === 'modify') f.softFp++
  }
}

// per-rule 审计
const ruleAudit = {}
for (const r of results) {
  if (r.expectRule) {
    const a = (ruleAudit[r.expectRule] ??= { samples: 0, firedAsExpected: 0, firedOther: 0, missed: 0 })
    a.samples++
    if (r.got === 'allow' && !r.rule) a.missed++
    else if (r.ruleMismatch) a.firedOther++
    else a.firedAsExpected++
  }
}
const firedRuleIds = new Set(results.map((r) => r.rule).filter(Boolean))
const neverFired = policyRuleIds.filter((id) => !firedRuleIds.has(id))

// ---- fp-risk 交叉验证 ----
// verify-fp-risk.mjs 已于 2026-10-21 上收到 project_standards（规则测试能力集中化，
// 见 spl-test-centralization）。按 SPL_AUDIT_DIR 环境变量 → sibling 默认路径的顺序查找，
// 找不到时降级为 { error } 而不是让整份评测失败。
let fpRiskSummary = null
if (withFpRisk) {
  const fpScript = resolveFpRiskScript()
  if (!fpScript) {
    fpRiskSummary = { error: 'verify-fp-risk.mjs not found (set SPL_AUDIT_DIR or clone project_standards as sibling)' }
  } else {
    const r = spawnSync(process.execPath, [fpScript, `--policy=${POLICY_PATH}`, '--baseline', '-'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 30_000,
    })
    if (r.status === 0) {
      try {
        const baseline = JSON.parse(r.stdout)
        fpRiskSummary = {
          blockRules: baseline.blockRules,
          highRisk: baseline.highRiskCount,
          mediumRisk: baseline.mediumRiskCount,
          lowRisk: baseline.lowRiskCount,
          top: baseline.results.slice(0, 8).map((x) => ({ id: x.id, score: x.fp.score, tier: x.fp.tier })),
        }
      } catch {
        fpRiskSummary = { error: 'parse failure' }
      }
    } else {
      fpRiskSummary = { error: (r.stderr ?? '').slice(0, 200) || 'exit ' + r.status }
    }
  }
}

// ---- 报告 ----
const pct = (n, d) => (d === 0 ? '—' : ((n / d) * 100).toFixed(1) + '%')
const genDate = new Date().toISOString().slice(0, 10)
const evalDir = join(root, 'docs', 'eval')
mkdirSync(evalDir, { recursive: true })
const mdPath = join(evalDir, `spl-accuracy-fp-report-${genDate}.md`)
const jsonPath = join(evalDir, `spl-accuracy-fp-report-${genDate}.json`)

const L = []
L.push(`# SPL 规则准确率/误报率评测报告 — ${genDate}`)
L.push('')
L.push(`- 策略文件: \`${relative(root, POLICY_PATH)}\`(apiVersion=${policyDoc.apiVersion}, 规则 ${policyRuleIds.length} 条,引擎加载 ${loadedPolicy.rules.length} 条)`)
L.push(`- 评测方式: 真实 InterventionEngine.evaluate(),enforce 模式,语料库 ${results.length} 个样本(攻击 ${attacks.length} / 良性 ${benigns.length},含变形绕过 ${evasions.length} 个)`)
L.push(`- 判定口径: 与策略契约期望(规则 action+severity 语义)逐条比对;中/低危 block 经 DecisionComposer 降级 warn 属契约内行为,不计缺陷`)
L.push(`- 评估总耗时: ${evalMsTotal}ms(平均 ${(evalMsTotal / results.length).toFixed(2)}ms/样本)`)
L.push('')
L.push('## 一、总体指标')
L.push('')
L.push('| 指标 | 数值 |')
L.push('|---|---|')
L.push(`| 攻击样本拦截率(block) | ${blocked.length}/${attacks.length} (${pct(blocked.length, attacks.length)}) |`)
L.push(`| 攻击样本检出率(非 allow) | ${detected.length}/${attacks.length} (${pct(detected.length, attacks.length)}) |`)
L.push(`| 攻击漏报 FN(allow) | ${fnAttacks.length} |`)
L.push(`| 期望 block 实际降级/误动作 | ${underBlock.length}(warn/escalate/modify) |`)
L.push(`| 期望非 block 被过度拦截 | ${overAction.length} |`)
L.push(`| 良性硬误报(block/escalate) | ${hardFp.length}/${benignExpectAllow.length} (${pct(hardFp.length, benignExpectAllow.length)}) |`)
L.push(`| 良性意外软误报(warn/modify) | ${softFpUnexpected.length}/${benignExpectAllow.length} (${pct(softFpUnexpected.length, benignExpectAllow.length)}) |`)
L.push(`| 良性 by-design 告警(命中预期 warn) | ${byDesignFlags.length}/${benignExpectWarn.length} (${pct(byDesignFlags.length, benignExpectWarn.length)}) |`)
L.push(`| by-design 告警面被放行 | ${byDesignMissed.length} |`)
L.push(`| by-design 告警面被升级拦截 | ${benignBlockedAnyway.length} |`)
L.push(`| 变形绕过检出率 | ${evasionDetected.length}/${evasions.length} (${pct(evasionDetected.length, evasions.length)})(block ${evasionBlocked.length}) |`)
L.push(`| 契约总一致率 | ${results.filter((r) => r.pass).length}/${results.length} (${pct(results.filter((r) => r.pass).length, results.length)}) |`)
L.push('')

L.push('## 二、家族维度明细')
L.push('')
L.push('| family | 样本 | 契约一致 | 攻击 | 拦截 | 检出 | 良性硬误报 | 良性软误报 |')
L.push('|---|---|---|---|---|---|---|---|')
for (const [name, f] of Object.entries(families)) {
  L.push(`| ${name} | ${f.total} | ${f.pass}/${f.total} | ${f.attack} | ${f.attackBlock} | ${f.attackDetect} | ${f.hardFp} | ${f.softFp} |`)
}
L.push('')

const pushDetail = (title, rows, lineFn) => {
  L.push(`## ${title}`)
  L.push('')
  if (rows.length === 0) {
    L.push('(无)')
  } else {
    for (const r of rows) L.push(lineFn(r))
  }
  L.push('')
}

pushDetail('三、漏报清单(攻击 → allow,按严重度排序)', fullMiss, (r) =>
  `- **${r.id}** [${r.family}]${r.evasion ? ' ⚡evasion' : ''} expect=${r.expect} got=allow${r.note ? ` — ${r.note}` : ''}`)
pushDetail('四、欠拦截清单(期望 block → warn/escalate/modify)', underBlock, (r) =>
  `- **${r.id}** [${r.family}] expect=block got=${r.got} rule=${r.rule ?? '-'}${r.downgraded ? '(sev 降级)' : ''}${r.note ? ` — ${r.note}` : ''}`)
pushDetail('五、硬误报清单(良性 → block/escalate)', hardFp, (r) =>
  `- **${r.id}** [${r.family}] got=${r.got} rule=${r.rule ?? '-'}${r.note ? ` — ${r.note}` : ''}`)
pushDetail('六、意外软误报清单(期望 allow → warn/modify)', softFpUnexpected, (r) =>
  `- **${r.id}** [${r.family}] got=${r.got} rule=${r.rule ?? '-'}${r.note ? ` — ${r.note}` : ''}`)
pushDetail('七、过度拦截清单(期望 warn/allow → block/escalate)', overAction, (r) =>
  `- **${r.id}** [${r.family}] expect=${r.expect} got=${r.got} rule=${r.rule ?? '-'}${r.note ? ` — ${r.note}` : ''}`)
pushDetail('八、命中规则与期望规则不一致(优先级/拦截面偏差)', results.filter((r) => r.ruleMismatch && r.pass), (r) =>
  `- **${r.id}** expectRule=${r.ruleMismatch.expected} actual=${r.ruleMismatch.actual}(决策仍一致)`)
pushDetail('九、变形绕过专项(evasion 样本)', evasions, (r) =>
  `- **${r.id}** got=${r.got}${r.got === 'allow' ? ' ❌未检出' : ' ✅'} rule=${r.rule ?? '-'}${r.note ? ` — ${r.note}` : ''}`)

L.push('## 十、规则命中审计(带 expectRule 的样本)')
L.push('')
L.push('| 规则 | 样本数 | 如期命中 | 命中但非期望规则 | 未命中 |')
L.push('|---|---|---|---|---|')
for (const [id, a] of Object.entries(ruleAudit)) {
  L.push(`| ${id} | ${a.samples} | ${a.firedAsExpected} | ${a.firedOther} | ${a.missed} |`)
}
L.push('')

L.push('## 十一、评测期间从未命中的规则(覆盖缺口参考)')
L.push('')
if (neverFired.length === 0) L.push('(无)')
else for (const id of neverFired) L.push(`- ${id}`)
L.push('')
L.push('> 说明:未命中 ≠ 规则失效 — 部分规则依赖 riskFlags/assetType 等特定通道,语料未覆盖所有输入通道;但自保护/入侵防御主链规则应重点复核。')
L.push('')

if (fpRiskSummary) {
  L.push('## 十二、静态 FP 风险交叉验证(verify-fp-risk.mjs)')
  L.push('')
  if (fpRiskSummary.error) {
    L.push(`(不可用: ${fpRiskSummary.error})`)
  } else {
    L.push(`block 规则 ${fpRiskSummary.blockRules} 条:🔴≥5 分 ${fpRiskSummary.highRisk} 条 / 🟠3-4 分 ${fpRiskSummary.mediumRisk} 条 / 🟢≤2 分 ${fpRiskSummary.lowRisk} 条`)
    L.push('')
    L.push('Top FP 风险 block 规则:')
    for (const t of fpRiskSummary.top) L.push(`- ${t.tier} score=${t.score} ${t.id}`)
  }
  L.push('')
}

writeFileSync(mdPath, L.join('\n') + '\n', 'utf8')
writeFileSync(jsonPath, JSON.stringify({ generatedAt: genDate, policy: relative(root, POLICY_PATH), totals: { samples: results.length, attack: attacks.length, benign: benigns.length }, metrics: {
  blockRate: blocked.length / attacks.length,
  detectRate: detected.length / attacks.length,
  fn: fnAttacks.length,
  hardFp: hardFp.length,
  softFpUnexpected: softFpUnexpected.length,
  byDesignFlags: byDesignFlags.length,
  evasionDetectRate: evasions.length ? evasionDetected.length / evasions.length : null,
  contractPass: results.filter((r) => r.pass).length / results.length,
}, fpRiskSummary, families, results }, null, 2), 'utf8')

// ---- stdout 摘要 ----
if (!quiet) {
  console.log(`\n=== SPL 准确率/误报率评测 — ${genDate} ===`)
  console.log(`policy: ${policyRuleIds.length} rules (engine loaded ${loadedPolicy.rules.length}); corpus: ${results.length} samples`)
  console.log(`\n[攻击 ${attacks.length}] block ${blocked.length} (${pct(blocked.length, attacks.length)}) | detect ${detected.length} (${pct(detected.length, attacks.length)}) | FN(allow) ${fnAttacks.length} | 欠拦截 ${underBlock.length} | 过度 ${overAction.length}`)
  console.log(`[良性 ${benigns.length}] 硬误报 ${hardFp.length} (${pct(hardFp.length, benignExpectAllow.length)} of expect-allow ${benignExpectAllow.length}) | 意外软误报 ${softFpUnexpected.length} | by-design 告警命中 ${byDesignFlags.length}/${benignExpectWarn.length}`)
  console.log(`[evasion ${evasions.length}] detect ${evasionDetected.length} (${pct(evasionDetected.length, evasions.length)}) | block ${evasionBlocked.length}`)
  console.log(`[contract] ${results.filter((r) => r.pass).length}/${results.length} pass (${pct(results.filter((r) => r.pass).length, results.length)})`)
  const show = (label, rows, limit = 99) => {
    if (!rows.length) return
    console.log(`\n--- ${label} (${rows.length}) ---`)
    for (const r of rows.slice(0, limit)) {
      console.log(`  ${r.id} [${r.family}] expect=${r.expect} got=${r.got} rule=${r.rule ?? '-'}${r.downgraded ? ' (downgraded)' : ''}${r.note ? ' | ' + r.note : ''}`)
    }
  }
  show('漏报 FN(attack→allow)', fullMiss)
  show('欠拦截(expect block→warn/escalate)', underBlock)
  show('硬误报(benign→block/escalate)', hardFp)
  show('意外软误报(benign→warn)', softFpUnexpected)
  show('过度拦截(expect warn/allow→block/escalate)', overAction)
  console.log(`\n--- family 表 ---`)
  for (const [name, f] of Object.entries(families)) {
    console.log(`  ${name.padEnd(32)} total=${String(f.total).padStart(3)} pass=${String(f.pass).padStart(3)} attack=${String(f.attack).padStart(3)} block=${String(f.attackBlock).padStart(3)} detect=${String(f.attackDetect).padStart(3)} hardFP=${f.hardFp} softFP=${f.softFp}`)
  }
  console.log(`\n--- 从未命中的规则 (${neverFired.length}) ---`)
  for (const id of neverFired) console.log(`  ${id}`)
  if (fpRiskSummary && !fpRiskSummary.error) {
    console.log(`\n--- verify-fp-risk 基线: 🔴${fpRiskSummary.highRisk} 🟠${fpRiskSummary.mediumRisk} 🟢${fpRiskSummary.lowRisk} (block rules ${fpRiskSummary.blockRules}) ---`)
  }
  console.log(`\n报告: ${relative(root, mdPath)}\nJSON: ${relative(root, jsonPath)}`)
}

rmSync(tmpDir, { recursive: true, force: true })
