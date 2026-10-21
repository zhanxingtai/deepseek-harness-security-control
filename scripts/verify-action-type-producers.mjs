// verify-action-type-producers.mjs —
//   「策略声明的匹配维度，src/ 里必须真有运行时 emit 点」门禁。
//
// ## 为什么必须有这道门禁
//
// 审计发现 6 条 self-protection-asset-* 规则永久失效：match 声明 actionType:
// asset_change / asset_remove，但资产采集器已移除，src/ 下不存在任何
// `actionType: 'asset_change'` 的 emit 点。规则本身写得完全正确、testCases 全绿——
// 因为 verify-self-protection-runner.ts 与 spl-eval-corpus.mjs 自己构造
// asset_change 事件喂给引擎。这类缺陷的所有常规信号都是绿的（pnpm test /
// pnpm verify / SPL 审计 / 规则召回率全过）：**防护是 0，但报告显示 100% 有效。**
// 靠"人记得检查"防不住，只能靠机器每次构建时检查。
//
// ## 为什么是「两个」维度
//
// 第一版只查 actionType，当天就漏掉同一个病的下一层：escalate 规则匹配的是
// riskFlagsAny: ['self_protection_behavior']，而该旗标全仓零生产点——运行时真正
// push 的是另一个名字（self_protection_internal），且只在内部 guard 吞异常时上报。
// 同样是「防护 0 但报告显示有效」。同一信号有三个维度，逐个下沉：
// actionType → riskFlags → params 字段名；第三个见「已知边界」。
//
// ## 判定口径
//
//   1. 取 enabled 规则的 match.actionType（'*' 通配跳过）与 match.riskFlagsAny /
//      match.riskFlagsAll。
//   2. actionType 用 RuleLoader 的 ACTION_TYPE_ALIASES 归一到规范值——emit 点写的
//      通常是别名形态（http_request），策略里写的是规范形态（network_http）。别名表
//      从 lib/ 直接 import，不在本脚本里另抄一份。
//   3. 扫 src/**/*.ts：
//        actionType —— 认 `actionType: '<字面量>'` 属性赋值形态。只认属性赋值是
//          有意的：类型白名单、schema 声明、别名表都是裸字符串，天然不会误认。
//        riskFlags  —— 认 `flags.push('X')` / `flags.add('X')` /
//          `risk_flags = ['X']`。riskFlags.ts 里的 `self_protection_behavior:
//          'self_protection_behavior'` 是常量声明而非写入，不会误认。
//
// ## 已知边界（有意不覆盖）
//
//   - 只认字面量。ctx.actionType = someVar 形式查不到，会误报。仓内当前 emit 点
//     全是字面量，出现动态形式时本门禁需要跟进。
//   - 不判断 emit 点是否真的可达（可能整条采集链没接上）。那是另一道题。
//   - **不校验 params 字段名维度**。一条规则可能匹配 params.file_path 而运行时
//     从不填这个字段。未做的原因是 FIELD_ALIASES（path→file_path/…、
//     command→cmd/…）让「哪些字段名算合法」本身就有歧义，硬查会大量误报。
//     等积累出可信的字段清单再补第三维。

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')
const SRC = join(ROOT, 'src')

// ---------------------------------------------------------------- 工具

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (p.endsWith('.ts') && !p.endsWith('.test.ts') && !p.endsWith('.d.ts')) out.push(p)
  }
  return out
}

/** match 里的列表字段在 YAML 里可能是数组，也可能是裸标量。统一成数组。 */
function listOf(rule, key) {
  const v = rule?.match?.[key]
  if (v == null) return []
  return Array.isArray(v) ? v : [v]
}

/** 别名 → 规范值。未知值原样返回（loader 对未知值也是保留原值 + warning）。 */
function canonical(t, aliases) {
  return aliases[t] ?? t
}

// ---------------------------------------------------------------- 加载

const yamlMod = await import('js-yaml')
const policyPath = join(ROOT, 'policies', 'default-policy.spl.yaml')
const policy = yamlMod.load(readFileSync(policyPath, 'utf8'))

const { ACTION_TYPE_ALIASES } = await import(
  new URL('../lib/intervention/RuleLoader.js', import.meta.url).href
)

const enabledRules = (policy.rules ?? []).filter((r) => r?.enabled !== false)

// ---------------------------------------------------------------- 扫 emit 点

/** src 文件相对路径 */
const files = walk(SRC)
const readSrc = (f) => ({ text: readFileSync(f, 'utf8'), rel: relative(ROOT, f).replace(/\\/g, '/') })

/** 规范 actionType → emit 它的文件集合 */
const actionTypeProducers = new Map()
/** riskFlag 字面量 → emit 它的文件集合 */
const riskFlagProducers = new Map()

const add = (map, key, rel) => {
  if (!map.has(key)) map.set(key, new Set())
  map.get(key).add(rel)
}

for (const f of files) {
  const { text, rel } = readSrc(f)
  for (const m of text.matchAll(/\bactionType\s*:\s*['"]([a-z_]+)['"]/g)) {
    add(actionTypeProducers, canonical(m[1], ACTION_TYPE_ALIASES), rel)
  }
  // riskFlags 的三种写入形态。只认 flags / dataLeakFlags 这两个具名变量，
  // 避免把任意 Map 的 .add() 当成旗标生产者。
  for (const m of text.matchAll(/\b(?:flags|dataLeakFlags)\.(?:push|add)\(\s*['"]([a-z_]+)['"]/g)) {
    add(riskFlagProducers, m[1], rel)
  }
  for (const m of text.matchAll(/\brisk_flags\s*[:=]\s*\[([^\]]*)\]/g)) {
    for (const lit of m[1].matchAll(/['"]([a-z_]+)['"]/g)) add(riskFlagProducers, lit[1], rel)
  }
}

// ---------------------------------------------------------------- 判定

const orphans = []
let dimOk = 0

// --- 维度一：actionType ---
const declaredActions = new Map()
for (const r of enabledRules) {
  for (const raw of listOf(r, 'actionType')) {
    if (raw === '*') continue
    const c = canonical(raw, ACTION_TYPE_ALIASES)
    if (!declaredActions.has(c)) declaredActions.set(c, new Set())
    declaredActions.get(c).add(r.id)
  }
}

console.log('[1/2] actionType 生产者门禁（策略声明 → src/ emit 点）\n')
for (const [c, ruleIds] of [...declaredActions].sort((a, b) => a[0].localeCompare(b[0]))) {
  const sites = actionTypeProducers.get(c)
  if (sites && sites.size > 0) {
    dimOk += 1
    console.log(`  ✓ ${c.padEnd(18)} ${ruleIds.size} 条规则 ← ${[...sites].sort().join(', ')}`)
  } else {
    orphans.push({ dim: 'actionType', signal: c, ruleIds: [...ruleIds].sort() })
    console.log(`  ✗ ${c.padEnd(18)} ${ruleIds.size} 条规则声明了它，但 src/ 下没有 emit 点`)
  }
}

// --- 维度二：riskFlags ---
const declaredFlags = new Map()
for (const r of enabledRules) {
  for (const key of ['riskFlagsAny', 'riskFlagsAll']) {
    for (const raw of listOf(r, key)) {
      if (!declaredFlags.has(raw)) declaredFlags.set(raw, new Set())
      declaredFlags.get(raw).add(r.id)
    }
  }
}

console.log('\n[2/2] riskFlags 生产者门禁（策略声明 → src/ emit 点）\n')
if (declaredFlags.size === 0) {
  console.log('  · 策略中没有规则使用 riskFlagsAny / riskFlagsAll，本维度跳过')
}
for (const [flag, ruleIds] of [...declaredFlags].sort((a, b) => a[0].localeCompare(b[0]))) {
  const sites = riskFlagProducers.get(flag)
  if (sites && sites.size > 0) {
    dimOk += 1
    console.log(`  ✓ ${flag.padEnd(18)} ${ruleIds.size} 条规则 ← ${[...sites].sort().join(', ')}`)
  } else {
    orphans.push({ dim: 'riskFlag', signal: flag, ruleIds: [...ruleIds].sort() })
    console.log(`  ✗ ${flag.padEnd(18)} ${ruleIds.size} 条规则声明了它，但 src/ 下没有 emit 点`)
  }
}

// ---------------------------------------------------------------- 结论

console.log()
if (orphans.length === 0) {
  console.log(`✓ verify-action-type-producers.mjs: PASS (${dimOk} 个信号均有运行时生产者)`)
} else {
  for (const o of orphans) {
    console.log(`  [孤儿 ${o.dim}] "${o.signal}" — 声明它的规则:`)
    for (const id of o.ruleIds) console.log(`      - ${id}`)
    console.log(`    这些规则永远不会触发，且各自的 testCases 会全绿`)
    console.log(`    （测试自己伪造了该信号）。修法二选一：`)
    console.log(`      a) 重新引入能产出 "${o.signal}" 的采集器 / 派生函数`)
    console.log(`      b) 给这些规则加 enabled: false + notes 说明，并从上面列表移除`)
    console.log()
  }
  console.log(`✗ verify-action-type-producers.mjs: FAIL (${orphans.length} 个信号无生产者)`)
  process.exitCode = 1
}