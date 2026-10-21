#!/usr/bin/env node
/**
 * prepare.mjs — marketplace bundle prep script.
 *
 * 2026-09-18 S11: pre-publish pipeline that:
 *  1. Runs `tsc -b` to produce lib/ (TypeScript → ESM JavaScript + .d.ts).
 *  2. Validates the marketplace metadata block (`dsh`, `dshWorkshop`,
 *     `engines`, `peerDependencies`).
 *  3. Generates the marketplace manifest (a JSON file derived from
 *     `package.json` for the registry to consume), including the
 *     auto-derived formal `displayName`.
 *  3b. Generates the marketplace locale files `locale/en.json` /
 *     `locale/zh.json` (`meta.title` = formal name) — the real
 *     display-name contract read by dsh-app-boot `readPluginMeta`.
 *  4. Stamps the build-time git SHA into the package's `dsh.bundle.gitSha`
 *     field — needed for the marketplace "what version of the source is
 *     this tarball built from" audit trail.
 *
 * Idempotent — safe to run multiple times in a row. The marketplace
 * publish flow (S13) calls this script before `pnpm pack`.
 */
import { execSync } from 'node:child_process'
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { deriveFormalName } from './formalName.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')

function readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'))
}

function writeJson(p, obj) {
  writeFileSync(p, JSON.stringify(obj, null, 2) + '\n')
}

function fail(msg) {
  console.error(`✗ prepare.mjs: ${msg}`)
  process.exit(1)
}

function step(label) {
  console.log(`▶ ${label}`)
}

// 1a. tsc -b (host: src → lib)
step('Running tsc -b (host)...')
try {
  execSync('node node_modules/typescript/bin/tsc -b tsconfig.json', {
    cwd: root,
    stdio: 'inherit',
  })
} catch {
  fail('tsc -b (host) failed')
}

// 1b. esbuild bundle (client: src/client → lib/client.js wrapped in the
//     host's `__ModuleLoader__.load({id, factory})` form, 2026-09-18 S12).
//     Earlier versions used `--format=iife` with the registration call at
//     the bottom of the IIFE — esbuild placed `import { ... } from 'react'`
//     at the top of the IIFE, where it executed as `__require("react")` at
//     script load time and threw before the registration ever ran. The
//     fix mirrors the reference impl: bundle to
//     `--format=cjs` and wrap the CJS body inside the factory so the
//     `require("react")` calls resolve lazily via the factory's `require`
//     parameter (the host's `makeRequire`). See build-client.mjs header.
step('Running esbuild bundle (client → lib/client.js CJS+factory wrap)...')
const clientSrc = join(root, 'src', 'client')
if (existsSync(clientSrc)) {
  try {
    execSync('node scripts/build-client.mjs', {
      cwd: root,
      stdio: 'inherit',
    })
  } catch {
    fail('build-client.mjs (esbuild) failed')
  }
} else {
  console.log('  ↳ src/client/ not present — skipping client build')
}

// 2. Validate marketplace metadata
step('Validating marketplace metadata...')
const pkg = readJson(join(root, 'package.json'))
if (!pkg.dsh) fail('package.json is missing the "dsh" block')
if (!pkg.dshWorkshop) fail('package.json is missing the "dshWorkshop" block')
if (!pkg.dshWorkshop.permissions?.includes('network:none')) {
  fail('dshWorkshop.permissions must include "network:none"')
}
if (pkg.dependencies && Object.keys(pkg.dependencies).length > 0) {
  fail(`dependencies must be empty for marketplace form; found: ${Object.keys(pkg.dependencies).join(', ')}`)
}
if (!pkg.engines?.node) fail('engines.node is required')
if (!pkg.keywords?.includes('dsh')) fail('keywords must include "dsh"')

// 2b. dsh.bundle.patch is the marketplace loader's identity check
//     (apps/cli/src/plugin.ts:34-37 → exportsPatch() reads
//     `manifest.dsh?.bundle?.patch !== undefined`). Without it DSH
//     installs the package as a plain dependency and emits
//     `warning: <name> declares no dsh.bundle — installed as a plain
//     dependency, not a profile layer`. The path must point at a
//     file that lands in the tarball (`files[]`).
if (!pkg.dsh.bundle) {
  fail('package.json is missing "dsh.bundle"')
} else {
  const patchPath = pkg.dsh.bundle.patch
  if (!patchPath || typeof patchPath !== 'string') {
    fail('dsh.bundle.patch is required (DSH exportsPatch() reads it; see apps/cli/src/plugin.ts:34-37)')
  } else if (!existsSync(join(root, patchPath))) {
    fail(`dsh.bundle.patch points at missing file: ${patchPath}`)
  } else if (!pkg.files?.includes(patchPath.replace(/^\.\//, ''))) {
    fail(
      `dsh.bundle.patch (${patchPath}) is not in package.json#files — ` +
        'the tarball would ship without it and DSH would refuse to load the bundle',
    )
  }
}

// 3. Generate marketplace manifest
step('Writing marketplace manifest...')
const formalName = deriveFormalName(pkg.version)
// 2026-09-23 S16 G12-G15: uiHints / contracts / configSchema / activation
//     blocks (per the marketplace install spec — uiHints + contracts +
//     #configSchema + #activation). These 4 top-level blocks are the
//     marketplace consumer's read surface for "where is the UI", "what does
//     the plugin subscribe to", "what config can the operator edit", and
//     "when does the plugin activate". They are sibling keys (NOT nested
//     inside dshWorkshop / the install spec) — see
//     the marketplace UI naming spec §3
//     for the shape decision (option A: top-level).
//
//     All 4 blocks are static — they mirror the source-of-truth files
//     (src/handlers.ts, src/typert/descriptors.ts, src/config.ts,
//     src/client/section.tsx). Edit the static lists here when the source
//     files change; verify-artifacts.mjs §12 catches drift.
const tabLabels = {
  overview: { en: 'Metrics', zh: '指标', description: '聚合指标 / 拦截数 / 规则加载数 / 运行时长' },
  events: { en: 'Event Stream', zh: '事件流', description: '本地 NDJSON 原始事件浏览 / 过滤' },
  recent: { en: 'Top Blocks', zh: '阻断记录', description: '最近 N 条 SPL block 决策，最新在前' },
  config: { en: 'Config', zh: '配置', description: '当前生效 Config 快照 + 实时编辑 + Draft / LivePatch' },
}
const uiHints = {
  // 6 个「默认展开」config key — advanced: false 让 marketplace 自动渲染
  // settings 页时把这些字段优先暴露给 operator，无需展开高级折叠区。
  // 对应 `uiHints.intervention.enabled / mode / failStrategy` 等 9 个 key 的
  // 子集（DSH 形态下 L1 内嵌不可关闭的字段不进 uiHints）。
  'intervention.enabled': { advanced: false },
  'intervention.mode': { advanced: false },
  'intervention.failStrategy': { advanced: false },
  'runtimeHooks.enabledAtSubprocess': { advanced: false },
  'runtimeHooks.blockAtSubprocess': { advanced: false },
  'collector.localOutputPath': { advanced: false },
  // Tab 标签 — 与 src/client/section.tsx:139-143 的 4 Tab label 一一对应。
  // marketplace detail page 渲染时如果 locale 加载失败，回退到这里的 label。
  // 顶层 uiHints.tabs.security-monitor.label = 'SST Security Control'
  // 是单 Tab 形态；DSH 是 4 Tab 形态，key 是 plugin id 而非 security-monitor。
  tabs: Object.fromEntries(
    Object.entries(tabLabels).map(([id, lbl]) => [
      id,
      { label: lbl.en, labelZh: lbl.zh, description: lbl.description },
    ]),
  ),
  // Web 设置页入口 URL（panelUrl）
  // 走独立 HTTP 路由；DSH marketplace sandbox `network:none` 禁 HTTP，所以
  // panel 由 dsh-client-ui-slots 注入，不需独立 URL。`panelUrl: null` 让
  // marketplace consumer 知道走 host slot 注入（keyed slot 而非 HTTP route）。
  panelUrl: null,
  panelIntegration: 'dsh-client-ui-slots',
}

// 9 个 Cordis event 订阅 — src/handlers.ts:53-134 的全部 ctx.on 调用。
// 与 src/types/index.ts 的 Events union 对应（不含 'security/decision'，
// 后者已声明但未订阅，是为未来 cordis event 留位）。
const contractHooks = [
  'agent/created',
  'agent/pre-step',
  'tools/pre-execute',
  'tools/post-execute',
  'tools/result',
  'tools/execute',
  'agent/turn-stopping',
  'fs/observed',
  'fs/write-intent',
]

// 11 条 Typert RPC — src/typert/descriptors.ts#SECURITY_MONITOR_INVOCATIONS
// 的 11 个 method 名。manifest 暴露 method 名 + 简述（来自 descriptors 同一行
// 的 description 字段），保持服务端/客户端/manifest 三面对齐。
const contractGatewayMethods = [
  { method: 'overview', description: 'mode / event counts / uptime / loaded rule count' },
  { method: 'recentBlocks', description: 'last N SPL block decisions, newest first (default 20)' },
  { method: 'rules', description: 'list enabled SPL rules with priority / risk / decision' },
  { method: 'reload', description: 'force a policy reload; returns {ok, ruleCount, error?}' },
  { method: 'getConfig', description: 'current effective Config snapshot — read-only mirror' },
  { method: 'validateConfigPatch', description: 'validate a partial Config patch — returns errors / warnings / normalized' },
  { method: 'saveConfigDraft', description: 'persist a validated Config patch to ~/.dsh/security-monitor-config.draft.json' },
  { method: 'getConfigDraftStatus', description: 'check whether a pending draft file exists' },
  { method: 'previewLivePatch', description: 'classify a Config patch into 🟢/🟡/🔴 — read-only' },
  { method: 'applyLivePatch', description: 'apply the 🟢 subset of a Config patch at runtime' },
  { method: 'events', description: 'browse / filter raw collected events from local NDJSON' },
]

// 0 条 HTTP route — DSH marketplace sandbox `network:none` 禁止 plugin 自开
// HTTP 路由（形态学差异）。所有面板交互走
// dsh-client-ui-slots 注入 + dsh-typert-protocol RPC。
const contractHttpRoutes = []

// configSchema — src/config.ts 的 12 块顶层结构松散型 JSON Schema。
// 内部子结构走 `additionalProperties: true`，让
// marketplace 自动渲染 settings 页 + patch 校验有顶层 shape 但不强约束子字段
// （Schemastery 在 src/config.schema.ts 承担运行期精确校验）。
const configSchema = {
  type: 'object',
  additionalProperties: true,
  description: 'Top-level Config shape (src/config.ts). Marketplace settings page renders from these block names; precise validation lives on src/config.schema.ts Schemastery.',
  properties: {
    mode: {
      type: 'string',
      enum: ['audit', 'enforce'],
      description: 'Mode switch — `audit` records but never blocks; `enforce` denies per SPL decisions.',
      advanced: false,
    },
    collector: {
      type: 'object',
      additionalProperties: true,
      description: 'Local NDJSON sink + disk-low degradation.',
      properties: {
        localOutputPath: { type: 'string', description: 'Path to security-events.jsonl (~ expansion supported).' },
        flushIntervalMs: { type: 'number', description: 'Batch flush interval.' },
        diskLowWatermarkBytes: { type: 'number', description: 'Free-disk low watermark → enforce-only mode.' },
      },
    },
    application: {
      type: 'object',
      additionalProperties: true,
      description: 'Application-layer collector settings (session TTL, result cap, payload size).',
    },
    networkCapture: {
      type: 'object',
      additionalProperties: true,
      description: 'In-process http.request / fetch / dns.lookup monitor (no outbound).',
      properties: {
        enabled: { type: 'boolean', description: 'Master switch.' },
        networkEnabled: { type: 'boolean', description: 'Capture network calls.' },
      },
    },
    intervention: {
      type: 'object',
      additionalProperties: true,
      description: 'SPL policy engine settings (policy paths, fail strategy, inline guards).',
      properties: {
        enabled: { type: 'boolean', description: 'Master switch.' },
        mode: { type: 'string', enum: ['audit', 'enforce'], description: 'Inherited from top-level mode.' },
        // 2026-10-10: align with the runtime enum in
        // `src/config/schema.ts:170` — three values, not two. The
        // third `fail_open_high_risk_only` keeps deny-listing for
        // risk-flagged actions while falling open on the rest.
        failStrategy: { type: 'string', enum: ['fail_open', 'fail_closed', 'fail_open_high_risk_only'], description: 'On SPL eval error: fail_open (allow), fail_closed (block), or fail_open_high_risk_only (allow on routine actions, block on risk-flagged ones).' },
        policyPaths: { type: 'array', items: { type: 'string' }, description: 'YAML/JSON policy file paths.' },
      },
    },
    runtimeHooks: {
      type: 'object',
      additionalProperties: true,
      description: 'Pre-spawn Runtime Hook at ctx.subprocess.spawn resolveExecutable seam).',
      properties: {
        enabledAtSubprocess: { type: 'boolean', description: 'Audit-mode visibility on (default true).' },
        blockAtSubprocess: { type: 'boolean', description: 'Opt-in enforce: throw SpawnDeniedError / ResolveExecutableDeniedError on hit.' },
      },
    },
    sensitivePathGuard: {
      type: 'object',
      additionalProperties: true,
      description: 'Inline sensitive-path deny-list. 24-entry hardcoded list with config override.',
    },
    inlinePromptInjection: {
      type: 'object',
      additionalProperties: true,
      description: 'Inline prompt-injection guard. 24 regex fingerprints across 5 families.',
    },
    envPassthroughGuard: {
      type: 'object',
      additionalProperties: true,
      description: 'Inline env-passthrough deny-list. 6-key hardcoded list (LD_PRELOAD / NODE_OPTIONS / etc.).',
    },
    stdioMirror: {
      type: 'object',
      additionalProperties: true,
      description: 'stdio pipe mirror argv-sidecar wrapper. Writes to separate NDJSON.',
    },
    loopedToolDetector: {
      type: 'object',
      additionalProperties: true,
      description: 'Per-tool loop detector. Audit-only sliding-window rate-limiter.',
    },
    tokenUsageDetector: {
      type: 'object',
      additionalProperties: true,
      description: 'Token-usage burst detector. Audit-only sliding-window mean baseline.',
    },
  },
}

const manifest = {
  schemaVersion: 1,
  name: pkg.name,
  version: pkg.version,
  // Formal display name (governed by the platform naming convention) —
  // derived from `version` by scripts/formalName.mjs, prerelease trimmed.
  displayName: formalName,
  description: pkg.description,
  // marketplace presentation surface
  // — per the marketplace install spec). `icon` /
  // `homepage` / `category` / `tier` / `owner` / `capabilities` /
  // `supportChannels` / `source` are the registry's read surface for
  // the plugin detail page; everything below is derived from
  // package.json so the single source of truth stays at the npm
  // manifest. Missing fields fail the verify-artifacts §11 gate. See
  // the marketplace presentation spec §2 G2.
  icon: pkg.icon ?? null,
  homepage: pkg.homepage ?? null,
  author: pkg.author ?? null,
  category: pkg.marketplace?.category ?? 'security-monitoring',
  tier: pkg.marketplace?.tier ?? 'community',
  // 2026-09-25 oss-prep #3: generic placeholder default. Operators
  // override via package.json#marketplace.owner at publish time.
  owner: pkg.marketplace?.owner ?? 'sst-security-control-dsh-contributors',
  license: pkg.license,
  keywords: pkg.keywords,
  capabilities: pkg.marketplace?.capabilities ?? [
    'intercept.tool_call',
    'intercept.message_write',
    'intercept.agent_run',
    'collect.application',
    'collect.network_http',
    'collect.network_dns',
    'collect.process_spawn',
    'collect.process_resolve',
    'rpc.security.status',
    'rpc.security.recent',
    'rpc.security.rules',
    'rpc.security.reload',
  ],
  supportChannels: pkg.marketplace?.supportChannels ?? {
    issues: pkg.bugs?.url ?? null,
    docs: 'docs/',
    discussion: pkg.homepage ?? null,
  },
  source: {
    type: 'git',
    url: pkg.repository?.url ?? null,
    ref: readGitSha(),
  },
  engines: pkg.engines,
  dsh: pkg.dsh,
  dshWorkshop: pkg.dshWorkshop,
  peerDependencies: pkg.peerDependencies ?? {},
  // Files included in the bundle — derived from package.json `files` + .npmignore.
  files: pkg.files ?? [],
  // Git SHA, if available. We write the current HEAD; the marketplace
  // may override it on submit.
  gitSha: readGitSha(),
  buildTimestamp: new Date().toISOString(),
  // ─────────────────────────────────────────────────────────────────────
  // 4 marketplace protocol blocks (top-level).
  // ─────────────────────────────────────────────────────────────────────
  // G15: activation — plugin starts up when marketplace loads it (default).
  activation: { onStartup: true },
  // G12: uiHints — Tab labels + advanced flags + panel integration hint.
  uiHints,
  // G13: contracts — Cordis event hooks + Typert RPC + (empty) HTTP routes.
  contracts: {
    hooks: contractHooks,
    gatewayMethods: contractGatewayMethods,
    httpRoutes: contractHttpRoutes,
  },
  // G14: configSchema — top-level Config shape (loose, additionalProperties).
  configSchema,
}
// Stamp the manifest's nested `dsh.bundle` copy from the same source, so
// the two gitSha fields in the manifest cannot drift apart. `dsh:` above
// aliases `pkg.dsh` by reference, so this must happen BEFORE the manifest
// is serialised — mutating `pkg.dsh` after the write is too late, which is
// why the nested copy used to freeze at whatever the committed
// package.json happened to hold.
manifest.dsh = manifest.dsh ?? {}
manifest.dsh.bundle = manifest.dsh.bundle ?? {}
manifest.dsh.bundle.gitSha = manifest.gitSha
manifest.dsh.bundle.buildTimestamp = manifest.buildTimestamp
writeJson(join(root, 'lib', 'marketplace.manifest.json'), manifest)

// 3b. Marketplace locale files. The real display-name
//     contract for the marketplace UI is `locale/<lang>.json`
//     `{"meta": {"title", "description"}}`, read by dsh-app-boot
//     `readPluginMeta` (`en.json` is the anchor; `zh.json` mirrors it —
//     the formal name already carries the Chinese suffix, so both files
//     are byte-identical). Generation is deterministic per version; the
//     outputs are committed (not gitignored) so the files[] existence
//     gate and fresh checkouts see them without running prepare.
//
//     2026-09-23 S15: `meta.icon` / `meta.homepage` /
//     `meta.keywords` mirror the same fields from package.json so the
//     marketplace detail page renders the icon + jumps to the homepage
//     even when only the locale files are read. See
//     the marketplace presentation spec §2 G2/G3.
step('Writing marketplace locale files (locale/en.json, locale/zh.json)...')
mkdirSync(join(root, 'locale'), { recursive: true })
const localeDoc = {
  meta: {
    title: formalName,
    description: pkg.description,
    icon: pkg.icon ?? null,
    homepage: pkg.homepage ?? null,
    keywords: pkg.keywords ?? [],
  },
}
writeJson(join(root, 'locale', 'en.json'), localeDoc)
writeJson(join(root, 'locale', 'zh.json'), localeDoc)

// 4. git SHA / build timestamp live in the manifest ONLY.
//
//    This used to be stamped into package.json's `dsh.bundle` and written
//    back to disk, which meant every `prepack` left a modified package.json
//    in the working tree — a permanently dirty repo, and a committed
//    `gitSha` that froze at whatever HEAD was when it was last run. The
//    stamp is now emitted once, into `manifest.gitSha` /
//    `manifest.buildTimestamp` (see step 3), which is what the marketplace
//    reads and what `verify-artifacts.mjs` asserts on.
//
//    Keep package.json read-only here: `formalName.test.ts` and the
//    `description`/`icon`/`homepage`/`keywords` parity checks all read the
//    committed package.json, so mutating it mid-run made those checks
//    order-dependent on whether prepare had already run.

// The pre-marketplace `install/` scratch dir was removed when the
// marketplace form replaced install.sh — tarballs now land wherever
// `npm pack --pack-destination <dir>` points the caller. The cleanup
// loop below is a no-op when the dir is absent,
// and is gated on existsSync so the step never crashes the script.
{
  const installDir = join(root, 'install')
  if (existsSync(installDir)) {
    step('Cleaning install/...')
    for (const f of readdirSync(installDir).filter((n) => n.endsWith('.tgz'))) {
      unlinkSync(join(installDir, f))
    }
  }
}

console.log(`✓ prepare.mjs complete — git SHA ${manifest.gitSha ?? '(none)'}`)

function readGitSha() {
  try {
    return execSync('git rev-parse --short HEAD', { cwd: root, encoding: 'utf8' }).trim()
  } catch {
    return null
  }
}
