#!/usr/bin/env node
/**
 * install-dev.mjs — 端到端 install 自动化 + UI 可见性自检.
 *
 * 一条命令 `pnpm install-dev` 完成 6 步流程 + 3-layer verify:
 *
 *   1. preflight    — 处理 pnpm 把 dev dep 推到 .ignored/ 的 esbuild 怪癖
 *   2. build        — tsc -b + scripts/build-client.mjs (生成 lib/index.js + lib/client.js)
 *   3. pack         — `pnpm pack --pack-destination install/` 产出 tarball
 *   4. plugin-add   — 在目标 DSH harness 上 `pnpm dsh plugin add <tarball>`
 *   5. restart-web  — kill 老 web + 后台启动新 web + 轮询端口 ready
 *   6. verify-3-layer
 *       (i)   layer state    — `pnpm dsh plugin list` 输出含 "layer" 而非 "plain dependency"
 *       (ii)  client bundle  — `${DSH_WEB_URL}/plugins/sst-security-control-dsh/client.js` 返回 200
 *       (iii) settings HTML — `${DSH_WEB_URL}/settings` HTML 含 "Security Monitor"
 *
 * 任一 step 失败: 标 `✗ FAIL at step <name>: <reason>`, exit 1, 不回滚已完成的
 * build/pack/plugin-add (留给操作员诊断). 全过: 输出 `✓ OK`, exit 0.
 *
 * 用法:
 *   pnpm install-dev                            # 全跑 + 3-layer verify
 *   pnpm install-dev --no-verify                # 跳过 verify
 *   pnpm install-dev --dry-run                  # 打印命令而不执行 (CI / 调试)
 *   pnpm install-dev --profile NAME             # 覆盖 DSH profile (默认 web)
 *   pnpm install-dev --web-url URL              # 覆盖 DSH web URL (默认 http://127.0.0.1:3080)
 *   DSH_HARNESS_DIR=../foo pnpm install-dev     # 覆盖 DSH 仓库路径 (默认 ../dsh-harness)
 *
 * 限制:
 *   - 本仓库无权改 host CLI 截胡 `--help` 的 bug (host `apps/cli/src/args.ts
 *     `parseDshArgs`). 脚本绕过方法: 传透 `plugin add <path>` 不调 `--help`.
 *   - macOS / Linux: 主测试平台. Windows (Git Bash / WSL): 未验证, 文档标注.
 * 不覆盖跨 profile 矩阵 / 容器化部署 / CI 自动 publish.
 */

import { existsSync, mkdirSync, statSync, readFileSync, readdirSync } from 'node:fs'
import { spawn, execFileSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dirname, '..')

class InstallDevError extends Error {
  constructor(step, reason) {
    super(`step=${step} reason=${reason}`)
    this.step = step
    this.reason = reason
  }
}

// ── arg / env parsing ──────────────────────────────────────────────────────

function parseArgs(argv) {
  const opts = {
    dryRun: false,
    skipVerify: false,
    profile: process.env.DSH_PROFILE || 'web',
    webUrl: process.env.DSH_WEB_URL || 'http://127.0.0.1:3080',
    harnessDir: process.env.DSH_HARNESS_DIR || join(ROOT, '..', 'dsh-harness'),
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--dry-run') opts.dryRun = true
    else if (a === '--no-verify') opts.skipVerify = true
    else if (a === '--profile') opts.profile = argv[++i]
    else if (a === '--web-url') opts.webUrl = argv[++i]
    else if (a === '--harness-dir') opts.harnessDir = argv[++i]
    else if (a === '--help' || a === '-h') {
      console.log('Usage: install-dev [--dry-run] [--no-verify] [--profile NAME] [--web-url URL] [--harness-dir DIR]')
      process.exit(0)
    } else {
      throw new InstallDevError('arg-parse', `unknown flag: ${a}`)
    }
  }
  return opts
}

// ── log helpers ────────────────────────────────────────────────────────────

const RESET = '\x1b[0m'
const DIM = '\x1b[2m'
const RED = '\x1b[31m'
const GREEN = '\x1b[32m'
const YELLOW = '\x1b[33m'
const CYAN = '\x1b[36m'

function makeLogger(dryRun) {
  return {
    info: (msg) => console.log(`${CYAN}▸${RESET} ${msg}`),
    ok: (msg) => console.log(`${GREEN}✓${RESET} ${msg}`),
    warn: (msg) => console.log(`${YELLOW}!${RESET} ${msg}`),
    err: (msg) => console.log(`${RED}✗${RESET} ${msg}`),
    dry: (msg) => console.log(`${DIM}· ${msg} (dry-run, skipped)${RESET}`),
    step: (n, msg) => console.log(`\n${GREEN}[${n}/6]${RESET} ${msg}`),
  }
}

// ── command runner ─────────────────────────────────────────────────────────

/**
 * Run a command. In dry-run mode, print it and return without executing.
 * Non-zero exit code → throw InstallDevError with the step name.
 */
function runOrDry(stepName, ctx, cmd, args, opts = {}) {
  const display = `${cmd} ${args.join(' ')}`
  if (ctx.dryRun) {
    ctx.log.dry(display)
    return { stdout: '', stderr: '', code: 0, dry: true }
  }
  ctx.log.info(`$ ${display}`)
  try {
    const stdout = execFileSync(cmd, args, {
      cwd: opts.cwd || ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: opts.timeout || 300_000,
      env: { ...process.env, ...(opts.env || {}) },
    })
    return { stdout, stderr: '', code: 0, dry: false }
  } catch (err) {
    const stdout = err.stdout?.toString() || ''
    const stderr = err.stderr?.toString() || ''
    const code = err.status ?? 1
    throw new InstallDevError(stepName, `command exited ${code}: ${display}\n${stderr || stdout}`)
  }
}

/** Async variant — captures stdout/stderr live (for long-running web server). */
function spawnBg(stepName, ctx, cmd, args, opts = {}) {
  const display = `${cmd} ${args.join(' ')}`
  if (ctx.dryRun) {
    ctx.log.dry(`${display} &`)
    return { pid: -1, dry: true }
  }
  ctx.log.info(`$ ${display} &`)
  const child = spawn(cmd, args, {
    cwd: opts.cwd || ROOT,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, ...(opts.env || {}) },
  })
  child.unref()
  return { pid: child.pid, dry: false, child }
}

// ── step 1: preflight ──────────────────────────────────────────────────────

function stepPreflight(ctx) {
  ctx.log.step(1, 'preflight — restore esbuild from .ignored/ if pnpm pushed it there')
  const ignored = join(ROOT, 'node_modules', '.ignored', 'esbuild')
  const canonical = join(ROOT, 'node_modules', 'esbuild')
  if (existsSync(ignored) && !existsSync(canonical)) {
    if (ctx.dryRun) {
      ctx.log.dry(`mv ${ignored} ${canonical}`)
      ctx.mvEsbuildRestored = true
      return
    }
    execFileSync('mv', [ignored, canonical], { stdio: 'inherit' })
    ctx.log.ok(`moved esbuild back: ${ignored} → ${canonical}`)
    ctx.mvEsbuildRestored = true
  } else if (existsSync(canonical)) {
    ctx.log.info('esbuild already at canonical path')
  } else {
    ctx.log.warn('esbuild not installed (will likely fail at build step)')
  }
}

function restorePreflight(ctx) {
  if (!ctx.mvEsbuildRestored) return
  const canonical = join(ROOT, 'node_modules', 'esbuild')
  const ignored = join(ROOT, 'node_modules', '.ignored', 'esbuild')
  if (existsSync(canonical) && !existsSync(ignored)) {
    try {
      execFileSync('mv', [canonical, ignored], { stdio: 'inherit' })
      console.log(`${DIM}· restored esbuild → ${ignored}${RESET}`)
    } catch (err) {
      console.error(`! failed to restore esbuild: ${err.message}`)
    }
  }
}

// ── step 2: build ──────────────────────────────────────────────────────────

function stepBuild(ctx) {
  ctx.log.step(2, 'build — tsc -b + build-client.mjs')
  runOrDry('build', ctx, 'node', ['scripts/prepare.mjs'], { cwd: ROOT })
  const clientJs = join(ROOT, 'lib', 'client.js')
  if (!ctx.dryRun && !existsSync(clientJs)) {
    throw new InstallDevError('build', `lib/client.js not produced at ${clientJs}`)
  }
  if (!ctx.dryRun) {
    const head = readFileSync(clientJs, 'utf8').slice(0, 200)
    if (!head.includes('window.__ModuleLoader__.load({') || !head.includes("id: 'sst-security-control-dsh'")) {
      throw new InstallDevError('build', 'lib/client.js header does not contain expected registration markers')
    }
    ctx.log.ok('lib/client.js header contains __ModuleLoader__.load({id: "sst-security-control-dsh", …})')
  }
}

// ── step 3: pack ───────────────────────────────────────────────────────────

function stepPack(ctx) {
  ctx.log.step(3, 'pack — npm pack → install/sst-security-control-dsh-*.tgz')
  const installDir = join(ROOT, 'install')
  if (!ctx.dryRun) mkdirSync(installDir, { recursive: true })
  runOrDry('pack', ctx, 'npm', ['pack', '--pack-destination', installDir], { cwd: ROOT })
  if (!ctx.dryRun) {
    const files = readdirSync(installDir).filter((f) => f.startsWith('sst-security-control-dsh-') && f.endsWith('.tgz'))
    if (files.length === 0) {
      throw new InstallDevError('pack', `no tarball in ${installDir}`)
    }
    files.sort()
    ctx.tarballPath = join(installDir, files[files.length - 1])
    const size = statSync(ctx.tarballPath).size
    if (size === 0) throw new InstallDevError('pack', `tarball is empty: ${ctx.tarballPath}`)
    ctx.log.ok(`tarball: ${ctx.tarballPath} (${(size / 1024).toFixed(1)} KB)`)
  }
}

// ── step 4: plugin-add ─────────────────────────────────────────────────────

function stepPluginAdd(ctx) {
  ctx.log.step(4, `plugin-add — register ${ctx.tarballPath || '<tarball>'} on profile=${ctx.profile}`)
  const harness = ctx.harnessDir
  if (!ctx.dryRun && !existsSync(harness)) {
    throw new InstallDevError('plugin-add', `harness dir not found: ${harness} (set DSH_HARNESS_DIR)`)
  }
  // Note: do NOT pass `--help` — host CLI's parseDshArgs intercepts --help
  // and falls through to pnpm help (see Out of Scope).
  runOrDry(
    'plugin-add',
    ctx,
    'pnpm',
    ['dsh', 'plugin', '--profile', ctx.profile, 'add', ctx.tarballPath || '<tarball>'],
    { cwd: harness, timeout: 180_000 },
  )
}

// ── step 5: restart-web ────────────────────────────────────────────────────

async function stepRestartWeb(ctx) {
  ctx.log.step(5, `restart-web — kill existing + start new on ${ctx.webUrl}`)
  if (ctx.dryRun) {
    ctx.log.dry(`pgrep -f 'bin.ts web --profile ${ctx.profile}'`)
    ctx.log.dry(`nohup node --import tsx/esm apps/cli/src/bin.ts web --profile ${ctx.profile} &`)
    ctx.log.dry(`curl -sI ${ctx.webUrl} (poll up to 30s)`)
    return
  }
  // 5a. find + kill existing web
  try {
    const pids = execFileSync('pgrep', ['-f', `bin.ts web --profile ${ctx.profile}`], { encoding: 'utf8' }).trim()
    if (pids) {
      for (const pid of pids.split('\n').filter(Boolean)) {
        try {
          process.kill(parseInt(pid, 10), 'TERM')
        } catch { /* already gone */ }
      }
      await sleep(1000)
      for (const pid of pids.split('\n').filter(Boolean)) {
        try {
          process.kill(parseInt(pid, 10), 0) // still alive?
          process.kill(parseInt(pid, 10), 'KILL')
        } catch { /* gone */ }
      }
      ctx.log.ok(`killed old web (pids: ${pids.replace(/\n/g, ',')})`)
    } else {
      ctx.log.info('no existing web process')
    }
  } catch {
    ctx.log.info('pgrep returned no matches')
  }

  // 5b. spawn new web
  const logPath = `/tmp/dsh-web-${ctx.profile}.log`
  spawnBg('restart-web', ctx, 'nohup', [
    'node', '--import', 'tsx/esm', 'apps/cli/src/bin.ts', 'web', '--profile', ctx.profile,
    '>', logPath, '2>&1',
  ], { cwd: ctx.harnessDir })
  ctx.log.info(`logs → ${logPath}`)

  // 5c. poll port
  const ready = await pollReady(ctx.webUrl, 30_000)
  if (!ready) throw new InstallDevError('restart-web', `web did not become ready at ${ctx.webUrl} within 30s`)
  ctx.log.ok(`web ready at ${ctx.webUrl}`)
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

async function pollReady(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const result = execFileSync('curl', ['-sI', '-o', '/dev/null', '-w', '%{http_code}', url], {
        encoding: 'utf8',
        timeout: 2000,
      }).trim()
      if (result.startsWith('2')) return true
    } catch { /* not ready yet */ }
    await sleep(500)
  }
  return false
}

// ── step 6: verify-3-layer ─────────────────────────────────────────────────

async function stepVerify(ctx) {
  if (ctx.skipVerify) {
    ctx.log.step(6, 'verify-3-layer — skipped (--no-verify)')
    return
  }
  ctx.log.step(6, 'verify-3-layer — layer state / client bundle URL / settings HTML')

  // 6 (i) layer state
  const listOut = runOrDry(
    'verify-layer-state',
    ctx,
    'pnpm',
    ['dsh', 'plugin', 'list', '--profile', ctx.profile],
    { cwd: ctx.harnessDir },
  )
  if (!ctx.dryRun) {
    if (!/sst-security-control-dsh/.test(listOut.stdout)) {
      throw new InstallDevError('verify-layer-state', 'plugin list does not mention sst-security-control-dsh')
    }
    if (!/\blayer\b/.test(listOut.stdout)) {
      throw new InstallDevError('verify-layer-state', 'plugin list does not show "layer" status (got plain dependency)')
    }
    ctx.log.ok('layer state: sst-security-control-dsh installed as layer')
  }

  // 6 (ii) client bundle URL
  const bundleUrl = `${ctx.webUrl}/plugins/sst-security-control-dsh/client.js`
  const bundleCheck = runOrDry(
    'verify-client-bundle',
    ctx,
    'curl',
    ['-sI', '-o', '/dev/null', '-w', '%{http_code}', bundleUrl],
    { cwd: ROOT, timeout: 10_000 },
  )
  if (!ctx.dryRun) {
    const code = bundleCheck.stdout.trim()
    if (!code.startsWith('2')) {
      throw new InstallDevError('verify-client-bundle', `GET ${bundleUrl} returned ${code}`)
    }
    ctx.log.ok(`client bundle URL: ${bundleUrl} (${code})`)
  } else {
    ctx.log.ok(`client bundle URL: ${bundleUrl}`)
  }

  // 6 (iii) settings HTML
  const html = runOrDry(
    'verify-settings-html',
    ctx,
    'curl',
    ['-s', `${ctx.webUrl}/settings`],
    { cwd: ROOT, timeout: 10_000 },
  )
  if (!ctx.dryRun && !/Security Monitor/.test(html.stdout)) {
    throw new InstallDevError('verify-settings-html', `GET ${ctx.webUrl}/settings HTML does not contain "Security Monitor"`)
  }
  ctx.log.ok('settings HTML contains "Security Monitor"')
}

// ── main ───────────────────────────────────────────────────────────────────

async function main() {
  let opts
  try {
    opts = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err.message)
    process.exit(2)
  }

  const ctx = {
    ...opts,
    log: makeLogger(opts.dryRun),
    mvEsbuildRestored: false,
    tarballPath: null,
  }

  process.on('SIGINT', () => {
    restorePreflight(ctx)
    process.exit(130)
  })

  console.log(`${CYAN}install-dev${RESET} profile=${ctx.profile} webUrl=${ctx.webUrl} harnessDir=${ctx.harnessDir}${opts.dryRun ? ' (DRY RUN)' : ''}${opts.skipVerify ? ' (no-verify)' : ''}`)
  console.log(`${DIM}  ROOT=${ROOT}${RESET}`)

  try {
    stepPreflight(ctx)
    stepBuild(ctx)
    stepPack(ctx)
    stepPluginAdd(ctx)
    await stepRestartWeb(ctx)
    await stepVerify(ctx)
  } catch (err) {
    if (err instanceof InstallDevError) {
      ctx.log.err(`FAIL at step ${err.step}: ${err.reason}`)
    } else {
      ctx.log.err(`FAIL (unexpected): ${err.stack || err.message}`)
    }
    restorePreflight(ctx)
    process.exit(1)
  }

  restorePreflight(ctx)
  if (ctx.skipVerify) {
    console.log(`\n${GREEN}✓ OK (unverified)${RESET}`)
  } else {
    console.log(`\n${GREEN}✓ OK${RESET}`)
  }
}

main().catch((err) => {
  console.error('unexpected:', err)
  process.exit(2)
})
