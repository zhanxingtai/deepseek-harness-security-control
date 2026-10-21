/**
 * Inline Self-Protection — hardcoded, non-overridable safety net.
 *
 * The three most critical SelfProtection rules (uninstall / kill-process /
 * restart-without-patch) live in TS source as a hardcoded safety net
 * that runs BEFORE `InterventionEngine`.
 *
 * Launcher / package-name literals are configurable via
 * `Config.inlineGuards.engineLaunchers` / `Config.inlineGuards.pluginPackageName`
 * — the marketplace distribution ships `DEFAULT_INLINE_GUARDS` as the
 * safe default; operators can extend but not shrink the set (the safety
 * net cannot be downgraded, but a different DSH distribution that uses
 * a different launcher command — e.g. a packaged `dsh` binary — can be
 * matched by adding it to `inlineGuards.engineLaunchers` in the patch).
 *
 * Design:
 *  - Operates directly on `InterventionContext` fields, bypassing the
 *    RuleMatcher / compile-cache SPL infrastructure (one less attack
 *    surface).
 *  - Only supports `block` decisions (other decision kinds are handled
 *    in the SPL layer).
 *  - Relationship to SPL: OR union — any inline match → block; SPL
 *    evaluation is skipped (saves latency, and inline cannot be softened
 *    by SPL rules).
 *  - Hits emit `inline_self_protection` events that are sourced
 *    separately from SPL decision events (the platform can alert on
 *    "safety-net fired" distinctly from ordinary SPL blocks).
 *
 * Why these three rules are inlined:
 *  - 001 uninstall: the plugin itself must not be uninstallable.
 *  - 014 kill-process: the plugin process must not be killable.
 *  - 015 restart-without-patch: the engine must not be restartable
 *    in "no patch" form.
 *
 * The remaining 18 SelfProtection rules stay in SPL — they are "patch"
 * rules, the inline three are "skeleton".
 */

import type { InterventionContext, SecurityDecision } from '../types/index.js'
import { canonicalizeCommand } from './RuleMatcher.js'
import { buildInlineGuardDecision } from '../utils/inlineGuardDecision.js'

/**
 * Inline-guards configuration consumed by the hardcoded safety net.
 *
 * Parameterised from the Config so a different DSH distribution
 * (custom launcher binary, renamed npm package) can be matched without
 * editing the plugin source. The marketplace ships `DEFAULT_INLINE_GUARDS`
 * so the default behaviour is byte-identical to the originally
 * hardcoded regex set.
 */
export interface InlineGuardsConfig {
  /**
   * Token strings that, when present in a tool command (after the standard
   * fragment-variable folding), identify the engine launcher surface.
   * Used to power the 015 (restart-without-patch) rule. The marketplace
   * default includes `pnpm dsh`, `npx dsh`, `node bin.ts`, plus
   * `systemd-run` / `systemctl` system-unit launchers.
   */
  engineLaunchers: string[]
  /**
   * The npm package name of the plugin itself. Used to power the 001
   * (uninstall) rule — matches `pnpm remove <name>`, `rm -rf <name>`,
   * etc. The marketplace default is `sst-security-control-dsh`.
   */
  pluginPackageName: string
  /**
   * Optional human-friendly log path / config file markers that, when
   * present, indicate a legitimate restart (used by 015's "patch present"
   * check). Default: `['security-monitor.patch.yml', 'security-monitor.patch.yaml']`.
   */
  patchMarkers: string[]
}

/**
 * The marketplace-shipped defaults. The hot path of the safety net is
 * "build regexes from this once at module init, then reuse forever" —
 * the regexes are cached per-call to the `evaluateInlineSelfProtection`
 * closure so the per-event overhead stays O(string scan).
 */
export const DEFAULT_INLINE_GUARDS: InlineGuardsConfig = {
  engineLaunchers: [
    'pnpm dsh',
    'pnpm exec dsh',
    'npx dsh',
    'npx dshe',
    'node bin.ts',
    'systemd-run',
    'systemctl',
  ],
  pluginPackageName: 'sst-security-control-dsh',
  patchMarkers: [
    'security-monitor.patch.yml',
    'security-monitor.patch.yaml',
  ],
}

/** Block codes used by the inline self-protection rules. Mirror the SPL blockCode values. */
export const INLINE_SELF_PROTECTION_CODES = {
  /** SPL SELF_PROTECTION_UNINSTALL_001 — plugin 卸载 */
  UNINSTALL: 'INLINE_SELF_PROTECTION_001',
  /** SPL SELF_PROTECTION_PROCESS_KILL_014 — kill 进程树 */
  KILL_PROCESS: 'INLINE_SELF_PROTECTION_014',
  /** SPL SELF_PROTECTION_RESTART_WITHOUT_PATCH_015 — 重启 engine 不带 patch */
  RESTART_NO_PATCH: 'INLINE_SELF_PROTECTION_015',
} as const

/**
 * Compiled regex bundle for the inline self-protection rules, built
 * once from an `InlineGuardsConfig`. Cached so repeated calls to
 * `evaluateInlineSelfProtection` with the same config don't re-parse
 * the launcher / package-name lists.
 */
interface CompiledGuards {
  /** Tool names that the 001 (uninstall) and 014 (kill) rules accept. */
  toolNames: Set<string>
  /** 001 regexes (uninstall patterns). */
  uninstallPatterns: RegExp[]
  /** 014 regexes (kill / fuser / pkill / taskkill). Hardcoded — the
   *  kill-tool surface is not launcher-specific. */
  killPatterns: RegExp[]
  /** 015 launch patterns (engine restarts). */
  restartLaunchPatterns: RegExp[]
  /** 015 patch-present patterns (legitimate restarts). */
  patchPresentPatterns: RegExp[]
}

// pwsh/powershell/cmd parity with KILL_TOOL_NAMES /
// RESTART_NO_PATCH_TOOL_NAMES: on Windows DSH dispatches shell commands
// through the `pwsh` tool. Without these names the uninstall gate silently
// no-ops for Windows shell invocations — the message-layer rule flags the
// intent while the tool layer lets the actual uninstall through.
const UNINSTALL_TOOL_NAMES = new Set([
  'exec',
  'execute',
  'run_command',
  'bash',
  'shell',
  'sh',
  'pwsh',
  'powershell',
  'powershell.exe',
  'cmd',
  'python',
  'node',
  'plugin',
  'plugin_uninstall',
  'manage_plugin',
  'pnpm',
  'npm',
  'yarn',
])

const KILL_TOOL_NAMES = new Set([
  'exec',
  'execute',
  'run_command',
  'bash',
  'shell',
  'sh',
  // PowerShell shells can invoke `Stop-Process` / `taskkill` (Windows-
  // native kill) and `kill -Id` (POSIX via pwsh). Without these names
  // the kill-pattern gate silently no-ops for
  // `pwsh -Command "Stop-Process -Id 1234"`, allowing the harness
  // PID tree to be terminated through an under-monitored shell.
  'pwsh',
  'powershell',
  // Windows cmd.exe runs `taskkill /PID <n>` and `taskkill /IM <name>`
  // natively; the KILL_COMMAND_PATTERNS already match `taskkill`.
  'cmd',
  'python',
  'python3',
  'node',
])

const RESTART_NO_PATCH_TOOL_NAMES = new Set([
  'exec',
  'execute',
  'run_command',
  'bash',
  'shell',
  'sh',
  'pwsh',
  'powershell',
  'cmd',
  'python',
  'python3',
  'node',
])

/**
 * Escape a string for safe inclusion as a literal in a `RegExp`.
 * Used to build the parameterised patterns from `InlineGuardsConfig`.
 */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * build KILL deny-list patterns from the configured
 * plugin-package-name + a fixed process-tree target set. The pre-tightening
 * patterns matched ANY `kill <pid>` invocation regardless of target —
 * an arbitrary PID blocked the same as a targeted process-tree kill. That
 * fired false positives for normal session-lifecycle work (test runners,
 * background processes, restart-of-unrelated-services).
 *
 * The tightened regex requires a SAME-LINE target reference to the engine /
 * plugin process tree within 140 chars (mirrors the SPL `SELF_PROTECTION_PROCESS_KILL_014`
 * window). Bare `kill <pid>` / `killall node` no longer hit the inline
 * safety net — they still flow through SPL (which has the same target-
 * aware rules) and get logged as `agent_tool_call`. Generic kill warnings
 * stay in the SPL layer (audit-only, not block): the inline layer is reserved
 * for `block` decisions, not alerts.
 *
 * The target token group is the same as SPL `SELF_PROTECTION_PROCESS_KILL_014` plus
 * the configured `pluginPackageName` so a renamed distribution still
 * matches itself.
 */
function buildKillPatterns(cfg: InlineGuardsConfig): RegExp[] {
  const plugin = escapeRegExp(cfg.pluginPackageName)
  const target = `(bin\\.ts|pnpm\\s+dsh|dsh\\s+(web|serve|run|ui|api)|deepseek-harness|security-monitor|${plugin})`
  return [
    // kill / killall / taskkill followed somewhere later by a target token
    new RegExp(`\\bkill\\b[^|;&\\n#]{0,140}?${target}`, 'i'),
    new RegExp(`\\b(killall|pkillall|taskkill)\\b[^|;&\\n#]{0,140}?${target}`, 'i'),
    // pkill / pgrep / pkillall -f <target>
    new RegExp(`\\b(pkill|pgrep|pkillall)\\b[^|;&\\n]{0,40}?-f\\b[^|;&\\n]{0,80}?${target}`, 'i'),
    // fuser -k / --kill followed by a target reference
    new RegExp(`\\bfuser\\b[^|;&\\n]{0,80}?-(k[a-zA-Z]*|--kill)\\b[^|;&\\n]{0,80}?${target}`, 'i'),
    // bare-numeric-PID: the patterns above
    // all require either a target token or a `-f` flag with a target
    // string. A bare `kill <digits>` names no process and so slips past
    // them. The harness host's own kill surface is
    // its children (terminated via direct signals, never through the
    // agent tool layer), so any `kill <pid>` reaching the agent's
    // tools/pre-execute gate is by definition operator- or attacker-
    // driven and matches the kill-bypass intent. The numeric-PID
    // pattern adds zero false-positive risk for legitimate work.
    new RegExp('\\bkill\\b\\s+\\d+\\b', 'i'),
    // bare `pkill <name>` without `-f`: the
    // existing pkill pattern requires `-f` (full-cmdline match), so a
    // process-name-only invocation bypasses it. Closing: any `pkill <name>`
    // where name is one of the engine-process basenames. Same rationale as
    // the numeric-PID pattern above.
    new RegExp('\\b(pkill|pkillall|killall)\\s+(?:pnpm|node|nodejs|npm|npx|tsx|ts-node|dsh)\\b', 'i'),
    // Windows parity: `taskkill /F /PID …` closes the bare-numeric-PID gap
    // on Windows; mirrors the numeric-PID pattern above.
    new RegExp('\\btaskkill\\b[^|;&\\n]{0,40}?/PID\\s+\\d+', 'i'),
  ]
}

/**
 * Build the compiled-guard bundle from the supplied config. The
 * `engineLaunchers` list is split into shell-launch tokens (must be
 * followed by `dsh`) and system-unit tokens (`systemd-run` /
 * `systemctl` followed by an engine command).
 */
function compileGuards(cfg: InlineGuardsConfig): CompiledGuards {
  const plugin = escapeRegExp(cfg.pluginPackageName)
  const launchers: RegExp[] = []
  for (const token of cfg.engineLaunchers) {
    const t = token.trim()
    if (!t) continue
    const esc = escapeRegExp(t)
    if (t === 'systemd-run' || t === 'systemctl') {
      // systemd-run / systemctl must be followed somewhere later by
      // `dsh` (the engine command). 140 chars is the same window
      // the hardcoded regex used.
      launchers.push(new RegExp(`\\b${esc}\\b[^|;&\\n]{0,140}?dsh`, 'i'))
    } else if (t.startsWith('node ')) {
      // `node <path>/bin.ts` is the engine launch surface when
      // running from a git checkout.
      launchers.push(new RegExp(`\\bnode\\b[^|;&\\n]{0,80}?bin\\.ts\\b`, 'i'))
    } else if (t === 'npx dshe') {
      // The `dshe` (DeepSeek Harness Engine) alias is the headless
      // runtime entry point — same protection.
      launchers.push(new RegExp(`\\bnpx?\\s+dshe\\b`, 'i'))
    } else if (t.startsWith('/') || t.startsWith('./') || t.startsWith('~')) {
      // Absolute or home-relative path launcher (e.g. `/opt/dsh/bin/dsh`).
      // The leading `/` is not a word boundary, so we match on the
      // path-literal directly (no `\b` anchors) — the path string is
      // distinctive enough on its own.
      launchers.push(new RegExp(esc, 'i'))
    } else {
      // Generic launcher — pnpm dsh, pnpm exec dsh, npx dsh, etc.
      // `pnpm exec` is already part of the literal — the regex below
      // matches `pnpm (exec )?dsh` so the literal entry is fine.
      launchers.push(new RegExp(`\\b${esc.replace(/ /g, '\\s+')}\\b`, 'i'))
    }
  }

  const patchMarkers: RegExp[] = cfg.patchMarkers.map((m) => {
    const esc = escapeRegExp(m)
    // Match `--patch <path>` where <path> may legitimately end with the
    // marker, OR a bare reference to `security-monitor.patch.yml` /
    // `<plugin>.patch.yml` / etc.
    return new RegExp(`--patch\\s+\\S*${esc}|${esc}`, 'i')
  })

  const uninstall: RegExp[] = [
    // pnpm/npm/yarn remove/rm ... <plugin>
    new RegExp(`\\b(npm|yarn|pnpm)\\s+(uninstall|remove|rm)\\b[^|;&\\n]*${plugin}`, 'i'),
    // dsh plugins|extensions uninstall ... <plugin>
    new RegExp(`\\bdsh\\s+(plugins?|extensions?)\\s+(uninstall|remove|disable|delete)\\b[^|;&\\n]*${plugin}`, 'i'),
    // rm/rmdir/mv/chmod/chown 插件目录
    new RegExp(`\\brm\\s+(-[a-zA-Z]*\\s+)?\\S*${plugin}`, 'i'),
    new RegExp(`\\brmdir\\s+\\S*${plugin}`, 'i'),
    new RegExp(`\\b(mv|chmod|chown)\\s+[^|;&\\n]*${plugin}`, 'i'),
  ]

  return {
    toolNames: UNINSTALL_TOOL_NAMES,
    uninstallPatterns: uninstall,
    killPatterns: buildKillPatterns(cfg),
    restartLaunchPatterns: launchers,
    patchPresentPatterns: patchMarkers,
  }
}

const DEFAULT_COMPILED = compileGuards(DEFAULT_INLINE_GUARDS)

/**
 * Evaluate the inline (hardcoded) self-protection rules against the given
 * intervention context. Returns a SecurityDecision (block) on the first hit,
 * or null when no inline rule fires. Null means the caller should fall
 * through to the regular SPL InterventionEngine.
 *
 * Order of checks: 001 → 014 → 015. The 3 rules are independent (different
 * action surfaces) so the order only matters for stable block_code in audit
 * events.
 *
 * The function is synchronous and never throws — any malformed input is
 * treated as "no match" (defensive).
 *
 * `guards` overrides the default launcher / package-name configuration.
 * Callers that don't supply one get `DEFAULT_INLINE_GUARDS`, so the
 * marketplace default behaviour is byte-identical to the originally
 * hardcoded regex set.
 */
export function evaluateInlineSelfProtection(
  ctx: InterventionContext,
  guards: InlineGuardsConfig = DEFAULT_INLINE_GUARDS,
): SecurityDecision | null {
  // The compiled-guard bundle is rebuilt on every call with a non-default
  // config. The default-guard cache is reused; non-default configs are
  // rare (test fixtures, custom distribution builds).
  const compiled = guards === DEFAULT_INLINE_GUARDS ? DEFAULT_COMPILED : compileGuards(guards)
  try {
    if (matchesUninstall(ctx, compiled)) {
      return buildInlineBlock(
        INLINE_SELF_PROTECTION_CODES.UNINSTALL,
        '该操作会卸载或禁用 ' + guards.pluginPackageName + ' 安全护栏；被内嵌硬编码 SelfProtection 阻断（不可被策略文件改写关闭）',
      )
    }
    if (matchesKill(ctx, compiled)) {
      return buildInlineBlock(
        INLINE_SELF_PROTECTION_CODES.KILL_PROCESS,
        '该操作会对 ' + guards.pluginPackageName + ' / engine 进程发信号；被内嵌硬编码 SelfProtection 阻断（不可被策略文件改写关闭）',
      )
    }
    if (matchesRestartNoPatch(ctx, compiled)) {
      return buildInlineBlock(
        INLINE_SELF_PROTECTION_CODES.RESTART_NO_PATCH,
        '该操作会重启 engine 但未带 --patch ' + guards.pluginPackageName + '；被内嵌硬编码 SelfProtection 阻断（不可被策略文件改写关闭）',
      )
    }
    return null
  } catch {
    // Defensive: any exception in the inline evaluator is treated as a
    // miss so the regular SPL pipeline can still attempt to evaluate.
    // Throwing here would block all tool calls when the inline module
    // is broken — exactly the wrong failure mode for a safety net.
    return null
  }
}

function matchesUninstall(ctx: InterventionContext, compiled: CompiledGuards): boolean {
  // actionType is restricted to `tool_call`
  // by design. The RuntimeHook spawn seam (`actionType:
  // 'process_start'`) is covered by the corresponding SPL
  // `SELF_PROTECTION_*` rules (001/010/011/012/013/014/015/016/017/018)
  // which declare `actionType: [tool_call, process_start]` on the
  // matching rule, AND by the inline `unpatched_engine` pre-eval gate
  // in `ApplicationCollector.evaluateTool` / `RuntimeHook.runEval` that
  // short-circuits engine-launcher binaries directly. Inline firing on
  // process_start would be duplicate work — the SPL layer is the live
  // cover at the spawn seam.
  if (ctx.actionType !== 'tool_call') return false
  const toolName = (ctx.toolName ?? '').toLowerCase()
  if (!compiled.toolNames.has(toolName)) return false
  const command = getCommandText(ctx)
  if (!command) return false
  const folded = canonicalizeCommand(command)
  return compiled.uninstallPatterns.some((rx) => rx.test(folded))
}

function matchesKill(ctx: InterventionContext, compiled: CompiledGuards): boolean {
  // See matchesUninstall — process_start is SPL-covered.
  if (ctx.actionType !== 'tool_call') return false
  const toolName = (ctx.toolName ?? '').toLowerCase()
  if (!KILL_TOOL_NAMES.has(toolName)) return false
  const command = getCommandText(ctx)
  if (!command) return false
  const folded = canonicalizeCommand(command)
  return compiled.killPatterns.some((rx) => rx.test(folded))
}

function matchesRestartNoPatch(ctx: InterventionContext, compiled: CompiledGuards): boolean {
  // See matchesUninstall — process_start is SPL-covered.
  if (ctx.actionType !== 'tool_call') return false
  const toolName = (ctx.toolName ?? '').toLowerCase()
  if (!RESTART_NO_PATCH_TOOL_NAMES.has(toolName)) return false
  const command = getCommandText(ctx)
  if (!command) return false
  const folded = canonicalizeCommand(command)
  if (!compiled.restartLaunchPatterns.some((rx) => rx.test(folded))) return false
  // (2) check patch present — if found, this is a legitimate restart
  if (compiled.patchPresentPatterns.some((rx) => rx.test(folded))) return false
  return true
}

/**
 * Extract the command string from the context, looking in the standard
 * `command` / `cmd` / `shell` / `script` / `exec` / `body` field aliases
 * (mirrors `RuleMatcher.getFieldValue` semantics; the inline module
 * re-implements a minimal version to avoid pulling in the full matcher
 * state for the hot path).
 */
function getCommandText(ctx: InterventionContext): string {
  const params = ctx.params ?? {}
  for (const key of ['command', 'cmd', 'shell', 'script', 'exec']) {
    const v = params[key]
    if (typeof v === 'string' && v.length > 0) return v
  }
  if (typeof ctx.body === 'string' && ctx.body.length > 0) return ctx.body
  return ''
}

function buildInlineBlock(blockCode: string, reason: string): SecurityDecision {
  // delegate to the shared
  // `buildInlineGuardDecision` so the four inline guards (self-
  // protection / sensitive-path / prompt-injection / env-passthrough)
  // produce byte-identical decision shapes. The local helper preserves
  // the existing two-arg call signature so the inline evaluator code
  // does not change.
  return buildInlineGuardDecision(
    {
      policyId: 'inline-self-protection',
      policyName: 'Inline Self-Protection (hardcoded, non-overridable)',
      blockCode,
    },
    reason,
  )
}
