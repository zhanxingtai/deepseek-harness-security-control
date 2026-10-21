/**
 * /security CLI.
 *
 * Registers a top-level `security` command on the harness's `dsh-commands`
 * runtime. Subcommands:
 *
 *   - `status`   — quick dashboard: mode / event counts / block count /
 *                  warn count / last 24h count / uptime seconds.
 *   - `recent N` — last N (default 20) SPL block decisions, most recent
 *                  first. Reads the local NDJSON audit sink via
 *                  `src/utils/ndjsonTail.ts` (the reader does not hold
 *                  any lock; tolerates partial-line writes).
 *   - `rules`    — list enabled SPL rules with their declared `severity`
 *                  (spec §3) and decision. Read-only snapshot of the
 *                  loaded policy.
 *   - `reload`   — request a policy reload through the InterventionEngine
 *                  (the actual file re-read + tamper check stays inside
 *                  the engine's `requestReload()`).
 *
 * Graceful degradation: when `ctx.commands` is not available (the
 * marketplace node does not have `@deepseek-ai/dsh-commands` installed,
 * or the lockfile did not pin it to a 0.1.5-rc.2 version), the register
 * call is a no-op, a warning is emitted via `ctx.logger`, and — when a
 * `DebugLog` handle is passed — a
 * `surface_unavailable` breadcrumb is written to the operator-visible
 * debug log so the silent "no CLI" symptom leaves a persistent trace.
 * The plugin continues to function in audit / enforce modes without the
 * CLI surface.
 */
import type { Context, Logger } from '../types/external.js'
import { LocalNdjsonSink } from '../collectors/LocalNdjsonSink.js'
import { InterventionEngine } from '../intervention/InterventionEngine.js'
import type { DebugLog } from '../utils/debugLog.js'
import type { Config } from '../config.js'
import { tailNdjson, isBlockDecision } from '../utils/ndjsonTail.js'
import {
  clampLimit,
  scanOverviewAggregates,
  STARTUP_TS,
} from '../status/overview.js'
import type { BlockRow, OverviewSnapshot } from '../typert/descriptors.js'

/** Shape of the `dsh-commands` runtime we actually use. Kept narrow so
 *  the file builds even when the peer package is not installed (the
 *  plugin still type-checks against the local mirror). */
export interface CommandRuntimeShape {
  register(definition: CommandDefinition): () => void
}

export interface CommandDefinition {
  name: string
  description: string
  input?: { hint?: string }
  recordInput?: boolean
  handler(invocation: CommandInvocation): Promise<CommandResult> | CommandResult
}

export interface CommandInvocation {
  commandId: string
  agent?: { id?: string; name?: string }
  rawInput: string
  attachments?: unknown[]
  signal?: AbortSignal
}

export type CommandResult =
  | { kind: 'success'; text?: string; sourceEventSeq?: string }
  | { kind: 'error'; text: string }

/**
 * Result payload returned by `status`. Re-exported from the Typert
 * descriptor so the CLI side stays in sync with the DSH Web
 * settings page — both surfaces now render the same shape. The
 * canonical definition lives on `src/typert/descriptors.ts`.
 * collapsed the duplicated `SecurityStatus`
 * interface and the parallel `BlockRow` shape into single
 * `OverviewSnapshot` / `BlockRow` definitions on the descriptor.
 */
export type SecurityStatus = OverviewSnapshot

/** Per-row payload for `recent N`. Re-export of the Typert wire-level
 * `BlockRow` so the CLI side stays in sync with the DSH Web
 *  settings page — both surfaces now render the same shape. The
 *  canonical definition lives on `src/typert/descriptors.ts`. */
export type { BlockRow }

/**
 * Register the `/security` command on the harness's `dsh-commands`
 * runtime. Returns a disposer function the plugin can call during
 * shutdown. If the commands runtime is unavailable the disposer is a
 * no-op and a single warning is logged.
 */
export function registerSecurityCommand(
  ctx: Context,
  sink: LocalNdjsonSink,
  engine: InterventionEngine,
  config: Config,
  debugLog?: DebugLog,
): () => void {
  // Mirrors the `ctx.subprocess` access pattern in src/index.ts: the local
  // `Context` stub does not declare the `commands` service, so we reach
  // through a typed cast. When the marketplace node resolves the real
  // `@deepseek-ai/cordis` Context (which carries the `commands` field
  // through Cordis module declaration merging with `@deepseek-ai/dsh-commands`),
  // the cast resolves to the live runtime. When the peer is absent, the
  // lookup returns undefined and we log + return a no-op disposer.
  const commands = (ctx as unknown as { commands?: CommandRuntimeShape }).commands
  if (!commands) {
    ctx.logger.warn(
      '[SecurityMonitor] /security CLI not registered: ctx.commands is unavailable. ' +
        'Install @deepseek-ai/dsh-commands@0.1.5-rc.2 on the marketplace node to enable it.',
    )
    // BUG: the warn above is invisible in headless mode (the
    // harness logger doesn't pipe plugin warns to stdout). The debug log
    // is the operator-visible diagnostic plane — record the degradation
    // there too so "the /security command silently doesn't exist" is
    // triageable from `security-monitor-debug.log`.
    debugLog?.write('surface_unavailable', {
      surface: 'cli',
      reason: 'ctx.commands is unavailable',
      peer: '@deepseek-ai/dsh-commands@0.1.5-rc.2',
    })
    return () => {
      /* no-op disposer */
    }
  }

  const definition: CommandDefinition = {
    name: 'security',
    description:
      'Inspect the security monitor: mode / counts / recent blocks / rule list / reload policy.',
    input: { hint: 'status | recent [N] | rules | reload' },
    recordInput: true,
    async handler(invocation: CommandInvocation): Promise<CommandResult> {
      try {
        const sub = parseSubcommand(invocation.rawInput ?? '')
        switch (sub.cmd) {
          case 'status':
            return await statusCommand(sink, engine, config)
          case 'recent':
            return await recentCommand(sink, sub.args[0])
          case 'rules':
            return rulesCommand(engine)
          case 'reload':
            return reloadCommand(engine)
          default:
            return {
              kind: 'error',
              text: `unknown subcommand: ${sub.cmd}. try: status | recent [N] | rules | reload`,
            }
        }
      } catch (error: unknown) {
        return {
          kind: 'error',
          text: `internal error: ${error instanceof Error ? error.message : String(error)}`,
        }
      }
    },
  }

  const dispose = commands.register(definition)
  return () => {
    try {
      dispose()
    } catch (error: unknown) {
      // Disposer failures must not crash plugin shutdown.
      ;(ctx.logger as Logger).warn?.(
        `[SecurityMonitor] /security command dispose failed: ${String(error)}`,
      )
    }
  }
}

/**
 * Parse the user input after `/security ` into a subcommand + arg list.
 *
 *   - empty input        → `status` (the default)
 *   - `status`           → `status`
 *   - `recent 50`        → `recent` with `50` as the first arg
 *   - `recent`           → `recent` with no args (default 20 in the handler)
 *   - `   rules   `      → `rules` (trimmed)
 *   - `reload`           → `reload`
 *
 * Whitespace-separated; quoting/escaping is intentionally NOT supported —
 * the subcommands take simple integers or no args, and forcing the
 * operator to use a complex parser for an internal CLI would be over-
 * engineered.
 */
export function parseSubcommand(line: string): { cmd: string; args: string[] } {
  const trimmed = line.trim()
  if (trimmed.length === 0) return { cmd: 'status', args: [] }
  const parts = trimmed.split(/\s+/).filter(Boolean)
  return { cmd: parts[0] ?? 'status', args: parts.slice(1) }
}

async function statusCommand(
  sink: LocalNdjsonSink,
  engine: InterventionEngine,
  config: Config,
): Promise<CommandResult> {
  const loaded = engine.getLoadedPolicy()
  const path = sink.getLocalOutputPath() ?? '(sink not initialized)'
  // One single-pass scan produces the block counts
  // AND the Metrics-page aggregates (`last24hTotalCount`, `byLayer`)
  // — one full-file pass instead of separate `countAllBlocks` +
  // `countLast24hBlocks` scans.
  const agg = path !== '(sink not initialized)' ? await scanOverviewAggregates(sink) : null
  const status: SecurityStatus = {
    // Read the live mode from the config the plugin was
    // started with — operators running in enforce must see 'enforce'
    // here to confirm the engine is denying calls. Mirrors the
    // typert/host.ts overview() source.
    mode: config.mode,
    // Same source as typert/host.ts overview() — `total` comes
    // from the full-file scan, not the restart-reset `stats.flushed`.
    totalEvents: agg?.totalCount ?? 0,
    blockCount: agg?.blockCount ?? 0,
    last24hBlockCount: agg?.last24hBlockCount ?? 0,
    threatCount: agg?.threatCount ?? 0,
    last24hThreatCount: agg?.last24hThreatCount ?? 0,
    last24hTotalCount: agg?.last24hTotalCount ?? 0,
    byLayer: agg?.byLayer ?? {},
    uptimeSec: Math.max(0, Math.floor((Date.now() - STARTUP_TS) / 1000)),
    loadedRuleCount: loaded.rules.filter((r) => r.enabled).length,
    localOutputPath: path,
  }
  return { kind: 'success', text: renderStatus(status) }
}

async function recentCommand(
  sink: LocalNdjsonSink,
  rawLimit: string | undefined,
): Promise<CommandResult> {
  const limit = clampLimit(rawLimit, 20, 1, 500)
  const path = sink.getLocalOutputPath()
  if (!path) {
    return { kind: 'error', text: 'sink not initialized; no audit log path available' }
  }
  const rows = await tailNdjson(path, limit, { filter: isBlockDecision })
  return { kind: 'success', text: renderBlocks(rows as unknown as BlockRow[], limit) }
}

function rulesCommand(engine: InterventionEngine): CommandResult {
  const loaded = engine.getLoadedPolicy()
  const enabled = loaded.rules.filter((r) => r.enabled)
  const lines: string[] = []
  lines.push(`SPL rules: ${enabled.length} enabled / ${loaded.rules.length} loaded`)
  if (loaded.error) lines.push(`(policy load error: ${loaded.error})`)
  for (const r of enabled) {
    const risk = r.severity ?? 'low'
    const decision = r.action?.decision ?? 'allow'
    lines.push(`  - ${r.id}\tpriority=${r.priority}\trisk=${risk}\tdecision=${decision}`)
  }
  return { kind: 'success', text: lines.join('\n') }
}

function reloadCommand(engine: InterventionEngine): CommandResult {
  const result = engine.requestReload()
  if (result.ok) {
    return {
      kind: 'success',
      text: `policy reloaded: ${result.ruleCount} rules (${result.error ? 'warning: ' + result.error : 'ok'})`,
    }
  }
  return {
    kind: 'error',
    text: `reload rejected: ${result.error ?? 'unknown error'}`,
  }
}

function renderStatus(s: SecurityStatus): string {
  return [
    `mode: ${s.mode}`,
    `events: ${s.totalEvents} total, ${s.last24hTotalCount} in last 24h, ${s.last24hBlockCount} blocks in last 24h`,
    `block (all-time): ${s.blockCount}`,
    `threat events (规则命中含标记未拦截): ${s.threatCount} all-time, ${s.last24hThreatCount} in last 24h`,
    `by layer: ${renderByLayer(s.byLayer)}`,
    `rules loaded: ${s.loadedRuleCount}`,
    `uptime: ${s.uptimeSec}s`,
    `output: ${s.localOutputPath}`,
  ].join('\n')
}

/** Render the BY LAYER bucket map as a stable,
 *  sorted `k=v` comma list so CLI output diffs cleanly between runs.
 *  Empty map → `(none)` (e.g. sink not initialized). */
function renderByLayer(byLayer: Record<string, number>): string {
  const entries = Object.entries(byLayer).sort(([a], [b]) => a.localeCompare(b))
  if (entries.length === 0) return '(none)'
  return entries.map(([k, v]) => `${k}=${v}`).join(', ')
}

function renderBlocks(rows: BlockRow[], limit: number): string {
  if (rows.length === 0) return `no blocks found in last ${limit} events.`
  const header = `recent blocks: ${rows.length} (limit=${limit})`
  const body = rows.map((r) => {
    const ts = new Date(r.ts).toISOString()
    const session = r.session_id ?? '-'
    const tool = r.tool_name ?? '-'
    const reason = r.block_reason ?? r.decision_internal ?? r.decision
    return `  ${ts}\tsession=${session}\ttool=${tool}\treason=${reason}`
  })
  return [header, ...body].join('\n')
}
