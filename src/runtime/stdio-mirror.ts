/**
 * Stdio pipe mirror — argv-sidecar wrapper.
 *
 * The harness's `ctx.subprocess.spawn(spec)` returns a `SubprocessHandle`
 * SYNCHRONOUSLY (subprocess-local/src/index.ts:179 —
 * `SubprocessSpawnResult` in the plugin stub now mirrors that handle
 * shape). We cannot intercept child stdin/stdout/stderr mid-flight, so
 * this module IS the interception point: `RuntimeHook.wrap()` rewrites
 * the harness's spec to `[node, <abs>/lib/runtime/stdio-mirror.js,
 * --flags, --, ...originalArgv]` and hands the rewritten spec to the
 * harness. The harness then spawns US (a normal Node.js subprocess), and
 * we spawn the real child.
 *
 * What this script does (per stream):
 *   1. Create an internal pipe pair (`parent_in ↔ child_in`,
 *      `child_out ↔ parent_out`, `child_err ↔ parent_err`).
 *   2. `child_process.spawn(originalArgv[0], originalArgv.slice(1),
 *      { stdio: ['pipe','pipe','pipe'], cwd, env: { ...process.env,
 *      ...spec.env } })` — the child always uses pipes from our side.
 *   3. Run pump loops:
 *        - parent process.stdin → child.stdin (when stdin mirror/relay is on)
 *        - child.stdout → NDJSON writer (truncated) + parent process.stdout
 *          (when relay is on)
 *        - child.stderr → NDJSON writer (truncated) + parent process.stderr
 *          (when relay is on)
 *   4. Each chunk goes through `limitPayloadSize(limitBytes)` so the NDJSON
 * file is bounded per ticket acceptance criterion.
 *   5. Propagate signals (SIGTERM / SIGINT / SIGHUP / SIGBREAK / SIGUSR2)
 *      from parent to child; honour `spec.signal` (AbortSignal) and
 *      `spec.graceMs` (SIGTERM → SIGKILL escalation).
 *   6. On child exit: write a `runtime_stdio_mirror_exit` event with
 *      `exit_code` + `exit_signal`. Exit with the child's code.
 *
 * Marketplace sandbox concerns:
 *   - This wrapper is spawned by the HARNESS, not by the plugin. The
 *     marketplace `dshWorkshop.permissions: ["network:none"]` and
 *     `dependencies: {}` block plugin-side subprocess forking, but
 *     `ctx.subprocess.spawn` is the harness's normal tool path; we just
 *     rewrite which binary it spawns.
 *   - This script only writes to a local NDJSON file (configurable). No
 *     network, no remote sink.
 *
 * Audit re-merge convention:
 *   - Wrapper events use `event_id = `${wrapperPid}-${seq}`` so they are
 *     unique by construction across processes.
 *   - Audit consumers re-merge on `(ts, child_pid, session_id, event_id)`.
 *     The wrapper's `session_id` is the host plugin's session_id (passed
 *     in via `--session-id` so post-hoc correlation works even when the
 *     host plugin's NDJSON is rotated or lost). The run/agent/task/turn
 *     correlation ids ride alongside as `--run-id` / `--agent-id` /
 *     `--task-id` / `--turn-id` — the same keys RuntimeHook's
 *     runtime_*_intent events carry — so mirror events join the spawn's
 *     audit trail without re-parsing `run_id`. Flags left unspecified
 *     leave the field undefined (JSON.stringify omits it, never '').
 */
import { spawn, type ChildProcess, type StdioOptions } from 'node:child_process'
import { appendFileSync, chmodSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname as pathDirname } from 'node:path'
import { EOL, hostname } from 'node:os'
import { limitPayloadSize } from '../utils/redact.js'
import { redactArgvEntries, redactStreamContent } from '../utils/contentRedactor.js'

// ---------------------------------------------------------------------------
// Argv contract — see RuntimeHook.mirrorWrap() in the host plugin for the
// producer side. Keep these names in sync.
//
// The child's env overrides do NOT ride the argv
// as `--env=<JSON>` anymore. Linux `/proc/<pid>/cmdline` is world-readable,
// so any local user could scrape the wrapper's argv and recover
// `spec.env`, which routinely carries tokens / API keys. The JSON now
// travels in the wrapper's OWN process environment under
// `DSH_MIRROR_ENV_JSON`: `/proc/<pid>/environ` is readable only by the
// owner (and root). The trade-off is documented where the var is
// consumed (parseWrapperArgv) and stripped before the business child is
// spawned (runWrapper).
// ---------------------------------------------------------------------------

/**
 * Process-env var through which the host hands the wrapper the
 * JSON-serialised child env (`Record<string,string>` formerly sent as
 * `--env=<JSON>` on argv). Owner-only `/proc/<pid>/environ` beats
 * world-readable `/proc/<pid>/cmdline` — see the argv-contract note
 * above. Exported so the host side (stdioMirrorEntry.ts) references the
 * same name instead of a drifting literal.
 */
export const MIRROR_ENV_VAR = 'DSH_MIRROR_ENV_JSON'

/** Per-stream mirror config derived from spec.stdio + the host plugin's
 *  StdioMirrorConfig. mode ∈ {'inherit','pipe','ignore'}; mirror=true
 *  means write chunks to NDJSON; relay=true means also forward to the
 *  parent's matching fd. */
export interface StdioStreamSpec {
  mode: 'inherit' | 'pipe' | 'ignore'
  mirror: boolean
  relay: boolean
}

export interface StdioMirrorSpec {
  stdin: StdioStreamSpec
  stdout: StdioStreamSpec
  stderr: StdioStreamSpec
}

/** CLI flags we parse. Mirrors the spec input from `RuntimeHook.mirrorWrap`. */
interface ParsedArgs {
  stdioSpec: StdioMirrorSpec
  limitBytes: number
  outputPath: string
  statusPath: string
  sessionId: string | undefined
  /** Run-level correlation ids — the same keys RuntimeHook's
   *  runtime_*_intent events carry (`session_id` / `run_id` /
   *  `agent_id` / `task_id` / `turn_id`). Absent flags stay undefined and
   *  JSON.stringify then omits the field from the event (never an empty
   *  string). */
  runId: string | undefined
  agentId: string | undefined
  taskId: string | undefined
  turnId: string | undefined
  childArgv: string[]
  cwd: string | undefined
  env: Record<string, string> | undefined
  /** : SIGTERM → SIGKILL escalation window. */
  graceMs: number | undefined
}

const DEFAULT_LIMIT_BYTES = 1024 * 1024

/**
 * Parse `process.argv.slice(2)` into the contract above. Throws
 * `Error('wrapper_argv_invalid: …')` on any malformed flag — the host
 * plugin catches the throw, writes a `runtime_stdio_mirror_error` event,
 * and falls through to a non-mirrored spawn (fail-open per `failOpenOnError`).
 */
export function parseWrapperArgv(argv: readonly string[]): ParsedArgs {
  let stdioSpecJson: string | undefined
  let limitBytes = DEFAULT_LIMIT_BYTES
  let outputPath: string | undefined
  let statusPath: string | undefined
  let sessionId: string | undefined
  let runId: string | undefined
  let agentId: string | undefined
  let taskId: string | undefined
  let turnId: string | undefined
  let cwd: string | undefined
  let parsedGraceMs: number | undefined

  let i = 0
  while (i < argv.length) {
    const a = argv[i]
    if (a === '--') {
      i++
      break
    }
    if (typeof a !== 'string' || !a.startsWith('--')) {
      throw new Error(`wrapper_argv_invalid: unexpected positional ${JSON.stringify(a)}`)
    }
    const eq = a.indexOf('=')
    const key = eq >= 0 ? a.slice(0, eq) : a
    const inlineVal = eq >= 0 ? a.slice(eq + 1) : undefined
    const takeNext = (): string => {
      if (inlineVal !== undefined) return inlineVal
      const v = argv[++i]
      if (typeof v !== 'string') throw new Error(`wrapper_argv_invalid: ${key} requires a value`)
      return v
    }
    switch (key) {
      case '--stdio-spec':
        stdioSpecJson = takeNext()
        break
      case '--limit-bytes':
        limitBytes = Number.parseInt(takeNext(), 10)
        if (!Number.isFinite(limitBytes) || limitBytes < 1) {
          throw new Error(`wrapper_argv_invalid: --limit-bytes must be a positive integer`)
        }
        break
      case '--output':
        outputPath = takeNext()
        break
      case '--status-path':
        statusPath = takeNext()
        break
      case '--session-id':
        sessionId = takeNext()
        break
      case '--run-id':
        runId = takeNext()
        break
      case '--agent-id':
        agentId = takeNext()
        break
      case '--task-id':
        taskId = takeNext()
        break
      case '--turn-id':
        turnId = takeNext()
        break
      case '--cwd':
        cwd = takeNext()
        break
      case '--grace-ms': {
        // SIGTERM → SIGKILL escalation window.
        // Only positive numbers are accepted; non-positive values are
        // treated as "no grace escalation" so a misconfigured host
        // doesn't accidentally kill the child instantly.
        const raw = Number.parseInt(takeNext(), 10)
        if (!Number.isFinite(raw) || raw <= 0) {
          throw new Error(`wrapper_argv_invalid: --grace-ms must be a positive integer`)
        }
        parsedGraceMs = raw
        break
      }
      default:
        throw new Error(`wrapper_argv_invalid: unknown flag ${key}`)
    }
    i++
  }

  if (stdioSpecJson === undefined) throw new Error('wrapper_argv_invalid: --stdio-spec is required')
  if (outputPath === undefined) throw new Error('wrapper_argv_invalid: --output is required')
  if (statusPath === undefined) throw new Error('wrapper_argv_invalid: --status-path is required')

  let stdioSpec: StdioMirrorSpec
  try {
    stdioSpec = JSON.parse(stdioSpecJson) as StdioMirrorSpec
  } catch (e) {
    throw new Error(`wrapper_argv_invalid: --stdio-spec is not valid JSON: ${(e as Error).message}`)
  }
  stdioSpec = validateStdioSpec(stdioSpec)

  let env: Record<string, string> | undefined
  // The child env arrives via the wrapper's OWN process environment
  // (host-injected `DSH_MIRROR_ENV_JSON`), not via argv.
  // Rationale: `/proc/<pid>/cmdline` is world-readable on Linux while
  // `/proc/<pid>/environ` is owner/root-only — argv was a cleartext
  // leak of `spec.env` (tokens / API keys) to any local user. An empty
  // or absent var means "no child env overrides" (the child then
  // inherits the wrapper's environment, as before). A non-empty var
  // that fails to parse is a host-side corruption and fails closed
  // with the same `wrapper_argv_invalid` contract as a malformed flag.
  const envJson = process.env[MIRROR_ENV_VAR]
  if (envJson !== undefined && envJson.length > 0) {
    try {
      env = JSON.parse(envJson) as Record<string, string>
    } catch (e) {
      throw new Error(`wrapper_argv_invalid: ${MIRROR_ENV_VAR} is not valid JSON: ${(e as Error).message}`)
    }
  }

  const childArgv = argv.slice(i)
  if (childArgv.length === 0) {
    throw new Error('wrapper_argv_invalid: missing child argv after `--`')
  }

  return {
    stdioSpec,
    limitBytes,
    outputPath,
    statusPath,
    sessionId,
    runId,
    agentId,
    taskId,
    turnId,
    childArgv,
    cwd,
    env,
    graceMs: parsedGraceMs,
  }
}

function validateStdioSpec(raw: unknown): StdioMirrorSpec {
  if (!raw || typeof raw !== 'object') {
    throw new Error('wrapper_argv_invalid: stdio-spec must be an object')
  }
  const r = raw as Record<string, unknown>
  const norm = (s: unknown, key: string): StdioStreamSpec => {
    if (!s || typeof s !== 'object') {
      throw new Error(`wrapper_argv_invalid: stdio-spec.${key} must be an object`)
    }
    const ss = s as Record<string, unknown>
    const mode = ss.mode
    if (mode !== 'inherit' && mode !== 'pipe' && mode !== 'ignore') {
      throw new Error(`wrapper_argv_invalid: stdio-spec.${key}.mode must be inherit|pipe|ignore`)
    }
    return {
      mode,
      mirror: ss.mirror === true,
      relay: ss.relay === true,
    }
  }
  return {
    stdin: norm(r.stdin, 'stdin'),
    stdout: norm(r.stdout, 'stdout'),
    stderr: norm(r.stderr, 'stderr'),
  }
}

// ---------------------------------------------------------------------------
// NDJSON event emission. The wrapper writes JSONL to the host plugin's
// NDJSON file by default (stdio mirror NDJSON
// unification) — wrapper events are interleaved with host events on the
// same ts axis and audit consumers read ONE file. Override
// `stdioMirror.outputPath` to point at a different volume for forensic
// isolation when needed.
//
// event_id is `${wrapperPid}-${seq}` so it is unique by construction
// across processes (no risk of collision with host events whose ids are
// uuid-like; the `wrapperPid-` prefix namespaces every wrapper event).
// ---------------------------------------------------------------------------

let writeSeq = 0
const wrapperPid = process.pid

function makeEventId(seq: number): string {
  return `${wrapperPid}-${seq}`
}

function writeEvent(outputPath: string, event: Record<string, unknown>): void {
  let line: string
  try {
    line = JSON.stringify(event) + EOL
  } catch {
    // Circular refs / BigInts are not JSON-serialisable; we still try to
    // emit a minimal event so the audit trail isn't silent.
    line = JSON.stringify({
      comm: 'sst-security-control-dsh',
      event_id: makeEventId(writeSeq++),
      event_type: 'runtime_stdio_mirror_error',
      layer: 'application',
      source_layer: 'runtime',
      ts: Date.now(),
      timestamp: Date.now(),
      pid: process.pid,
      collection_method: 'stdio_mirror',
      wrapper_pid: wrapperPid,
      error_message: 'event_serialize_failed',
      host_id: hostname(),
      container_id: process.env.CONTAINER_ID || 'host',
    }) + EOL
  }
  try {
    appendFileSync(outputPath, line, { encoding: 'utf8' })
  } catch {
    // Disk-full / perms — best effort. We can't do anything useful here.
  }
}

function ensureOutputDir(outputPath: string): void {
  try {
    mkdirSync(pathDirname(outputPath), { recursive: true })
  } catch {
    // best effort — appendFileSync will surface ENOENT on its own
  }
}

/**
 * merge two pre-sorted, pre-deduped `redactedKeys`
 * arrays into one sorted, deduped list. The argv-side list and the
 * per-chunk content list are kept separately so `runWrapper` can hoist
 * argv redaction once and `startPump` can append per-chunk content
 * keys without walking argv again. Both inputs come from the
 * `redactArgvEntries` / `redactStreamContent` helpers, which already
 * sort + dedupe — so the merge is a Set-union + sort.
 */
function mergeRedactedKeys(
  a: readonly string[],
  b: readonly string[],
): string[] {
  if (a.length === 0) return [...b]
  if (b.length === 0) return [...a]
  const set = new Set<string>(a)
  for (const k of b) set.add(k)
  return [...set].sort()
}

// ---------------------------------------------------------------------------
// Pump loop — reads chunks from a ReadableStream, writes to (a) NDJSON
// (truncated, via synchronous appendFileSync) and optionally (b) a
// WritableStream (relay to parent fd). Per-chunk synchronous writes keep
// the audit trail loss-free for short-lived commands; the previous
// queue + 50ms-interval design dropped chunks when the source stream's
// `end`/`close` fired before the first tick (the harness's pipe-mode
// case for stdin reached EOF immediately).
// ---------------------------------------------------------------------------

interface PumpStats {
  bytes: number
  chunks: number
}

function startPump(opts: {
  outputPath: string
  stream: NodeJS.ReadableStream | null
  relay: NodeJS.WritableStream | null
  direction: 'parent_to_child' | 'child_to_parent'
  streamName: 'stdin' | 'stdout' | 'stderr'
  limitBytes: number
  childPid: number
  childArgv: readonly string[]
  /**
   * argv redaction is computed ONCE in `runWrapper`
   * and threaded through here so every per-chunk mirror event carries the
   * same redacted `cmdline` and the same `argv` redactedKeys. Without this
   * hoisting each event would re-walk argv — cheap, but the deterministic
   * shape (one redacted cmdline, one argv-side redactedKeys list merged
   * with the per-chunk content keys) keeps the audit trail easy to diff.
   */
  redactedArgv: readonly string[]
  argvRedactedKeys: readonly string[]
  sessionId: string | undefined
  runId: string | undefined
  agentId: string | undefined
  taskId: string | undefined
  turnId: string | undefined
  childExited: { value: boolean }
}): PumpStats {
  const stats: PumpStats = { bytes: 0, chunks: 0 }
  if (!opts.stream) return stats
  const cmdline = opts.redactedArgv.join(' ')
  const exe = opts.redactedArgv[0] ?? ''

  // Per-chunk handler: relay (if enabled) + mirror (if enabled). The
  // mirror side writes synchronously to the NDJSON file via
  // `appendFileSync` (bounded by `limitBytes` via `limitPayloadSize`).
  // We previously queued + drained on a 50ms interval, but the queue
  // was lost when the source stream's `end`/`close` fired before the
  // first tick — especially for `process.stdin` which reaches EOF
  // immediately in the harness's pipe-mode case. Synchronous writes
  // are bounded (single 1 MiB chunk → single appendFileSync call) and
  // keep the audit trail loss-free for short-lived commands.
  //
  // Invariant #6: `content` and `cmdline`
  // are redacted before emit. `cmdline` was already redacted in
  // `runWrapper` (argv hoisted); `content` runs through `redactStreamContent`
  // per chunk so credential-shaped strings (Bearer tokens, AKIA, ghp_,
  // URL query secrets, …) never land on disk. The merged `redacted_keys`
  // side-channel names the credential families that fired — operators see
  // `bearer_token`, `query.token`, `pem_private_key`, etc. without the
  // masked value.
  const writeMirrorEvent = (chunk: Buffer): void => {
    const rawText = chunk.toString('utf8')
    const redacted = redactStreamContent(rawText)
    const mergedKeys = mergeRedactedKeys(opts.argvRedactedKeys, redacted.redactedKeys)
    writeEvent(opts.outputPath, {
      comm: 'sst-security-control-dsh',
      event_id: makeEventId(writeSeq++),
      event_type: 'runtime_stdio_mirror',
      layer: 'application',
      source_layer: 'runtime',
      ts: Date.now(),
      timestamp: Date.now(),
      pid: process.pid,
      collection_method: 'stdio_mirror',
      wrapper_pid: wrapperPid,
      child_pid: opts.childPid,
      session_id: opts.sessionId,
      run_id: opts.runId,
      agent_id: opts.agentId,
      task_id: opts.taskId,
      turn_id: opts.turnId,
      cmdline,
      exe,
      stream: opts.streamName,
      direction: opts.direction,
      bytes: chunk.length,
      content: redacted.value,
      content_length: chunk.length,
      redacted_keys: mergedKeys,
      host_id: hostname(),
      container_id: process.env.CONTAINER_ID || 'host',
    })
  }

  opts.stream.on('data', (chunk: Buffer | string) => {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk
    stats.chunks += 1
    stats.bytes += buf.length

    if (opts.relay) {
      try {
        opts.relay!.write(buf)
      } catch {
        // parent fd closed; continue mirroring
      }
    }

    if (!opts.childExited.value) {
      // Mirror — apply limitPayloadSize so the audit chunk is bounded.
      const text = buf.toString('utf8')
      const capped = limitPayloadSize(text, opts.limitBytes)
      writeMirrorEvent(Buffer.from(capped.value, 'utf8'))
    }
  })

  // The post-exit 200ms grace in runWrapper handles any final tail; we
  // don't need a drain interval because the synchronous write path is
  // already loss-free.

  return stats
}

// ---------------------------------------------------------------------------
// Signal propagation + status.json companion. The companion file is read by
// `scripts/inspect-events.mjs` (or any audit consumer) on next plugin
// startup so a wrapper crash surfaces even if no `runtime_stdio_mirror_exit`
// line ever landed.
// ---------------------------------------------------------------------------

function writeStatusFile(path: string, status: Record<string, unknown>): void {
  try {
    mkdirSync(pathDirname(path), { recursive: true })
    writeFileSync(path, JSON.stringify(status), { encoding: 'utf8' })
    // The status file intentionally carries raw
    // argv (product decision — see parseWrapperArgv) so it must be
    // owner-only; creation falls back to the umask (typically 0644).
    // Idempotent chmod, best-effort (EPERM on Windows).
    chmodSync(path, 0o600)
  } catch {
    // best effort
  }
}

function propagateSignal(child: ChildProcess, signal: NodeJS.Signals): void {
  try {
    child.kill(signal)
  } catch {
    // child already exited
  }
}

function installSignalHandlers(child: ChildProcess, graceMs: number | undefined): () => void {
  // pre-fix the wrapper only declared
  // `killTimer` but never armed it — the documented SIGTERM → SIGKILL
  // escalation was a no-op. Now: every signal sent to the wrapper
  // propagates as SIGTERM-equivalent to the child AND arms a SIGKILL
  // timer for `graceMs` (only when graceMs > 0). The timer is `.unref`'d
  // so a stale grace window never pins the wrapper's event loop — if the
  // child has already exited by the time the timer fires, the kill is a
  // no-op (process gone, EBADF/ECHRNG swallowed inside `propagateSignal`).
  let killTimer: NodeJS.Timeout | undefined
  const armEscalation = (): void => {
    if (typeof graceMs !== 'number' || graceMs <= 0) return
    if (killTimer) return // already armed — multiple signals share one window
    killTimer = setTimeout(() => {
      killTimer = undefined
      propagateSignal(child, 'SIGKILL')
    }, graceMs)
    // unref so the timer alone never keeps the wrapper alive past
    // natural exit (pumps / status-file flush own the lifetime).
    killTimer.unref?.()
  }
  const handlers: Array<[NodeJS.Signals, () => void]> = [
    ['SIGTERM', () => { propagateSignal(child, 'SIGTERM'); armEscalation() }],
    ['SIGINT', () => { propagateSignal(child, 'SIGINT'); armEscalation() }],
    ['SIGHUP', () => { propagateSignal(child, 'SIGHUP'); armEscalation() }],
    ['SIGBREAK', () => { propagateSignal(child, 'SIGBREAK'); armEscalation() }],
    ['SIGUSR2', () => { propagateSignal(child, 'SIGUSR2'); armEscalation() }],
  ]
  for (const [sig, fn] of handlers) {
    try {
      process.on(sig, fn)
    } catch {
      // SIGBREAK is Windows-only — safe to ignore on POSIX
    }
  }
  // Last-resort: when the wrapper itself exits, ensure the child is gone.
  const onWrapperExit = (): void => {
    try {
      child.kill('SIGTERM')
    } catch {
      // ignore
    }
  }
  process.on('exit', onWrapperExit)
  // Cancel any pending escalation when the child exits cleanly — the
  // SIGKILL timer never needs to fire after we've observed the exit.
  child.once('exit', () => {
    if (killTimer) {
      clearTimeout(killTimer)
      killTimer = undefined
    }
  })

  return () => {
    for (const [sig, fn] of handlers) {
      try {
        process.off(sig, fn)
      } catch {
        // ignore
      }
    }
    try {
      process.off('exit', onWrapperExit)
    } catch {
      // ignore
    }
    if (killTimer) {
      clearTimeout(killTimer)
      killTimer = undefined
    }
  }
}

// ---------------------------------------------------------------------------
// Main — runs only when this file is the entry point. We do NOT call main()
// at module scope so unit tests can import `parseWrapperArgv` etc. without
// forking a real child.
// ---------------------------------------------------------------------------

/**
 * strip the inline-env-passthrough deny-list
 * from the merged env before the wrapper spawns the real child. The host
 * plugin already blocks dangerous env via `EnvPassthroughGuard` on the
 * ORIGINAL spec.env (see `RuntimeHook.runEval`), but the wrapper's own
 * `process.env` carries the operator's shell env (if `LD_PRELOAD` is set
 * in the operator's terminal, every child forked from the harness inherits
 * it). Stripping here is defense-in-depth: even if a future regression
 * bypassed the host guard, the wrapper still removes the dangerous keys
 * before passing them through.
 *
 * The deny-list mirrors `DEFAULT_DANGEROUS_ENV_KEYS` in
 * `src/intervention/EnvPassthroughGuard.ts` but is duplicated as a
 * literal here to keep the wrapper self-contained (it runs as a separate
 * Node.js process and cannot import from the host plugin module graph).
 * If the catalogue changes upstream, update both copies.
 */
const DANGEROUS_ENV_KEYS_LOWER = new Set([
  'ld_preload',
  'ld_library_path',
  'node_options',
  'pythonpath',
  'pythonstartup',
  'node_path',
  'bash_env',
  'env',
  'prompt_command',
  'ssh_auth_sock',
])
function sanitizeEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {}
  for (const [k, v] of Object.entries(env)) {
    if (DANGEROUS_ENV_KEYS_LOWER.has(k.toLowerCase())) continue
    out[k] = v
  }
  return out
}

export async function runWrapper(parsed: ParsedArgs): Promise<number> {
  ensureOutputDir(parsed.outputPath)

  // Invariant #6 — every event the wrapper
  // emits from here on carries a redacted `cmdline` (joined from the
  // redacted argv) and a `redacted_keys` side-channel naming the
  // credential families that fired. Argv redaction is hoisted ONCE so
  // per-chunk events can splice the content-side redaction without
  // re-walking argv.
  const argvRedaction = redactArgvEntries(parsed.childArgv)
  const redactedArgv = argvRedaction.argv
  const argvRedactedKeys = argvRedaction.redactedKeys
  const cmdline = redactedArgv.join(' ')
  const exe = redactedArgv[0] ?? ''
  const startedAt = Date.now()

  // pre-fix, this initial write carried
  // `ok: true` BEFORE the spawn even ran. If the wrapper crashed
  // between this point and the post-exit write (signal handler
  // exception, host plugin teardown mid-spawn, OOM, uncaught throw),
  // the status file would persist with `ok: true` — a phantom
  // success that contradicts the missing `runtime_stdio_mirror_exit`
  // audit line. Audit consumers keying off the status file alone
  // would have marked the spawn successful. The initial write now
  // carries `phase: 'spawning'` and `ok: false` (the spawn has not
  // yet succeeded); only the post-exit path promotes to
  // `phase: 'exited'` + `ok: <actual outcome>`. Consumers reading
  // a stale status.json see a clear "in flight / failed" signal.
  writeStatusFile(parsed.statusPath, {
    ok: false,
    phase: 'spawning',
    wrapper_pid: wrapperPid,
    started_at: startedAt,
    child_argv: parsed.childArgv,
    cwd: parsed.cwd,
    session_id: parsed.sessionId,
  })

  const stdio: StdioOptions = ['pipe', 'pipe', 'pipe']
  let child: ChildProcess
  try {
    // sanitizeEnv strips the inline-env-
    // passthrough deny-list from the merged parent+spec env before
    // handing it to the real child. See `sanitizeEnv` for rationale.
    //
    // The copy also lets us drop `DSH_MIRROR_ENV_JSON` (the
    // host-injected child-env side-channel) so the business child never
    // sees the JSON blob — its env contract is exactly what it was when
    // the env rode argv (`{...process.env, ...spec.env}` minus the
    // dangerous deny-list keys).
    const mergedEnv: NodeJS.ProcessEnv = parsed.env
      ? { ...process.env, ...parsed.env }
      : { ...process.env }
    delete mergedEnv[MIRROR_ENV_VAR]
    const childEnv = sanitizeEnv(mergedEnv)
    child = spawn(parsed.childArgv[0]!, parsed.childArgv.slice(1), {
      stdio,
      cwd: parsed.cwd,
      env: childEnv,
      // detached: false — the wrapper is the parent for signal propagation.
      detached: false,
    })
  } catch (e) {
    const message = (e as Error).message
    // redact error_message so a Node ENOENT or permission error
    // surfacing an argv-shaped path can't leak a credential.
    const errorRedaction = redactStreamContent(`spawn_failed: ${message}`)
    writeEvent(parsed.outputPath, {
      comm: 'sst-security-control-dsh',
      event_id: makeEventId(writeSeq++),
      event_type: 'runtime_stdio_mirror_error',
      layer: 'application',
      source_layer: 'runtime',
      ts: Date.now(),
      timestamp: Date.now(),
      pid: process.pid,
      collection_method: 'stdio_mirror',
      wrapper_pid: wrapperPid,
      session_id: parsed.sessionId,
      run_id: parsed.runId,
      agent_id: parsed.agentId,
      task_id: parsed.taskId,
      turn_id: parsed.turnId,
      cmdline,
      exe,
      error_message: errorRedaction.value,
      redacted_keys: mergeRedactedKeys(argvRedactedKeys, errorRedaction.redactedKeys),
      host_id: hostname(),
      container_id: process.env.CONTAINER_ID || 'host',
    })
    writeStatusFile(parsed.statusPath, {
      ok: false,
      wrapper_pid: wrapperPid,
      started_at: startedAt,
      child_argv: parsed.childArgv,
      error: errorRedaction.value,
    })
    return 127
  }

  const childPid = child.pid ?? -1
  const cleanupSignals = installSignalHandlers(child, parsed.graceMs)

  // Marker: emit the intent event so consumers can correlate the child
  // pid back to a session / agent task.
  writeEvent(parsed.outputPath, {
    comm: 'sst-security-control-dsh',
    event_id: makeEventId(writeSeq++),
    event_type: 'runtime_stdio_mirror',
    layer: 'application',
    source_layer: 'runtime',
    ts: Date.now(),
    timestamp: Date.now(),
    pid: process.pid,
    collection_method: 'stdio_mirror',
    wrapper_pid: wrapperPid,
    child_pid: childPid,
    session_id: parsed.sessionId,
    run_id: parsed.runId,
    agent_id: parsed.agentId,
    task_id: parsed.taskId,
    turn_id: parsed.turnId,
    cmdline,
    exe,
    stream: 'meta',
    direction: 'meta',
    bytes: 0,
    content: '',
    content_length: 0,
    redacted_keys: argvRedactedKeys,
    host_id: hostname(),
    container_id: process.env.CONTAINER_ID || 'host',
  })

  const childExited = { value: false }

  // Wire the pumps.
  const stdinSpec = parsed.stdioSpec.stdin
  const stdoutSpec = parsed.stdioSpec.stdout
  const stderrSpec = parsed.stdioSpec.stderr

  // stdin pump: parent → child.
  // - mode='ignore': don't connect anything; close child stdin so the child
  //   gets EOF immediately.
  // - mode='inherit': relay parent's process.stdin to child.stdin; mirror.
  // - mode='pipe': don't connect parent (harness writes to our stdin via
  //   opaque handle); we can't relay anyway, so close child stdin.
  if (stdinSpec.mode === 'inherit' && (stdinSpec.relay || stdinSpec.mirror)) {
    startPump({
      outputPath: parsed.outputPath,
      stream: process.stdin,
      relay: stdinSpec.relay ? child.stdin : null,
      direction: 'parent_to_child',
      streamName: 'stdin',
      limitBytes: parsed.limitBytes,
      childPid,
      childArgv: redactedArgv,
      redactedArgv,
      argvRedactedKeys,
      sessionId: parsed.sessionId,
      runId: parsed.runId,
      agentId: parsed.agentId,
      taskId: parsed.taskId,
      turnId: parsed.turnId,
      childExited,
    })
  } else if (stdinSpec.mode === 'pipe' || stdinSpec.mode === 'ignore') {
    // Close child stdin so the child sees EOF; the harness writes to our
    // stdin via opaque handle but we can't relay that into the child.
    try {
      child.stdin?.end()
    } catch {
      // ignore
    }
  }

  // stdout pump: child → parent.
  // - mode='ignore': skip (child probably doesn't write to stdout anyway).
  // - mode='inherit': relay to process.stdout (tty) + mirror.
  // - mode='pipe': capture only (mirror); no relay.
  if (stdoutSpec.mode !== 'ignore') {
    startPump({
      outputPath: parsed.outputPath,
      stream: child.stdout,
      relay: stdoutSpec.relay ? process.stdout : null,
      direction: 'child_to_parent',
      streamName: 'stdout',
      limitBytes: parsed.limitBytes,
      childPid,
      childArgv: redactedArgv,
      redactedArgv,
      argvRedactedKeys,
      sessionId: parsed.sessionId,
      runId: parsed.runId,
      agentId: parsed.agentId,
      taskId: parsed.taskId,
      turnId: parsed.turnId,
      childExited,
    })
  }

  // stderr pump: same shape as stdout.
  if (stderrSpec.mode !== 'ignore') {
    startPump({
      outputPath: parsed.outputPath,
      stream: child.stderr,
      relay: stderrSpec.relay ? process.stderr : null,
      direction: 'child_to_parent',
      streamName: 'stderr',
      limitBytes: parsed.limitBytes,
      childPid,
      childArgv: redactedArgv,
      redactedArgv,
      argvRedactedKeys,
      sessionId: parsed.sessionId,
      runId: parsed.runId,
      agentId: parsed.agentId,
      taskId: parsed.taskId,
      turnId: parsed.turnId,
      childExited,
    })
  }

  // Wait for the child to exit; propagate its exit code.
  const exitInfo = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
    (resolve) => {
      child.once('exit', (code, signal) => {
        childExited.value = true
        resolve({ code, signal })
      })
      child.once('error', (e) => {
        childExited.value = true
        // redact error_message for the same reason as spawn_failed.
        const errorRedaction = redactStreamContent(`child_error: ${e.message}`)
        writeEvent(parsed.outputPath, {
          comm: 'sst-security-control-dsh',
          event_id: makeEventId(writeSeq++),
          event_type: 'runtime_stdio_mirror_error',
          layer: 'application',
          source_layer: 'runtime',
          ts: Date.now(),
          timestamp: Date.now(),
          pid: process.pid,
          collection_method: 'stdio_mirror',
          wrapper_pid: wrapperPid,
          child_pid: childPid,
          session_id: parsed.sessionId,
          run_id: parsed.runId,
          agent_id: parsed.agentId,
          task_id: parsed.taskId,
          turn_id: parsed.turnId,
          cmdline,
          exe,
          error_message: errorRedaction.value,
          redacted_keys: mergeRedactedKeys(argvRedactedKeys, errorRedaction.redactedKeys),
          host_id: hostname(),
          container_id: process.env.CONTAINER_ID || 'host',
        })
        resolve({ code: 1, signal: null })
      })
    },
  )

  cleanupSignals()

  // Drain any remaining mirror chunks before exiting. We give pumps a
  // brief grace period (200ms) to flush their queues; for very long
  // outputs this might lose tail chunks, but the alternative (block
  // exit indefinitely) is worse for audit fidelity.
  await new Promise<void>((resolve) => setTimeout(resolve, 200))

  const exitCode = exitInfo.code !== null ? exitInfo.code : signalToCode(exitInfo.signal)
  writeEvent(parsed.outputPath, {
    comm: 'sst-security-control-dsh',
    event_id: makeEventId(writeSeq++),
    event_type: 'runtime_stdio_mirror_exit',
    layer: 'application',
    source_layer: 'runtime',
    ts: Date.now(),
    timestamp: Date.now(),
    pid: process.pid,
    collection_method: 'stdio_mirror',
    wrapper_pid: wrapperPid,
    child_pid: childPid,
    session_id: parsed.sessionId,
    run_id: parsed.runId,
    agent_id: parsed.agentId,
    task_id: parsed.taskId,
    turn_id: parsed.turnId,
    cmdline,
    exe,
    exit_code: exitCode,
    exit_signal: exitInfo.signal,
    duration_ms: Date.now() - startedAt,
    redacted_keys: argvRedactedKeys,
    host_id: hostname(),
    container_id: process.env.CONTAINER_ID || 'host',
  })

  // the post-exit write now reflects the
  // ACTUAL outcome (`ok: exitCode === 0 && !exitInfo.signal`) and
  // carries `phase: 'exited'`. The previous unconditional `ok: true`
  // left a non-zero exit code visible in the same record but
  // contradicted itself — a `runtime_stdio_mirror_exit` event with
  // `exit_code: 1` paired with a status.json carrying `ok: true`
  // was the same ghost-success shape, just less common.
  const exitedOk = exitCode === 0 && exitInfo.signal === null
  writeStatusFile(parsed.statusPath, {
    ok: exitedOk,
    phase: 'exited',
    wrapper_pid: wrapperPid,
    started_at: startedAt,
    child_pid: childPid,
    child_argv: parsed.childArgv,
    exit_code: exitCode,
    exit_signal: exitInfo.signal,
  })

  return exitCode
}

/**
 * Real signal→code mapping for the stdio-mirror exit
 * record. POSIX shells use `128 + signo` as the exit status when a process
 * is terminated by a signal; a bare `128` for
 * every signal makes it impossible to distinguish SIGTERM (128+15=143)
 * from SIGHUP (128+1=129) at the audit level. The `exit_signal` field is
 * still emitted verbatim, so consumers that key off the symbolic name are
 * unaffected.
 *
 * Coverage is the standard POSIX signal set the wrapper propagates (see
 * `signalListeners` at the top of this file): SIGTERM / SIGINT / SIGHUP /
 * SIGBREAK / SIGUSR2 + SIGKILL (escalation). Anything outside this set
 * falls back to `128` — the audit consumer resolves via `exit_signal`.
 */
const SIGNAL_EXIT_CODE: Readonly<Record<NodeJS.Signals, number>> = {
  SIGHUP: 128 + 1,
  SIGINT: 128 + 2,
  SIGQUIT: 128 + 3,
  SIGILL: 128 + 4,
  SIGTRAP: 128 + 5,
  SIGABRT: 128 + 6,
  // SIGIOT (legacy synonym for SIGABRT on some platforms) — Node keeps
  // it in the Signals union; the runtime maps both to signo 6.
  SIGIOT: 128 + 6,
  SIGBUS: 128 + 7,
  SIGFPE: 128 + 8,
  SIGKILL: 128 + 9,
  SIGUSR1: 128 + 10,
  SIGSEGV: 128 + 11,
  SIGUSR2: 128 + 12,
  SIGPIPE: 128 + 13,
  SIGALRM: 128 + 14,
  SIGTERM: 128 + 15,
  SIGCHLD: 128 + 17,
  SIGCONT: 128 + 18,
  SIGSTOP: 128 + 19,
  SIGTSTP: 128 + 20,
  SIGTTIN: 128 + 21,
  SIGTTOU: 128 + 22,
  SIGURG: 128 + 23,
  SIGXCPU: 128 + 24,
  SIGXFSZ: 128 + 25,
  SIGVTALRM: 128 + 26,
  SIGPROF: 128 + 27,
  SIGWINCH: 128 + 28,
  // SIGIO (Linux) / SIGPOLL (BSD legacy synonym) — Node keeps both
  // in the Signals union; runtime collapses to signo 29.
  SIGIO: 128 + 29,
  SIGPOLL: 128 + 29,
  SIGPWR: 128 + 30,
  SIGSYS: 128 + 31,
  // Linux-specific legacy signal numbers Node still exposes.
  SIGSTKFLT: 128 + 16,
  SIGUNUSED: 128 + 31,
  // Windows-specific. SIGBREAK is well-defined on Windows; the rest
  // are accepted as signals by libuv but may not fire there in practice.
  SIGBREAK: 128 + 21,
  // BSD / Linux legacy aliases. SIGLOST is the BSD legacy synonym for
  // SIGPWR; SIGINFO is a non-termination signal that some shells surface
  // for `Ctrl+T`. Neither fires in normal agent-fork flows, but the
  // libuv Signals union includes them.
  SIGLOST: 128 + 30,
  SIGINFO: 128 + 29,
}

function signalToCode(signal: NodeJS.Signals | null): number {
  if (!signal) return 0
  return SIGNAL_EXIT_CODE[signal] ?? 128
}

// Entry-point guard — only run when invoked as a script (not when
// imported by tests). Node's `import.meta.url` + `process.argv[1]`
// comparison handles both ESM `node path.js` and `node --input-type=module`.
const isEntry = (() => {
  try {
    if (typeof import.meta.url !== 'string') return false
    const argv1 = process.argv[1]
    if (!argv1) return false
    // Best-effort — works for absolute paths, relative paths, and when
    // invoked via the symlinked plugin directory. Split on BOTH path
    // separators: on Windows process.argv[1] carries backslashes, and
    // splitting on '/' alone leaves the whole (backslashed) path as the
    // "basename", which never matches the forward-slash import.meta.url
    // — the wrapper then silently no-ops instead of running the child.
    return import.meta.url.endsWith(argv1.split(/[\\/]/).pop() ?? '__never__')
  } catch {
    return false
  }
})()

if (isEntry) {
  let parsed: ParsedArgs
  try {
    parsed = parseWrapperArgv(process.argv.slice(2))
  } catch (e) {
    process.stderr.write(`stdio-mirror wrapper failed: ${(e as Error).message}\n`)
    process.exit(2)
  }
  runWrapper(parsed).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(`stdio-mirror wrapper crashed: ${(e as Error).message}\n`)
      process.exit(1)
    },
  )
}