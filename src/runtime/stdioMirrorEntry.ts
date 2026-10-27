/**
 * Stdio pipe mirror — host-side helper.
 *
 * The bundled `lib/runtime/stdio-mirror.js` is the wrapper process the
 * harness spawns on the rewritten argv. This module is the **host-side**
 * counterpart that:
 *   - resolves the wrapper's on-disk path from `import.meta.url`
 *     (canonical pattern in this codebase — see `src/bootstrap.ts:81-83`,
 *     `scripts/build-client.mjs:66-67`).
 *   - normalises `SubprocessSpawnSpec.stdio` into the per-stream
 *     `{ mode, mirror, relay }` triple the wrapper consumes.
 *   - rebuilds the argv vector so the harness spawns the wrapper instead
 *     of the user's original command.
 *
 * Why this is a separate module from `src/runtime/stdio-mirror.ts`:
 *   - The wrapper is the entry point of a separate Node.js process —
 *     compiled to `lib/runtime/stdio-mirror.js`. Keeping it self-contained
 *     (no cross-imports into the plugin) means a future launch via
 *     `node <abs>/lib/runtime/stdio-mirror.js ...` always works without
 *     resolving relative paths or shared state.
 *   - This module is loaded by the host plugin (RuntimeHook.wrap) and
 *     can freely import config types / types/index.ts / etc.
 */
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { SubprocessSpawnSpec } from '../types/external.js'
import type { StdioMirrorConfig } from '../config.js'
import { MIRROR_ENV_VAR, type StdioMirrorSpec, type StdioStreamSpec } from './stdio-mirror.js'

/**
 * Resolve the absolute path of the bundled wrapper script.
 *
 * The wrapper is emitted to `<pkg>/lib/runtime/stdio-mirror.js` by tsc
 * (the `rootDir: ./src` mirror in tsconfig.json).
 * This module compiles to
 * `<pkg>/lib/runtime/stdioMirrorEntry.js` and the wrapper sits BESIDE it
 * at `<pkg>/lib/runtime/stdio-mirror.js` (tsc rootDir mirror). Resolving
 * the wrapper as a sibling
 * of this module keeps the resolution install-path-agnostic (packed
 * install / pnpm link / dev `--patch` all share the same layout).
 */
export function resolveStdioMirrorWrapperPath(): string {
  const here = dirname(fileURLToPath(import.meta.url))
  return join(here, 'stdio-mirror.js')
}

/**
 * Normalise `SubprocessSpawnSpec.stdio` into the per-stream triple the
 * wrapper expects.
 *
 * Mode dispatch (per ticket acceptance):
 *   - spec.stdio === 'ignore' → all three streams disabled; caller MUST
 *     skip the wrapper entirely (return value `{ shouldMirror: false }`).
 *     NOTE: the real harness `stdio` is ALWAYS the per-stream
 *     object `SubprocessStdio` (subprocess/src/types.ts:77-107) — this
 *     string form is only reachable through the plugin stub / unit tests.
 *   - spec.stdio === 'inherit' (or undefined) → all three streams set to
 *     mode='inherit', relay=true (preserve harness tty transport),
 *     mirror=true.
 *   - spec.stdio === 'pipe' → all three streams set to mode='pipe',
 *     relay=false (we can't relay pipe-mode bytes back to the harness's
 *     opaque handle anyway), mirror=true.
 *   - per-stream object → independent flags per stream; when EVERY stream
 *     normalises to `mirror: false` (all 'ignore' / absent) the caller
 *     skips the wrapper — the deep-check replaces the pre-
 *     `spec.stdio !== 'ignore'` gate, which was dead code in production
 *     because the harness never sends the string form.
 *
 * Note: when `stdio.stdin === 'pipe'` the wrapper closes child-side
 * stdin immediately (the harness writes to our stdin via an opaque
 * handle that we can't see). This is intentional — see Plan agent Q2.
 */
export function buildStdioMirrorSpec(
  specStdio: SubprocessSpawnSpec['stdio'],
  _config: StdioMirrorConfig,
): { shouldMirror: false } | { shouldMirror: true; spec: StdioMirrorSpec } {
  if (specStdio === 'ignore') {
    return { shouldMirror: false }
  }

  if (specStdio === 'inherit' || specStdio === undefined) {
    const s = (mode: 'inherit' | 'pipe'): StdioStreamSpec => ({
      mode,
      mirror: true,
      relay: mode === 'inherit',
    })
    return {
      shouldMirror: true,
      spec: { stdin: s('inherit'), stdout: s('inherit'), stderr: s('inherit') },
    }
  }

  if (specStdio === 'pipe') {
    const s: StdioStreamSpec = { mode: 'pipe', mirror: true, relay: false }
    return {
      shouldMirror: true,
      spec: { stdin: { ...s }, stdout: { ...s }, stderr: { ...s } },
    }
  }

  // Per-stream object form. Deep-check each fd — only skip the
  // wrapper when there is no stream worth mirroring (the production form
  // of the old, dead `spec.stdio !== 'ignore'` gate).
  const norm = (raw: 'pipe' | 'inherit' | 'ignore' | { maxBytes?: number } | undefined): StdioStreamSpec => {
    if (raw === undefined || raw === 'ignore') {
      return { mode: 'ignore', mirror: false, relay: false }
    }
    if (raw === 'pipe' || typeof raw === 'object') {
      // `maxBytes` is harness-side; we apply our own payloadLimitBytes via
      // `--limit-bytes` flag. The mirror is unconditional; relay is off
      // because pipe-mode bytes can't reach the parent tty.
      return { mode: 'pipe', mirror: true, relay: false }
    }
    // 'inherit'
    return { mode: 'inherit', mirror: true, relay: true }
  }
  const stdin = norm(specStdio.stdin)
  const stdout = norm(specStdio.stdout)
  const stderr = norm(specStdio.stderr)
  if (!stdin.mirror && !stdout.mirror && !stderr.mirror) {
    return { shouldMirror: false }
  }
  return {
    shouldMirror: true,
    spec: { stdin, stdout, stderr },
  }
}

/**
 * Rewrite `spec.argv` so the harness spawns the wrapper instead of the
 * user's original command. Returns a new spec object with the same
 * fields minus `argv` (which is replaced).
 *
 * The wrapper is invoked as:
 *   `[node, <abs>/lib/runtime/stdio-mirror.js, --stdio-spec=<JSON>,
 *     --limit-bytes=<N>, --output=<path>, --status-path=<path>,
 *     --session-id=<sid>, --run-id=<rid>, --agent-id=<aid>,
 *     --task-id=<tid>, --turn-id=<tid2>, --cwd=<cwd>, --grace-ms=<ms>,
 *     --, ...originalArgv]`
 *
 * The child env (`spec.env`) deliberately does
 * NOT appear on that argv. The former `--env=<JSON>` flag put the env —
 * which routinely carries tokens / API keys — into
 * `/proc/<pid>/cmdline`, world-readable on Linux. The host instead
 * injects the JSON into the wrapper's OWN process environment as
 * `DSH_MIRROR_ENV_JSON` (`/proc/<pid>/environ` is owner/root-only); the
 * wrapper reads it back from `process.env` (see `parseWrapperArgv` in
 * stdio-mirror.ts) and deletes the var before spawning the business
 * child, so the child's env contract is unchanged.
 *
 * `--session-id` correlates mirror events back to the agent
 * session / run_id / task_id; `--run-id` / `--agent-id` / `--task-id` /
 * `--turn-id` carry the remaining RuntimeHook correlation keys so
 * wrapper events join runtime_*_intent events on the same dashboard
 * fields. Cross-process event_id uniqueness
 * comes from `wrapperPid` (built into `event_id`); host seq is no
 * longer threaded into the wrapper.
 */
export function rewriteSpecForMirror(
  spec: SubprocessSpawnSpec,
  wrapperPath: string,
  mirrorSpec: StdioMirrorSpec,
  config: StdioMirrorConfig,
  meta: {
    sessionId?: string
    runId?: string
    agentId?: string
    taskId?: string
    turnId?: string
    statusPath: string
  },
): SubprocessSpawnSpec {
  const args: string[] = [
    process.execPath,
    wrapperPath,
    `--stdio-spec=${JSON.stringify(mirrorSpec)}`,
    `--limit-bytes=${config.payloadLimitBytes}`,
    `--output=${config.outputPath}`,
    `--status-path=${meta.statusPath}`,
  ]
  if (meta.sessionId) {
    args.push(`--session-id=${meta.sessionId}`)
  }
  // RuntimeHook correlation keys — same names/order as the intent events.
  // Each flag is only emitted when the host actually has the value; the
  // wrapper then writes the field (or omits it when the flag is absent).
  if (meta.runId) {
    args.push(`--run-id=${meta.runId}`)
  }
  if (meta.agentId) {
    args.push(`--agent-id=${meta.agentId}`)
  }
  if (meta.taskId) {
    args.push(`--task-id=${meta.taskId}`)
  }
  if (meta.turnId) {
    args.push(`--turn-id=${meta.turnId}`)
  }
  if (spec.cwd) {
    args.push(`--cwd=${spec.cwd}`)
  }
  // plumb the host's graceMs through to the
  // wrapper so SIGTERM → SIGKILL escalation actually fires. Pre-fix the
  // wrapper declared the timer but never armed it because no value
  // crossed the process boundary.
  if (typeof spec.graceMs === 'number' && spec.graceMs > 0) {
    args.push(`--grace-ms=${spec.graceMs}`)
  }
  args.push('--')
  // spec.argv is readonly; spread to detach.
  args.push(...spec.argv)
  // When the caller supplies a child env, carry it to the wrapper through
  // the wrapper's OWN environment (`DSH_MIRROR_ENV_JSON`) instead of
  // `--env=` on argv — argv is world-readable via `/proc/<pid>/cmdline`,
  // the wrapper's environ is owner-only. The wrapper strips the var
  // before spawning the business child, so the child still receives
  // exactly `spec.env` (merged over the inherited environment) and
  // never sees the JSON blob.
  const env = spec.env
    ? { ...spec.env, [MIRROR_ENV_VAR]: JSON.stringify(spec.env) }
    : spec.env
  return {
    argv: args,
    cwd: spec.cwd,
    env,
    stdio: spec.stdio,
    graceMs: spec.graceMs,
    signal: spec.signal,
  }
}