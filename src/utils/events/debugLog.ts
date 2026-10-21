/**
 * DebugLog — operator-facing diagnostic log for **install / deploy / runtime error
 * analysis**. When a
 * marketplace install goes sideways (config integrity failure,
 * pre-Node-injection env guard triggered, RuntimeHook seam not
 * available, schema validation fallback, NetworkHttpCollector patch
 * failed, signal-handler install failed, policy file missing or
 * unparsable), operators want a single on-disk breadcrumb trail to
 * triage WITHOUT enabling engine-side verbose logging.
 *
 * **What it is**:
 *   - Append-only NDJSON file at `~/.dsh/security-monitor-debug.log`
 *     (or `collector.debugLogPath` from `cordis.patch.yml`).
 *   - One line per event: `{ ts, phase, ...payload }`.
 *   - chmod 0o600 applied on first write, on creation, and after every
 *     rotation (the underlying `appendToCappedNdjson` unlinks+recreates
 *     on rotation, which resets mode bits to the umask). Steady-state
 *     appends skip the chmod — see `write()` below.
 *   - Synchronous (uses `appendFileSync` via `appendToCappedNdjson`).
 *   - No-op when `debugLogPath` is empty/unset — the rest of the
 *     plugin is unaffected.
 *
 * **What it is NOT**:
 *   - Not a security event — does NOT flow through `LocalNdjsonSink`
 *     and is NOT subject to `redactSensitiveBody`. Operators may
 *     intentionally write unredacted error context (stack traces,
 *     argv previews, env var names) to this log because the
 *     default permissions are 0o600 and the file is opt-in.
 *   - Not a generic logger — phases are stable identifiers (`phase`
 *     field is a closed set per the implementation, plus an
 *     `escape-hatch: string` for future additions without touching
 *     this file).
 *   - Not sampled — every call writes a line. Operators who want
 *     sampling should set `debugLogPath` empty in production and
 *     only flip it on when triaging.
 *
 * **Phases emitted today**:
 *   - `LocalNdjsonSink` (existing): initialize, flush_empty,
 *     local_direct, local_batch, integrity, integrity_gap, truncate,
 *     shutdown.
 *   - `src/index.ts` error sites:
 *     disabled_by_config, config_integrity_failed, env_guard_violation,
 *     schema_fallback, runtime_hook_install_failed,
 *     runtime_hook_installed, runtime_hook_deferred_failed,
 *     network_capture_install_failed, signal_handlers_install_failed.
 *   - `src/commands/security.ts` + `src/typert/host.ts` + bootstrap:
 *     surface_unavailable — one line per
 *     degraded operator surface (cli / remote / network_capture), with
 *     `surface` + `reason` (+ `peer` for the peer-dep surfaces).
 *
 * The phases string union is intentionally open (`string`) so future
 * components can introduce new keys without a TypeScript breaking
 * change; the documented set above is the current contract.
 */

import { chmodSync } from 'node:fs'
import { appendToCappedNdjson, DEFAULT_MAX_NDJSON_BYTES } from './cappedNdjson.js'
import { expandHome } from '../policy/expandHome.js'

/**
 * Logger contract — accepts the harness's `ctx.logger` (has
 * `.info` / `.warn` / `.error`) or any structural subset. `.warn`
 * is the only one DebugLog uses directly; `.error` is forwarded to
 * `appendToCappedNdjson` for its own failure reporting.
 */
export type DebugLogger = { warn: (msg: string) => void; error: (msg: string) => void }

export interface DebugLogOptions {
  /** Absolute, post-expansion file path. Empty/undefined = disabled. */
  path?: string
  /** Max file size in bytes before rotation. Defaults to 50 MiB. */
  maxBytes?: number
  /** Optional logger; failures write a single warn and continue. */
  logger?: DebugLogger
}

/**
 * Expand a debug-log path (empty stays empty; `~/` expanded). Thin wrapper
 * over the shared `expandHome` (`src/utils/policy/expandHome.ts`) —
 * kept as a named export because the debug-log path historically tolerated
 * an empty string (shared helper would return it unchanged anyway, but the
 * guard documents the contract).
 */
export function expandDebugLogPath(p: string): string {
  if (!p) return ''
  return expandHome(p)
}

export class DebugLog {
  private readonly path?: string
  private readonly maxBytes: number
  private readonly logger?: DebugLogger
  /**
   * Audit-TOCTOU hardening: chmod must not fire after EVERY
   * append, which both wastes a syscall per line and leaves a window where
   * a freshly created file sat at umask perms (typically 0644 =
   * group/world readable) before the chmod landed. The chmod fires
   * only when the mode may actually have drifted: the first write after
   * startup (tightens a legacy umask-created file), the creation call,
   * and each rotation (unlink+recreate resets mode bits to the umask).
   * Reset to `false` on chmod failure so the next write retries.
   */
  private chmodPending = true

  constructor(options: DebugLogOptions) {
    const raw = (options.path ?? '').trim()
    this.path = raw ? raw : undefined
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_NDJSON_BYTES
    this.logger = options.logger
  }

  /** True iff `path` was non-empty at construction. */
  isEnabled(): boolean {
    return this.path !== undefined
  }

  /** Resolved absolute path, or undefined when disabled. */
  getPath(): string | undefined {
    return this.path
  }

  /**
   * Append one NDJSON line `{ ts, phase, ...payload }` to the log.
   *
   * Always best-effort — failures only emit a single warn, never
   * throw, consistent with the "never throw to the host" design
   * invariant. chmod 0o600 is re-asserted only on first write /
   * creation / rotation (see `chmodPending`); steady-state appends
   * leave the existing 0o600 file untouched.
   */
  write(phase: string, payload: Record<string, unknown> = {}): void {
    if (!this.path) return
    const line = JSON.stringify({ ts: Date.now(), phase, ...payload }) + '\n'
    try {
      const result = appendToCappedNdjson(this.path, [line], this.maxBytes, {
        logger: this.logger as DebugLogger | undefined,
      })
      if (this.chmodPending || result.truncated) {
        try {
          chmodSync(this.path, 0o600)
          this.chmodPending = false
        } catch {
          /* EPERM on Windows; ENOENT before first write race */
        }
      }
    } catch (error: unknown) {
      this.logger?.warn(
        `[DebugLog] write failed (phase=${phase}): ${
          error instanceof Error ? error.message : String(error)
        }`,
      )
    }
  }
}

/**
 * Construct a DebugLog from the marketplace `Config['collector']`
 * shape (or a structural subset thereof). Centralised so `apply()`
 * and `LocalNdjsonSink` agree on path resolution + defaults.
 */
export function createDebugLogFromConfig(
  config: { debugLogPath?: string },
  logger?: DebugLogger,
): DebugLog {
  return new DebugLog({
    path: expandDebugLogPath(config.debugLogPath ?? ''),
    logger,
  })
}