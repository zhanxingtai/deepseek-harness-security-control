/**
 * Policy file watcher — HMR for SPL policy reloads.
 *
 * replace the `setInterval` polling reload (inherited from
 * pre-marketplace) with native `fs.watch`, plus an automatic polling fallback
 * for WSL / network mounts where inotify is unavailable or unreliable.
 *
 * Design constraints (carried from):
 *  - `dependencies: {}` — no `chokidar` (marketplace hard requirement).
 *    Use Node's built-in `fs.watch` + a polling fallback the watcher
 *    itself manages.
 *  - Fail-loud on invalid YAML: the watcher only DETECTS the change; the
 *    engine's reload then drops the failing file's rules and surfaces
 *    the breakage — a loud warning through the host logger plus a
 * `security_audit/policy_reload_error` audit event (
 * wired in bootstrap). A hash-verified parse failure is
 *    NOT `policy_tamper` (that event is reserved for rejected reloads
 *    where the file hash diverged from baseline).
 *  - Never throw to the host: all errors are logged and the watcher
 *    re-arms itself (degraded mode).
 */
import { existsSync, readFileSync, statSync, watch, type FSWatcher } from 'node:fs'
import { dirname, resolve } from 'node:path'

export type PolicyWatcherListener = (event: {
  path: string
  reason: 'change' | 'rename' | 'error'
  error?: string
}) => void

export interface PolicyWatcherOptions {
  /** Polling interval in ms when the watcher falls back to polling. Default 1000. */
  pollIntervalMs?: number
  /** Logger for degraded-mode messages. */
  logger?: {
    warn: (m: string, ...a: unknown[]) => void
    error: (m: string, ...a: unknown[]) => void
  }
  /**
   * Optional override for the WSL heuristic. When true, the watcher
   * short-circuits to polling immediately (skipping the native fs.watch
   * attempt that would drop events on 9P / virtiofs / WSL mounts).
   */
  forcePoll?: boolean
}

/**
 * Detect the WSL / 9P / virtiofs case where `fs.watch` is unreliable.
 *
 * Heuristic: read /proc/version. WSL1 + WSL2 both contain "Microsoft"
 * or "WSL" in the kernel banner. Real Linux distros don't. Reading
 * /proc/version is harmless on every Unix; on Windows it throws and
 * the function returns false (Windows uses ReadDirectoryChangesW,
 * which is reliable).
 */
function detectWSL(): boolean {
  try {
    const v = readFileSync('/proc/version', 'utf8')
    return /microsoft|wsl/i.test(v)
  } catch {
    return false
  }
}

function mtimeOf(path: string): number | undefined {
  try {
    if (!existsSync(path)) return undefined
    return statSync(path).mtimeMs
  } catch {
    return undefined
  }
}

/**
 * Watch a list of policy files for changes.
 *
 * The returned handle exposes `close()` for clean teardown. The watcher
 * is idempotent — calling `close()` twice is safe, and `start()` is a
 * no-op when the watcher is already running.
 *
 * On the first `fs.watch` failure the watcher transparently falls back
 * to polling (re-arms every `pollIntervalMs`). On WSL the watcher
 * short-circuits to polling immediately to avoid the 5-second event-loss
 * window documented in the design notes.
 */
export class PolicyWatcher {
  private paths: string[]
  private listeners: PolicyWatcherListener[] = []
  private watchers: FSWatcher[] = []
  private pollTimer?: ReturnType<typeof setInterval>
  private lastMtime = new Map<string, number>()
  private closed = false
  private started = false
  private mode: 'native' | 'poll' | 'wsl-poll' = 'native'
  private readonly options: Required<Omit<PolicyWatcherOptions, 'logger' | 'forcePoll'>> & {
    logger?: PolicyWatcherOptions['logger']
    forcePoll: boolean
  }

  constructor(paths: string[], options: PolicyWatcherOptions = {}) {
    this.paths = paths.map((p) => resolve(p))
    this.options = {
      pollIntervalMs: options.pollIntervalMs ?? 1000,
      logger: options.logger,
      forcePoll: options.forcePoll ?? false,
    }
    if (this.options.forcePoll) {
      this.mode = 'poll'
    } else if (detectWSL()) {
      this.mode = 'wsl-poll'
    }
  }

  /** Subscribe to change events. Returns an unsubscribe function. */
  subscribe(listener: PolicyWatcherListener): () => void {
    this.listeners.push(listener)
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener)
    }
  }

  /** Start watching. Safe to call multiple times — subsequent calls are no-ops. */
  start(): void {
    if (this.closed || this.started) return
    this.started = true
    this.options.logger?.warn?.(
      `[PolicyWatcher] starting mode=${this.mode} paths=${this.paths.length}`,
    )
    this.seedMtimes()
    if (this.mode !== 'native') {
      this.startPolling()
      return
    }
    let nativeOk = true
    for (const p of this.paths) {
      try {
        const w = watch(p, { persistent: false }, (eventType) => {
          if (this.closed) return
          this.lastMtime.set(p, mtimeOf(p) ?? -1)
          this.fire({
            path: p,
            reason: eventType === 'rename' ? 'rename' : 'change',
          })
        })
        w.on('error', (err) => {
          this.options.logger?.warn?.(
            `[PolicyWatcher] fs.watch error on ${p}: ${String(err)} — falling back to polling`,
          )
          nativeOk = false
          this.teardownNative()
          this.startPolling()
        })
        this.watchers.push(w)
      } catch (err) {
        this.options.logger?.warn?.(
          `[PolicyWatcher] fs.watch setup failed on ${p}: ${String(err)} — falling back to polling`,
        )
        nativeOk = false
        break
      }
    }
    if (!nativeOk) {
      this.teardownNative()
      this.startPolling()
    }
  }

  private startPolling(): void {
    if (this.pollTimer || this.closed) return
    this.mode = this.mode === 'native' ? 'poll' : this.mode
    this.pollTimer = setInterval(() => {
      if (this.closed) return
      for (const p of this.paths) {
        const m = mtimeOf(p)
        if (m === undefined) {
          const prev = this.lastMtime.get(p)
          if (prev !== undefined && prev !== -1) {
            this.lastMtime.set(p, -1)
            this.fire({ path: p, reason: 'rename' })
          }
          continue
        }
        const prev = this.lastMtime.get(p)
        if (prev === undefined) {
          this.lastMtime.set(p, m)
        } else if (prev !== m) {
          this.lastMtime.set(p, m)
          this.fire({ path: p, reason: 'change' })
        }
      }
    }, this.options.pollIntervalMs)
  }

  private seedMtimes(): void {
    for (const p of this.paths) {
      this.lastMtime.set(p, mtimeOf(p) ?? -1)
    }
  }

  private teardownNative(): void {
    for (const w of this.watchers) {
      try {
        w.close()
      } catch {
        // best-effort
      }
    }
    this.watchers = []
  }

  private fire(event: {
    path: string
    reason: 'change' | 'rename' | 'error'
    error?: string
  }): void {
    for (const l of this.listeners) {
      try {
        l(event)
      } catch {
        // listener must not throw — but if it does, keep going
      }
    }
  }

  /** Idempotent. */
  close(): void {
    if (this.closed) return
    this.closed = true
    this.teardownNative()
    if (this.pollTimer) {
      clearInterval(this.pollTimer)
      this.pollTimer = undefined
    }
  }

  /** For tests + diagnostics. */
  getMode(): 'native' | 'poll' | 'wsl-poll' {
    return this.mode
  }

  /**
   * For tests: bypass the fs.watch native path and force polling. Used
   * by the test suite to assert the WSL fallback path works without
   * needing a real WSL environment.
   */
  __forcePollMode(): void {
    this.teardownNative()
    this.startPolling()
  }
}

/**
 * Walk a list of policy paths and return the unique set of (file, dir)
 * pairs to watch. `fs.watch` on a directory catches add/remove of
 * entries; `fs.watch` on a file catches content changes. We watch the
 * file itself; the caller is responsible for atomic-rename edge cases
 * (re-create after rename) via the mtime polling path.
 */
export function expandWatchPaths(paths: string[]): { files: string[]; dirs: string[] } {
  const files = new Set<string>()
  const dirs = new Set<string>()
  for (const p of paths) {
    const abs = resolve(p)
    files.add(abs)
    dirs.add(dirname(abs))
  }
  return { files: [...files], dirs: [...dirs] }
}
