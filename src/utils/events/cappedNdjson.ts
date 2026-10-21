/**
 * Capped NDJSON file writer.
 *
 * Enforces a hard byte limit on local NDJSON sinks. When the active file
 * exceeds the cap it is rotated atomically (write-new → rename-over-target),
 * rather than keeping a rotation history. This matches the operator
 * requirement that long-running nodes must not grow their local audit trail
 * without bound.
 *
 * All operations are synchronous and best-effort; failures are surfaced via
 * the optional logger rather than thrown, consistent with the "never throw
 * to the host" design invariant.
 */
import { appendFileSync, existsSync, mkdirSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** Default cap: 50 MiB. */
export const DEFAULT_MAX_NDJSON_BYTES = 50 * 1024 * 1024

export interface CappedNdjsonResult {
  /** True if the existing file was rotated because it exceeded the cap. */
  truncated: boolean
  /** Bytes before the append (or before rotation if truncated). */
  previousBytes: number
}

export interface CappedNdjsonOptions {
  /** Logger for warnings. */
  logger?: Pick<Console, 'warn' | 'error'>
}

/**
 * Append `lines` (already-serialized NDJSON lines, each including its own
 * trailing `\n`) to `filePath`. When the existing file exceeds `maxBytes` it
 * is rotated atomically — the new lines land in a sibling `.tmp` file, which
 * is `rename(2)`-d over the target so the audit trail never has a window
 * where the file is unlinked-but-not-yet-replaced. Directories are created
 * recursively when missing.
 *
 * Returns whether the file was rotated and its byte size before the append.
 *
 * (atomic rotation): pre-fix the over-cap path
 * was `unlinkSync` → `appendFileSync`, leaving a window where the file did
 * not exist on disk. A process crash in that window would erase the audit
 * trail; the inode-based `checkLocalIntegrity` would also flag every
 * post-rotation event as a tamper because the inode number changes on
 * delete-then-create. The mechanism: write the new content to a sibling `.tmp`
 * file, then `renameSync` over the target (atomic on POSIX, and on Windows
 * since Node 18 via `MoveFileEx` semantics). The rename creates a new
 * inode for the target — `checkLocalIntegrity` is rotation-aware and
 * ignores inode drift immediately after a rotation (see `LocalNdjsonSink`).
 */
export function appendToCappedNdjson(
  filePath: string,
  lines: string[],
  maxBytes: number = DEFAULT_MAX_NDJSON_BYTES,
  options: CappedNdjsonOptions = {},
): CappedNdjsonResult {
  const dir = dirname(filePath)
  if (!existsSync(dir)) {
    try {
      mkdirSync(dir, { recursive: true })
    } catch (error: unknown) {
      options.logger?.warn(
        `[CappedNdjson] failed to create directory ${dir}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      )
    }
  }

  let previousBytes = 0
  let truncated = false

  if (existsSync(filePath)) {
    try {
      previousBytes = statSync(filePath).size
      if (previousBytes > maxBytes) {
        truncated = true
      }
    } catch (error: unknown) {
      options.logger?.warn(
        `[CappedNdjson] failed to stat ${filePath}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      )
      previousBytes = 0
    }
  }

  if (lines.length === 0) {
    return { truncated, previousBytes }
  }

  // Rotation path: write the new lines to a sibling `.tmp` file, then
  // `rename(2)` over the target. POSIX rename is atomic; Windows MoveFile
  // is atomic for same-volume renames since Node 18. Either way the audit
  // trail never has a "file does not exist" window — readers either see
  // the old (full) file or the new (post-rotation) file.
  if (truncated) {
    const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`
    try {
      writeFileSync(tmpPath, lines.join(''), { encoding: 'utf8' })
      renameSync(tmpPath, filePath)
    } catch (error: unknown) {
      options.logger?.warn(
        `[CappedNdjson] failed to rotate ${filePath}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      )
      // Best-effort cleanup of the orphan tmp so a retry can reuse the slot.
      try {
        if (existsSync(tmpPath)) unlinkSync(tmpPath)
      } catch {
        // ignore
      }
      // Fall back to append so we don't lose the event entirely. The file
      // will be over cap again, but the next append call will retry the
      // rotation path.
      try {
        appendFileSync(filePath, lines.join(''), { encoding: 'utf8' })
      } catch (error2: unknown) {
        options.logger?.warn(
          `[CappedNdjson] fallback append also failed: ${
            error2 instanceof Error ? error2.message : String(error2)
          }`,
        )
      }
    }
    return { truncated, previousBytes }
  }

  // Normal path: append under cap.
  try {
    appendFileSync(filePath, lines.join(''), { encoding: 'utf8' })
  } catch (error: unknown) {
    options.logger?.warn(
      `[CappedNdjson] failed to append to ${filePath}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }

  return { truncated, previousBytes }
}

/**
 * Check whether `filePath` currently exceeds the cap without mutating it.
 * Used by callers that need to reset their own state before the next write.
 */
export function isOverNdjsonCap(filePath: string, maxBytes: number = DEFAULT_MAX_NDJSON_BYTES): boolean {
  if (!existsSync(filePath)) return false
  try {
    return statSync(filePath).size > maxBytes
  } catch {
    return false
  }
}
