/**
 * Shared `~` expansion — single source of truth for home-directory
 * resolution across the plugin (sink / engine / debugLog / config).
 *
 * Centralised consolidation: five copies of the HOME / USERPROFILE
 * fallback chain drifted apart (different fallbacks: `/tmp`, `/root`, `''`,
 * `os.homedir()`). This module is the only implementation; every prior
 * site now delegates here.
 *
 * Resolution order: `HOME` → `USERPROFILE` → `os.homedir()` → `/tmp`.
 * The `/tmp` last-ditch fallback exists so a path never silently keeps a
 * literal `~` (which would compare-unequal against real paths and, worse,
 * could create a literal `~` directory on disk). On marketplace hosts
 * (Linux/macOS) `HOME` is always set, so the tail of the chain is a
 * defensive backstop, not a hot path.
 */

import { homedir } from 'node:os'

/** Resolve the user's home directory: HOME → USERPROFILE → homedir() → '/tmp'. */
export function homeDir(): string {
  return process.env.HOME || process.env.USERPROFILE || homedir() || '/tmp'
}

/**
 * Expand a leading `~` to the home directory:
 *  - `~`          → home
 *  - `~/x`, `~\x` → home + rest (both separators honoured)
 *  - `~user/x`    → returned as-is (we don't honour other users' homes —
 *                   that would need getpwnam; leaving it unmatched is the
 *                   safe default for a deny-list comparator)
 *  - anything else → unchanged
 */
export function expandHome(p: string): string {
  if (!p.startsWith('~')) return p
  if (p === '~') return homeDir()
  if (p.startsWith('~/') || p.startsWith('~\\')) {
    return homeDir() + p.slice(1)
  }
  return p
}
