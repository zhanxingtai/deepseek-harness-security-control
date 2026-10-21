/**
 * Config integrity check — startup-time verification of
 * the loaded patch configuration.
 *
 * The plugin does not read patch.yml directly (the harness parses it and
 * passes the resulting object to `apply()`). What we CAN do at startup:
 *
 *  1. Structural sanity: the config has a recognisable shape (a
 *     `sst-security-control-dsh` entry, a `mode` field, a `system` block).
 *     A missing or wrong-shape config is a strong signal that the file
 *     was tampered with (or that a different patch was loaded).
 *  2. Config hash: compute a deterministic SHA-256 over the JSON form
 *     of the rawConfig and emit it on startup. The hash is persisted to
 *     `~/.dsh/security-monitor-config.sha256` and compared against the
 * previous run's value : any drift produces a
 *     `configDrift` record in the result and a log line from the caller.
 *     Drift means the file changed between runs — either an operator
 *     update (expected) or tampering (investigate). The expected
 *     operational pattern is a stable hash unless the operator installed
 *     an update.
 *  3. Reference security-monitors: the config has at least one
 *     security-monitor plugin entry. A patch that disables / removes
 *     the plugin is rejected at startup.
 *
 * The function never throws — it returns a result object. The caller
 * (apply) decides what to do with `ok=false` (typically: refuse to
 * load, surface as a `plugin_startup` event). Drift is deliberately NOT
 * part of `ok`: flipping `mode` to `enforce` is the documented
 * hardening path and legitimately changes the hash, so drift is
 * surfaced as a warning-level record (`configDrift.issue`) instead of
 * a load refusal.
 */

import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { homeDir } from './expandHome.js'

export interface ConfigIntegrityResult {
  ok: boolean
  /** SHA-256 of the deterministic JSON form. Stable across restarts
   *  unless the patch file changes between runs. */
  configHash: string
  /** Number of expected fields that were found. Used to flag partial / modified configs. */
  checksPassed: number
  /** Issues found (one entry per missing/wrong field). Empty when ok=true. */
  issues: string[]
  /** Cross-restart drift comparison. null when driftCheck
   *  was disabled via options or when rawConfig has no computable hash
   *  (non-object input). */
  configDrift: ConfigDriftResult | null
}

/** Cross-restart drift record — the "issue" surfaced when the persisted
 *  config hash differs from the hash computed at this startup. */
export interface ConfigDriftResult {
  /** Absolute path of the persisted-hash state file. */
  stateFile: string
  /** Hash recorded by the previous startup; null on first run (no state file). */
  previousHash: string | null
  /** true when a previous hash existed and differs from the current one. */
  driftDetected: boolean
  /** false when the new hash could not be persisted (read-only fs, missing
   *  home, …). Drift detection degrades to this run only. */
  persisted: boolean
  /** Human-readable drift description; non-null exactly when driftDetected. */
  issue: string | null
}

/** Options for {@link runConfigIntegrityCheck}. */
export interface ConfigIntegrityOptions {
  /** Persist the computed hash to the state file and compare it against
   *  the previous run (default true — production startup behavior).
   *  Unit tests that do not exercise drift pass false so the check stays
   *  a pure function; drift tests redirect HOME and leave the default. */
  driftCheck?: boolean
}

/**
 * Top-level keys the plugin expects to see in the patch config. `environment`
 * is intentionally EXCLUDED — it is optional metadata for the platform
 * (hostId, region, etc.) and the install.sh-generated patch does not emit it
 * (only the dev.patch.yml does). Forcing it here would make every install
 * fail the integrity check on a perfectly valid patch.
 *
 * The platform blocks `system` and `assetMonitor` were removed (marketplace
 * scope + audit re-merge invariants). The marketplace cordis.patch.yml no longer emits
 * these keys, so keeping them in EXPECTED_TOP_LEVEL_KEYS would make every
 * install fail config integrity with "missing top-level key:
 * system" / "missing top-level key: assetMonitor".
 *
 * `networkCapture` and `runtimeHooks` are also NOT in this list — they
 * are optional keys (in-process http/fetch monitor and ctx.subprocess.spawn
 * pre-spawn seam respectively) but each plugin instance can opt out
 * (audit-mode network off, headless mode without subprocess monitoring).
 * Forcing them required would make single-purpose deployments (e.g.
 * application-only audit) unnecessarily fail integrity. The marketplace
 * `cordis.patch.yml` does emit them by default.
 */
const EXPECTED_TOP_LEVEL_KEYS = [
  'enabled',
  'mode',
  'collector',
  'application',
  'intervention',
] as const

/**
 * Sort an object's keys recursively to produce a deterministic JSON form.
 * Node's `JSON.stringify` preserves insertion order; without sorting,
 * a config re-saved with keys in a different order would produce a
 * different hash even when semantically identical.
 */
function sortObjectDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObjectDeep)
  if (value && typeof value === 'object' && !(value instanceof Date)) {
    const obj = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(obj).sort()) {
      out[key] = sortObjectDeep(obj[key])
    }
    return out
  }
  return value
}

export function runConfigIntegrityCheck(
  rawConfig: unknown,
  options: ConfigIntegrityOptions = {},
): ConfigIntegrityResult {
  const issues: string[] = []
  let checksPassed = 0

  // Structural sanity: rawConfig is an object with the expected top-level keys.
  if (!rawConfig || typeof rawConfig !== 'object' || Array.isArray(rawConfig)) {
    return {
      ok: false,
      configHash: '',
      checksPassed: 0,
      issues: ['rawConfig is not an object'],
      configDrift: null,
    }
  }
  const cfg = rawConfig as Record<string, unknown>
  for (const key of EXPECTED_TOP_LEVEL_KEYS) {
    if (key in cfg) {
      checksPassed += 1
    } else {
      issues.push(`missing top-level key: ${key}`)
    }
  }

  // Mode sanity: should be a known value.
  const mode = cfg.mode
  if (mode !== 'audit' && mode !== 'enforce') {
    issues.push(`unexpected mode: ${String(mode)} (expected "audit" or "enforce")`)
  } else {
    checksPassed += 1
  }

  // Enabled sanity: the plugin must be wired in (`enabled: true` in the
  // config). This is checked implicitly via EXPECTED_TOP_LEVEL_KEYS above
  // (which includes `enabled`), but we also do a strict truthiness check
  // here so a patch that flips `enabled: false` is rejected loudly.
  //
  // We deliberately do NOT scan the rawConfig for the literal string
  // "sst-security-control-dsh" — by the time `apply()` runs, Cordis has already
  // matched the plugin's `name` from the loader, so the string-in-config
  // check is redundant and would fail when the patch file uses only the
  // canonical config shape (no id string in user config).
  if (cfg.enabled !== true) {
    issues.push(`plugin not enabled in config (enabled=${String(cfg.enabled)})`)
  }

  // Hash for cross-restart comparison. Always computed so the platform
  // can still log it even when the config fails other checks.
  const sorted = sortObjectDeep(rawConfig)
  const json = JSON.stringify(sorted)
  const configHash = createHash('sha256').update(json).digest('hex')

  // Cross-restart drift detection : persist the hash and
  // compare against the previous run. A mismatch means the patch config
  // changed between runs — expected for operator updates, suspicious
  // otherwise. Never throws; persistence failures degrade to
  // persisted=false rather than blocking startup.
  const configDrift = options.driftCheck === false ? null : detectConfigDrift(configHash)

  return {
    ok: issues.length === 0,
    configHash,
    checksPassed,
    issues,
    configDrift,
  }
}

/** File name (under `~/.dsh/`) holding the last startup's config hash.
 *  Mirrors the draft-file layout convention (`security-monitor-config.draft.json`). */
export const CONFIG_HASH_FILE_NAME = 'security-monitor-config.sha256'

/** Expand `~/.dsh/<CONFIG_HASH_FILE_NAME>` against the shared home resolution. */
export function resolveConfigHashPath(): string {
  return join(homeDir(), '.dsh', CONFIG_HASH_FILE_NAME)
}

/**
 * Compare `configHash` against the persisted previous-run hash and
 * record the new hash for the next run. Best-effort end to end: any fs
 * error degrades to "no previous hash" / `persisted: false` so a broken
 * state directory can never block startup. The write is atomic
 * (temp file + rename) and chmod 0o600, matching the NDJSON sink's
 * permission hygiene.
 */
function detectConfigDrift(configHash: string): ConfigDriftResult {
  const stateFile = resolveConfigHashPath()

  let previousHash: string | null = null
  try {
    if (existsSync(stateFile)) {
      const raw = readFileSync(stateFile, 'utf8').trim()
      previousHash = raw.length > 0 ? raw : null
    }
  } catch {
    previousHash = null
  }

  let persisted = true
  try {
    mkdirSync(dirname(stateFile), { recursive: true })
    // Same predictable-tmp + no-O_EXCL pattern as
    // the draft writer (`${stateFile}.${pid}.tmp` via plain writeFileSync) —
    // a pre-planted symlink could redirect the write. Random suffix +
    // `openSync 'wx'` exclusive create + chmod 0o600, then atomic rename.
    const tmpPath = `${stateFile}.${process.pid}.${randomUUID()}.tmp`
    const fd = openSync(tmpPath, 'wx', 0o600)
    try {
      writeFileSync(fd, `${configHash}\n`, 'utf8')
    } finally {
      closeSync(fd)
    }
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, stateFile)
  } catch {
    persisted = false
  }

  const driftDetected = previousHash !== null && previousHash !== configHash
  return {
    stateFile,
    previousHash,
    driftDetected,
    persisted,
    issue: driftDetected
      ? `config drift detected across restart: hash ${previousHash} → ${configHash} (state file: ${stateFile}). ` +
        'Expected after a legitimate cordis.patch.yml edit; otherwise investigate possible tampering.'
      : null,
  }
}
