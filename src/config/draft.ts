/**
 * Config draft file lifecycle.
 *
 * The settings-page Config tab writes operator edits to
 * `~/.dsh/security-monitor-config.draft.json` (atomic temp-file + rename).
 * The next `apply()` call deep-merges the envelope's `patch` field on top
 * of the patch-YAML-normalized Config; the file is NOT deleted by the
 * plugin (operators may inspect / remove it manually).
 *
 * Consumers:
 *   - `src/init.ts`           — `resolveDraftPath`, `readDraftFile`, `applyDraftToConfig`
 *   - `src/typert/host.ts`    — `+writeDraftFile` + `getConfigDraftStatus` (which calls `readDraftFile` directly)
 *   - `tests/config/draft.test.ts` — direct unit tests (need `DRAFT_FILE_NAME` + the above)
 *
 * collapsed the five function bodies, dropped
 * `clonePatch` (now `structuredClone`), and merged the envelope / status
 * / whitelist types into a single block.
 */
import { randomUUID } from 'node:crypto'
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { normalizeConfig, type Config } from '../config.js'
import { homeDir } from '../utils/expandHome.js'

/** Envelope schema version. Bump when the on-disk shape changes. */
export const DRAFT_SCHEMA_VERSION = 1

/** File name (under `~/.dsh/`). Tests assert this constant for path layout. */
export const DRAFT_FILE_NAME = 'security-monitor-config.draft.json'

/** On-disk envelope — written by `writeDraftFile`, read by `readDraftFile`. */
export interface DraftEnvelope {
  schemaVersion: number
  patchedAt: string
  operator: string
  patch: Record<string, unknown>
}

/** Top-level keys the marketplace validator accepts. Any other key is
 *  dropped at validate time; the merge re-asserts here so a malformed
 *  draft cannot silently land an unknown block.
 *
 *  Covers the 7 §6.2 sub-blocks
 *  (`sensitivePathGuard` / `inlinePromptInjection` /
 *  `stdioMirror` / `envPassthroughGuard` / `loopedToolDetector` /
 *  `tokenUsageDetector` / `sinkDiskLow`) — without them the merge
 *  treats the keys as `undefined` and drops them before the apply()
 *  merge, so an operator edit to any of them would have zero effect.
 *  The companion parity test (`tests/configParity.test.ts`) walks
 *  the keys exported by `Config` in src/config.ts and asserts every
 *  one is listed here. */
/** Internal — exported only for the parity test (`tests/configParity.test.ts`).
 *  The runtime draft writer does not need to expose this; it is consumed
 *  by `applyDraftToConfig` below. */
export const PATCH_TOP_LEVEL_KEYS = [
  'mode', 'enabled', 'hostId', 'containerId',
  'collector', 'application', 'networkCapture',
  'intervention', 'runtimeHooks', 'inlineGuards',
  // §6.2 — inline deny-list guards
  'sensitivePathGuard', 'inlinePromptInjection',
  // §6.2 — stdio pipe mirror
  'stdioMirror',
  // §6.2 — env-passthrough guard
  'envPassthroughGuard',
  // sensitiveHeaderGuard must be listed here — otherwise the validator
  // accepts the block but applyDraftToConfig silently drops it, so UI edits
  // to sensitiveHeaderGuard.keys never land.
  'sensitiveHeaderGuard',
  // §6.2 — per-tool loop detector
  'loopedToolDetector',
  // §6.2 — token-usage burst detector
  'tokenUsageDetector',
  // §6.2 — sink disk-low degradation
  'sinkDiskLow',
] as const

/** Expand `~/.dsh/<DRAFT_FILE_NAME>` against the shared home resolution. */
export function resolveDraftPath(): string {
  return join(homeDir(), '.dsh', DRAFT_FILE_NAME)
}

/** Atomic write — temp file + rename, never throws (returns ok/err tuple). */
export function writeDraftFile(
  patch: Record<string, unknown>,
  operator: string,
  nowIso: string = new Date().toISOString(),
  now: () => number = Date.now,
): { ok: true; path: string } | { ok: false; error: string } {
  try {
    const path = resolveDraftPath()
    mkdirSync(dirname(path), { recursive: true })
    const envelope: DraftEnvelope = {
      schemaVersion: DRAFT_SCHEMA_VERSION,
      patchedAt: nowIso,
      operator: operator.slice(0, 256),
      patch: structuredClone(patch),
    }
    // The tmp name must be unguessable
    // (`${path}.${now()}.${randomUUID()}.tmp`) and written with O_EXCL — a same-user
    // attacker could pre-plant a symlink at the tmp path and redirect
    // the write to clobber an arbitrary file; the draft itself also
    // landed at umask perms. So: random UUID suffix + `openSync 'wx'`
    // exclusive create (fails EEXIST on a pre-planted symlink) + chmod
    // 0o600 before the atomic rename; the final draft is re-chmodded
    // after rename so a pre-existing umask-created draft is tightened.
    const tmpPath = `${path}.${now()}.${randomUUID()}.tmp`
    const fd = openSync(tmpPath, 'wx', 0o600)
    try {
      writeFileSync(fd, JSON.stringify(envelope, null, 2) + '\n', 'utf8')
    } finally {
      closeSync(fd)
    }
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, path)
    chmodSync(path, 0o600)
    return { ok: true, path }
  } catch (error: unknown) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }
}

/** Read the envelope from disk. Returns null on missing / corrupt /
 *  unsupported schema version — never throws so a bad draft cannot
 *  block startup. */
export function readDraftFile(): DraftEnvelope | null {
  const path = resolveDraftPath()
  if (!existsSync(path)) return null
  try {
    const obj = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
    if (!obj || typeof obj !== 'object') return null
    if (obj['schemaVersion'] !== DRAFT_SCHEMA_VERSION) return null
    if (typeof obj['patchedAt'] !== 'string') return null
    const patch = obj['patch']
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) return null
    return {
      schemaVersion: DRAFT_SCHEMA_VERSION,
      patchedAt: obj['patchedAt'],
      operator: typeof obj['operator'] === 'string' ? obj['operator'] : '',
      patch: patch as Record<string, unknown>,
    }
  } catch {
    return null
  }
}

/** Deep-merge a draft `patch` on top of an already-normalized `Config`.
 *  Block-level keys are merged one level deep — primitive values
 *  overwrite; arrays are replaced (not concatenated). Unknown top-level
 *  keys on the patch are silently dropped (the validator already
 *  rejected them). Returns a fresh copy; `base` is not mutated. */
export function applyDraftToConfig(base: Config, patch: Record<string, unknown>): Config {
  const out: Record<string, unknown> = { ...base }
  for (const key of PATCH_TOP_LEVEL_KEYS) {
    const value = patch[key]
    if (value === undefined) continue
    // Sub-block keys → shallow-merge so a partial operator edit doesn't
    // wipe the rest of the sub-block. `inlineGuards` is special only in
    // that its arrays are intentionally replaced by the shallow-merge
    // semantics (no concat), matching the documented shallow-merge contract.
    // The predicate covers the 7
    // §6.2 sub-blocks (sensitivePathGuard / inlinePromptInjection
    // / stdioMirror / envPassthroughGuard / loopedToolDetector /
    // tokenUsageDetector / sinkDiskLow) — without them the keys are
    // silently dropped because (a) `PATCH_TOP_LEVEL_KEYS` must enumerate
    // them and (b) the predicate must accept them for the shallow-merge
    // to fire.
    if (
      (key === 'collector' || key === 'application' || key === 'networkCapture' ||
       key === 'intervention' || key === 'runtimeHooks' || key === 'inlineGuards' ||
       key === 'sensitivePathGuard' || key === 'inlinePromptInjection' ||
       key === 'stdioMirror' || key === 'envPassthroughGuard' ||
       key === 'sensitiveHeaderGuard' ||
       key === 'loopedToolDetector' || key === 'tokenUsageDetector' ||
       key === 'sinkDiskLow') &&
      value && typeof value === 'object' && !Array.isArray(value)
    ) {
      out[key] = { ...(base[key as keyof Config] as unknown as Record<string, unknown>), ...value }
    } else {
      out[key] = value
    }
  }
  // base 已经过一次 normalizeConfig,
  // 顶层 mode 已物化进嵌套 intervention.mode(第一次归一时 nested 缺失,
  // 由顶层传播得到)。draft 改顶层 mode 后再走 normalizeConfig 时,
  // 嵌套字段被视为"操作者显式设置"而优先,顶层新值被吞掉——表现为
  // 草稿写了 enforce、重启后事件里仍是 audit。
  // 这里在重归一前剥掉嵌套 mode,让顶层值重新传播;draft 同时显式给
  // intervention.mode 的,浅合并已写回嵌套字段,保持"显式嵌套优先"。
  if (patch['mode'] === 'enforce' || patch['mode'] === 'audit') {
    const nestedPatch = patch['intervention']
    const nestedExplicit = nestedPatch && typeof nestedPatch === 'object' && !Array.isArray(nestedPatch)
      && 'mode' in (nestedPatch as Record<string, unknown>)
    if (!nestedExplicit) {
      const nested = out['intervention']
      if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
        delete (nested as Record<string, unknown>)['mode']
      }
    }
  }
  // (draft→normalize pipeline gap): feed the
  // merged shape back through `normalizeConfig()` so the draft write-path
  // benefits from the same UNION-fallback + force-enabled semantics as
  // `apply()` / `livePatch()`. 5 sub-block lists
  // (`inlineGuards.engineLaunchers` / `sensitivePathGuard.paths` /
  // `inlinePromptInjection.patterns` / `envPassthroughGuard.keys`) silently
  // re-assert the marketplace hardcoded catalogue if the operator clears
  // them, and `enabled` is force-reasserted on the four inline guards.
  // Previously the draft path returned a raw merged Config that bypassed
  // these safety-net invariants — a UI bug or malicious operator clearing
  // `engineLaunchers: []` would stay cleared until next `apply()`.
  return normalizeConfig(out)
}