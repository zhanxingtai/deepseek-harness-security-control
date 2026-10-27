import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  CONFIG_HASH_FILE_NAME,
  runConfigIntegrityCheck,
} from '../src/utils/configIntegrity.js'

// runConfigIntegrityCheck persists the config hash
// to `~/.dsh/security-monitor-config.sha256` by default. Redirect HOME so
// neither the pre-existing hash tests nor the drift tests below touch the
// developer's real home directory.
let tmpDir: string
let originalHome: string | undefined
let originalUserProfile: string | undefined

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'sec-mgr-integrity-'))
  mkdirSync(join(tmpDir, '.dsh'), { recursive: true })
  originalHome = process.env.HOME
  originalUserProfile = process.env.USERPROFILE
  process.env.HOME = tmpDir
  process.env.USERPROFILE = tmpDir
})

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME
  else process.env.HOME = originalHome
  if (originalUserProfile === undefined) delete process.env.USERPROFILE
  else process.env.USERPROFILE = originalUserProfile
  rmSync(tmpDir, { recursive: true, force: true })
})

/** Minimal config that passes the structural check. */
function validConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    enabled: true,
    mode: 'audit',
    collector: {},
    application: {},
    intervention: {},
    ...overrides,
  }
}

function stateFilePath(): string {
  return join(tmpDir, '.dsh', CONFIG_HASH_FILE_NAME)
}

/**
 * fix: the integrity check was rejecting the install.sh
 * generated patch and the canonical Cordis patch shape.
 *
 * Two changes were made:
 *  - `environment` is no longer REQUIRED (the install.sh heredoc does not
 *    emit it; only dev.patch.yml does). Treating it as required caused
 *    every install to fail the integrity check on a perfectly valid patch.
 *  - The previous "scan rawConfig for the literal string
 *    'sst-security-control-dsh'" check was removed; by the time `apply()` runs,
 *    Cordis has already matched the plugin name at the loader stage, so
 *    the string-search was redundant and failed on the canonical config
 *    shape. The check now verifies `cfg.enabled === true` instead.
 *
 * 2026-09-19 (post-marketplace marketplace rollout): EXPECTED_TOP_LEVEL_KEYS dropped
 * the pre-marketplace platform-deployment blocks `system` (Python psutil process
 * monitor, removed) and `assetMonitor` (AssetCollector
 * removed) — see the marketplace scope + audit re-merge invariants.
 * The marketplace cordis.patch.yml no longer emits
 * these keys. Added the v0.5.x keys `networkCapture` and `runtimeHooks`.
 *
 * All tests below exercise the post-2026-09-19 marketplace contract.
 */

describe('runConfigIntegrityCheck ( / fix / cleanup)', () => {
  it('passes the marketplace cordis.patch.yml shape (no system/assetMonitor)', () => {
    // 2026-09-19: matches the actual cordis.patch.yml emitted by
    // scripts/prepare.mjs in the marketplace form. No `system`,
    // `assetMonitor`, `environment`, `auth`, `endpoint`, or
    // `application.runtimeHooks` — those are pre-marketplace platform-deployment
    // knobs that were removed in the marketplace scope cutover.
    const r = runConfigIntegrityCheck({
      enabled: true,
      mode: 'audit',
      hostId: null,
      containerId: 'host',
      collector: {
        localOutputPath: '~/.dsh/security-events.jsonl',
        batchSize: 100,
        flushIntervalMs: 1000,
        validateEvents: true,
        maxFileBytes: 52428800,
        debugLogPath: '',
      },
      application: {
        captureUserPrompt: true,
        captureSystemPrompt: true,
        captureAgentPlan: true,
        captureReasoning: true,
        toolResultMaxChars: 100000,
        sessionTtlMs: 1800000,
      },
      networkCapture: {
        enabled: true,
        redactBodies: true,
        captureResponseBody: true,
        maxBodyBytes: 1048576,
        maxRequestBodyBytes: 1024 * 1024,
      },
      runtimeHooks: {
        enabled: true,
        networkEnabled: true,
        enabledAtSubprocess: true,
        blockAtSubprocess: false,
      },
      intervention: {
        enabled: true,
        mode: 'audit',
        policyPath: '~/.dsh/security-policy.spl.yaml',
        reloadIntervalMs: 30000,
        decisionTimeoutMs: 50,
        failStrategy: 'fail_open',
      },
    })
    expect(r.ok).toBe(true)
    expect(r.issues).toEqual([])
  })

  it('still passes a slim cordis.yml shape (only required keys, no extras)', () => {
    // 2026-09-19: the operator might deploy with only the minimum required
    // top-level keys. integrity check should not require
    // networkCapture / runtimeHooks to be present (those are optional in
    // normalizeConfig). It only checks the REQUIRED ones
    // (enabled/mode/collector/application/intervention).
    const r = runConfigIntegrityCheck({
      enabled: true,
      mode: 'audit',
      collector: { localOutputPath: '~/.dsh/security-events.jsonl' },
      application: {},
      intervention: { enabled: true, mode: 'audit' },
    })
    expect(r.ok).toBe(true)
    expect(r.issues).toEqual([])
  })

  it('rejects a config missing top-level keys', () => {
    const r = runConfigIntegrityCheck({ mode: 'audit' })
    expect(r.ok).toBe(false)
    expect(r.issues.some((i) => i.includes('missing top-level key'))).toBe(true)
  })

  it('rejects a non-object rawConfig', () => {
    expect(runConfigIntegrityCheck(null).ok).toBe(false)
    expect(runConfigIntegrityCheck('string').ok).toBe(false)
    expect(runConfigIntegrityCheck([]).ok).toBe(false)
  })

  it('rejects a config with enabled: false', () => {
    const r = runConfigIntegrityCheck({
      enabled: false,
      mode: 'audit',
      collector: {},
      application: {},
      intervention: {},
    })
    expect(r.ok).toBe(false)
    expect(r.issues.some((i) => i.includes('not enabled in config'))).toBe(true)
  })

  it('rejects a config with enabled missing', () => {
    const r = runConfigIntegrityCheck({
      mode: 'audit',
      collector: {},
      application: {},
      intervention: {},
    })
    expect(r.ok).toBe(false)
    expect(r.issues.some((i) => i.includes('not enabled in config'))).toBe(true)
  })

  it('hash is stable across re-orderings of the same object', () => {
    const a = { enabled: true, mode: 'audit', x: 1, y: 2 }
    const b = { y: 2, x: 1, mode: 'audit', enabled: true }
    const ha = runConfigIntegrityCheck(a).configHash
    const hb = runConfigIntegrityCheck(b).configHash
    expect(ha).toBe(hb)
  })

  it('hash changes when content changes', () => {
    const a = { enabled: true, mode: 'audit', x: 1 }
    const b = { enabled: true, mode: 'audit', x: 2 }
    expect(runConfigIntegrityCheck(a).configHash).not.toBe(runConfigIntegrityCheck(b).configHash)
  })

  it('rejects unexpected mode value', () => {
    const r = runConfigIntegrityCheck({
      enabled: true,
      mode: 'unknown-mode',
      collector: {},
      application: {},
      intervention: {},
    })
    expect(r.issues.some((i) => i.includes('unexpected mode'))).toBe(true)
  })
})

/**
 * cross-restart config drift detection.
 *
 * The startup integrity check persists the config SHA-256 to
 * `~/.dsh/security-monitor-config.sha256` and compares it against the
 * previous run. A mismatch means the patch config changed between runs:
 * expected after a legitimate operator edit, suspicious otherwise. Drift
 * is a warning-level record (NOT an `ok=false` refusal) because flipping
 * `mode` to `enforce` is the documented hardening path and must not lock
 * the host out on the next start.
 */
describe('runConfigIntegrityCheck — cross-restart drift detection', () => {
  it('first run records the hash to the state file and reports no drift', () => {
    const r = runConfigIntegrityCheck(validConfig())
    expect(r.ok).toBe(true)
    expect(r.configDrift).not.toBeNull()
    expect(r.configDrift?.previousHash).toBeNull()
    expect(r.configDrift?.driftDetected).toBe(false)
    expect(r.configDrift?.persisted).toBe(true)
    expect(r.configDrift?.issue).toBeNull()
    expect(r.configDrift?.stateFile).toBe(stateFilePath())

    const stateFile = stateFilePath()
    expect(existsSync(stateFile)).toBe(true)
    expect(readFileSync(stateFile, 'utf8')).toBe(`${r.configHash}\n`)
    // Permission hygiene matches the NDJSON sink contract (0600). Mode
    // bits are meaningless on Windows (NTFS) — chmod there only toggles
    // the read-only attribute, so the assertion is POSIX-only.
    if (process.platform !== 'win32') {
      expect(statSync(stateFile).mode & 0o777).toBe(0o600)
    }
  })

  it('second run with an identical config reports no drift', () => {
    const first = runConfigIntegrityCheck(validConfig())
    const second = runConfigIntegrityCheck(validConfig())
    expect(second.configDrift?.previousHash).toBe(first.configHash)
    expect(second.configDrift?.driftDetected).toBe(false)
    expect(second.configDrift?.issue).toBeNull()
  })

  it('tampered config across restart is detected and the plugin still loads', () => {
    // Simulate: startup with the factory config, operator/attacker edits
    // cordis.patch.yml (mode flip), harness restarts.
    const first = runConfigIntegrityCheck(validConfig({ mode: 'audit' }))
    const second = runConfigIntegrityCheck(validConfig({ mode: 'enforce' }))

    expect(second.ok).toBe(true)
    expect(second.configDrift?.driftDetected).toBe(true)
    expect(second.configDrift?.previousHash).toBe(first.configHash)
    expect(second.configDrift?.issue).toContain('config drift detected')
    expect(second.configDrift?.issue).toContain(first.configHash)
    expect(second.configDrift?.issue).toContain(second.configHash)
    expect(second.issues).toEqual([])

    // The new hash is recorded: a third run with the tampered config is
    // the new baseline and must not keep flagging drift.
    const third = runConfigIntegrityCheck(validConfig({ mode: 'enforce' }))
    expect(third.configDrift?.driftDetected).toBe(false)
  })

  it('key reordering alone does not produce drift', () => {
    runConfigIntegrityCheck({ enabled: true, mode: 'audit', collector: {}, application: {}, intervention: {} })
    const r = runConfigIntegrityCheck({ intervention: {}, application: {}, collector: {}, mode: 'audit', enabled: true })
    expect(r.configDrift?.driftDetected).toBe(false)
  })

  it('corrupt state file content is treated as drift', () => {
    writeFileSync(stateFilePath(), 'not-a-hash\n', 'utf8')
    const r = runConfigIntegrityCheck(validConfig())
    expect(r.configDrift?.driftDetected).toBe(true)
    expect(r.configDrift?.issue).toContain('not-a-hash')
  })

  it('unwritable state dir degrades to persisted=false without throwing', () => {
    // Replace ~/.dsh with a regular file so mkdir/write fail deterministically
    // (independent of the test runner's OS user).
    rmSync(join(tmpDir, '.dsh'), { recursive: true, force: true })
    writeFileSync(join(tmpDir, '.dsh'), 'i am a file, not a directory\n', 'utf8')
    const r = runConfigIntegrityCheck(validConfig())
    expect(r.ok).toBe(true)
    expect(r.configDrift?.persisted).toBe(false)
    expect(r.configDrift?.driftDetected).toBe(false)
    expect(r.configDrift?.previousHash).toBeNull()
  })

  it('driftCheck: false skips state-file I/O entirely', () => {
    const r = runConfigIntegrityCheck(validConfig(), { driftCheck: false })
    expect(r.configDrift).toBeNull()
    expect(existsSync(stateFilePath())).toBe(false)
  })

  it('non-object rawConfig yields configDrift=null (no hash to compare)', () => {
    expect(runConfigIntegrityCheck(null).configDrift).toBeNull()
    expect(runConfigIntegrityCheck([]).configDrift).toBeNull()
  })
})
