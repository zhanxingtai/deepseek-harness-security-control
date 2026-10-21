/**
 * A follow-up: DebugLog — install / deploy diagnostic log.
 *
 * Contract under test (see src/utils/debugLog.ts for the full doc):
 *   - Empty / unset path → fully disabled, write() is a no-op.
 *   - `~/` path expansion via HOME / USERPROFILE.
 *   - Each write() emits ONE NDJSON line `{ ts, phase, ...payload }`.
 *   - chmod 0o600 applied on first write / creation / rotation (the
 *     rotation path unlinks+recreates, falling back to the umask
 *     otherwise); steady-state appends skip the re-chmod
 *     (2026-10-10 fix — see `chmodPending` in src/utils/events/debugLog.ts).
 *   - Synchronous: appendFileSync-based; the line is durable before
 *     write() returns.
 *   - Best-effort: a write failure logs a single warn and continues.
 *   - isEnabled() returns true iff path was non-empty at construction.
 *
 * The chmod path is OS-gated — Windows (NTFS) doesn't honour POSIX
 * mode bits and the chmodSync call throws EPERM. The DebugLog
 * swallows that internally; tests on Windows still pass because the
 * chmod-on-failure is best-effort.
 */

import { describe, expect, it } from 'vitest'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { DebugLog, createDebugLogFromConfig, expandDebugLogPath } from '../src/utils/debugLog.js'

function withTmpDir<T>(fn: (dir: string) => T): T {
  const dir = join(
    tmpdir(),
    `debug-log-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  )
  mkdirSync(dir, { recursive: true })
  try {
    return fn(dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

function readJsonl(path: string): Array<Record<string, unknown>> {
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
}

describe('DebugLog', () => {
  describe('isEnabled / write no-op', () => {
    it('is disabled when constructed with an empty path', () => {
      const log = new DebugLog({ path: '' })
      expect(log.isEnabled()).toBe(false)
      expect(log.getPath()).toBeUndefined()
      // No-op write must NOT throw and must NOT create any file.
      log.write('phase', { foo: 'bar' })
    })

    it('is disabled when constructed without a path argument', () => {
      const log = new DebugLog({})
      expect(log.isEnabled()).toBe(false)
      log.write('phase', { foo: 'bar' })
    })

    it('is enabled when constructed with a non-empty path', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'debug.log')
        const log = new DebugLog({ path })
        expect(log.isEnabled()).toBe(true)
        expect(log.getPath()).toBe(path)
      })
    })
  })

  describe('expandDebugLogPath', () => {
    it('returns "" for an empty input', () => {
      expect(expandDebugLogPath('')).toBe('')
    })

    it('passes through an absolute / relative path unchanged', () => {
      expect(expandDebugLogPath('/tmp/x.log')).toBe('/tmp/x.log')
      expect(expandDebugLogPath('./local.log')).toBe('./local.log')
    })

    it('expands ~/ using HOME / USERPROFILE', () => {
      const originalHome = process.env['HOME']
      const originalProfile = process.env['USERPROFILE']
      try {
        process.env['HOME'] = '/tmp/fake-home'
        delete process.env['USERPROFILE']
        expect(expandDebugLogPath('~/debug.log')).toBe('/tmp/fake-home/debug.log')
      } finally {
        if (originalHome === undefined) delete process.env['HOME']
        else process.env['HOME'] = originalHome
        if (originalProfile === undefined) delete process.env['USERPROFILE']
        else process.env['USERPROFILE'] = originalProfile
      }
    })
  })

  describe('write() — NDJSON output + chmod 600', () => {
    it('appends one valid NDJSON line per write with ts + phase + payload', () => {
      withTmpDir((dir) => {
        const path = join(dir, 'subdir', 'debug.log')
        // subdir doesn't exist yet — appendToCappedNdjson / DebugLog must
        // create it (mkdir -p semantics) so operators don't have to
        // pre-create the directory tree.
        const log = new DebugLog({ path })
        const before = Date.now()
        log.write('config_integrity_failed', { reason: 'checksum mismatch', attempt: 1 })
        log.write('runtime_hook_install_failed', { path: 'inject', error: 'subprocess unavailable' })
        const after = Date.now()

        const lines = readJsonl(path)
        expect(lines).toHaveLength(2)

        expect(lines[0]?.phase).toBe('config_integrity_failed')
        expect(lines[0]?.reason).toBe('checksum mismatch')
        expect(lines[0]?.attempt).toBe(1)
        expect(typeof lines[0]?.ts).toBe('number')
        const ts0 = lines[0]?.ts as number
        expect(ts0).toBeGreaterThanOrEqual(before)
        expect(ts0).toBeLessThanOrEqual(after)

        expect(lines[1]?.phase).toBe('runtime_hook_install_failed')
        expect(lines[1]?.path).toBe('inject')
        expect(lines[1]?.error).toBe('subprocess unavailable')
      })
    })

    it('chmods the file to 0o600 after writing (POSIX-only, skip on Windows)', () => {
      if (process.platform === 'win32') return // NTFS — mode bits meaningless
      withTmpDir((dir) => {
        const path = join(dir, 'debug.log')
        // Pre-create with a permissive mode to confirm DebugLog tightens it.
        writeFileSync(path, '')
        chmodSync(path, 0o644)

        const log = new DebugLog({ path })
        log.write('initialize', { localOutputPath: '/tmp/x' })

        const st = statSync(path)
        // mode bits 0o600 → st.mode & 0o777 === 0o600
        expect(st.mode & 0o777).toBe(0o600)
      })
    })

    it('re-chmods after the rotation path (file replaced)', () => {
      if (process.platform === 'win32') return
      withTmpDir((dir) => {
        const path = join(dir, 'debug.log')
        const log = new DebugLog({ path, maxBytes: 64 /* tiny cap to force rotation */ })
        // Write enough lines to trigger rotation (appendToCappedNdjson
        // unlinks + recreates the file when it exceeds maxBytes).
        for (let i = 0; i < 20; i++) {
          log.write('padding', { idx: i, blob: 'x'.repeat(40) })
        }
        // File should still exist (rotation unlinks old + writes new).
        expect(existsSync(path)).toBe(true)
        const st = statSync(path)
        expect(st.mode & 0o777).toBe(0o600)
      })
    })
  })

  describe('failure handling', () => {
    it('emits a warn to the injected logger and never throws on write failure', () => {
      withTmpDir((dir) => {
        // Force an underlying appendToCappedNdjson failure by pointing
        // the log at a path inside an existing regular file (so the
        // mkdir will fail). The error message text differs across
        // node versions, so we accept any warn that mentions a failure.
        const blockingFile = join(dir, 'blocker')
        writeFileSync(blockingFile, '')
        const brokenPath = join(blockingFile, 'debug.log')

        const messages: string[] = []
        const log = new DebugLog({
          path: brokenPath,
          logger: {
            warn: (msg) => messages.push(msg),
            error: (msg) => messages.push(msg),
          },
        })

        expect(() => log.write('initialize', { foo: 'bar' })).not.toThrow()
        expect(messages.length).toBeGreaterThanOrEqual(1)
        // The DebugLog wrap (when it fires) prepends "[DebugLog] write
        // failed"; appendToCappedNdjson prefixes its own "[CappedNdjson]"
        // marker. Either is acceptable evidence that a non-fatal failure
        // surfaced — operators see both on the same line in practice.
        expect(messages.some((m) => /DebugLog.*write failed|failed to append/.test(m))).toBe(true)
      })
    })
  })

  describe('createDebugLogFromConfig', () => {
    it('returns a disabled log when the config has an empty / missing path', () => {
      expect(createDebugLogFromConfig({}).isEnabled()).toBe(false)
      expect(createDebugLogFromConfig({ debugLogPath: '' }).isEnabled()).toBe(false)
    })

    it('returns an enabled log when the config has a non-empty path', () => {
      withTmpDir((dir) => {
        const log = createDebugLogFromConfig({ debugLogPath: join(dir, 'debug.log') })
        expect(log.isEnabled()).toBe(true)
      })
    })

    it('expands ~/ in the config path', () => {
      const originalHome = process.env['HOME']
      try {
        process.env['HOME'] = '/tmp/fake-home'
        const log = createDebugLogFromConfig({ debugLogPath: '~/debug.log' })
        expect(log.getPath()).toBe('/tmp/fake-home/debug.log')
      } finally {
        if (originalHome === undefined) delete process.env['HOME']
        else process.env['HOME'] = originalHome
      }
    })
  })
})