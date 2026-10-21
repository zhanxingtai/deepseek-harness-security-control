import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, appendFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PolicyWatcher, expandWatchPaths } from '../src/utils/policyWatcher.js'

describe('PolicyWatcher ( HMR)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-pw-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('fires on file change in native mode', async () => {
    const file = join(tmpDir, 'policy.json')
    writeFileSync(file, '{"apiVersion":"security.use/v2","kind":"Policy","rules":[]}')
    const watcher = new PolicyWatcher([file], { forcePoll: false })
    const events: Array<{ path: string; reason: string }> = []
    watcher.subscribe((e) => events.push({ path: e.path, reason: e.reason }))
    watcher.start()
    // Force poll mode so the test is deterministic across platforms —
    // the inotify trip on tmpfs (CI Linux) is reliable but the
    // macOS / WSL ones can drop the first event. Both code paths are
    // covered by separate tests below.
    watcher.__forcePollMode()
    appendFileSync(file, '\n// touched')
    // Polling cadence is 1000ms by default — wait a bit longer.
    await new Promise((r) => setTimeout(r, 1300))
    watcher.close()
    expect(events.some((e) => e.reason === 'change')).toBe(true)
  })

  it('WSL fallback: forcePoll mode fires on file change', async () => {
    const file = join(tmpDir, 'policy.json')
    writeFileSync(file, '{"apiVersion":"security.use/v2","kind":"Policy","rules":[]}')
    const watcher = new PolicyWatcher([file], { forcePoll: true, pollIntervalMs: 100 })
    expect(watcher.getMode()).toBe('poll')
    const events: Array<{ path: string; reason: string }> = []
    watcher.subscribe((e) => events.push({ path: e.path, reason: e.reason }))
    watcher.start()
    writeFileSync(file, '{"apiVersion":"security.use/v2","kind":"Policy","rules":[{"id":"r1"}]}')
    await new Promise((r) => setTimeout(r, 250))
    watcher.close()
    expect(events.some((e) => e.reason === 'change')).toBe(true)
  })

  it('fires on file deletion (rename)', async () => {
    const file = join(tmpDir, 'policy.json')
    writeFileSync(file, '{}')
    const watcher = new PolicyWatcher([file], { forcePoll: true, pollIntervalMs: 100 })
    const events: Array<{ path: string; reason: string }> = []
    watcher.subscribe((e) => events.push({ path: e.path, reason: e.reason }))
    watcher.start()
    rmSync(file)
    await new Promise((r) => setTimeout(r, 250))
    watcher.close()
    expect(events.some((e) => e.reason === 'rename')).toBe(true)
  })

  it('idempotent close', () => {
    const file = join(tmpDir, 'p.json')
    writeFileSync(file, '{}')
    const watcher = new PolicyWatcher([file], { forcePoll: true })
    watcher.close()
    watcher.close() // second close is a no-op, must not throw
  })

  it('idempotent start (no duplicate timers)', () => {
    const file = join(tmpDir, 'p.json')
    writeFileSync(file, '{}')
    const watcher = new PolicyWatcher([file], { forcePoll: true, pollIntervalMs: 100 })
    watcher.start()
    watcher.start() // second start is a no-op
    watcher.close()
  })

  it('listener exceptions do not break the watcher', async () => {
    const file = join(tmpDir, 'p.json')
    writeFileSync(file, '{}')
    const watcher = new PolicyWatcher([file], { forcePoll: true, pollIntervalMs: 100 })
    let otherCalled = 0
    watcher.subscribe(() => {
      throw new Error('listener boom')
    })
    watcher.subscribe(() => {
      otherCalled += 1
    })
    watcher.start()
    writeFileSync(file, '{} // touched')
    await new Promise((r) => setTimeout(r, 250))
    watcher.close()
    expect(otherCalled).toBeGreaterThan(0)
  })

  it('expandWatchPaths returns file + dir pairs', () => {
    const a = join(tmpDir, 'a.json')
    const b = join(tmpDir, 'sub', 'b.json')
    writeFileSync(a, '{}')
    const { files, dirs } = expandWatchPaths([a, b])
    expect(files).toContain(a)
    expect(dirs).toContain(tmpDir)
  })
})
