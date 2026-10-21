/**
 * (atomic rotation): the pre-fix rotation
 * path was `unlinkSync` → `appendFileSync`, leaving a window where the
 * audit trail did not exist on disk. A process crash in that window
 * would erase the audit log; the inode-based integrity check would
 * also flag every post-rotation event as a tamper because the inode
 * changes on delete-then-create. The fix: write the new content to a
 * sibling `.tmp` file, then `rename(2)` over the target so the trail
 * never has a "file does not exist" gap.
 *
 * These tests pin the contract:
 *  1. Under cap: appendFileSync-style append (no tmp file lingers).
 *  2. Over cap: rotation via tmp+rename (the original file is gone in
 *     favour of the new one — there is no window where it doesn't exist).
 *  3. The tmp file does NOT linger on the happy path.
 *  4. previousBytes reflects the pre-rotation size.
 *  5. Empty-lines input is a no-op (no rotation triggered).
 *  6. Missing directory is created on demand.
 */
import { mkdtempSync, rmSync, existsSync, statSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { appendToCappedNdjson, isOverNdjsonCap } from '../src/utils/cappedNdjson.js'

let tmpDir: string
beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'capped-ndjson-'))
})
afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

function listTmpSiblings(filePath: string): string[] {
  const { readdirSync } = require('node:fs') as typeof import('node:fs')
  // Split on BOTH separators — on Windows join() produces backslashes,
  // and a '/'-only regex leaves dir === filePath (ENOTDIR on readdir).
  const dir = filePath.replace(/[\\/][^\\/]+$/, '')
  const base = filePath.replace(/^.*[\\/]/, '')
  return readdirSync(dir).filter((f) => f.startsWith(`${base}.`) && f.endsWith('.tmp'))
}

describe('appendToCappedNdjson — atomic rotation', () => {
  it('under cap: appends without rotating (no tmp file)', () => {
    const path = join(tmpDir, 'events.jsonl')
    const r1 = appendToCappedNdjson(path, ['{"i":1}\n'], 1024)
    expect(r1.truncated).toBe(false)
    expect(r1.previousBytes).toBe(0)
    expect(existsSync(path)).toBe(true)
    expect(listTmpSiblings(path)).toEqual([])

    const r2 = appendToCappedNdjson(path, ['{"i":2}\n'], 1024)
    expect(r2.truncated).toBe(false)
    expect(r2.previousBytes).toBeGreaterThan(0)
    expect(readFileSync(path, 'utf8')).toBe('{"i":1}\n{"i":2}\n')
  })

  it('over cap: rotates via tmp+rename — file always exists', () => {
    const path = join(tmpDir, 'events.jsonl')
    // Seed an over-cap file.
    appendToCappedNdjson(path, ['x'.repeat(2048) + '\n'], 1024)
    expect(statSync(path).size).toBeGreaterThan(1024)

    // The rotation path must NOT leave a window where the file is missing.
    // We assert the file exists immediately after the call returns.
    const r = appendToCappedNdjson(path, ['{"i":fresh}\n'], 1024)
    expect(r.truncated).toBe(true)
    expect(r.previousBytes).toBeGreaterThan(1024)
    expect(existsSync(path)).toBe(true)
    expect(readFileSync(path, 'utf8')).toBe('{"i":fresh}\n')
    // No orphan tmp lingers.
    expect(listTmpSiblings(path)).toEqual([])
  })

  it('empty lines: reports truncated=true on over-cap (no actual rotation fires)', () => {
    // Contract: `truncated` reflects the EXISTING file's over-cap state,
    // not "we performed a rotation this call". Empty lines still surface
    // the over-cap condition so callers can log a warning — but no
    // tmp+rename is performed (no lines to write).
    const path = join(tmpDir, 'events.jsonl')
    appendToCappedNdjson(path, ['x'.repeat(2048) + '\n'], 1024)
    const r = appendToCappedNdjson(path, [], 1024)
    expect(r.truncated).toBe(true)
    expect(r.previousBytes).toBeGreaterThan(1024)
    // The over-cap content is preserved (no rotation fires without lines).
    expect(statSync(path).size).toBeGreaterThan(1024)
    // No orphan tmp lingers from the no-op.
    expect(listTmpSiblings(path)).toEqual([])
  })

  it('missing directory: created on demand for both append and rotation paths', () => {
    const nested = join(tmpDir, 'a', 'b', 'c', 'events.jsonl')
    appendToCappedNdjson(nested, ['{"first":true}\n'], 1024)
    expect(existsSync(nested)).toBe(true)
    expect(readFileSync(nested, 'utf8')).toBe('{"first":true}\n')

    // Force a rotation.
    appendToCappedNdjson(nested, ['x'.repeat(2048) + '\n'], 1024)
    appendToCappedNdjson(nested, ['{"after":true}\n'], 1024)
    expect(readFileSync(nested, 'utf8')).toBe('{"after":true}\n')
  })

  it('rotation preserves previousBytes accurately (pre-rotation size, not post)', () => {
    const path = join(tmpDir, 'events.jsonl')
    const seedSize = 1500
    appendToCappedNdjson(path, ['y'.repeat(seedSize) + '\n'], 1024)
    const r = appendToCappedNdjson(path, ['{"after":true}\n'], 1024)
    expect(r.truncated).toBe(true)
    // previousBytes reflects the pre-rotation byte size — important for
    // callers that publish it on the rotation event (LocalNdjsonSink
    // uses it for capacity telemetry).
    expect(r.previousBytes).toBe(seedSize + 1)
  })
})

describe('isOverNdjsonCap (unchanged contract)', () => {
  it('returns false when the file does not exist', () => {
    expect(isOverNdjsonCap(join(tmpDir, 'nope.jsonl'), 100)).toBe(false)
  })
  it('returns true when size exceeds the cap', () => {
    const path = join(tmpDir, 'events.jsonl')
    appendToCappedNdjson(path, ['z'.repeat(200) + '\n'], 100)
    expect(isOverNdjsonCap(path, 100)).toBe(true)
  })
  it('returns false when size is at or under the cap', () => {
    const path = join(tmpDir, 'events.jsonl')
    appendToCappedNdjson(path, ['a\n'], 100)
    expect(isOverNdjsonCap(path, 100)).toBe(false)
  })
})