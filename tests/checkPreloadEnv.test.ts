/**
 * Tests for checkPreloadEnv (src/index.ts).
 *
 * The soft guard refuses to load the plugin when the surrounding process
 * env carries pre-load-injection vectors (NODE_OPTIONS / PYTHONSTARTUP /
 * PYTHONPATH / LD_PRELOAD ...). The 2026-10-10 H1 fix tokenizes
 * NODE_OPTIONS instead of matching one big regex, because Node accepts the
 * SHORT alias `-r` for `--require` and the old long-flag-only regex let
 * `NODE_OPTIONS="-r /tmp/evil.js"` sail through.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { checkPreloadEnv } from '../src/index.js'

const SAVED_ENV = { ...process.env }

function setEnv(key: string, value: string | undefined): void {
  if (value === undefined) delete process.env[key]
  else process.env[key] = value
}

describe('checkPreloadEnv', () => {
  beforeEach(() => {
    // Start each case from a clean slate so tests are order-independent.
    for (const key of ['NODE_OPTIONS', 'PYTHONSTARTUP', 'PYTHONNOUSERSITE', 'PYTHONPATH', 'LD_PRELOAD']) {
      delete process.env[key]
    }
  })

  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (!(key in SAVED_ENV)) delete process.env[key]
    }
    Object.assign(process.env, SAVED_ENV)
  })

  it('accepts an empty / unset NODE_OPTIONS', () => {
    expect(checkPreloadEnv().violations).toEqual([])
    setEnv('NODE_OPTIONS', '   ')
    expect(checkPreloadEnv().violations).toEqual([])
  })

  it('accepts benign tuning flags', () => {
    setEnv('NODE_OPTIONS', '--max-old-space-size=4096 --trace-gc')
    expect(checkPreloadEnv().violations).toEqual([])
  })

  it('rejects long preload / inspect flags', () => {
    for (const value of [
      '--require /tmp/evil.js',
      '--require=/tmp/evil.js',
      '--import file:///tmp/evil.mjs',
      '--inspect=0.0.0.0:9229',
      '--inspect-brk',
      '--loader ts-node/esm',
      '--experimental-vm-modules',
    ]) {
      setEnv('NODE_OPTIONS', value)
      expect(checkPreloadEnv().violations, `expected rejection for ${value}`).toHaveLength(1)
    }
  })

  it('rejects the short -r alias in every spelling (H1)', () => {
    // Node documents `-r` as the short form of `--require` and accepts it
    // inside NODE_OPTIONS; each spelling below must trip the guard.
    for (const value of [
      '-r /tmp/evil.js',
      '-r/tmp/evil.js',
      '-r=/tmp/evil.js',
      '--max-old-space-size=1024 -r /tmp/evil.js',
      '-r /tmp/a.js --max-old-space-size=1024',
    ]) {
      setEnv('NODE_OPTIONS', value)
      expect(checkPreloadEnv().violations, `expected rejection for ${value}`).toHaveLength(1)
    }
  })

  it('still allows benign flags combined after the H1 fix', () => {
    setEnv('NODE_OPTIONS', '--max-old-space-size=4096 --trace-gc --no-warnings')
    expect(checkPreloadEnv().violations).toEqual([])
  })

  it('flags PYTHONSTARTUP / PYTHONPATH / LD_PRELOAD when set', () => {
    setEnv('PYTHONSTARTUP', '/tmp/startup.py')
    setEnv('PYTHONPATH', '/tmp/pylib')
    setEnv('LD_PRELOAD', '/tmp/evil.so')
    const violations = checkPreloadEnv().violations
    expect(violations).toHaveLength(3)
  })

  it('allows the recommended PYTHONNOUSERSITE=1 hardening value', () => {
    setEnv('PYTHONNOUSERSITE', '1')
    expect(checkPreloadEnv().violations).toEqual([])
    setEnv('PYTHONNOUSERSITE', '0')
    expect(checkPreloadEnv().violations).toHaveLength(1)
  })
})
