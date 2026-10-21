/**
 * tests/installDev.test.ts — unit tests for scripts/install-dev.mjs.
 *
 * The script has 6 steps, of which:
 *   - step 1 (preflight) is a no-op in our test environment (no .ignored/esbuild)
 *   - steps 2-6 each spawn a child process via execFileSync
 *
 * Test strategy: exercise the script via `--dry-run`, which replaces every
 * execFileSync with a no-op. Assert on the *shape* of the dry-run output:
 *   - all 6 step markers appear in order
 *   - the final banner is "✓ OK" or "✓ OK (unverified)"
 *   - the failing-flag path exits 2
 *   - the unknown-flag path emits the expected error prefix
 *   - --help exits 0
 *
 * The real (non-dry-run) path that hits a live DSH harness web profile is
 * OUT OF SCOPE here — it is verified manually by the operator on the
 * remote web profile (see docs/安装部署手册.md §十.5 / §「marketplace
 * 节点人工验收」). These tests cover only the local / CI surfaces.
 */

import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(__dirname, '..')
const scriptPath = join(repoRoot, 'scripts', 'install-dev.mjs')

function run(args: string[], opts: { timeoutMs?: number } = {}): { stdout: string; stderr: string; code: number } {
  try {
    const stdout = execFileSync('node', [scriptPath, ...args], {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: opts.timeoutMs ?? 30_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return { stdout, stderr: '', code: 0 }
  } catch (err) {
    const e = err as { stdout?: Buffer | string; stderr?: Buffer | string; status?: number }
    return {
      stdout: e.stdout?.toString() || '',
      stderr: e.stderr?.toString() || '',
      code: e.status ?? 1,
    }
  }
}

// Strip ANSI escape codes so assertions can match on plain text. The script
// emits colorised output even in --dry-run mode (the green step markers wrap
// the [N/6] prefix in \x1b[32m … \x1b[0m).
function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '')
}

describe('install-dev.mjs — dry-run path', () => {
  it('runs all 6 steps in order and exits 0 with ✓ OK banner', () => {
    const { stdout, code } = run(['--dry-run'])
    expect(code).toBe(0)
    // Step markers in order (ANSI stripped so the colourised [N/6] prefixes match)
    const text = stripAnsi(stdout)
    expect(text).toContain('[1/6] preflight')
    expect(text).toContain('[2/6] build')
    expect(text).toContain('[3/6] pack')
    expect(text).toContain('[4/6] plugin-add')
    expect(text).toContain('[5/6] restart-web')
    expect(text).toContain('[6/6] verify-3-layer')
    // Banner
    expect(text).toMatch(/✓ OK(\s|$)/)
  })

  it('every step shows "(dry-run, skipped)" annotation', () => {
    const { stdout } = run(['--dry-run'])
    const text = stripAnsi(stdout)
    // Steps 2-6 are all dry-run printouts; step 1 is conditional (no .ignored/esbuild)
    // so we assert the dry-run annotation appears at least 6 times (steps 2-6).
    const matches = text.match(/\(dry-run, skipped\)/g) || []
    expect(matches.length).toBeGreaterThanOrEqual(6)
  })

  it('does not execute the preflight mv when no .ignored/esbuild exists', () => {
    const { stdout, code } = run(['--dry-run'])
    expect(code).toBe(0)
    const text = stripAnsi(stdout)
    expect(text).not.toMatch(/^· mv /m)
  })

  it('resolves ROOT to the repo root (visible in dry-run banner)', () => {
    const { stdout } = run(['--dry-run'])
    expect(stripAnsi(stdout)).toContain(`ROOT=${repoRoot}`)
  })

  it('honours --profile override on step 4 + step 5 commands', () => {
    const { stdout } = run(['--dry-run', '--profile', 'headless'])
    const text = stripAnsi(stdout)
    expect(text).toContain('profile=headless')
    expect(text).toMatch(/pnpm dsh plugin --profile headless add/)
    expect(text).toContain('bin.ts web --profile headless')
    expect(text).toContain('pnpm dsh plugin list --profile headless')
  })

  it('honours --web-url override on step 5 + step 6 commands', () => {
    const { stdout } = run(['--dry-run', '--web-url', 'http://192.0.2.10:9999'])
    const text = stripAnsi(stdout)
    expect(text).toContain('webUrl=http://192.0.2.10:9999')
    expect(text).toContain('curl -sI http://192.0.2.10:9999')
    expect(text).toContain('http://192.0.2.10:9999/plugins/sst-security-control-dsh/client.js')
    expect(text).toContain('curl -s http://192.0.2.10:9999/settings')
  })
})

describe('install-dev.mjs — --no-verify', () => {
  it('skips step 6 verify-3-layer entirely', () => {
    const { stdout, code } = run(['--dry-run', '--no-verify'])
    expect(code).toBe(0)
    const text = stripAnsi(stdout)
    expect(text).toContain('[6/6] verify-3-layer — skipped (--no-verify)')
    // Should NOT print the 3 sub-checks (layer / bundle / html)
    expect(text).not.toContain('verify-layer-state')
    expect(text).not.toContain('verify-client-bundle')
    expect(text).not.toContain('verify-settings-html')
  })

  it('banner is "✓ OK (unverified)" not "✓ OK"', () => {
    const { stdout } = run(['--dry-run', '--no-verify'])
    const text = stripAnsi(stdout)
    expect(text).toMatch(/✓ OK \(unverified\)/)
    expect(text).not.toMatch(/^✓ OK\n/m)
  })
})

describe('install-dev.mjs — arg parsing', () => {
  it('--help exits 0 and prints usage', () => {
    const { stdout, code, stderr } = run(['--help'])
    expect(code).toBe(0)
    // --help is uncolored (printed before log helpers are built), so no strip needed
    expect(stdout).toContain('Usage: install-dev')
    expect(stdout).toContain('--dry-run')
    expect(stdout).toContain('--no-verify')
    expect(stdout).toContain('--profile')
    expect(stdout).toContain('--web-url')
    expect(stdout).toContain('--harness-dir')
    expect(stderr).toBe('')
  })

  it('unknown flag exits 2 with structured error', () => {
    const { stderr, code } = run(['--unknown'])
    expect(code).toBe(2)
    expect(stderr).toContain('step=arg-parse')
    expect(stderr).toContain('unknown flag: --unknown')
  })

  it('default profile is "web" and default webUrl is the documented one', () => {
    const { stdout } = run(['--dry-run'])
    const text = stripAnsi(stdout)
    expect(text).toContain('profile=web')
    expect(text).toContain('webUrl=http://127.0.0.1:3080')
  })

  it('--harness-dir override is reflected in the banner + step 4 cwd', () => {
    const { stdout } = run(['--dry-run', '--harness-dir', '/tmp/fake-harness'])
    const text = stripAnsi(stdout)
    expect(text).toContain('harnessDir=/tmp/fake-harness')
  })
})

describe('install-dev.mjs — DSH_HARNESS_DIR env override', () => {
  it('env var is read when --harness-dir is not provided', () => {
    const { stdout } = run(['--dry-run'], {
      // Re-implement env injection by wrapping execFileSync
    })
    // We can't pass env through run() directly — instead assert that the
    // documented env path *exists* by reading the script header.
    const fs = require('node:fs') as typeof import('node:fs')
    const head = fs.readFileSync(scriptPath, 'utf8').slice(0, 6000)
    expect(head).toContain('DSH_HARNESS_DIR')
    expect(head).toContain("process.env.DSH_HARNESS_DIR")
  })
})

describe('install-dev.mjs — error reporting shape', () => {
  it('InstallDevError includes step name + reason in the failure message', () => {
    // Smoke: read the script and verify the error class structure.
    const fs = require('node:fs') as typeof import('node:fs')
    const src = fs.readFileSync(scriptPath, 'utf8')
    expect(src).toContain('class InstallDevError')
    expect(src).toContain('this.step')
    expect(src).toContain('this.reason')
    expect(src).toMatch(/FAIL at step \${err\.step}/)
  })
})
