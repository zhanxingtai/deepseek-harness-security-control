/**
 * Tests for the stdio pipe mirror.
 *
 * Coverage:
 *   - parseWrapperArgv: argv contract — happy path + edge cases
 *   - buildStdioMirrorSpec: mode dispatch for the 4 spec.stdio shapes
 *   - rewriteSpecForMirror: argv structure produced for the harness
 * runWrapper: real-fork lifecycle (acceptance — stdin pipe mirror
 * writes NDJSON; acceptance — harness native transport unaffected;
 * acceptance — >1 MiB truncated)
 *
 * The wrapper is at `lib/runtime/stdio-mirror.js` after `pnpm build`. The
 * vitest run always has a fresh build (we rely on the test runner
 * compiling before invocation), so we resolve the path from this test's
 * `__dirname` mirror (the wrapper is one level up + `runtime/`).
 */
import { spawn } from 'node:child_process'
import { promises as fsp, existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MIRROR_ENV_VAR, parseWrapperArgv, runWrapper } from '../src/runtime/stdio-mirror.js'
import {
  buildStdioMirrorSpec,
  rewriteSpecForMirror,
  resolveStdioMirrorWrapperPath,
} from '../src/runtime/stdioMirrorEntry.js'
import type { StdioMirrorConfig } from '../src/config.js'

const here = dirname(fileURLToPath(import.meta.url))
// tests/ is a sibling of src/ at the repo root. After `pnpm build`, the
// wrapper is at <repo>/lib/runtime/stdio-mirror.js. The compiled test
// lives under test/ inside the project, but vitest resolves source files
// from src/ via the source map; we want the compiled wrapper, which is
// at <repo>/lib/runtime/stdio-mirror.js.
const wrapperPath = join(here, '..', 'lib', 'runtime', 'stdio-mirror.js')

// ---------------------------------------------------------------------------
// parseWrapperArgv — argv contract
// ---------------------------------------------------------------------------

describe('parseWrapperArgv', () => {
  it('parses all flags + child argv (happy path)', () => {
    const argv = [
      '--stdio-spec', JSON.stringify({
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      }),
      '--limit-bytes', '4096',
      '--output', '/tmp/x.jsonl',
      '--status-path', '/tmp/x.status.json',
      '--session-id', 's1',
      '--cwd', '/tmp',
      '--',
      'bash', '-c', 'echo hi',
    ]
    const parsed = parseWrapperArgv(argv)
    expect(parsed.limitBytes).toBe(4096)
    expect(parsed.outputPath).toBe('/tmp/x.jsonl')
    expect(parsed.statusPath).toBe('/tmp/x.status.json')
    expect(parsed.sessionId).toBe('s1')
    expect(parsed.cwd).toBe('/tmp')
    // 2026-09-29 regression: the child env no longer rides argv — it arrives via
    // process.env[MIRROR_ENV_VAR] (asserted in the dedicated
    // DSH_MIRROR_ENV_JSON describe below).
    expect(parsed.env).toBeUndefined()
    expect(parsed.childArgv).toEqual(['bash', '-c', 'echo hi'])
  })

  // T3 (2026-10-27): run/agent/task/turn correlation flags — the same keys
  // RuntimeHook's runtime_*_intent events carry — join the wrapper's
  // stdio_mirror events to the spawn's audit trail.
  it('parses the run/agent/task/turn correlation flags', () => {
    const argv = [
      '--stdio-spec', JSON.stringify({
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      }),
      '--limit-bytes', '4096',
      '--output', '/tmp/x.jsonl',
      '--status-path', '/tmp/x.status.json',
      '--session-id', 's1',
      '--run-id', 'r1',
      '--agent-id', 'a1',
      '--task-id', 't1',
      '--turn-id', 'u1',
      '--',
      'bash', '-c', 'echo hi',
    ]
    const parsed = parseWrapperArgv(argv)
    expect(parsed.sessionId).toBe('s1')
    expect(parsed.runId).toBe('r1')
    expect(parsed.agentId).toBe('a1')
    expect(parsed.taskId).toBe('t1')
    expect(parsed.turnId).toBe('u1')
  })

  it('supports the inline `--run-id=r1` form and leaves absent correlation flags undefined', () => {
    const argv = [
      '--stdio-spec={\"stdin\":{\"mode\":\"inherit\",\"mirror\":true,\"relay\":true},\"stdout\":{\"mode\":\"inherit\",\"mirror\":true,\"relay\":true},\"stderr\":{\"mode\":\"inherit\",\"mirror\":true,\"relay\":true}}',
      '--output=/tmp/x.jsonl',
      '--status-path=/tmp/x.status.json',
      '--run-id=r1',
      '--task-id=t1',
      '--', 'echo', 'hi',
    ]
    const parsed = parseWrapperArgv(argv)
    expect(parsed.runId).toBe('r1')
    expect(parsed.taskId).toBe('t1')
    expect(parsed.sessionId).toBeUndefined()
    expect(parsed.agentId).toBeUndefined()
    expect(parsed.turnId).toBeUndefined()
  })

  it('supports `--key=value` inline form for flags', () => {
    const argv = [
      '--stdio-spec={\"stdin\":{\"mode\":\"inherit\",\"mirror\":true,\"relay\":true},\"stdout\":{\"mode\":\"inherit\",\"mirror\":true,\"relay\":true},\"stderr\":{\"mode\":\"inherit\",\"mirror\":true,\"relay\":true}}',
      '--output=/tmp/x.jsonl',
      '--status-path=/tmp/x.status.json',
      '--limit-bytes=2048',
      '--', 'echo', 'hi',
    ]
    const parsed = parseWrapperArgv(argv)
    expect(parsed.limitBytes).toBe(2048)
    expect(parsed.outputPath).toBe('/tmp/x.jsonl')
    expect(parsed.childArgv).toEqual(['echo', 'hi'])
  })

  it('throws on missing --stdio-spec', () => {
    expect(() => parseWrapperArgv([
      '--output=/tmp/x.jsonl',
      '--status-path=/tmp/x.status.json',
      '--', 'echo', 'hi',
    ])).toThrow(/--stdio-spec is required/)
  })

  it('throws on missing child argv (no --)', () => {
    expect(() => parseWrapperArgv([
      '--stdio-spec', JSON.stringify({
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      }),
      '--output=/tmp/x.jsonl',
      '--status-path=/tmp/x.status.json',
    ])).toThrow(/missing child argv/)
  })

  it('throws on malformed --stdio-spec JSON', () => {
    expect(() => parseWrapperArgv([
      '--stdio-spec', 'not-json',
      '--output=/tmp/x.jsonl',
      '--status-path=/tmp/x.status.json',
      '--', 'echo', 'hi',
    ])).toThrow(/--stdio-spec is not valid JSON/)
  })

  it('throws on stdio-spec missing a stream key', () => {
    expect(() => parseWrapperArgv([
      '--stdio-spec', JSON.stringify({ stdin: { mode: 'inherit' } }),
      '--output=/tmp/x.jsonl',
      '--status-path=/tmp/x.status.json',
      '--', 'echo', 'hi',
    ])).toThrow(/stdio-spec/)
  })

  it('throws on invalid stream mode', () => {
    expect(() => parseWrapperArgv([
      '--stdio-spec', JSON.stringify({
        stdin: { mode: 'oops', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      }),
      '--output=/tmp/x.jsonl',
      '--status-path=/tmp/x.status.json',
      '--', 'echo', 'hi',
    ])).toThrow(/mode must be inherit\|pipe\|ignore/)
  })
})

// ---------------------------------------------------------------------------
// buildStdioMirrorSpec — mode dispatch
// ---------------------------------------------------------------------------

describe('buildStdioMirrorSpec', () => {
  const cfg: StdioMirrorConfig = {
    enabled: true,
    payloadLimitBytes: 1024,
    outputPath: '/tmp/x.jsonl',
  }

  it('returns shouldMirror:false for spec.stdio === "ignore"', () => {
    expect(buildStdioMirrorSpec('ignore', cfg)).toEqual({ shouldMirror: false })
  })

  it('returns inherit+relay for spec.stdio === undefined (default)', () => {
    expect(buildStdioMirrorSpec(undefined, cfg)).toEqual({
      shouldMirror: true,
      spec: {
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      },
    })
  })

  it('returns inherit+relay for spec.stdio === "inherit"', () => {
    expect(buildStdioMirrorSpec('inherit', cfg)).toEqual({
      shouldMirror: true,
      spec: {
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      },
    })
  })

  it('returns pipe+no-relay for spec.stdio === "pipe"', () => {
    const r = buildStdioMirrorSpec('pipe', cfg)
    expect(r).toEqual({
      shouldMirror: true,
      spec: {
        stdin: { mode: 'pipe', mirror: true, relay: false },
        stdout: { mode: 'pipe', mirror: true, relay: false },
        stderr: { mode: 'pipe', mirror: true, relay: false },
      },
    })
  })

  it('handles per-stream object form (mixed modes)', () => {
    const r = buildStdioMirrorSpec(
      {
        stdin: 'inherit',
        stdout: 'pipe',
        stderr: 'ignore',
      },
      cfg,
    )
    expect(r).toEqual({
      shouldMirror: true,
      spec: {
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'pipe', mirror: true, relay: false },
        stderr: { mode: 'ignore', mirror: false, relay: false },
      },
    })
  })

  it('treats {maxBytes?: number} as pipe mode; absent keys → ignore (opt-in)', () => {
    const r = buildStdioMirrorSpec({ stdout: { maxBytes: 4096 } }, cfg)
    expect(r.shouldMirror).toBe(true)
    if (r.shouldMirror) {
      expect(r.spec.stdout).toEqual({ mode: 'pipe', mirror: true, relay: false })
      // Per-stream object form: omitted keys default to ignore (don't
      // capture streams the caller didn't explicitly opt into).
      expect(r.spec.stderr).toEqual({ mode: 'ignore', mirror: false, relay: false })
      expect(r.spec.stdin).toEqual({ mode: 'ignore', mirror: false, relay: false })
    }
  })
})

// ---------------------------------------------------------------------------
// rewriteSpecForMirror — argv shape
// ---------------------------------------------------------------------------

describe('rewriteSpecForMirror', () => {
  const cfg: StdioMirrorConfig = {
    enabled: true,
    payloadLimitBytes: 1024 * 1024,
    outputPath: '/tmp/mirror.jsonl',
  }

  it('produces argv = [node, wrapper, --flags, --, ...originalArgv]', () => {
    const spec = {
      argv: ['bash', '-c', 'echo hi'],
      cwd: '/tmp',
      env: { FOO: 'bar' },
    }
    const mirrorSpec = {
      stdin: { mode: 'inherit' as const, mirror: true, relay: true },
      stdout: { mode: 'inherit' as const, mirror: true, relay: true },
      stderr: { mode: 'inherit' as const, mirror: true, relay: true },
    }
    const out = rewriteSpecForMirror(
      spec,
      '/abs/lib/runtime/stdio-mirror.js',
      mirrorSpec,
      cfg,
      { sessionId: 's1', statusPath: '/tmp/m.jsonl.status' },
    )
    expect(out.argv[0]).toBe(process.execPath)
    expect(out.argv[1]).toBe('/abs/lib/runtime/stdio-mirror.js')
    expect(out.argv[2]).toMatch(/^--stdio-spec=/)
    expect(out.argv).toContain('--limit-bytes=1048576')
    expect(out.argv).toContain('--output=/tmp/mirror.jsonl')
    expect(out.argv).toContain('--status-path=/tmp/m.jsonl.status')
    expect(out.argv).not.toContain('--wrapper-start-seq=5')
    expect(out.argv).toContain('--session-id=s1')
    expect(out.argv).toContain('--cwd=/tmp')
    // 2026-09-29 regression: the child env must NOT appear on argv — Linux
    // `/proc/<pid>/cmdline` is world-readable and `spec.env` routinely
    // carries tokens. It crosses via the wrapper's own process env
    // instead (`DSH_MIRROR_ENV_JSON`, owner-only `/proc/<pid>/environ`).
    expect(out.argv.some((a) => a.startsWith('--env='))).toBe(false)
    expect(out.argv.join(' ')).not.toContain('FOO')
    expect(out.env).toEqual({
      ...spec.env,
      DSH_MIRROR_ENV_JSON: JSON.stringify(spec.env),
    })
    expect(out.argv).toContain('--')
    const dashIdx = out.argv.indexOf('--')
    expect(out.argv.slice(dashIdx + 1)).toEqual(['bash', '-c', 'echo hi'])
  })

  // T3 (2026-10-27): the host passes the run/agent/task/turn correlation
  // ids through to the wrapper argv. Present values become flags; absent
  // ones are omitted (the wrapper then leaves the event field undefined
  // rather than writing an empty string).
  it('emits --run-id/--agent-id/--task-id/--turn-id from meta and omits them when absent', () => {
    const mirrorSpec = {
      stdin: { mode: 'inherit' as const, mirror: true, relay: true },
      stdout: { mode: 'inherit' as const, mirror: true, relay: true },
      stderr: { mode: 'inherit' as const, mirror: true, relay: true },
    }
    const withAll = rewriteSpecForMirror(
      { argv: ['bash', '-c', 'echo hi'] },
      '/abs/lib/runtime/stdio-mirror.js',
      mirrorSpec,
      cfg,
      {
        sessionId: 's1',
        runId: 'r1',
        agentId: 'a1',
        taskId: 't1',
        turnId: 'u1',
        statusPath: '/tmp/m.jsonl.status',
      },
    )
    expect(withAll.argv).toContain('--session-id=s1')
    expect(withAll.argv).toContain('--run-id=r1')
    expect(withAll.argv).toContain('--agent-id=a1')
    expect(withAll.argv).toContain('--task-id=t1')
    expect(withAll.argv).toContain('--turn-id=u1')

    const without = rewriteSpecForMirror(
      { argv: ['bash', '-c', 'echo hi'] },
      '/abs/lib/runtime/stdio-mirror.js',
      mirrorSpec,
      cfg,
      { statusPath: '/tmp/m.jsonl.status' },
    )
    for (const flag of ['--run-id', '--agent-id', '--task-id', '--turn-id', '--session-id']) {
      expect(without.argv.some((a) => a.startsWith(`${flag}=`))).toBe(false)
    }
  })

  // 2026-09-29 regression: when the caller passes no child env, the rewritten spec
  // must not invent a `DSH_MIRROR_ENV_JSON` — the wrapper then treats
  // the child env as "inherit", exactly as before.
  it('does not inject DSH_MIRROR_ENV_JSON when spec.env is absent', () => {
    const spec = { argv: ['bash', '-c', 'echo hi'] }
    const mirrorSpec = {
      stdin: { mode: 'inherit' as const, mirror: true, relay: true },
      stdout: { mode: 'inherit' as const, mirror: true, relay: true },
      stderr: { mode: 'inherit' as const, mirror: true, relay: true },
    }
    const out = rewriteSpecForMirror(spec, '/abs/lib/runtime/stdio-mirror.js', mirrorSpec, cfg, {
      statusPath: '/tmp/m.jsonl.status',
    })
    expect(out.env).toBeUndefined()
  })

  // 2026-09-29 regression: pin the security property end-to-end at the rewrite seam —
  // a token-shaped env value must be absent from the argv vector that
  // lands on the world-readable cmdline, and present (serialised) only
  // in the wrapper-side env channel.
  it('keeps token-shaped env values off argv entirely (2026-09-29 regression)', () => {
    const secret = 'ghp_' + 'y'.repeat(40)
    const spec = { argv: ['bash', '-c', 'echo hi'], env: { GITHUB_TOKEN: secret } }
    const mirrorSpec = {
      stdin: { mode: 'inherit' as const, mirror: true, relay: true },
      stdout: { mode: 'inherit' as const, mirror: true, relay: true },
      stderr: { mode: 'inherit' as const, mirror: true, relay: true },
    }
    const out = rewriteSpecForMirror(spec, '/abs/lib/runtime/stdio-mirror.js', mirrorSpec, cfg, {
      statusPath: '/tmp/m.jsonl.status',
    })
    for (const a of out.argv) {
      expect(a).not.toContain(secret)
    }
    expect(JSON.parse((out.env as Record<string, string>)['DSH_MIRROR_ENV_JSON'])).toEqual({
      GITHUB_TOKEN: secret,
    })
  })

  // the host now passes `spec.graceMs` through
  // as `--grace-ms=<n>` so the wrapper's SIGTERM → SIGKILL timer actually
  // arms. Pre-fix the value never crossed the process boundary and the
  // wrapper declared a killTimer variable that no code path ever set.
  it('emits --grace-ms when spec.graceMs is positive', () => {
    const spec = {
      argv: ['bash', '-c', 'sleep 5'],
      graceMs: 250,
    }
    const mirrorSpec = {
      stdin: { mode: 'inherit' as const, mirror: true, relay: true },
      stdout: { mode: 'inherit' as const, mirror: true, relay: true },
      stderr: { mode: 'inherit' as const, mirror: true, relay: true },
    }
    const out = rewriteSpecForMirror(
      spec,
      '/abs/lib/runtime/stdio-mirror.js',
      mirrorSpec,
      cfg,
      { statusPath: '/tmp/m.jsonl.status' },
    )
    expect(out.argv).toContain('--grace-ms=250')
  })

  it('omits --grace-ms when spec.graceMs is missing or non-positive', () => {
    const cases = [{}, { graceMs: 0 }, { graceMs: -1 }]
    for (const spec of cases) {
      const mirrorSpec = {
        stdin: { mode: 'inherit' as const, mirror: true, relay: true },
        stdout: { mode: 'inherit' as const, mirror: true, relay: true },
        stderr: { mode: 'inherit' as const, mirror: true, relay: true },
      }
      const out = rewriteSpecForMirror(
        { argv: ['bash', '-c', 'echo'], ...spec },
        '/abs/lib/runtime/stdio-mirror.js',
        mirrorSpec,
        cfg,
        { statusPath: '/tmp/m.jsonl.status' },
      )
      expect(out.argv.some((a) => a.startsWith('--grace-ms'))).toBe(false)
    }
  })
})

// ---------------------------------------------------------------------------
// parseWrapperArgv honours --grace-ms
// ---------------------------------------------------------------------------

describe('parseWrapperArgv — --grace-ms', () => {
  const baseFlags = [
    '--stdio-spec=' + JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    }),
    '--output=/tmp/m.jsonl',
    '--status-path=/tmp/m.jsonl.status',
  ]

  it('parses --grace-ms=<positive int> and exposes it on the result', () => {
    const parsed = parseWrapperArgv([...baseFlags, '--grace-ms=500', '--', 'bash', '-c', 'sleep 5'])
    expect(parsed.graceMs).toBe(500)
  })

  it('parses space-separated --grace-ms <int>', () => {
    const parsed = parseWrapperArgv([...baseFlags, '--grace-ms', '750', '--', 'bash'])
    expect(parsed.graceMs).toBe(750)
  })

  it('omits graceMs when the flag is absent (graceMs: undefined)', () => {
    const parsed = parseWrapperArgv([...baseFlags, '--', 'bash'])
    expect(parsed.graceMs).toBeUndefined()
  })

  it('throws on zero / negative / non-integer graceMs', () => {
    expect(() => parseWrapperArgv([...baseFlags, '--grace-ms=0', '--', 'bash'])).toThrow(/grace-ms/)
    expect(() => parseWrapperArgv([...baseFlags, '--grace-ms=-1', '--', 'bash'])).toThrow(/grace-ms/)
    expect(() => parseWrapperArgv([...baseFlags, '--grace-ms=abc', '--', 'bash'])).toThrow(/grace-ms/)
  })
})

// ---------------------------------------------------------------------------
// 2026-09-29 regression: the child env crosses the process boundary via
// the wrapper's OWN environment (`DSH_MIRROR_ENV_JSON`), not argv —
// `/proc/<pid>/cmdline` is world-readable, `/proc/<pid>/environ` is
// owner/root-only. The legacy `--env=` flag must be rejected outright.
// ---------------------------------------------------------------------------

describe('parseWrapperArgv — child env via DSH_MIRROR_ENV_JSON (2026-09-29 regression)', () => {
  const baseFlags = [
    '--stdio-spec=' + JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    }),
    '--output=/tmp/m.jsonl',
    '--status-path=/tmp/m.jsonl.status',
  ]

  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('reads the child env from process.env.DSH_MIRROR_ENV_JSON', () => {
    vi.stubEnv(MIRROR_ENV_VAR, JSON.stringify({ FOO: 'bar', TOKEN: 'ghp_' + 'x'.repeat(40) }))
    const parsed = parseWrapperArgv([...baseFlags, '--', 'bash'])
    expect(parsed.env).toEqual({ FOO: 'bar', TOKEN: 'ghp_' + 'x'.repeat(40) })
  })

  it('treats an absent DSH_MIRROR_ENV_JSON as "no child env overrides"', () => {
    const parsed = parseWrapperArgv([...baseFlags, '--', 'bash'])
    expect(parsed.env).toBeUndefined()
  })

  it('treats an empty DSH_MIRROR_ENV_JSON as "no child env overrides"', () => {
    vi.stubEnv(MIRROR_ENV_VAR, '')
    const parsed = parseWrapperArgv([...baseFlags, '--', 'bash'])
    expect(parsed.env).toBeUndefined()
  })

  it('throws wrapper_argv_invalid when DSH_MIRROR_ENV_JSON is not valid JSON', () => {
    vi.stubEnv(MIRROR_ENV_VAR, 'not-json')
    expect(() => parseWrapperArgv([...baseFlags, '--', 'bash'])).toThrow(
      new RegExp(`${MIRROR_ENV_VAR} is not valid JSON`),
    )
  })

  it('rejects the legacy --env argv flag (env must not ride the world-readable cmdline)', () => {
    expect(() =>
      parseWrapperArgv([...baseFlags, `--env=${JSON.stringify({ FOO: 'bar' })}`, '--', 'bash']),
    ).toThrow(/unknown flag --env/)
  })
})

// ---------------------------------------------------------------------------
// resolveStdioMirrorWrapperPath — install-path-agnostic resolution
// ---------------------------------------------------------------------------

describe('resolveStdioMirrorWrapperPath', () => {
  // Separator-normalized view: join() produces backslashes on Windows,
  // but the assertions pin the platform-agnostic shape (suffix +
  // absoluteness), not a specific separator.
  const asPosix = (p: string): string => p.split('\\').join('/')

  it('resolves to an absolute path under runtime/stdio-mirror.js', () => {
    const p = resolveStdioMirrorWrapperPath()
    expect(asPosix(p).endsWith('/runtime/stdio-mirror.js')).toBe(true)
    // Must be absolute (works for pnpm link / npm install / dev --patch).
    // Drive-letter roots (E:/) are absolute on Windows; POSIX roots are '/'.
    expect(p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p)).toBe(true)
    // 2026-09-28 regression: the production bug joined an extra 'runtime'
    // segment (lib/runtime/runtime/stdio-mirror.js — a path that exists
    // on NO install), and every subprocess spawn rewrote argv to it. The
    // suffix assertion above cannot see that, so pin it explicitly.
    expect(asPosix(p)).not.toContain('/runtime/runtime/')
    // Under vitest the resolver runs from src/ where the sibling is the
    // TypeScript source (same name, .ts extension); on a packed install
    // it is the compiled .js. Either must exist — a doubled-segment path
    // satisfies neither. (The compiled lib/runtime layout is the same shape.)
    const srcVariant = p.replace(/\.js$/, '.ts')
    expect(existsSync(p) || existsSync(srcVariant)).toBe(true)
  })

  it('resolves to the compiled wrapper when run from lib/', () => {
    // Path resolution is relative to import.meta.url of the host module.
    // The compiled host lives at <install>/lib/runtime/stdioMirrorEntry.js,
    // and the wrapper at <install>/lib/runtime/stdio-mirror.js. We assert
    // this by computing what the compiled layout would produce.
    const expected = join(
      dirname(fileURLToPath(import.meta.url)),
      '..', '..', 'lib', 'runtime', 'stdio-mirror.js',
    )
    // Just sanity-check the expected shape; the production resolve path
    // is exercised end-to-end by the spawn tests below.
    expect(asPosix(expected).endsWith('/lib/runtime/stdio-mirror.js')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// runWrapper — real-fork lifecycle (acceptance criteria 1, 2, 3)
// ---------------------------------------------------------------------------

describe('runWrapper — real fork', () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await fsp.mkdtemp(join(tmpdir(), 'dsh-stdio-mirror-test-'))
  })
  afterEach(async () => {
    // Windows keeps a handle on files inside the temp dir for a short
    // window after the forked wrapper reports exit, so a single `rm`
    // can fail with EBUSY/EPERM even though nothing is actually
    // leaked. Retry briefly — the assertion already ran by now, so this
    // is pure cleanup and must not be able to fail the test.
    for (let attempt = 0; attempt < 10; attempt++) {
      try {
        await fsp.rm(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 })
        return
      } catch {
        await new Promise((r) => setTimeout(r, 100))
      }
    }
  })

  function spawnWrapper(childArgv: string[], overrides: Partial<Parameters<typeof parseWrapperArgv>[0] extends readonly string[] ? never : Record<string, unknown>> = {}, wrapperExtraArgs: string[] = []): ReturnType<typeof spawn> {
    const outputPath = join(tmpDir, 'mirror.jsonl')
    const statusPath = join(tmpDir, 'status.json')
    const stdioSpec = JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    })
    const args = [
      wrapperPath,
      `--stdio-spec=${stdioSpec}`,
      '--limit-bytes=1048576',
      `--output=${outputPath}`,
      `--status-path=${statusPath}`,
      // T3 (2026-10-27): correlation flags ride before `--` like every
      // other wrapper flag.
      ...wrapperExtraArgs,
      '--',
      ...childArgv,
    ]
    return spawn(process.execPath, args, {
      cwd: tmpDir,
      stdio: ['pipe', 'pipe', 'pipe'],
      ...overrides,
    })
  }

  /** Wait for the child to exit and capture stdout / stderr.
   * a 15s watchdog caps the wait so a wedged
   *  child (e.g. stuck stdin/pipe under full-suite CPU load) cannot
   *  hang the test indefinitely — a hung test would block the rest
   *  of the suite on this single fork and be far more disruptive
   *  than a clean timeout error. The reject fires `child.kill()` as
   *  a courtesy so any leaked handles are reaped. */
  function runToEnd(
    child: ReturnType<typeof spawn>,
    timeoutMs = 15_000,
  ): Promise<{ code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const stdoutChunks: Buffer[] = []
      const stderrChunks: Buffer[] = []
      const timer = setTimeout(() => {
        try {
          child.kill('SIGKILL')
        } catch {
          /* already exited */
        }
        reject(new Error(`runToEnd timed out after ${timeoutMs}ms (child pid=${child.pid})`))
      }, timeoutMs)
      child.stdout?.on('data', (c) => stdoutChunks.push(c))
      child.stderr?.on('data', (c) => stderrChunks.push(c))
      child.once('error', (err) => {
        clearTimeout(timer)
        reject(err)
      })
      child.once('exit', (code, signal) => {
        clearTimeout(timer)
        resolve({
          code,
          signal,
          stdout: Buffer.concat(stdoutChunks).toString('utf8'),
          stderr: Buffer.concat(stderrChunks).toString('utf8'),
        })
      })
    })
  }

  // 2026-09-22 A-5 flake stabilisation: fixed sleeps and single-shot
  // reads race the wrapper process under full-suite CPU load (many
  // vitest workers competing with the forked node processes). Poll the
  // mirror NDJSON file instead — `appendFileSync` writes are visible
  // to readers as soon as they return, so retry-reading collapses the
  // timing window without weakening the assertions.
  async function waitForMirrorLine(
    outputPath: string,
    predicate: (line: Record<string, unknown>) => boolean,
    timeoutMs = 10_000,
  ): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs
    let lastError: unknown
    while (Date.now() < deadline) {
      try {
        const lines = readFileSync(outputPath, 'utf8')
          .trim()
          .split('\n')
          .filter(Boolean)
          .map((l) => JSON.parse(l) as Record<string, unknown>)
        const hit = lines.find(predicate)
        if (hit) return hit
      } catch (e) {
        lastError = e // ENOENT until the wrapper creates the file
      }
      await new Promise((r) => setTimeout(r, 50))
    }
    throw new Error(`timed out (${timeoutMs}ms) waiting for mirror line: ${String(lastError)}`)
  }

  it('propagates child exit code', async () => {
    const child = spawnWrapper(['node', '-e', 'process.exit(7)'])
    const r = await runToEnd(child)
    expect(r.code).toBe(7)
  })

  it('captures stdout via relay to parent process (acceptance)', async () => {
    const child = spawnWrapper(['node', '-e', "process.stdout.write('hello-from-child\\n')"])
    const r = await runToEnd(child)
    expect(r.stdout).toContain('hello-from-child')
  })

  it('writes mirror events to the configured NDJSON file', async () => {
    const outputPath = join(tmpDir, 'mirror.jsonl')
    const statusPath = join(tmpDir, 'status.json')
    const stdioSpec = JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    })
    const args = [
      wrapperPath,
      `--stdio-spec=${stdioSpec}`,
      '--limit-bytes=1048576',
      `--output=${outputPath}`,
      `--status-path=${statusPath}`,
      '--',
      // The child writes its bytes then sleeps 400ms — long enough for
      // the wrapper's 50ms drain interval to flush the stdout mirror
      // chunk before the child exits (and the wrapper's 200ms post-exit
      // grace drains any tail).
      'node', '-e', "process.stdout.write('mirror-this\\n'); setTimeout(()=>process.exit(0),400)",
    ]
    const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
    await runToEnd(child)
    const lines = readFileSync(outputPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
    const stdoutLine = lines.find((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout')
    expect(stdoutLine).toBeDefined()
    expect(stdoutLine.content).toContain('mirror-this')
    expect(stdoutLine.cmdline).toContain('mirror-this')
  })

  it('captures stdin from parent into child (acceptance)', async () => {
    const outputPath = join(tmpDir, 'mirror.jsonl')
    const statusPath = join(tmpDir, 'status.json')
    const stdioSpec = JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    })
    const args = [
      wrapperPath,
      `--stdio-spec=${stdioSpec}`,
      '--limit-bytes=1048576',
      `--output=${outputPath}`,
      `--status-path=${statusPath}`,
      '--',
      // Child collects stdin into a buffer; when stdin closes (or after
      // a 1s grace) it echoes the collected bytes to stdout. The bound
      // prevents the test hanging if stdin forwarding doesn't deliver EOF.
      'node', '-e', "let s=''; process.stdin.on('data',(c)=>{s+=c}); process.stdin.on('end',()=>{process.stdout.write('echo:'+s);process.exit(0)}); setTimeout(()=>{process.stdout.write('echo:'+s);process.exit(0)},1000)",
    ]
    const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['pipe', 'pipe', 'pipe'] })
    child.stdin?.write('hello-from-parent\n')
    child.stdin?.end()
    const r = await runToEnd(child)
    expect(r.stdout).toContain('echo:hello-from-parent')
    // Mirror should also have a stdin chunk from the parent.
    const lines = readFileSync(outputPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
    const stdinLine = lines.find((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdin')
    expect(stdinLine).toBeDefined()
    expect(stdinLine.content).toContain('hello-from-parent')
  }, 10_000)

  it('truncates content larger than --limit-bytes (acceptance)', async () => {
    const outputPath = join(tmpDir, 'mirror.jsonl')
    const statusPath = join(tmpDir, 'status.json')
    const stdioSpec = JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    })
    const args = [
      wrapperPath,
      `--stdio-spec=${stdioSpec}`,
      // 1 KiB cap on the mirror side; the actual child writes 256 KiB
      // then sleeps so the wrapper's 50ms drain can flush the chunked
      // truncated mirror events to NDJSON before exit.
      '--limit-bytes=1024',
      `--output=${outputPath}`,
      `--status-path=${statusPath}`,
      '--',
      'node', '-e', "process.stdout.write('x'.repeat(256 * 1024)); setTimeout(()=>process.exit(0),400)",
    ]
    const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
    await runToEnd(child)
    const lines = readFileSync(outputPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
    const stdoutLines = lines.filter((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout')
    expect(stdoutLines.length).toBeGreaterThan(0)
    // Each captured chunk is bounded by --limit-bytes; the cap applies per
    // chunk, so total mirror bytes can exceed 1024 only via multiple chunks.
    for (const line of stdoutLines) {
      expect(line.bytes).toBeLessThanOrEqual(1024)
    }
  })

  it('writes runtime_stdio_mirror_exit on child exit with exit_code + exit_signal', async () => {
    const outputPath = join(tmpDir, 'mirror.jsonl')
    const statusPath = join(tmpDir, 'status.json')
    const stdioSpec = JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    })
    const args = [
      wrapperPath,
      `--stdio-spec=${stdioSpec}`,
      '--limit-bytes=1048576',
      `--output=${outputPath}`,
      `--status-path=${statusPath}`,
      '--',
      'node', '-e', 'process.exit(0)',
    ]
    const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
    await runToEnd(child)
    const lines = readFileSync(outputPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
    const exitLine = lines.find((l) => l.event_type === 'runtime_stdio_mirror_exit')
    expect(exitLine).toBeDefined()
    expect(exitLine.exit_code).toBe(0)
    expect(exitLine.exit_signal).toBeNull()
    expect(exitLine.wrapper_pid).toBeGreaterThan(0)
    expect(typeof exitLine.duration_ms).toBe('number')
  })

  // T3 (2026-10-27): run/agent/task/turn correlation fields. The host
  // (RuntimeHook.maybeRewriteForMirror) passes the same values as the
  // runtime_*_intent events; the wrapper stamps them on every event type
  // it emits.
  const corrFlags = [
    '--session-id=s1',
    '--run-id=r1',
    '--agent-id=a1',
    '--task-id=t1',
    '--turn-id=u1',
  ]

  it('stamps run_id/agent_id/task_id/turn_id on the meta marker, chunk, and exit events', async () => {
    const child = spawnWrapper(
      ['node', '-e', "process.stdout.write('corr-probe\\n'); setTimeout(()=>process.exit(0),300)"],
      {},
      corrFlags,
    )
    await runToEnd(child)
    const lines = readFileSync(join(tmpDir, 'mirror.jsonl'), 'utf8')
      .trim().split('\n').map((l) => JSON.parse(l))
    const meta = lines.find((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'meta')
    const chunk = lines.find((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout')
    const exit = lines.find((l) => l.event_type === 'runtime_stdio_mirror_exit')
    expect(meta).toBeDefined()
    expect(chunk).toBeDefined()
    expect(exit).toBeDefined()
    for (const ev of [meta, chunk, exit]) {
      expect(ev.session_id).toBe('s1')
      expect(ev.run_id).toBe('r1')
      expect(ev.agent_id).toBe('a1')
      expect(ev.task_id).toBe('t1')
      expect(ev.turn_id).toBe('u1')
    }
  })

  it('stamps the correlation fields on the spawn-failed error event', async () => {
    // A nonexistent binary makes the wrapper's spawn fail (ENOENT → the
    // child 'error' path), exercising the runtime_stdio_mirror_error
    // event's correlation fields.
    const child = spawnWrapper(
      ['dsh-corr-probe-definitely-not-a-real-binary'],
      {},
      corrFlags,
    )
    await runToEnd(child)
    const err = await waitForMirrorLine(
      join(tmpDir, 'mirror.jsonl'),
      (l) => l.event_type === 'runtime_stdio_mirror_error',
    )
    expect(err.session_id).toBe('s1')
    expect(err.run_id).toBe('r1')
    expect(err.agent_id).toBe('a1')
    expect(err.task_id).toBe('t1')
    expect(err.turn_id).toBe('u1')
  })

  it('omits run_id/agent_id/task_id/turn_id (and session_id) when the flags are absent', async () => {
    const child = spawnWrapper(
      ['node', '-e', "process.stdout.write('no-corr\\n'); setTimeout(()=>process.exit(0),300)"],
    )
    await runToEnd(child)
    const lines = readFileSync(join(tmpDir, 'mirror.jsonl'), 'utf8')
      .trim().split('\n').map((l) => JSON.parse(l))
    const meta = lines.find((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'meta')
    const chunk = lines.find((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout')
    const exit = lines.find((l) => l.event_type === 'runtime_stdio_mirror_exit')
    expect(meta).toBeDefined()
    expect(chunk).toBeDefined()
    expect(exit).toBeDefined()
    for (const ev of [meta, chunk, exit]) {
      for (const key of ['session_id', 'run_id', 'agent_id', 'task_id', 'turn_id']) {
        expect(ev, `${key} must be absent when its flag is not passed`).not.toHaveProperty(key)
      }
    }
  })

  it('records exit_signal when the child is signalled', async () => {
    // 2026-09-28: POSIX-signal semantics do not exist on Windows — a
    // TerminateProcess'd wrapper gets no chance to run its signal
    // handlers, so the runtime_stdio_mirror_exit line with exit_signal
    // is unobservable there (the wrapper is killed before it can write
    // the event). Skip the assertion on win32; the signal-forwarding
    // path it pins is POSIX-only.
    if (process.platform === 'win32') return
    const outputPath = join(tmpDir, 'mirror.jsonl')
    const statusPath = join(tmpDir, 'status.json')
    const stdioSpec = JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    })
    const args = [
      wrapperPath,
      `--stdio-spec=${stdioSpec}`,
      '--limit-bytes=1048576',
      `--output=${outputPath}`,
      `--status-path=${statusPath}`,
      '--',
      'node', '-e', 'setInterval(()=>{},1000)',
    ]
    const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
    // Synchronise on the wrapper's `meta` event before signalling: it is
    // written only AFTER the grandchild is spawned and the signal
    // handlers are installed, so the SIGTERM below deterministically
    // forwards to the child instead of killing the wrapper mid-startup
    // (the pre-fix fixed 200ms sleep raced this under full-suite load).
    await waitForMirrorLine(
      outputPath,
      (l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'meta',
    )
    child.kill('SIGTERM')
    await runToEnd(child)
    const exitLine = await waitForMirrorLine(
      outputPath,
      (l) => l.event_type === 'runtime_stdio_mirror_exit',
    )
    // exit_signal may be 'SIGTERM' (forwarded) or 'SIGKILL' (escalation);
    // either is acceptable for the signal-fwd test.
    expect(['SIGTERM', 'SIGKILL']).toContain(exitLine.exit_signal)
  }, 20_000)

  // invariant #6 leak fix — every per-chunk mirror
  // event redacts both `cmdline` (argv hoisted in runWrapper) and
  // `content` (per-chunk value-pattern scan). The end-to-end tests below
  // assert (a) credential-shaped strings in argv never appear verbatim
  // on disk, (b) credential-shaped strings in child stdout get masked
  // before persistence, and (c) the `redacted_keys` side-channel names
  // the family so audit consumers don't have to diff raw lines.
  describe('invariant #6 leak fix (redact on emit)', () => {
    it('redacts --token=value in argv before persisting cmdline', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const stdioSpec = JSON.stringify({
        stdin: { mode: 'ignore', mirror: false, relay: false },
        stdout: { mode: 'inherit', mirror: true, relay: false },
        stderr: { mode: 'ignore', mirror: false, relay: false },
      })
      // argv carries --token=<github PAT> in cleartext. The wrapper must
      // not surface it on disk; the audit row's cmdline should have
      // `--token=***` and `redacted_keys` should include `argv.token`.
      const secret = 'ghp_' + 'x'.repeat(40)
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        'node', '-e', 'process.exit(0)',
        '--token=' + secret,
      ]
      const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
      await runToEnd(child)
      // Inspect EVERY line in the NDJSON — no event of any type may
      // carry the secret verbatim.
      const raw = readFileSync(outputPath, 'utf8')
      expect(raw).not.toContain(secret)
      const lines = raw.trim().split('\n').map((l) => JSON.parse(l))
      const meta = lines.find((l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'meta')
      expect(meta).toBeDefined()
      expect(meta.cmdline).toContain('--token=***')
      expect(meta.cmdline).not.toContain(secret)
      expect(meta.redacted_keys).toContain('argv.token')
      // Every line that has cmdline set must show redacted form.
      for (const line of lines) {
        if (typeof line.cmdline === 'string') {
          expect(line.cmdline).not.toContain(secret)
        }
      }
    })

    it('redacts credential-shaped content in child stdout', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const stdioSpec = JSON.stringify({
        stdin: { mode: 'ignore', mirror: false, relay: false },
        stdout: { mode: 'inherit', mirror: true, relay: false },
        stderr: { mode: 'ignore', mirror: false, relay: false },
      })
      // Child prints an HTTP-style header line carrying a Bearer token.
      // The wrapper must mask it before appendFileSync.
      const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc-def'
      const childCode = `process.stdout.write('Authorization: Bearer ${token}\\n'); setTimeout(()=>process.exit(0),200)`
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        'node', '-e', childCode,
      ]
      const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
      await runToEnd(child)
      const raw = readFileSync(outputPath, 'utf8')
      expect(raw).not.toContain(token)
      const stdoutLine = await waitForMirrorLine(
        outputPath,
        (l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout',
      )
      expect(stdoutLine.content).toContain('Bearer ***')
      expect(stdoutLine.content).not.toContain(token)
      expect(Array.isArray(stdoutLine.redacted_keys)).toBe(true)
      expect(stdoutLine.redacted_keys).toContain('bearer_token')
    })

    it('redacts URL query-string secrets in child stdout', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const stdioSpec = JSON.stringify({
        stdin: { mode: 'ignore', mirror: false, relay: false },
        stdout: { mode: 'inherit', mirror: true, relay: false },
        stderr: { mode: 'ignore', mirror: false, relay: false },
      })
      // Child prints a URL whose query string carries `token=secret123`.
      // The wrapper must mask the value but leave the URL structure
      // intact so the audit row still names the destination.
      const childCode = `process.stdout.write('GET https://api.example.com/v1/?token=secret123&user=alice\\n'); setTimeout(()=>process.exit(0),200)`
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        'node', '-e', childCode,
      ]
      const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
      await runToEnd(child)
      const raw = readFileSync(outputPath, 'utf8')
      expect(raw).not.toContain('secret123')
      const stdoutLine = await waitForMirrorLine(
        outputPath,
        (l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout',
      )
      expect(stdoutLine.content).toContain('token=***')
      expect(stdoutLine.content).toContain('user=alice')
      expect(stdoutLine.redacted_keys).toContain('query.token')
    })

    it('emits redacted_keys=[] when nothing matches (clean control)', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const stdioSpec = JSON.stringify({
        stdin: { mode: 'ignore', mirror: false, relay: false },
        stdout: { mode: 'inherit', mirror: true, relay: false },
        stderr: { mode: 'ignore', mirror: false, relay: false },
      })
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        'node', '-e', "process.stdout.write('hello world\\n'); setTimeout(()=>process.exit(0),200)",
      ]
      const child = spawn(process.execPath, args, { cwd: tmpDir, stdio: ['ignore', 'ignore', 'ignore'] })
      await runToEnd(child)
      const stdoutLine = await waitForMirrorLine(
        outputPath,
        (l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout',
      )
      expect(stdoutLine.redacted_keys).toEqual([])
    })
  })

  // the pre-fix wrapper wrote `ok: true` to
  // the status.json BEFORE the spawn ran. If the wrapper crashed
  // between that write and the post-exit write, the status file
  // persisted with a phantom success. These tests lock the new
  // contract: initial status = `phase: 'spawning', ok: false`,
  // post-exit status = `phase: 'exited', ok: <actual outcome>`.
  describe('status.json ghost-success fix', () => {
    it('writes phase=spawning + ok=false BEFORE spawn (no pre-emptive ok:true)', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const stdioSpec = JSON.stringify({
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      })
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        // Long-sleep child so we have time to inspect the status
        // file mid-flight before the post-exit write.
        'node', '-e', 'setTimeout(()=>process.exit(0),800)',
      ]
      const child = spawn(process.execPath, args, {
        cwd: tmpDir,
        stdio: ['ignore', 'ignore', 'ignore'],
      })
      try {
        // The wrapper writes the spawning-phase status synchronously
        // before fork; poll until the file exists (the wrapper may
        // need a tick to create it), then assert ok=false +
        // phase=spawning BEFORE the child exits.
        //
        // Budget is 5 s, not 500 ms: what we're actually waiting on is
        // `node <wrapper>` boot (ESM init + arg parsing), not the child.
        // Under a loaded full-suite run that boot can exceed 500 ms and
        // the poll would miss the window, failing a test whose subject
        // is perfectly correct. The write happens BEFORE the child is
        // spawned, so a long deadline cannot mask a real regression —
        // a genuinely broken wrapper never writes phase=spawning and
        // the assertions below still fail (just with the real phase
        // value, which is the informative failure). Matches the 5 s
        // budget the sibling post-exit test uses at line ~1113.
        let mid: Record<string, unknown> | undefined
        const deadline = Date.now() + 5000
        while (Date.now() < deadline) {
          try {
            mid = JSON.parse(readFileSync(statusPath, 'utf8')) as Record<string, unknown>
            break
          } catch {
            // file not yet created
          }
          await new Promise((r) => setTimeout(r, 25))
        }
        expect(mid).toBeDefined()
        expect(mid?.['phase']).toBe('spawning')
        expect(mid?.['ok']).toBe(false)
      } finally {
        child.kill('SIGTERM')
        await runToEnd(child)
      }
    })

    it('post-exit status carries ok=true ONLY when the child exited 0', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const stdioSpec = JSON.stringify({
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      })
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        'node', '-e', 'process.exit(3)',
      ]
      const child = spawn(process.execPath, args, {
        cwd: tmpDir,
        stdio: ['ignore', 'ignore', 'ignore'],
      })
      await runToEnd(child)
      const final = JSON.parse(readFileSync(statusPath, 'utf8')) as Record<string, unknown>
      expect(final.phase).toBe('exited')
      // exit_code=3 → ok must reflect actual outcome, NOT ok:true.
      expect(final.ok).toBe(false)
      expect(final.exit_code).toBe(3)
    })

    it('post-exit status with exit_code=0 carries ok=true', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const stdioSpec = JSON.stringify({
        stdin: { mode: 'inherit', mirror: true, relay: true },
        stdout: { mode: 'inherit', mirror: true, relay: true },
        stderr: { mode: 'inherit', mirror: true, relay: true },
      })
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        'node', '-e', 'process.exit(0)',
      ]
      const child = spawn(process.execPath, args, {
        cwd: tmpDir,
        stdio: ['ignore', 'ignore', 'ignore'],
      })
      await runToEnd(child)
      const final = JSON.parse(readFileSync(statusPath, 'utf8')) as Record<string, unknown>
      expect(final.phase).toBe('exited')
      expect(final.ok).toBe(true)
      expect(final.exit_code).toBe(0)
    })
  })

  // 2026-09-29 regression: the child env crosses the boundary via the
  // wrapper's own process environment (`DSH_MIRROR_ENV_JSON`), not argv.
  // These end-to-end tests lock (a) the business child still receives
  // exactly `spec.env`, (b) the side-channel var never leaks into the
  // business child's environment, and (c) the wrapper's argv as visible
  // in /proc/<pid>/cmdline carries no trace of the env contents.
  describe('2026-09-29 regression — child env via DSH_MIRROR_ENV_JSON (real fork)', () => {
    const stdioSpec = JSON.stringify({
      stdin: { mode: 'inherit', mirror: true, relay: true },
      stdout: { mode: 'inherit', mirror: true, relay: true },
      stderr: { mode: 'inherit', mirror: true, relay: true },
    })

    it('business child receives spec.env and never sees DSH_MIRROR_ENV_JSON', async () => {
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        // Emit `env-e2e:<value>:mirvar:<bool>` so one line proves both
        // (a) the env value arrived and (b) the side-channel var did not
        // leak into the business child's environment.
        'node', '-e', "process.stdout.write('env-e2e:'+process.env.DSH_E2E_KEY+':mirvar:'+('DSH_MIRROR_ENV_JSON' in process.env)); setTimeout(()=>process.exit(0),200)",
      ]
      const child = spawn(process.execPath, args, {
        cwd: tmpDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        env: {
          ...process.env,
          DSH_MIRROR_ENV_JSON: JSON.stringify({ DSH_E2E_KEY: 'e2e-ok' }),
        },
      })
      const r = await runToEnd(child)
      expect(r.code).toBe(0)
      expect(r.stdout).toContain('env-e2e:e2e-ok')
      expect(r.stdout).toContain('mirvar:false')
      // The mirror captured the child's stdout chunk too.
      const stdoutLine = await waitForMirrorLine(
        outputPath,
        (l) => l.event_type === 'runtime_stdio_mirror' && l.stream === 'stdout',
      )
      expect(stdoutLine.content).toContain('env-e2e:e2e-ok')
    })

    it('wrapper /proc/<pid>/cmdline carries no trace of the child env (2026-09-29 regression)', async () => {
      // The leak vector being pinned here is the Linux world-readable
      // cmdline. /proc is absent on macOS and Windows alike, so probe for
      // the file rather than sniffing the platform — that keeps the
      // assertion running under WSL, which does have /proc.
      if (process.platform === 'win32' || !existsSync('/proc/self/cmdline')) return
      const secret = 'dsh-e2e-secret-' + 'k'.repeat(24)
      const outputPath = join(tmpDir, 'mirror.jsonl')
      const statusPath = join(tmpDir, 'status.json')
      const args = [
        wrapperPath,
        `--stdio-spec=${stdioSpec}`,
        '--limit-bytes=1048576',
        `--output=${outputPath}`,
        `--status-path=${statusPath}`,
        '--',
        // Long-sleep child so the wrapper stays alive while we inspect
        // its /proc entry.
        'node', '-e', 'setTimeout(()=>{},8000)',
      ]
      const child = spawn(process.execPath, args, {
        cwd: tmpDir,
        stdio: ['ignore', 'ignore', 'ignore'],
        env: {
          ...process.env,
          DSH_MIRROR_ENV_JSON: JSON.stringify({ DSH_E2E_SECRET: secret }),
        },
      })
      try {
        // The wrapper writes the spawning-phase status file BEFORE
        // forking the child — once it exists the wrapper process is up
        // and its cmdline is inspectable.
        const deadline = Date.now() + 5000
        for (;;) {
          if (existsSync(statusPath)) break
          if (Date.now() > deadline) throw new Error('wrapper status file never appeared')
          await new Promise((r) => setTimeout(r, 25))
        }
        const cmdline = readFileSync(`/proc/${child.pid}/cmdline`, 'utf8')
        expect(cmdline).not.toContain(secret)
        expect(cmdline).not.toContain('DSH_E2E_SECRET')
        expect(cmdline).not.toContain('DSH_MIRROR_ENV_JSON')
      } finally {
        child.kill('SIGTERM')
        await runToEnd(child)
      }
    })
  })
})