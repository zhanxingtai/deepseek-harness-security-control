/**
 * Unit tests for the inline sensitive-path guard (Stage 3 §6.2).
 *
 * Mirrors the structure of `tests/intervention.test.ts`:
 *   - Pure-function helpers (path normalisation) — table-driven via it.each
 *   - `evaluateSensitivePathGuard` — positive / negative / disabled
 *   - Config normalisation — empty / override / disabled invariants
 *   - SensitivePathWatcher — emits security_audit on change + idempotent stop
 *
 * The negative-test path uses non-sensitive absolute paths
 * (`/tmp/innocent.txt`) so we exercise the comparator's "no-match"
 * branch without conflicting with `/etc/shadow` etc.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, utimesSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, sep } from 'node:path'
import { normalizeConfig } from '../src/config.js'
import {
  DEFAULT_SENSITIVE_PATHS,
  INLINE_SENSITIVE_PATH_CODE,
  buildSensitivePathBlock as _buildSensitivePathBlock_unused,
  compilePattern as _compilePattern_unused,
  evaluateSensitivePathGuard,
  listWatchedDirectories,
  resolveSymlink,
  stripTrailingSlash,
} from '../src/intervention/SensitivePathGuard.js'
import { expandHome } from '../src/utils/expandHome.js'
import {
  SensitivePathWatcher,
} from '../src/intervention/SensitivePathWatcher.js'
import type { InterventionContext, SecurityDecision, SecurityEvent } from '../src/types/index.js'

// Suppress the unused warning — these symbols are public-by-export for
// future test consumers; we don't want a `noUnusedLocals` build break.
void _buildSensitivePathBlock_unused
void _compilePattern_unused

// ---------------------------------------------------------------------------
// path-normalization helpers
// ---------------------------------------------------------------------------

describe('expandHome', () => {
  const HOME = process.env.HOME ?? '/root'
  const CASES: Array<{ input: string; expected: string }> = [
    { input: '~/.ssh/id_rsa', expected: `${HOME}/.ssh/id_rsa` },
    { input: '~/foo/bar', expected: `${HOME}/foo/bar` },
    { input: '~', expected: HOME },
    { input: '/etc/shadow', expected: '/etc/shadow' },
    { input: 'rel/path', expected: 'rel/path' },
    { input: '~user/something', expected: '~user/something' },
  ]
  it.each(CASES)('expands $input → $expected', ({ input, expected }) => {
    expect(expandHome(input)).toBe(expected)
  })
})

describe('stripTrailingSlash', () => {
  const CASES: Array<{ input: string; expected: string }> = [
    { input: '/etc/', expected: '/etc' },
    { input: '/etc/shadow/', expected: '/etc/shadow' },
    { input: '/etc/shadow', expected: '/etc/shadow' },
    { input: '/', expected: '/' },
  ]
  it.each(CASES)('strips $input → $expected', ({ input, expected }) => {
    expect(stripTrailingSlash(input)).toBe(expected)
  })
})

describe('resolveSymlink', () => {
  const CASES: Array<{ input: string; expectSame: boolean }> = [
    { input: '/etc/shadow', expectSame: true },
    { input: '/this/path/definitely/does/not/exist', expectSame: true },
    { input: '/proc/non/existent', expectSame: true },
  ]
  it.each(CASES)('resolves $input without throwing (expectSame=$expectSame)', ({ input, expectSame }) => {
    const result = resolveSymlink(input)
    if (expectSame) expect(result).toBe(input)
    else expect(result).not.toBe(input)
  })
})

// ---------------------------------------------------------------------------
// evaluateSensitivePathGuard — positive matches
// ---------------------------------------------------------------------------

function makeCtx(params: Record<string, unknown>, body?: string): InterventionContext {
  return {
    actionType: 'tool_call',
    toolName: 'bash',
    params,
    body,
  }
}

const HOME = process.env.HOME ?? '/root'

describe('evaluateSensitivePathGuard — positive matches (deny-list fires)', () => {
  const POSITIVE_CASES: Array<{ name: string; ctx: InterventionContext; pattern: string }> = [
    { name: '~/.ssh/id_rsa via params.path', pattern: '~/.ssh/id_rsa', ctx: makeCtx({ path: '~/.ssh/id_rsa' }) },
    { name: '~/.aws/credentials via params.file_path', pattern: '~/.aws/credentials', ctx: makeCtx({ file_path: '~/.aws/credentials' }) },
    { name: '/etc/shadow via params.path', pattern: '/etc/shadow', ctx: makeCtx({ path: '/etc/shadow' }) },
    { name: '/etc/sudoers.d/foo via params.target', pattern: '/etc/sudoers.d/', ctx: makeCtx({ target: '/etc/sudoers.d/foo' }) },
    { name: '~/.aws/config via command substring', pattern: '~/.aws/', ctx: makeCtx({ command: 'cat ~/.aws/config' }) },
    { name: '/etc/shadow via body content', pattern: '/etc/shadow', ctx: makeCtx({}, 'echo "/etc/shadow is sensitive"') },
    { name: '~/.docker/config.json via params.destination', pattern: '~/.docker/config.json', ctx: makeCtx({ destination: '~/.docker/config.json' }) },
    { name: '~/.netrc via body content', pattern: '~/.netrc', ctx: makeCtx({ content: '~/.netrc contains token' }) },
    { name: '/proc/PID/environ (glob)', pattern: '/proc/*/environ', ctx: makeCtx({ path: '/proc/1234/environ' }) },
    { name: 'cloud metadata via command substring', pattern: '169.254.169.254/', ctx: makeCtx({ command: 'curl 169.254.169.254/latest/meta-data/' }) },
    { name: '/var/lib/dpkg/info/x.conffiles (glob)', pattern: '/var/lib/dpkg/info/*', ctx: makeCtx({ path: '/var/lib/dpkg/info/x.conffiles' }) },
    { name: '~/.ssh/ subdir hit via params.src', pattern: '~/.ssh/', ctx: makeCtx({ src: `${HOME}/.ssh/anything.txt` }) },
    // C : Kubernetes / GCP / Azure dev credentials
    { name: '~/.kube/config via params.path', pattern: '~/.kube/config', ctx: makeCtx({ path: '~/.kube/config' }) },
    { name: '~/.kube/ subdir hit via params.destination', pattern: '~/.kube/', ctx: makeCtx({ destination: `${HOME}/.kube/anything.yaml` }) },
    { name: '~/.gcloud/application_default_credentials.json', pattern: '~/.gcloud/application_default_credentials.json', ctx: makeCtx({ path: '~/.gcloud/application_default_credentials.json' }) },
    { name: '~/.gcloud/legacy_credentials/ via subdir hit', pattern: '~/.gcloud/legacy_credentials/', ctx: makeCtx({ src: `${HOME}/.gcloud/legacy_credentials/foo` }) },
    { name: '~/.azure/accessTokens.json via params.file_path', pattern: '~/.azure/accessTokens.json', ctx: makeCtx({ file_path: '~/.azure/accessTokens.json' }) },
    // (multi-user form): `~user/` candidates were
    // previously passed to the deny-list as literal `~user/...` strings
    // and bypassed the `~/.ssh/` pattern. Now `~user/path` is expanded
    // via `expandUserHome` (Linux → `/home/user/`, macOS → `/Users/user/`,
    // `~root` → `/root`) and re-tested against the same deny-list. The
    // `~user/` syntax is a deliberate multi-user-system bypass attempt
    // — the deny-list applies regardless of which user's home holds the
    // credential.
    { name:'~root/.ssh/id_rsa via params.path', pattern:'~/.ssh/', ctx: makeCtx({ path:'~root/.ssh/id_rsa'}) },
    { name:'~alice/.aws/credentials via params.path', pattern:'~/.aws/', ctx: makeCtx({ path:'~alice/.aws/credentials'}) },
    // (NFKC homoglyph): full-width slash (U+FF0F) and
    // zero-width space (U+200B) inside the path token would have
    // slipped past the previous `\/` regex. Now `normalizeForScan`
    // NFKC-collapses `／` → `/` and strips the ZWSP before the regex
    // runs, so the canonical ASCII form reaches the deny-list.
    { name:'~/.ssh/id_rsa with full-width slash + ZWSP', pattern:'~/.ssh/', ctx: makeCtx({ path:'~/​／.ssh​/id_rsa'}) },
  ]
  it.each(POSITIVE_CASES)('$name', ({ ctx, pattern }) => {
    const decision = evaluateSensitivePathGuard(ctx, defaultCfg())
    expect(decision).not.toBeNull()
    expect(decision!.decision).toBe('block')
    expect(decision!.block_code).toBe(INLINE_SENSITIVE_PATH_CODE)
    expect(decision!.policy_id).toBe('inline-sensitive-path-guard')
    expect(decision!.fail_strategy).toBe('inline_self_protection')
    expect(decision!.intervention.block_code).toBe(INLINE_SENSITIVE_PATH_CODE)
    // the reason should mention both the resolved path and the matched pattern
    expect(decision!.block_reason).toContain(pattern.replace(/\/$/, '').replace(/\*$/, '').replace(/^~/, HOME) || pattern)
  })
})

// ---------------------------------------------------------------------------
// symlink-aliasing bypass — an innocent-looking path that
// `realpath`-resolves to a deny-listed credential file must still fire the
// guard. Prior to the fix, `findHit` matched literal variants only and let
// `/tmp/innocent -> ~/.ssh/id_rsa` slip past the `~/.ssh/` deny-list.
// ---------------------------------------------------------------------------

describe('evaluateSensitivePathGuard — symlink-aliasing bypass', () => {
  let tmpRoot: string
  let originalHome: string | undefined

  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'sensitive-path-symlink-'))
    // Redirect HOME so the marketplace `~/.ssh/id_rsa` fallback resolves
    // inside our temp tree (no real user files touched). The original
    // HOME is restored in `afterEach`.
    originalHome = process.env.HOME
    process.env.HOME = tmpRoot
    mkdirSync(join(tmpRoot, '.ssh'), { recursive: true })
    writeFileSync(
      join(tmpRoot, '.ssh', 'id_rsa'),
      '-----BEGIN RSA PRIVATE KEY-----\nfake-key-bytes\n-----END RSA PRIVATE KEY-----\n',
      'utf8',
    )
  })

  afterEach(() => {
    if (originalHome === undefined) {
      delete process.env.HOME
    } else {
      process.env.HOME = originalHome
    }
    rmSync(tmpRoot, { recursive: true, force: true })
  })

  it('blocks a literal innocent-name path that symlinks to ~/.ssh/id_rsa', () => {
    // The attacker pattern: an "innocent" filename whose realpath lands
    // on the deny-list. Before the fix, the literal `/tmp/.../innocent`
    // candidate did NOT match `~/.ssh/` and the call slipped past.
    const symlinkPath = join(tmpRoot, 'innocent')
    // Best-effort symlink creation; on platforms that refuse link
    // creation (e.g. some CI sandboxes), skip the test gracefully.
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require('node:fs').symlinkSync(join(tmpRoot, '.ssh', 'id_rsa'), symlinkPath)
    } catch (err) {
      // Skip — the regression test is filesystem-dependent.
      if ((err as NodeJS.ErrnoException).code === 'EPERM' || (err as NodeJS.ErrnoException).code === 'ENOTSUP') {
        return
      }
      throw err
    }
    const ctx = makeCtx({ path: symlinkPath })
    const decision = evaluateSensitivePathGuard(ctx, defaultCfg())
    expect(decision).not.toBeNull()
    expect(decision!.decision).toBe('block')
    expect(decision!.block_code).toBe(INLINE_SENSITIVE_PATH_CODE)
    // The audit_details.resolved_path is the realpath that fired the
    // deny-list — confirms the symlink bypass was closed (the literal
    // symlink name did NOT match; the resolved realpath did).
    expect(decision!.audit_details?.resolved_path).toBe(join(tmpRoot, '.ssh', 'id_rsa'))
  })

  it('blocks a literal innocent-name path that symlinks to ~/.aws/credentials', () => {
    // Second marketplace baseline path: ~/.aws/credentials.
    mkdirSync(join(tmpRoot, '.aws'), { recursive: true })
    writeFileSync(join(tmpRoot, '.aws', 'credentials'), '[default]\naws_access_key_id=AKIA…\n', 'utf8')
    const symlinkPath = join(tmpRoot, 'notes.txt')
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require('node:fs').symlinkSync(join(tmpRoot, '.aws', 'credentials'), symlinkPath)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EPERM' || (err as NodeJS.ErrnoException).code === 'ENOTSUP') {
        return
      }
      throw err
    }
    const ctx = makeCtx({ path: symlinkPath })
    const decision = evaluateSensitivePathGuard(ctx, defaultCfg())
    expect(decision).not.toBeNull()
    expect(decision!.decision).toBe('block')
  })

  it('does NOT block an innocent-name symlink whose target is NOT on the deny-list', () => {
    // Negative case: a benign symlink must still pass through.
    writeFileSync(join(tmpRoot, 'harmless.txt'), 'no secrets here\n', 'utf8')
    const symlinkPath = join(tmpRoot, 'shortcut')
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require('node:fs').symlinkSync(join(tmpRoot, 'harmless.txt'), symlinkPath)
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EPERM' || (err as NodeJS.ErrnoException).code === 'ENOTSUP') {
        return
      }
      throw err
    }
    const ctx = makeCtx({ path: symlinkPath })
    expect(evaluateSensitivePathGuard(ctx, defaultCfg())).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// evaluateSensitivePathGuard — ** glob support + audit
// ---------------------------------------------------------------------------

describe('** multi-segment glob support + audit_details', () => {
  it('compiles and matches a literal ** glob pattern across multiple segments', () => {
    const cfg = defaultCfg({ paths: ['/var/lib/dpkg/**'] })
    const decision = evaluateSensitivePathGuard(
      makeCtx({ path: '/var/lib/dpkg/info/python3.conffiles' }),
      cfg,
    )
    expect(decision).not.toBeNull()
    expect(decision!.decision).toBe('block')
    expect(decision!.block_code).toBe(INLINE_SENSITIVE_PATH_CODE)
    const details = (decision as unknown as {
      audit_details?: Record<string, unknown>
    }).audit_details
    expect(details?.['matched_pattern']).toBe('/var/lib/dpkg/**')
    expect(details?.['pattern_kind']).toBe('multi_glob')
  })

  it('compiles and matches a ** glob rooted at a literal leaf (no trailing slash)', () => {
    const cfg = defaultCfg({ paths: ['/var/lib/dpkg/**/conffiles'] })
    const decision = evaluateSensitivePathGuard(
      makeCtx({ path: '/var/lib/dpkg/info/python3.postinst/conffiles' }),
      cfg,
    )
    expect(decision).not.toBeNull()
    expect(decision!.decision).toBe('block')
    const details = (decision as unknown as {
      audit_details?: Record<string, unknown>
    }).audit_details
    expect(details?.['pattern_kind']).toBe('multi_glob')
  })

  it('** with directory-prefix tail matches arbitrary depth under the prefix', () => {
    const cfg = defaultCfg({ paths: ['/var/lib/**/private/**'] })
    const decision = evaluateSensitivePathGuard(
      makeCtx({ path: '/var/lib/something/private/inner/leaf.txt' }),
      cfg,
    )
    expect(decision).not.toBeNull()
    expect(decision!.decision).toBe('block')
    const details = (decision as unknown as {
      audit_details?: Record<string, unknown>
    }).audit_details
    expect(details?.['pattern_kind']).toBe('multi_glob')
  })

  it('classifies single-* and literal patterns distinctly from ** in audit_details', () => {
    // Single-* (one segment, e.g. /proc/*/environ) → single_glob
    const single = evaluateSensitivePathGuard(
      makeCtx({ path: '/proc/1234/environ' }),
      defaultCfg({ paths: ['/proc/*/environ'] }),
    )
    const singleDetails = (single as unknown as {
      audit_details?: Record<string, unknown>
    }).audit_details
    expect(singleDetails?.['pattern_kind']).toBe('single_glob')

    // Literal (no wildcard) → literal
    const literal = evaluateSensitivePathGuard(
      makeCtx({ path: '/etc/shadow' }),
      defaultCfg({ paths: ['/etc/shadow'] }),
    )
    const literalDetails = (literal as unknown as {
      audit_details?: Record<string, unknown>
    }).audit_details
    expect(literalDetails?.['pattern_kind']).toBe('literal')

    // ** (multi-segment) → multi_glob
    const multi = evaluateSensitivePathGuard(
      makeCtx({ path: '/var/lib/dpkg/info/python3.conffiles' }),
      defaultCfg({ paths: ['/var/lib/dpkg/**'] }),
    )
    const multiDetails = (multi as unknown as {
      audit_details?: Record<string, unknown>
    }).audit_details
    expect(multiDetails?.['pattern_kind']).toBe('multi_glob')
  })

  it('records resolved_path and field_source on the audit_details for downstream consumers', () => {
    const cfg = defaultCfg({ paths: ['~/.ssh/**'] })
    const decision = evaluateSensitivePathGuard(
      makeCtx({ command: 'cat ~/.ssh/id_rsa' }),
      cfg,
    )
    expect(decision).not.toBeNull()
    const details = (decision as unknown as {
      audit_details?: Record<string, unknown>
      risk_flags?: string[]
    })
    expect(details.audit_details?.['matched_pattern']).toBe('~/.ssh/**')
    expect(details.audit_details?.['pattern_kind']).toBe('multi_glob')
    expect(String(details.audit_details?.['resolved_path'])).toMatch(/\.ssh\/id_rsa$/)
    expect(details.audit_details?.['field_source']).toBe('params.command')
    expect(details.risk_flags).toEqual(['sensitive_path_access'])
  })

  it('** glob does NOT over-match a single-segment sibling pattern', () => {
    // /var/lib/dpkg/** must NOT match /var/lib/other/file (the ** requires
    // at least one segment under /var/lib/dpkg). This guards against a
    // regex that broadens the deny-list into adjacent directories.
    const cfg = defaultCfg({ paths: ['/var/lib/dpkg/**'] })
    const decision = evaluateSensitivePathGuard(
      makeCtx({ path: '/var/lib/other/file' }),
      cfg,
    )
    expect(decision).toBeNull()
  })

  it('compiles a path with multiple ** segments correctly (mid-pattern wildcard)', () => {
    const cfg = defaultCfg({ paths: ['/var/lib/**/private/**'] })
    expect(
      evaluateSensitivePathGuard(
        makeCtx({ path: '/var/lib/a/b/c/private/d/e' }),
        cfg,
      ),
    ).not.toBeNull()
  })

  it('rejects an empty segment in the pattern (defensive guard)', () => {
    // A double-slash in a pattern produces an empty segment; the
    // compiler must silently drop it instead of producing an
    // over-broad regex.
    const cfg = defaultCfg({ paths: ['/var//lib'] })
    const decision = evaluateSensitivePathGuard(
      makeCtx({ path: '/var/lib' }),
      cfg,
    )
    expect(decision).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// evaluateSensitivePathGuard — negative matches
// ---------------------------------------------------------------------------

describe('evaluateSensitivePathGuard — negative matches (no block)', () => {
  const NEGATIVE_CASES: Array<{ name: string; ctx: InterventionContext }> = [
    { name: 'non-sensitive file in /tmp', ctx: makeCtx({ path: '/tmp/innocent.txt' }) },
    { name: 'non-sensitive file in /var/log', ctx: makeCtx({ path: '/var/log/agent.log' }) },
    { name: 'command without any path token', ctx: makeCtx({ command: 'echo hello world' }) },
    { name: 'empty params', ctx: makeCtx({}) },
    { name: 'disabled guard (enabled:false)', ctx: makeCtx({ path: '~/.ssh/id_rsa' }) },
  ]
  it.each(NEGATIVE_CASES)('$name → null', ({ ctx }) => {
    const cfg = NEGATIVE_CASES.indexOf(NEGATIVE_CASES.find((c) => c.ctx === ctx)!) === 4
      ? { ...defaultCfg(), enabled: false }
      : defaultCfg()
    expect(evaluateSensitivePathGuard(ctx, cfg)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Config normalisation — fallback list survives paths: []
// ---------------------------------------------------------------------------

function defaultCfg(overrides: Partial<{
  enabled: boolean
  paths: string[]
  watchEnabled: boolean
  watchDebounceMs: number
}> = {}): import('../src/intervention/SensitivePathGuard.js').SensitivePathGuardConfig {
  // Default = marketplace-shipped defaults (post-normalise).
  return {
    enabled: overrides.enabled ?? true,
    paths: overrides.paths ?? DEFAULT_SENSITIVE_PATHS.slice(),
    watchEnabled: overrides.watchEnabled ?? true,
    watchDebounceMs: overrides.watchDebounceMs ?? 500,
  }
}

describe('normalizeConfig — sensitivePathGuard fallback semantics', () => {
  const FALLBACK_CASES: Array<{
    name: string
    input: unknown
    check: (cfg: ReturnType<typeof normalizeConfig>) => void
  }> = [
    {
      name: 'paths: [] → fallback list',
      input: { sensitivePathGuard: { paths: [] } },
      check: (cfg) => {
        expect(cfg.sensitivePathGuard.paths.length).toBeGreaterThan(10)
        expect(cfg.sensitivePathGuard.paths).toContain('~/.ssh/id_rsa')
        expect(cfg.sensitivePathGuard.paths).toContain('/etc/shadow')
      },
    },
    {
      name: 'omitted → fallback list',
      input: {},
      check: (cfg) => {
        expect(cfg.sensitivePathGuard.paths.length).toBeGreaterThan(10)
        expect(cfg.sensitivePathGuard.paths).toContain('~/.aws/credentials')
      },
    },
    {
      name:'user override survives (UNION semantics)',
      input: { sensitivePathGuard: { paths: ['/custom/path'] } },
      check: (cfg) => {
        // deny-list is UNION — operator entries extend
        // the marketplace 24-entry baseline instead of replacing it.
        // Before : `paths: ['/custom/path']` would silently strip
        // the safety-net defaults (~/.ssh/, ~/.aws/, /etc/shadow, etc.).
        expect(cfg.sensitivePathGuard.paths).toContain('/custom/path')
        expect(cfg.sensitivePathGuard.paths).toContain('~/.ssh/id_rsa')
        expect(cfg.sensitivePathGuard.paths).toContain('/etc/shadow')
        expect(cfg.sensitivePathGuard.paths.length).toBeGreaterThan(20)
      },
    },
    {
      name:'enabled:false is REJECTED and force-asserted to true (safety-net invariant)',
      input: { sensitivePathGuard: { enabled: false, paths: [] } },
      check: (cfg) => {
        // prior behaviour honored `enabled: false`; that was a
        // latent bypass of the safety-net invariant. The deny-list itself
        // is still populated even when the inline guard is forced-on —
        // forcing `enabled: true` does not erase the safety-net records.
        expect(cfg.sensitivePathGuard.enabled).toBe(true)
        expect(cfg.sensitivePathGuard.paths.length).toBeGreaterThan(10)
      },
    },
  ]
  it.each(FALLBACK_CASES)('$name', ({ input, check }) => {
    const cfg = normalizeConfig(input)
    check(cfg)
  })
})

// ---------------------------------------------------------------------------
// listWatchedDirectories
// ---------------------------------------------------------------------------

describe('listWatchedDirectories', () => {
  it('skips non-absolute paths', () => {
    const out = listWatchedDirectories(['relative/path', '~/.ssh/'])
    // Only absolute paths are returned; `~/.ssh/` is absolute after expansion.
    const dirs = out.map((d) => d.directory)
    expect(dirs).toContain(`${HOME}/.ssh`)
    expect(dirs).not.toContain('relative/path')
  })

  it('walks up to the literal-ancestor for glob patterns', () => {
    const out = listWatchedDirectories(['/proc/*/environ', '/var/lib/dpkg/info/*'])
    const dirs = out.map((d) => d.directory)
    // For `/proc/*/environ`, the literal ancestor is `/proc`.
    expect(dirs).toContain('/proc')
    // For `/var/lib/dpkg/info/*`, the literal ancestor is `/var/lib/dpkg/info`.
    expect(dirs).toContain('/var/lib/dpkg/info')
  })

  it('dedupes overlapping patterns', () => {
    const out = listWatchedDirectories(['/etc/shadow', '/etc/'])
    // `/etc/shadow` strips to `/etc/shadow`; `/etc/` strips to `/etc`. Both are returned once.
    const dirs = out.map((d) => d.directory)
    expect(dirs).toContain('/etc/shadow')
    expect(dirs).toContain('/etc')
  })
})

// ---------------------------------------------------------------------------
// SensitivePathWatcher — emits security_audit on change
// ---------------------------------------------------------------------------

class StubEventCollector {
  events: SecurityEvent[] = []
  report(event: SecurityEvent): void {
    this.events.push(event)
  }
}

describe('SensitivePathWatcher', () => {
  let tmpRoot: string
  let collector: StubEventCollector
  let watcher: SensitivePathWatcher
  let originalHome: string | undefined

  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), 'sensitive-path-'))
    collector = new StubEventCollector()
    // Redirect HOME so the `~/.ssh/` fallback entry resolves inside our
    // temp tree — without this the test silently depends on the machine
    // running it actually having a ~/.ssh directory.
    originalHome = process.env.HOME
    process.env.HOME = tmpRoot
    mkdirSync(join(tmpRoot, '.ssh'), { recursive: true })
  })

  afterEach(() => {
    watcher?.stop()
    if (originalHome === undefined) {
      delete process.env.HOME
    } else {
      process.env.HOME = originalHome
    }
    rmSync(tmpRoot, { recursive: true, force: true })
  })

  it('installs watchers for the fallback list and stops idempotently', () => {
    watcher = new SensitivePathWatcher({
      eventCollector: collector as unknown as Parameters<typeof SensitivePathWatcher>[0]['eventCollector'],
      cfg: { enabled: true, paths: DEFAULT_SENSITIVE_PATHS.slice(), watchEnabled: true, watchDebounceMs: 30 },
      sessionResolve: () => undefined,
      logger: { warn: () => {} },
    })
    watcher.start()
    const desc1 = watcher.describe()
    expect(desc1.directories.length).toBeGreaterThan(0)
    // Stop is idempotent.
    watcher.stop()
    watcher.stop()
    const desc2 = watcher.describe()
    expect(desc2.directories.length).toBe(0)
    expect(desc2.pendingTimers).toBe(0)
  })

  it('emits security_audit on file change inside a watched directory', async () => {
    const targetDir = join(tmpRoot, 'ssh')
    mkdirSync(targetDir, { recursive: true })
    const targetFile = join(targetDir, 'id_rsa')
    writeFileSync(targetFile, 'placeholder', { mode: 0o600 })

    watcher = new SensitivePathWatcher({
      eventCollector: collector as unknown as Parameters<typeof SensitivePathWatcher>[0]['eventCollector'],
      cfg: {
        enabled: true,
        paths: [`${targetDir}/`],
        watchEnabled: true,
        watchDebounceMs: 20,
      },
      sessionResolve: () => ({ sessionId: 'sess-1', runId: 'run-1', agentId: 'agent-1' }),
      logger: { warn: () => {} },
    })
    watcher.start()

    // Touch the file to trigger a 'change' event. utimesSync fires even when
    // the file contents are unchanged, which `fs.watch` does not see —
    // re-writing content does fire.
    writeFileSync(targetFile, 'updated')
    // Wait for the event to land. This used to be a fixed 80 ms sleep
    // (debounce is 20 ms), which is a race: `fs.watch` delivery is
    // prompt on a quiet Linux box but routinely slower on Windows, and
    // the watcher itself falls back to polling when fs.watch setup fails
    // — both make a fixed sleep flaky rather than wrong. Poll for the
    // event with a deadline instead; the assertions below are unchanged.
    const deadline = Date.now() + 5000
    let events = collector.events.filter((e) => e.event_type === 'security_audit')
    while (events.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25))
      events = collector.events.filter((e) => e.event_type === 'security_audit')
    }
    expect(events.length).toBeGreaterThanOrEqual(1)
    const last = events[events.length - 1]!
    expect(last.audit_category).toBe('integrity')
    expect(last.audit_action).toBe('detect')
    expect(last.severity).toBe('high')
    expect(last.outcome).toBe('success')
    expect(last.reason).toBe('deny')
    expect(last.audit_details?.watcher).toBe('sensitive-path-guard')
    expect(last.risk_flags).toContain('sensitive_path_access')
  })

  it('skips directories that do not exist on this host', () => {
    const warnings: string[] = []
    watcher = new SensitivePathWatcher({
      eventCollector: collector as unknown as Parameters<typeof SensitivePathWatcher>[0]['eventCollector'],
      cfg: { enabled: true, paths: ['/this/path/definitely/does/not/exist'], watchEnabled: true, watchDebounceMs: 10 },
      sessionResolve: () => undefined,
      logger: { warn: (m: string) => { warnings.push(m) } },
    })
    watcher.start()
    const skipped = warnings.find((w) => w.includes('sensitive_path_watcher_skip'))
    expect(skipped).toBeDefined()
    expect(skipped).toContain('reason=not_found')
  })
})

// ---------------------------------------------------------------------------
// Integration — guard fires through ApplicationCollector.evaluateTool path
// ---------------------------------------------------------------------------

describe('evaluateSensitivePathGuard — malformed contexts do not throw', () => {
  const STRESS_CASES: Array<{ name: string; ctx: InterventionContext }> = [
    { name: 'params is null', ctx: { actionType: 'tool_call', toolName: 'bash', params: null as unknown as Record<string, unknown> } },
    { name: 'params is not an object', ctx: { actionType: 'tool_call', toolName: 'bash', params: 'string-not-object' as unknown as Record<string, unknown> } },
    { name: 'body is a number', ctx: { actionType: 'message_write', toolName: 'write', body: 42 as unknown as string } },
    { name: 'argv is not an array', ctx: { actionType: 'process_start', toolName: 'subprocess', params: { argv: 'oops' as unknown as string[] } } },
  ]
  it.each(STRESS_CASES)('$name → null (no throw, no block)', ({ ctx }) => {
    expect(() => evaluateSensitivePathGuard(ctx, defaultCfg())).not.toThrow()
    expect(evaluateSensitivePathGuard(ctx, defaultCfg())).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Type sanity — ensure the SecurityDecision shape matches the inline guard
// ---------------------------------------------------------------------------

describe('evaluateSensitivePathGuard — SecurityDecision shape', () => {
  it('always returns mode=enforce (cannot be downgraded)', () => {
    const decision = evaluateSensitivePathGuard(
      makeCtx({ path: '~/.ssh/id_rsa' }),
      defaultCfg(),
    )
    expect(decision).not.toBeNull()
    expect(decision!.mode).toBe('enforce')
    expect(decision!.intervention.mode).toBe('enforce')
    expect(decision!.appealable).toBe(false)
  })

  it('carries the canonical block_code for downstream consumers', () => {
    const decision: SecurityDecision | null = evaluateSensitivePathGuard(
      makeCtx({ path: '/etc/shadow' }),
      defaultCfg(),
    )
    expect(decision).not.toBeNull()
    expect(decision!.block_code).toBe('INLINE_SENSITIVE_PATH_001')
  })
})
