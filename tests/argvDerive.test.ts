/**
 * Tests for the argvDerive helper.
 *
 * The helper extracts a single command string from a SubprocessSpawnSpec's
 * argv vector, so the existing SPL rules written for `tools/pre-execute`
 * can match at the subprocess seam. The trickiest cases are bash's
 * `argv = ['bash', '-c', command]` and pwsh's `-Command cmd`.
 */
import { describe, expect, it } from 'vitest'
import {
  argvMentionsSecurityMonitorPatch,
  deriveBodyFromArgv,
  isEngineLauncher,
} from '../src/utils/argvDerive.js'

describe('deriveBodyFromArgv', () => {
  it('extracts the bash command from -c argv', () => {
    expect(deriveBodyFromArgv(['bash', '-c', 'echo hello'])).toBe('echo hello')
    expect(deriveBodyFromArgv(['/bin/bash', '-c', 'rm -rf /tmp/x'])).toBe('rm -rf /tmp/x')
    expect(deriveBodyFromArgv(['sh', '-c', 'cat /etc/passwd'])).toBe('cat /etc/passwd')
  })

  it('handles bash with --command long flag', () => {
    expect(deriveBodyFromArgv(['bash', '--command', 'echo hi'])).toBe('echo hi')
  })

  it('handles bash -i (interactive) followed by -c', () => {
    expect(deriveBodyFromArgv(['bash', '-i', '-c', 'date'])).toBe('date')
  })

  it('returns positional script path when bash has no -c', () => {
    // `bash script.sh` — the script path is the most useful body.
    expect(deriveBodyFromArgv(['bash', '/tmp/run.sh'])).toBe('/tmp/run.sh')
  })

  it('returns joined argv when bash has only flags', () => {
    // `bash -i` (no script) — fall back to argv.join(' ').
    expect(deriveBodyFromArgv(['bash', '-i', '-l'])).toBe('bash -i -l')
  })

  it('extracts the pwsh command from -Command argv', () => {
    expect(deriveBodyFromArgv(['pwsh', '-NoLogo', '-Command', 'Get-Date'])).toBe('Get-Date')
    expect(deriveBodyFromArgv(['powershell', '-Command', 'whoami'])).toBe('whoami')
  })

  it('extracts pwsh -c (the short form)', () => {
    expect(deriveBodyFromArgv(['pwsh', '-c', 'Write-Host hi'])).toBe('Write-Host hi')
  })

  it('returns encoded sentinel for pwsh -EncodedCommand', () => {
    // base64-encoded commands are opaque; we surface them with a sentinel
    // so dashboards can see the choice without decoding.
    expect(deriveBodyFromArgv(['pwsh', '-EncodedCommand', 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKQA='])).toMatch(/^<encoded:/)
  })

  it('returns joined argv for unknown executables', () => {
    expect(deriveBodyFromArgv(['/usr/bin/curl', '-X', 'POST', 'https://example.com'])).toBe(
      '/usr/bin/curl -X POST https://example.com',
    )
    expect(deriveBodyFromArgv(['node', 'app.js', '--flag'])).toBe('node app.js --flag')
  })

  it('handles broken argv shapes defensively', () => {
    expect(deriveBodyFromArgv([])).toBe('')
    expect(deriveBodyFromArgv(['bash'])).toBe('bash')
    // -c with no value: fall through to joined argv (still lets SPL
    // rules see the literal `-c` token as data, so the missing-value
    // edge case is observable).
    expect(deriveBodyFromArgv(['bash', '-c'])).toBe('bash -c')
  })

  it('trims trailing NULs/spaces from the extracted command', () => {
    // Linux /proc/<pid>/cmdline reports trailing empties; the harness
    // passes them through verbatim.
    expect(deriveBodyFromArgv(['bash', '-c', 'echo hi\0\0\0'])).toBe('echo hi')
  })
})

describe('isEngineLauncher', () => {
  it('matches the engine-launcher basenames', () => {
    expect(isEngineLauncher('/usr/bin/node', [])).toBe(true)
    expect(isEngineLauncher('pnpm', [])).toBe(true)
    expect(isEngineLauncher('', ['/usr/local/bin/npx'])).toBe(true)
    expect(isEngineLauncher('', ['/usr/bin/tsx', 'bin.ts'])).toBe(true)
    expect(isEngineLauncher('', ['node', 'lib/index.js'])).toBe(true)
  })

  it('does not match non-engine binaries', () => {
    expect(isEngineLauncher('/usr/bin/cat', [])).toBe(false)
    expect(isEngineLauncher('/bin/bash', ['bash', '-c', 'echo hi'])).toBe(false)
    expect(isEngineLauncher('', [])).toBe(false)
  })
})

describe('argvMentionsSecurityMonitorPatch', () => {
  it('returns true for a legitimate restart argv', () => {
    expect(
      argvMentionsSecurityMonitorPatch([
        'pnpm',
        'dsh',
        '--patch',
        '/abs/security-monitor.patch.yml',
      ]),
    ).toBe(true)
  })

  it('matches the inline form --patch=...', () => {
    expect(
      argvMentionsSecurityMonitorPatch(['pnpm', 'dsh', '--patch=/data/security-monitor.patch.yml']),
    ).toBe(true)
  })

  it('returns false for an unpatched restart', () => {
    // The 015 attacker — flag missing.
    expect(argvMentionsSecurityMonitorPatch(['pnpm', 'dsh', 'web'])).toBe(false)
  })

  it('returns false for an empty argv', () => {
    expect(argvMentionsSecurityMonitorPatch([])).toBe(false)
  })

  it('does NOT match the bare word security-monitor — must be a patch reference', () => {
    // Defensive: the word alone is not enough; an attacker who embeds
    // 'security-monitor' in a write body must still be flagged unpatched.
    expect(argvMentionsSecurityMonitorPatch(['echo', 'security-monitor'])).toBe(false)
  })
})