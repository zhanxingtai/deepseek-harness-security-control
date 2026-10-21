import { describe, expect, it } from 'vitest'
import {
  extractCommandString,
  isShellLikeTool,
  parseShellFileOps,
} from '../src/utils/shellFileOps.js'

describe('parseShellFileOps — shell verbs', () => {
  it('detects cat reading a file', () => {
    expect(parseShellFileOps('cat /etc/passwd')).toEqual([
      { op: 'read', path: '/etc/passwd', source: 'shell' },
    ])
  })

  it('detects head / tail / less / more / sort / wc', () => {
    expect(parseShellFileOps('head -n 5 /var/log/app.log')).toEqual([
      { op: 'read', path: '/var/log/app.log', source: 'shell' },
    ])
    expect(parseShellFileOps('tail -f /var/log/syslog')).toEqual([
      { op: 'read', path: '/var/log/syslog', source: 'shell' },
    ])
    expect(parseShellFileOps('sort /tmp/data.csv')).toEqual([
      { op: 'read', path: '/tmp/data.csv', source: 'shell' },
    ])
  })

  it('detects tee writing to a file', () => {
    expect(parseShellFileOps('tee /tmp/out.log')).toEqual([
      { op: 'write', path: '/tmp/out.log', source: 'shell' },
    ])
    expect(parseShellFileOps('tee -a /var/log/writes')).toEqual([
      { op: 'write', path: '/var/log/writes', source: 'shell' },
    ])
  })

  it('detects cp: read of src + write of dst', () => {
    expect(parseShellFileOps('cp /etc/passwd /tmp/leak.txt')).toEqual([
      { op: 'read', path: '/etc/passwd', source: 'shell' },
      { op: 'write', path: '/tmp/leak.txt', source: 'shell' },
    ])
  })

  it('detects mv: delete of src(s) + write of dst (rename semantics)', () => {
    // 2026-08-18: prior behaviour emitted `[read, write]` which read
    // like a copy. `mv` is a rename — the source disappears from its
    // origin. Re-spelled to `[delete, write]` so the audit signal matches
    // the file system effect.
    expect(parseShellFileOps('mv /tmp/a /tmp/b')).toEqual([
      { op: 'delete', path: '/tmp/a', source: 'shell' },
      { op: 'write', path: '/tmp/b', source: 'shell' },
    ])
  })

  it('detects rm', () => {
    expect(parseShellFileOps('rm -rf /var/log/app')).toEqual([
      { op: 'delete', path: '/var/log/app', source: 'shell' },
    ])
  })

  it('detects chmod with mode preserved', () => {
    expect(parseShellFileOps('chmod 777 /etc/shadow')).toEqual([
      { op: 'privilege', path: '/etc/shadow', mode: '777', source: 'shell' },
    ])
    expect(parseShellFileOps('chmod -R u+x /opt/scripts')).toEqual([
      { op: 'privilege', path: '/opt/scripts', mode: 'u+x', source: 'shell' },
    ])
  })

  it('detects chown / chgrp', () => {
    expect(parseShellFileOps('chown root:root /etc/passwd')).toEqual([
      { op: 'privilege', path: '/etc/passwd', mode: 'root:root', source: 'shell' },
    ])
    expect(parseShellFileOps('chgrp wheel /var/log/secure')).toEqual([
      { op: 'privilege', path: '/var/log/secure', mode: 'wheel', source: 'shell' },
    ])
  })

  it('detects dd if= / of=', () => {
    expect(parseShellFileOps('dd if=/dev/zero of=/tmp/fill.bin bs=1M count=10')).toEqual([
      { op: 'read', path: '/dev/zero', source: 'shell' },
      { op: 'write', path: '/tmp/fill.bin', source: 'shell' },
    ])
  })

  it('detects sed -i as in-place write', () => {
    expect(parseShellFileOps(`sed -i 's/foo/bar/' /etc/hosts`)).toEqual([
      { op: 'write', path: '/etc/hosts', source: 'shell' },
    ])
  })

  it('detects awk reading files', () => {
    expect(parseShellFileOps(`awk '{print $1}' /var/log/access.log`)).toEqual([
      { op: 'read', path: '/var/log/access.log', source: 'shell' },
    ])
  })

  it('detects shell redirects', () => {
    expect(parseShellFileOps('cat /etc/passwd > /tmp/leak.txt')).toEqual([
      { op: 'read', path: '/etc/passwd', source: 'shell' },
      { op: 'write', path: '/tmp/leak.txt', source: 'shell' },
    ])
    expect(parseShellFileOps('echo leaked >> /tmp/leak.txt')).toEqual([
      { op: 'write', path: '/tmp/leak.txt', source: 'shell' },
    ])
    expect(parseShellFileOps('sort < /tmp/in.csv')).toEqual([
      { op: 'read', path: '/tmp/in.csv', source: 'shell' },
    ])
  })

  it('handles pipelines as separate segments', () => {
    expect(parseShellFileOps('cat /etc/passwd | grep root > /tmp/leak.txt')).toEqual([
      { op: 'read', path: '/etc/passwd', source: 'shell' },
      { op: 'write', path: '/tmp/leak.txt', source: 'shell' },
    ])
  })

  it('handles && chains', () => {
    expect(parseShellFileOps('rm /tmp/a && echo done > /tmp/done.log')).toEqual([
      { op: 'delete', path: '/tmp/a', source: 'shell' },
      { op: 'write', path: '/tmp/done.log', source: 'shell' },
    ])
  })

  it('handles quoted paths with spaces', () => {
    expect(parseShellFileOps('cat "/etc/with space/file"')).toEqual([
      { op: 'read', path: '/etc/with space/file', source: 'shell' },
    ])
    expect(parseShellFileOps(`cat '/etc/single quoted/file'`)).toEqual([
      { op: 'read', path: '/etc/single quoted/file', source: 'shell' },
    ])
  })

  it('returns empty array when no file op is recognized', () => {
    expect(parseShellFileOps('ls -la /tmp')).toEqual([])
    expect(parseShellFileOps('echo hello world')).toEqual([])
    expect(parseShellFileOps('git status')).toEqual([])
  })

  it('ignores file-descriptor redirections as paths', () => {
    // Without the fd-redirect filter, `2>&1` and friends were classified
    // as a literal read target. The probe showed:
    //   "cat /etc/passwd 2>&1 | head"
    //     -> [{read,/etc/passwd}, {read,2>&1}]
    expect(parseShellFileOps('cat /etc/passwd 2>&1 | head')).toEqual([
      { op: 'read', path: '/etc/passwd', source: 'shell' },
    ])
    expect(parseShellFileOps('cat /etc/passwd 1>&2')).toEqual([
      { op: 'read', path: '/etc/passwd', source: 'shell' },
    ])
  })

  it('treats `--` as end-of-options, never a path', () => {
    // The `--` marker signals "no more flag parsing" — subsequent args
    // are always positionals. But `--` itself is never a file path, and
    // the prior implementation attached it as one (probe showed
    //   "rm -rf -- /tmp/foo" -> [{delete,--}, {delete,/tmp/foo}]
    //   "cat -- /etc/hosts"  -> [{read,--},   {read,/etc/hosts}]).
    expect(parseShellFileOps('rm -rf -- /tmp/foo')).toEqual([
      { op: 'delete', path: '/tmp/foo', source: 'shell' },
    ])
    expect(parseShellFileOps('cat -- /etc/hosts')).toEqual([
      { op: 'read', path: '/etc/hosts', source: 'shell' },
    ])
  })

  it('detects find ... -delete as start-path read + delete', () => {
    // `find / -mtime +7 -delete` previously emitted nothing. We now
    // surface the start paths as both `read` (find descends into them)
    // and `delete` (the -delete predicate acts on whatever matches,
    // including the start path). Over-reporting the start path is the
    // accepted trade-off: -delete is inherently dangerous, and the
    // start path is the natural audit anchor.
    expect(parseShellFileOps('find /etc -name "*.conf" -delete')).toEqual([
      { op: 'read', path: '/etc', source: 'shell' },
      { op: 'delete', path: '/etc', source: 'shell' },
    ])
    expect(parseShellFileOps('find / -mtime +7 -delete')).toEqual([
      { op: 'read', path: '/', source: 'shell' },
      { op: 'delete', path: '/', source: 'shell' },
    ])
  })

  it('does not flag find without -delete', () => {
    // `find` without -delete is read-only — no file ops emitted.
    expect(parseShellFileOps('find /etc -name "*.conf"')).toEqual([])
  })

  it('detects tar -c archive creation: write archive + read sources', () => {
    expect(parseShellFileOps('tar -czf /tmp/a.tar.gz /etc /var/log')).toEqual([
      { op: 'write', path: '/tmp/a.tar.gz', source: 'shell' },
      { op: 'read', path: '/etc', source: 'shell' },
      { op: 'read', path: '/var/log', source: 'shell' },
    ])
  })

  it('detects tar -x extraction: read archive + write -C dir', () => {
    expect(parseShellFileOps('tar -xzf /tmp/a.tar.gz -C /opt/restore')).toEqual([
      { op: 'read', path: '/tmp/a.tar.gz', source: 'shell' },
      { op: 'write', path: '/opt/restore', source: 'shell' },
    ])
  })

  it('detects unzip: read archive + write -d destination', () => {
    expect(parseShellFileOps('unzip -o evil.zip -d /tmp/')).toEqual([
      { op: 'read', path: 'evil.zip', source: 'shell' },
      { op: 'write', path: '/tmp/', source: 'shell' },
    ])
    // -d may appear before the archive (positional order doesn't matter
    // for the write target; the archive is the FIRST positional arg).
    expect(parseShellFileOps('unzip -d /tmp loot.zip')).toEqual([
      { op: 'read', path: 'loot.zip', source: 'shell' },
      { op: 'write', path: '/tmp', source: 'shell' },
    ])
  })

  it('returns empty array for empty / non-string input', () => {
    expect(parseShellFileOps('')).toEqual([])
    expect(parseShellFileOps(undefined as unknown as string)).toEqual([])
    expect(parseShellFileOps(null as unknown as string)).toEqual([])
  })

  it('deduplicates repeated (op, path) pairs', () => {
    // `cat foo` AND a redirect from `foo` would otherwise double-emit.
    // We dedupe on (op, path).
    const result = parseShellFileOps('cat /tmp/a && cp /tmp/a /tmp/a')
    const aCount = result.filter((op) => op.path === '/tmp/a').length
    expect(aCount).toBeLessThanOrEqual(2)
  })

  it('preserves first-occurrence order across pipeline segments', () => {
    const result = parseShellFileOps('rm /tmp/a; cat /tmp/b > /tmp/c')
    expect(result).toEqual([
      { op: 'delete', path: '/tmp/a', source: 'shell' },
      { op: 'read', path: '/tmp/b', source: 'shell' },
      { op: 'write', path: '/tmp/c', source: 'shell' },
    ])
  })
})

describe('parseShellFileOps — inline scripts', () => {
  it('detects python -c with open() in read mode', () => {
    expect(parseShellFileOps(`python -c "open('/etc/passwd').read()"`)).toEqual([
      { op: 'read', path: '/etc/passwd', source: 'python' },
    ])
  })

  it('detects python -c with open() in write mode', () => {
    expect(parseShellFileOps(`python3 -c 'open("/tmp/leak.txt","w").write("x")'`)).toEqual([
      { op: 'write', path: '/tmp/leak.txt', source: 'python' },
    ])
  })

  it('detects python os.unlink / os.remove', () => {
    expect(parseShellFileOps(`python -c "import os; os.unlink('/etc/secret')"`)).toEqual([
      { op: 'delete', path: '/etc/secret', source: 'python' },
    ])
  })

  it('detects node fs.readFileSync / fs.writeFileSync', () => {
    expect(parseShellFileOps(`node -e "fs.readFileSync('/etc/shadow','utf8')"`)).toEqual([
      { op: 'read', path: '/etc/shadow', source: 'node' },
    ])
    expect(parseShellFileOps(`node -e "fs.writeFileSync('/tmp/leak','x')"`)).toEqual([
      { op: 'write', path: '/tmp/leak', source: 'node' },
    ])
  })

  it('detects node fs.unlinkSync / fs.appendFileSync', () => {
    expect(parseShellFileOps(`node -e "fs.unlinkSync('/tmp/x')"`)).toEqual([
      { op: 'delete', path: '/tmp/x', source: 'node' },
    ])
    expect(parseShellFileOps(`node -e "fs.appendFileSync('/tmp/x','y')"`)).toEqual([
      { op: 'write', path: '/tmp/x', source: 'node' },
    ])
  })
})

describe('isShellLikeTool', () => {
  it('returns true for common shell interpreters', () => {
    expect(isShellLikeTool('bash')).toBe(true)
    expect(isShellLikeTool('Bash')).toBe(true)
    expect(isShellLikeTool('zsh')).toBe(true)
    expect(isShellLikeTool('fish')).toBe(true)
    expect(isShellLikeTool('sh')).toBe(true)
    expect(isShellLikeTool('shell')).toBe(true)
    expect(isShellLikeTool('run_shell_command')).toBe(true)
  })

  it('returns true for python / node / ruby / perl', () => {
    expect(isShellLikeTool('python')).toBe(true)
    expect(isShellLikeTool('python3')).toBe(true)
    expect(isShellLikeTool('run_python')).toBe(true)
    expect(isShellLikeTool('node')).toBe(true)
    expect(isShellLikeTool('nodejs')).toBe(true)
    expect(isShellLikeTool('ruby')).toBe(true)
    expect(isShellLikeTool('perl')).toBe(true)
  })

  it('returns true for generic exec / run / run_command / run_code', () => {
    expect(isShellLikeTool('exec')).toBe(true)
    expect(isShellLikeTool('run')).toBe(true)
    expect(isShellLikeTool('run_command')).toBe(true)
    expect(isShellLikeTool('run_code')).toBe(true)
  })

  it('returns false for unrelated tools', () => {
    expect(isShellLikeTool('read')).toBe(false)
    expect(isShellLikeTool('write')).toBe(false)
    expect(isShellLikeTool('web_search')).toBe(false)
    expect(isShellLikeTool('fetch')).toBe(false)
    expect(isShellLikeTool('image_generate')).toBe(false)
  })

  it('returns false for empty / non-string input', () => {
    expect(isShellLikeTool('')).toBe(false)
    expect(isShellLikeTool(undefined as unknown as string)).toBe(false)
    expect(isShellLikeTool(null as unknown as string)).toBe(false)
  })
})

describe('extractCommandString', () => {
  it('extracts from `command` field', () => {
    expect(extractCommandString({ command: 'cat /etc/passwd' })).toBe('cat /etc/passwd')
  })

  it('tries the documented aliases in order', () => {
    expect(extractCommandString({ cmd: 'ls' })).toBe('ls')
    expect(extractCommandString({ shell: 'bash' })).toBe('bash')
    expect(extractCommandString({ script: 'print' })).toBe('print')
    expect(extractCommandString({ exec: 'sh' })).toBe('sh')
    expect(extractCommandString({ code: 'open()' })).toBe('open()')
    expect(extractCommandString({ body: 'text' })).toBe('text')
  })

  it('prefers the first matching alias in declared order', () => {
    expect(extractCommandString({ command: 'a', cmd: 'b', script: 'c' })).toBe('a')
    expect(extractCommandString({ cmd: 'b', script: 'c' })).toBe('b')
  })

  it('returns undefined for non-string or empty fields', () => {
    expect(extractCommandString({ command: '' })).toBeUndefined()
    expect(extractCommandString({ command: '   ' })).toBeUndefined()
    expect(extractCommandString({ command: 123 as unknown as string })).toBeUndefined()
  })

  it('returns undefined when no matching alias is present', () => {
    expect(extractCommandString({ unrelated: 'x' })).toBeUndefined()
    expect(extractCommandString(undefined)).toBeUndefined()
  })
})