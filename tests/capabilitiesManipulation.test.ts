/**
 * Tests for block-exec-capabilities-manipulation (priority 1100,
 *
 *
 * Background: pre-R-10 the capabilities(7) attack surface was unblocked —
 * `setcap cap_net_bind_service=+ep /bin/bash` / `capsh --add-cap` /
 * `getcap /bin/bash` / `getpcaps <pid>` / `pscap` / `setpriv --inh-caps`
 * all fell through every existing SPL rule. POLICY_EXEC_PRIV_ESC_001
 * covers chmod +s / sudo chmod +s / su / pkexec, but the capabilities(7)
 * machinery uses a different syscall (capset/capget) and a different
 * namespace (the per-file xattr `security.capability`).
 *
 * R-10 closes the gap with two parallel rules:
 *   - `block-exec-capabilities-manipulation` (priority 1100) — 写入类
 *     block:setcap with `cap_<name>=<flags>`, capsh --add-cap /
 *     --drop-cap / --caps / --inh / --amb / --secure-bits / --priv,
 *     chcap, setpriv --inh-caps
 *   - `warn-capabilities-introspection` (priority 880) — 只读查询类
 *     warn(2026-10-20 从 block 拆出):getcap / getpcaps / pscap。
 *     corpus 把 `getcap /usr/bin/python3` 标成负例——只读查询不是攻击,
 *     合法运维场景不少,所以降到可申诉 warn 而非 block。
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

describe('block-exec-capabilities-manipulation', () => {
  let config: Config
  let interventionEngine: InterventionEngine
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-caps-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function withDefaultPolicy(): InterventionEngine {
    const defaultPolicyPath = fileURLToPath(
      new URL('../policies/default-policy.spl.yaml', import.meta.url),
    )
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPath: defaultPolicyPath, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
    })
    interventionEngine = new InterventionEngine(config)
    interventionEngine.initialize()
    return interventionEngine
  }

  // -------------------------------------------------------------
  // POSITIVE — canonical capabilities-manipulation patterns must block.
  // -------------------------------------------------------------
  describe('must block canonical capabilities-manipulation patterns', () => {
    const mustBlock: Array<{ cmd: string; toolName: string }> = [
      // ---- setcap ----
      {
        cmd: 'setcap cap_net_bind_service=+ep /bin/bash',
        toolName: 'setcap',
      },
      {
        cmd: 'setcap cap_net_bind_service,cap_net_raw=+ep /usr/bin/python3',
        toolName: 'setcap',
      },
      {
        cmd: 'setcap cap_sys_admin+ep /bin/bash',
        toolName: 'setcap',
      },
      {
        cmd: 'sudo setcap cap_dac_read_search=+ep /bin/cat',
        toolName: 'bash',
      },
      // ---- capsh ----
      {
        cmd: 'capsh --add-cap=cap_net_bind_service+ep --print',
        toolName: 'capsh',
      },
      {
        cmd: 'capsh --drop-cap=cap_sys_admin -- -c /bin/bash',
        toolName: 'capsh',
      },
      {
        cmd: 'capsh --caps="cap_net_bind_service+epi" -- -c /bin/sh',
        toolName: 'capsh',
      },
      {
        cmd: 'capsh --secure-bits=0x2 --',
        toolName: 'capsh',
      },
      // ---- getpcaps / pscap / chcap ----
      {
        cmd: 'chcap /bin/bash cap_net_bind_service=+ep',
        toolName: 'chcap',
      },
      // ---- setpriv --inh-caps ----
      {
        cmd: 'setpriv --inh-caps=+ep -- /bin/bash',
        toolName: 'setpriv',
      },
    ]

    for (const { cmd, toolName } of mustBlock) {
      it(`blocks [${toolName}] ${cmd.slice(0, 60)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.decision).toBe('block')
        expect(d.block_code).toBe('SELF_PROTECTION_CAPABILITIES_026')
      })
    }
  })

  // -------------------------------------------------------------
  // POSITIVE — 只读 capabilities 查询在 2026-10-20 的 P1 FP 收窄里
  // 从 block 拆到 warn-capabilities-introspection。写入类
  // (setcap / capsh / chcap / setpriv) 仍在 block — 见上一个 describe。
  // 这里锁住"查询类降级为可申诉 warn"这条口径,防止被后续改动
  // 又悄悄升回 block(或反之掉回 allow)。
  // -------------------------------------------------------------
  describe('must warn (not block) on read-only capabilities introspection', () => {
    const mustWarn: Array<{ cmd: string; toolName: string }> = [
      { cmd: 'getcap /bin/bash', toolName: 'getcap' },
      { cmd: 'getcap -r /usr/bin', toolName: 'getcap' },
      { cmd: 'getcap -rv /usr/sbin', toolName: 'getcap' },
      { cmd: 'getpcaps 1234', toolName: 'getpcaps' },
      { cmd: 'pscap', toolName: 'pscap' },
    ]

    for (const { cmd, toolName } of mustWarn) {
      it(`warns [${toolName}] ${cmd.slice(0, 60)} ( severity=low, appealable)`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.decision).toBe('warn')
        expect(d.severity).toBe('low')
        expect(d.block_code).toBe('INTRUSION_DEFENSE_CAPABILITIES_INTROSPECTION_027')
      })
    }
  })

  // -------------------------------------------------------------
  // POSITIVE — process_start actionType (RuntimeHook seam).
  // -------------------------------------------------------------
  describe('process_start actionType — RuntimeHook seam coverage', () => {
    it('blocks setcap when invoked via direct-binary spawn', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'process_start',
        toolName: 'setcap',
        params: { command: 'setcap cap_net_bind_service=+ep /bin/bash' },
      })
      expect(d.decision).toBe('block')
      expect(d.block_code).toBe('SELF_PROTECTION_CAPABILITIES_026')
    })
  })

  // -------------------------------------------------------------
  // NEGATIVE — benign capability-related text must NOT fire.
  // -------------------------------------------------------------
  describe('FP-tightening: benign capability-related text must remain allowed', () => {
    const mustAllow = [
      // Reading a man page that mentions capabilities
      { toolName: 'bash', cmd: 'man capabilities' },
      // Searching for `capabilities` in source code
      { toolName: 'bash', cmd: 'grep -r capabilities /etc/' },
      // Capabilities is a python project / library (PyPI)
      { toolName: 'bash', cmd: 'pip install capabilities' },
      // Reading /proc/self/status (no setcap/capsh/getcap)
      { toolName: 'bash', cmd: 'cat /proc/self/status' },
      // Plain bash command with "cap" substring
      { toolName: 'bash', cmd: 'echo hello world' },
      // `getcap` not present (other introspection tools)
      { toolName: 'bash', cmd: 'ls -la /usr/bin' },
    ]

    for (const { toolName, cmd } of mustAllow) {
      it(`allows [${toolName}] ${cmd.slice(0, 60)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.block_code).not.toBe('SELF_PROTECTION_CAPABILITIES_026')
      })
    }
  })

  // -------------------------------------------------------------
  // PRIORITY — capabilities (1100) must outrank other exec rules.
  // -------------------------------------------------------------
  it('priority 1100 — load check', async () => {
    const fs = await import('node:fs')
    const yaml = await import('js-yaml')
    const doc = yaml.load(
      fs.readFileSync('policies/default-policy.spl.yaml', 'utf8'),
    ) as { rules: Array<{ id: string; priority: number }> }
    const r = doc.rules.find((x) => x.id === 'block-exec-capabilities-manipulation')!
    expect(r.priority).toBe(1100)
  })
})