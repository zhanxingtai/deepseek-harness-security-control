/**
 * Tests for SELF_PROTECTION_PRIVESC_001 (priority 1200,
 * self-protection tier privilege-escalation bypass).
 *
 * Background: earlier the SELF_PROTECTION_* tier (priority 1200) had no
 * dedicated privilege-escalation rule. An attacker could:
 *   1. Gain root via chmod +s / chown root / sudo -i / os.setuid / nsenter
 *   2. Then tamper with the plugin files / events / policy
 *
 * The existing `block-exec-privilege-escalation` (priority 900) and
 * `block-exec-capabilities-manipulation` (priority 1100) cover the
 * generic exec-side surface, but neither sits at the self-protection
 * tier — a policy-file edit removing the 900-tier rule would leave
 * the rail open. SELF_PROTECTION_PRIVESC_001 closes this by:
 *
 *   - Sibling to 014/015/016/017/018 (priority 1200) — same "unremovable"
 *     posture via the SPL pin semantic + hardcoded inline guards.
 *   - Coverage of the BYPASS primitives: chmod SUID, chown root, doas,
 *     newgrp/sg, sudo -i, os.setuid(0), nsenter, chroot.
 *
 * Difference from `block-exec-privilege-escalation`:
 *   - Lower priority tier (900 vs 1200) — generic exec layer
 *   - Only catches `sudo chmod +s` / `sudo chown root` / `su root` /
 *     `pkexec` / `setuid()` — misses bare `chmod +s`, `chown root`,
 *     `doas`, `newgrp`, `sudo -i`, scripted os.setuid, nsenter, chroot.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

describe('SELF_PROTECTION_PRIVESC_001', () => {
  let config: Config
  let interventionEngine: InterventionEngine
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-privesc-'))
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

  // ----------------------------------------------------------------
  // POSITIVE — privilege-escalation bypass primitives must block.
  // ----------------------------------------------------------------
  describe('must block privilege-escalation bypass primitives', () => {
    const mustBlock: Array<{ toolName: string; cmd: string; reason: string }> = [
      // (a) chmod +s — SUID bit on attacker binary
      { toolName: 'bash', cmd: 'chmod +s /tmp/evil && /tmp/evil', reason: 'chmod +s' },
      { toolName: 'bash', cmd: 'chmod 4755 /bin/cp', reason: 'chmod 4755' },
      { toolName: 'bash', cmd: 'chmod u+s /tmp/payload', reason: 'chmod u+s' },
      { toolName: 'bash', cmd: 'chmod 6755 /tmp/x', reason: 'chmod 6755' },
      // (b) chown root — root-ownership transfer
      { toolName: 'bash', cmd: 'chown root:root /tmp/evil && chmod +s /tmp/evil', reason: 'chown root' },
      // chown 只有点名监控资产时才算自保护旁路（两种参数顺序都覆盖）
      { toolName: 'bash', cmd: 'chown root:root /var/log/dshwatch.log', reason: 'chown monitor asset (root first)' },
      { toolName: 'bash', cmd: 'chown dshwatch/dshwatch.log root:root', reason: 'chown monitor asset (root last)' },
      { toolName: 'bash', cmd: 'chown 0:0 ./process_monitor.conf', reason: 'chown monitor asset 0:0' },
      // (c) doas — BSD sudo alternative
      { toolName: 'bash', cmd: 'doas bash', reason: 'doas bash' },
      { toolName: 'bash', cmd: 'doas sh', reason: 'doas sh' },
      // (d) newgrp / sg — group escalation
      { toolName: 'bash', cmd: 'newgrp wheel', reason: 'newgrp wheel' },
      { toolName: 'bash', cmd: 'newgrp root', reason: 'newgrp root' },
      { toolName: 'bash', cmd: 'sg root bash', reason: 'sg root bash' },
      { toolName: 'bash', cmd: 'newgrp shadow', reason: 'newgrp shadow' },
      // (e) interactive root via sudo
      { toolName: 'bash', cmd: 'sudo -i', reason: 'sudo -i' },
      { toolName: 'bash', cmd: 'sudo -s', reason: 'sudo -s' },
      { toolName: 'bash', cmd: 'sudo bash', reason: 'sudo bash' },
      { toolName: 'bash', cmd: 'sudo su', reason: 'sudo su' },
      { toolName: 'bash', cmd: 'sudo zsh', reason: 'sudo zsh' },
      // (f) scripted setuid(0)
      {
        toolName: 'bash',
        cmd: "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        reason: 'python os.setuid',
      },
      {
        toolName: 'bash',
        cmd: 'node -e "process.setuid(0); require(\\"child_process\\").exec(\\"/bin/bash\\")"',
        reason: 'node process.setuid',
      },
      // (g) nsenter into harness namespace
      { toolName: 'bash', cmd: 'nsenter -t 1 --all --pid --mount', reason: 'nsenter -t 1' },
      // process_start actionType (RuntimeHook seam)
      { toolName: 'bash', cmd: 'chmod +s /tmp/evil', reason: 'process_start chmod +s' },
    ]

    for (const { cmd, toolName, reason } of mustBlock) {
      it(`blocks [${reason}] ${cmd.slice(0, 50)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.decision).toBe('block')
        expect(d.block_code).toBe('INTRUSION_DEFENSE_PRIVESC_008')
      })
    }
  })

  // ----------------------------------------------------------------
  // POSITIVE — process_start actionType coverage
  // ----------------------------------------------------------------
  describe('process_start actionType — RuntimeHook seam coverage', () => {
    it('blocks direct chmod +s spawn', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'process_start',
        toolName: 'chmod',
        params: { command: 'chmod +s /tmp/evil' },
      })
      expect(d.decision).toBe('block')
      expect(d.block_code).toBe('INTRUSION_DEFENSE_PRIVESC_008')
    })

    it('blocks direct sudo -i spawn', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'process_start',
        toolName: 'sudo',
        params: { command: 'sudo -i' },
      })
      expect(d.decision).toBe('block')
      expect(d.block_code).toBe('INTRUSION_DEFENSE_PRIVESC_008')
    })
  })

  // ----------------------------------------------------------------
  // NEGATIVE — legitimate permission operations must remain allowed.
  // ----------------------------------------------------------------
  describe('FP-tightening: legitimate permission operations must remain allowed', () => {
    const mustAllow = [
      // Legitimate chmod without SUID bit
      { toolName: 'bash', cmd: 'chmod 755 /opt/app' },
      { toolName: 'bash', cmd: 'chmod 644 /tmp/report.txt' },
      { toolName: 'bash', cmd: 'chmod 600 /home/user/.ssh/id_rsa' },
      { toolName: 'bash', cmd: 'chmod +x /opt/app/start.sh' },
      { toolName: 'bash', cmd: 'chmod u+x /opt/app/start.sh' },
      { toolName: 'bash', cmd: 'chmod -R 755 /opt/app/lib' },
      // Legitimate chown to non-root user
      { toolName: 'bash', cmd: 'chown app:app /opt/app/data' },
      { toolName: 'bash', cmd: 'chown -R user:group /home/user' },
      // chown root 到非监控文件是通用提权，不再算自保护旁路
      { toolName: 'bash', cmd: 'chown root /tmp/payload' },
      { toolName: 'bash', cmd: 'chown 0:0 /tmp/payload' },
      // chroot 已降 warn（容器/测试环境常规手法），不再 block
      { toolName: 'bash', cmd: 'chroot /tmp/fakeroot /bin/bash' },
      { toolName: 'bash', cmd: 'chroot --help' },
      // Legitimate sudo for non-root command
      { toolName: 'bash', cmd: 'sudo systemctl restart nginx' },
      { toolName: 'bash', cmd: 'sudo apt-get update' },
      // Legitimate nsenter without target PID
      { toolName: 'bash', cmd: 'nsenter --user --mount --uts -- /bin/bash' },
    ]

    for (const { cmd, toolName } of mustAllow) {
      it(`allows [${toolName}] ${cmd.slice(0, 50)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.block_code).not.toBe('INTRUSION_DEFENSE_PRIVESC_008')
      })
    }
  })

  // ----------------------------------------------------------------
  // ----------------------------------------------------------------
  // 分层：`/opt/dsh/...` 这类监控安装路径由优先级更高的自保护规则先拦
  // （SELF_PROTECTION_UNINSTALL_001）。要锁的不变量是「被拦」，不是具体编码。
  it('blocks chown onto the monitor install dir (higher-priority rule wins)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'chown root:root /opt/dsh/sst-security-control-dsh/lib/collector.js' },
    })
    expect(d.decision).toBe('block')
  })

  // ----------------------------------------------------------------
  // chroot 从 block 拆到 warn-chroot-usage：容器/测试环境常规手法，
  // 按 block 见一次拦一次是纯噪声，但仍保留可见性。
  // ----------------------------------------------------------------
  describe('chroot downgraded to warn (not block)', () => {
    const mustWarn = [
      { toolName: 'bash', cmd: 'chroot /tmp/fakeroot /bin/bash' },
      { toolName: 'bash', cmd: 'chroot /opt /bin/sh' },
      { toolName: 'bash', cmd: 'chroot /tmp' },
    ]

    for (const { cmd, toolName } of mustWarn) {
      it(`warns [${cmd.slice(0, 44)}]`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.decision).toBe('warn')
        expect(d.block_code).toBe('INTRUSION_DEFENSE_CHROOT_015')
      })
    }

    it('allows chroot --help (help text is not a chroot invocation)', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'tool_call',
        toolName: 'bash',
        params: { command: 'chroot --help' },
      })
      expect(d.decision).toBe('allow')
      expect(d.block_code).toBeUndefined()
    })
  })

  // PRIORITY — 1200 (self-protection tier, sibling of 014/015/016/017/018).
  // ----------------------------------------------------------------
  it('priority 1200 — load check', async () => {
    const fs = await import('node:fs')
    const yaml = await import('js-yaml')
    const doc = yaml.load(
      fs.readFileSync('policies/default-policy.spl.yaml', 'utf8'),
    ) as { rules: Array<{ id: string; priority: number }> }
    const r = doc.rules.find((x) => x.id === 'self-protection-block-privilege-escalation')!
    // priority 1200 → 1100 to match user-issued re-classification
    // (intrusion_defense tier sits at 1100; self-protection tier stays at 1200+).
    expect(r.priority).toBe(1100)
  })
})