/**
 * Tests for the 5 new SPL rules added in :
 *
 *   - self-protection-block-cron-modify (priority 1250)
 *     /etc/cron.d / cron.daily / cron.hourly / cron.weekly / cron.monthly
 *     (previous rule only matched /etc/cron literal)
 *   - self-protection-block-ld-so-preload (priority 1250)
 *     /etc/ld.so.preload | /etc/ld.so.conf.d/ (glibc hijack)
 *   - self-protection-block-selinux-apparmor-disable (priority 1250)
 *     setenforce 0 / aa-complain / semodule -r / systemctl stop apparmor
 *   - self-protection-block-firewall-flush (priority 1250)
 *     iptables -F / nft flush / ufw disable / firewalld-cmd remove
 *   - self-protection-block-write-firewall-flush-script (priority 1250)
 *     write-tool body containing firewall-flush script (indirect)
 *
 * All five are defense-in-depth only — primary controls are the host's
 * filesystem permissions + device-cgroup / nftables / LSM policies.
 * Block / escalate is recorded but the security net is the kernel layer.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

describe('SPL rule gap fixes', () => {
  let config: Config
  let interventionEngine: InterventionEngine
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-p3c-'))
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
  // self-protection-block-cron-modify
  // -------------------------------------------------------------
  describe('self-protection-block-cron-modify', () => {
    const mustBlock = [
      // /etc/cron.d / cron.daily / cron.hourly / cron.weekly / cron.monthly
      { toolName: 'bash', cmd: 'echo "* * * * * /tmp/evil" > /etc/cron.d/payload' },
      { toolName: 'bash', cmd: 'cp x.sh /etc/cron.daily/runjob' },
      { toolName: 'bash', cmd: 'mv x.sh /etc/cron.hourly/check' },
      { toolName: 'bash', cmd: 'tee /etc/cron.weekly/x.sh < payload' },
      // crontab interactive edits
      { toolName: 'bash', cmd: 'crontab -e' },
    ]

    for (const c of mustBlock) {
      it(`blocks [${c.toolName}] ${c.cmd.slice(0, 80)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { command: c.cmd },
        })
        // crontab -e/-l is also caught by pre-existing self-protection-block-scheduled-task-command
        // (priority 1250, higher). Accept either block_code.
        // SELF_PROTECTION_TIMER_001 → SELF_PROTECTION_SCHEDULED_TASK_COMMAND_042.
        expect(['SELF_PROTECTION_CRON_046', 'SELF_PROTECTION_SCHEDULED_TASK_COMMAND_042']).toContain(d.block_code)
      })
    }

    // write tool body — separate rule: self-protection-block-write-cron-payload
    const mustBlockWrite = [
      { toolName: 'write', writeBody: '* * * * * /tmp/x\necho x > /etc/cron.d/p' },
    ]
    for (const c of mustBlockWrite) {
      it(`blocks [${c.toolName}] body containing /etc/cron.* path`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { content: c.writeBody },
        })
        expect(d.block_code).toBe('SELF_PROTECTION_CRON_PAYLOAD_047')
      })
    }

    const mustAllow = [
      // benign /etc read
      { toolName: 'bash', cmd: 'ls /etc/cron.d' },
      // /etc/cron.deny (POSIX access-control file, not a payload)
      { toolName: 'bash', cmd: 'cat /etc/cron.deny' },
      // crontab -l is read-only
      // listing (legitimate operator inspection). It must NOT be blocked
      // or escalated by self-protection-block-cron-modify (or the
      // sibling self-protection-block-scheduled-task-command) — those
      // rules only flag write/delete variants (-e/-r/-d).
      { toolName: 'bash', cmd: 'crontab -l' },
    ]

    for (const c of mustAllow) {
      it(`allows [${c.toolName}] ${c.cmd.slice(0, 80)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { command: c.cmd },
        })
        expect(d.block_code).not.toBe('SELF_PROTECTION_CRON_046')
      })
    }
  })

  // -------------------------------------------------------------
  // self-protection-block-ld-so-preload
  // -------------------------------------------------------------
  describe('self-protection-block-ld-so-preload', () => {
    const mustBlock = [
      { toolName: 'bash', cmd: 'echo /tmp/evil.so > /etc/ld.so.preload' },
      { toolName: 'bash', cmd: 'cp /tmp/evil.conf /etc/ld.so.conf.d/zz-evil.conf' },
      { toolName: 'bash', cmd: 'echo include /tmp/evil > /etc/ld.so.conf' },
      { toolName: 'bash', cmd: 'ldconfig -f /etc/ld.so.conf' },
    ]

    for (const c of mustBlock) {
      it(`blocks [${c.toolName}] ${c.cmd.slice(0, 80)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { command: c.cmd },
        })
        // SELF_PROTECTION_LDSO_001 → SELF_PROTECTION_LDSO_PRELOAD_048
        // (category-prefix alignment; the write-tool body variant below
        //  uses SELF_PROTECTION_LDSO_PAYLOAD_049 instead).
        expect(d.block_code).toBe('SELF_PROTECTION_LDSO_PRELOAD_048')
      })
    }

    // write-tool body — separate rule self-protection-block-write-ld-so-payload
    it('blocks write tool body containing ld.so.preload path', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'tool_call',
        toolName: 'write',
        params: { content: '/tmp/evil.so\nLD_PRELOAD=/etc/ld.so.preload' },
      })
      // write-payload rule's new blockCode.
      expect(d.block_code).toBe('SELF_PROTECTION_LDSO_PAYLOAD_049')
    })

    it('allows ldconfig without -f flag', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'tool_call',
        toolName: 'bash',
        params: { command: 'ldconfig' },
      })
      expect(d.block_code).not.toBe('SELF_PROTECTION_LDSO_PRELOAD_048')
    })
  })

  // -------------------------------------------------------------
  // self-protection-block-selinux-apparmor-disable
  // -------------------------------------------------------------
  describe('self-protection-block-selinux-apparmor-disable', () => {
    const mustBlock = [
      { toolName: 'bash', cmd: 'setenforce 0' },
      { toolName: 'bash', cmd: 'setenforce permissive' },
      { toolName: 'bash', cmd: 'aa-complain /usr/bin/python3' },
      { toolName: 'bash', cmd: 'aa-disable /etc/apparmor.d/usr.bin.firefox' },
      { toolName: 'bash', cmd: 'semodule -r unconfined' },
      { toolName: 'bash', cmd: 'systemctl stop apparmor' },
      { toolName: 'bash', cmd: 'service selinux stop' },
    ]

    for (const c of mustBlock) {
      it(`blocks [${c.toolName}] ${c.cmd.slice(0, 80)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { command: c.cmd },
        })
        expect(d.block_code).toBe('SELF_PROTECTION_SELINUX_APPARMOR_DISABLE_050')
      })
    }

    const mustAllow = [
      { toolName: 'bash', cmd: 'setenforce 1' },
      { toolName: 'bash', cmd: 'aa-status' },
      { toolName: 'bash', cmd: 'sestatus' },
    ]

    for (const c of mustAllow) {
      it(`allows [${c.toolName}] ${c.cmd.slice(0, 80)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { command: c.cmd },
        })
        expect(d.block_code).not.toBe('SELF_PROTECTION_SELINUX_APPARMOR_DISABLE_050')
      })
    }
  })

  // -------------------------------------------------------------
  // self-protection-block-firewall-flush
  // -------------------------------------------------------------
  describe('self-protection-block-firewall-flush', () => {
    const mustEscalate = [
      { toolName: 'bash', cmd: 'iptables -F' },
      { toolName: 'bash', cmd: 'iptables --flush' },
      { toolName: 'bash', cmd: 'iptables -X' },
      { toolName: 'bash', cmd: 'iptables -t nat -F' },
      { toolName: 'bash', cmd: 'ip6tables -F' },
      { toolName: 'bash', cmd: 'nft flush ruleset' },
      { toolName: 'bash', cmd: 'nft delete rule inet filter input' },
      { toolName: 'bash', cmd: 'ufw disable' },
      { toolName: 'bash', cmd: 'ufw reset' },
      { toolName: 'bash', cmd: 'firewalld-cmd --remove-service=http --permanent' },
    ]

    for (const c of mustEscalate) {
      it(`escalates [${c.toolName}] ${c.cmd.slice(0, 80)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { command: c.cmd },
        })
        expect(d.block_code).toBe('SELF_PROTECTION_FIREWALL_051')
      })
    }

    const mustAllow = [
      { toolName: 'bash', cmd: 'iptables -L' },
      { toolName: 'bash', cmd: 'nft list ruleset' },
      { toolName: 'bash', cmd: 'ufw status' },
    ]

    for (const c of mustAllow) {
      it(`allows [${c.toolName}] ${c.cmd.slice(0, 80)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { command: c.cmd },
        })
        expect(d.block_code).not.toBe('SELF_PROTECTION_FIREWALL_051')
      })
    }
  })

  // -------------------------------------------------------------
  // self-protection-block-write-firewall-flush-script
  // -------------------------------------------------------------
  describe('self-protection-block-write-firewall-flush-script', () => {
    const mustBlock = [
      {
        toolName: 'write',
        writeBody: '#!/bin/bash\niptables -F\nufw disable\n',
      },
      {
        toolName: 'create',
        writeBody: 'nft flush ruleset',
      },
      {
        toolName: 'edit',
        writeBody: 'firewalld-cmd --remove-service=ssh --permanent',
      },
    ]

    for (const c of mustBlock) {
      it(`blocks [${c.toolName}] body containing firewall flush`, async () => {
        const engine = withDefaultPolicy()
        // production-traffic tightening: write tools
        // surface content via params.content (FIELD_ALIASES → body).
        // ApplicationCollector does NOT lift args.body for write
        // tools, so the top-level body field never reaches this rule
        // in production. Removing it from the test closes the gap
        // where the original `bodyRegex:` clause matched against a
        // top-level body that production never sends.
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: c.toolName,
          params: { content: c.writeBody },
        })
        expect(d.block_code).toBe('SELF_PROTECTION_FIREWALL_052')
      })
    }

    it('allows firewall-status script (no flush/reset)', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'tool_call',
        toolName: 'write',
        params: { content: '#!/bin/bash\niptables -L\nufw status\n' },
      })
      expect(d.block_code).not.toBe('SELF_PROTECTION_FIREWALL_052')
    })
  })

  // -------------------------------------------------------------
  // PRIORITY — load check (all 7 new rules must be at priority 1250)
  // -------------------------------------------------------------
  it('priority load check (all 7 new rules at 1250)', async () => {
    const fs = await import('node:fs')
    const yaml = await import('js-yaml')
    const doc = yaml.load(
      fs.readFileSync('policies/default-policy.spl.yaml', 'utf8'),
    ) as { rules: Array<{ id: string; priority: number }> }
    for (const id of [
      'self-protection-block-cron-modify',
      'self-protection-block-write-cron-payload',
      'self-protection-block-ld-so-preload',
      'self-protection-block-write-ld-so-payload',
      'self-protection-block-selinux-apparmor-disable',
      'self-protection-block-firewall-flush',
      'self-protection-block-write-firewall-flush-script',
    ]) {
      const r = doc.rules.find((x) => x.id === id)
      expect(r, `rule ${id} not found`).toBeDefined()
      expect(r!.priority).toBe(1250)
    }
  })
})
