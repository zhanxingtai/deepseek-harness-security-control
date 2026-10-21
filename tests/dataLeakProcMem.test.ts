/**
 * Tests for block-data-exfil-process-memory-dump (priority 1100,
 * 1st wave — procfs / devmem / coredump).
 *
 * Background: pre-R-10 the process-memory side channel was unblocked.
 * Reads from `/proc/<pid>/(mem|maps|cmdline|environ|...)` and
 * `/dev/(mem|kmem)` and `gcore <pid>` never trigger an outbound
 * event — they're a side channel that bypasses every existing
 * detection rule.
 *
 * R-10 closes(2026-10-20 P1 FP 收窄后拆成两组):
 *   block — `block-data-exfil-process-memory-dump`(priority 1100):
 *   - /proc/<pid>/(mem|maps|smaps|smaps_rollup|environ) — 真实内存 /
 *     凭据面(environ 含 AWS_ACCESS_KEY 等)
 *   - /proc/self 和 /proc/curproc(同一面,无 PID)
 *   - /proc/<pid>/(cwd|fd/<n>|root) — symlink dereference attacks
 *   - /dev/mem, /dev/kmem, /dev/kmsg — raw memory reads
 *   - `gcore <pid>` — gdb-mediated full process coredump
 *     (the canonical "dump ssh-agent and walk the heap" attack)
 *   - memdump / procdump / systemd-coredump / kdump — utility-form
 *     coredump paths
 *
 *   warn — `warn-procfs-credential-bearing`(priority 880):
 *   - /proc/<pid>/(cmdline|status|io|stack|auxv|exe|syscall|wchan)
 *     这些是进程元数据而非内存 dump,合法运维场景不少,记 warn
 *     可申诉但不阻断。
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

describe('block-data-exfil-process-memory-dump ( 1st wave)', () => {
  let config: Config
  let interventionEngine: InterventionEngine
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-procmem-'))
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
      // 0 = no deadline (the default 150 ms can trip when the full suite
      // runs this test cold). The deadline path is covered by
      // intervention.test.ts; these data-leak tables only assert verdict
      // shape, not deadline behaviour.
      intervention: { policyPath: defaultPolicyPath, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
    })
    interventionEngine = new InterventionEngine(config)
    interventionEngine.initialize()
    return interventionEngine
  }

  // -------------------------------------------------------------
  // POSITIVE — procfs / devmem / coredump must block.
  // -------------------------------------------------------------
  describe('must block process memory access patterns', () => {
    const mustBlock: Array<{ cmd: string; toolName: string }> = [
      // ---- /proc/<pid>/<sensitive> ----
      { toolName: 'bash', cmd: 'cat /proc/1234/mem' },
      { toolName: 'bash', cmd: 'cat /proc/1234/environ' },
      // /proc/self (no PID)
      { toolName: 'bash', cmd: 'cat /proc/self/mem' },
      // /proc/<pid>/cwd / fd (symlink attacks)
      { toolName: 'bash', cmd: 'ls -la /proc/1234/cwd' },
      { toolName: 'bash', cmd: 'readlink /proc/1234/fd/3' },
      { toolName: 'bash', cmd: 'ls /proc/1234/root' },
      // ---- /dev/mem and /dev/kmem ----
      { toolName: 'bash', cmd: 'dd if=/dev/mem of=/tmp/leak.bin' },
      { toolName: 'bash', cmd: 'head -c 1000 /dev/kmem' },
      { toolName: 'bash', cmd: 'dd if=/dev/kmsg of=/tmp/ringbuffer' },
      // ---- gcore (gdb coredump) ----
      { toolName: 'gcore', cmd: 'gcore 1234' },
      { toolName: 'bash', cmd: 'gcore -o /tmp/dump 1234' },
      { toolName: 'bash', cmd: 'gcore --output /tmp/leak 5678' },
      // ---- memdump / procdump / systemd-coredump / kdump ----
      { toolName: 'memdump', cmd: 'memdump --pid 1234 --output /tmp/leak' },
      { toolName: 'procdump', cmd: 'procdump -p 1234 -o /tmp/leak' },
      { toolName: 'systemd-coredump', cmd: 'systemd-coredump --pid 1234 -o /tmp/leak' },
      { toolName: 'kdump', cmd: 'kdump --pid 1234 --output /tmp/leak' },
      // ---- bash-wrapped direct-binary (RuntimeHook seam) ----
      { toolName: 'bash', cmd: 'gcore 1234' },
    ]

    for (const { cmd, toolName } of mustBlock) {
      it(`blocks on [${toolName}] ${cmd.slice(0, 60)} ( severity=high, no downgrade)`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        // severity elevated low→high per spec §6.3 Tier 名单制
        // (data_leak_monitoring Tier-2). `block` no longer downgrades to
        // `warn`; trace fields (severity_downgraded / severity_rule_id)
        // no longer apply.
        expect(d.decision).toBe('block')
        expect(d.severity).toBe('high')
        expect(d.severity_downgraded).toBeUndefined()
        expect(d.severity_rule_id).toBeUndefined()
        expect(d.block_code).toBe('DATA_LEAK_MONITORING_PROCESS_MEMORY_007')
      })
    }
  })

  // -------------------------------------------------------------
  // POSITIVE — procfs 凭据类状态文件从 block 拆到
  // warn-procfs-credential-bearing(priority 880)，三批降级：
  //   - cmdline/stack/auxv/exe/wchan：进程元数据，无凭据
  //   - maps/smaps/smaps_rollup：只是「地址→权限」表，不含内存内容。
  //     `cat /proc/self/maps` 是查 ASLR / JVM 的标准读法，按 block 拦
  //     是纯噪声；真正读内存内容的是 /proc/<pid>/mem，仍在 block 子集。
  // status/io 只有 uid/gid/线程数，`ps` 自己就在读，连 warn 都不必，已移出。
  // -------------------------------------------------------------
  describe('must warn (not block) on procfs credential-bearing reads', () => {
    const mustWarn: Array<{ cmd: string; toolName: string }> = [
      { toolName: 'bash', cmd: 'cat /proc/1234/cmdline' },
      { toolName: 'bash', cmd: 'cat /proc/1234/stack' },
      { toolName: 'bash', cmd: 'cat /proc/1234/auxv' },
      { toolName: 'bash', cmd: 'readlink /proc/1234/exe' },
      { toolName: 'bash', cmd: 'cat /proc/1234/maps' },
      { toolName: 'bash', cmd: 'cat /proc/1234/smaps' },
      { toolName: 'bash', cmd: 'cat /proc/1234/smaps_rollup' },
      { toolName: 'bash', cmd: 'cat /proc/current/maps' },
      { toolName: 'bash', cmd: 'cat /proc/1234/maps > /tmp/leak' },
    ]

    for (const { cmd, toolName } of mustWarn) {
      it(`warns on [${toolName}] ${cmd.slice(0, 60)} ( severity=low, appealable)`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.decision).toBe('warn')
        expect(d.severity).toBe('low')
        expect(d.block_code).toBe('DATA_LEAK_MONITORING_PROCFS_CREDENTIAL_008')
      })
    }
  })

  // -------------------------------------------------------------
  // POSITIVE — process_start actionType (RuntimeHook seam).
  // -------------------------------------------------------------
  describe('process_start actionType — RuntimeHook seam coverage', () => {
    it('blocks on gcore via direct-binary spawn ( severity=high, no downgrade)', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'process_start',
        toolName: 'gcore',
        params: { command: 'gcore 1234' },
      })
      expect(d.decision).toBe('block')
      expect(d.severity).toBe('high')
      expect(d.severity_downgraded).toBeUndefined()
      expect(d.severity_rule_id).toBeUndefined()
      expect(d.block_code).toBe('DATA_LEAK_MONITORING_PROCESS_MEMORY_007')
    })

    it('blocks on /proc/<pid>/mem via direct-binary spawn ( severity=high, no downgrade)', async () => {
      const engine = withDefaultPolicy()
      const d = await engine.evaluate({
        actionType: 'process_start',
        toolName: 'cat',
        params: { command: 'cat /proc/1234/mem' },
      })
      expect(d.decision).toBe('block')
      expect(d.severity).toBe('high')
      expect(d.severity_downgraded).toBeUndefined()
      expect(d.severity_rule_id).toBeUndefined()
      expect(d.block_code).toBe('DATA_LEAK_MONITORING_PROCESS_MEMORY_007')
    })
  })

  // -------------------------------------------------------------
  // NEGATIVE — legitimate /proc reads must remain allowed.
  // -------------------------------------------------------------
  describe('FP-tightening: legitimate /proc reads must remain allowed', () => {
    const mustAllow = [
      // /proc/cpuinfo, /proc/meminfo — system info (no PID)
      { toolName: 'cat', cmd: 'cat /proc/cpuinfo' },
      { toolName: 'cat', cmd: 'cat /proc/meminfo' },
      { toolName: 'cat', cmd: 'cat /proc/loadavg' },
      { toolName: 'cat', cmd: 'cat /proc/version' },
      { toolName: 'cat', cmd: 'cat /proc/uptime' },
      { toolName: 'bash', cmd: 'ls /proc/' },
      // /proc/<pid>/comm (process name — not sensitive)
      // Note: this may or may not match — the rule allows several paths.
      // We keep this in mustAllow because /proc/<pid>/comm is not in
      // the deny-list (it's just a process name).
      { toolName: 'bash', cmd: 'cat /proc/1234/comm' },
      // /proc/<pid>/stat — process stats (not in deny-list)
      { toolName: 'bash', cmd: 'cat /proc/1234/stat' },
      // ps / lsof / pgrep (no PID-path)
      { toolName: 'bash', cmd: 'ps aux' },
      { toolName: 'bash', cmd: 'lsof -p 1234' },
      { toolName: 'bash', cmd: 'pgrep -f myprocess' },
      // grep over proc text (no PID-path)
      { toolName: 'bash', cmd: 'grep -r "pattern" /proc/' },
      // gcore without a PID number (no target — `gcore --help` is OK)
      { toolName: 'gcore', cmd: 'gcore --help' },
      // memdump / procdump without target PID
      { toolName: 'memdump', cmd: 'memdump --help' },
      { toolName: 'procdump', cmd: 'procdump --help' },
    ]

    for (const { toolName, cmd } of mustAllow) {
      it(`allows [${toolName}] ${cmd.slice(0, 60)}`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName,
          params: { command: cmd },
        })
        expect(d.block_code).not.toBe('DATA_LEAK_MONITORING_PROCESS_MEMORY_007')
      })
    }
  })

  // -------------------------------------------------------------
  // PRIORITY — 1100 (matches DATA_LEAK_PASTE_SERVICE_*).
  // -------------------------------------------------------------
  it('priority 1100 — load check', async () => {
    const fs = await import('node:fs')
    const yaml = await import('js-yaml')
    const doc = yaml.load(
      fs.readFileSync('policies/default-policy.spl.yaml', 'utf8'),
    ) as { rules: Array<{ id: string; priority: number }> }
    const r = doc.rules.find((x) => x.id === 'block-data-exfil-process-memory-dump')!
    expect(r.priority).toBe(1100)
  })
})