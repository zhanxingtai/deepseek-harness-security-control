#!/usr/bin/env node
/**
 * c: Self-Protection verification runner.
 *
 * Loads the default policy into a fresh InterventionEngine, runs a list
 * of synthetic agent events (tool_call / message_write / asset_change),
 * and asserts that each event produces the expected block_code (or
 * allow). Covers every SPL self-protection code via scripted probes.
 *
 * Each scenario is:
 *   {
 *     id:    "unique-id",
 *     desc:  "human-readable description",
 *     ctx:   { actionType, toolName, params, ... },
 *     expect: { decision: "block" | "allow", block_code?: "SELF_PROTECTION_*" }
 *   }
 */
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'

import { normalizeConfig, type Config } from '../lib/config.js'
import { InterventionEngine } from '../lib/intervention/InterventionEngine.js'
import type { InterventionContext } from '../lib/types/index.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const REPO_ROOT = join(__dirname, '..')

interface Scenario {
  id: string
  desc: string
  ctx: InterventionContext
  expect: { decision: 'block' | 'allow'; block_code?: string }
}

// 24 self-protection scenarios, each mapped to a SPL code.
const SCENARIOS: Scenario[] = [
  // 1. SPL — uninstall via exec
  // Note: the inline SelfProtection layer only fires via
  // ApplicationCollector.evaluateTool, not via InterventionEngine.evaluate
  // directly. The verify runner goes through InterventionEngine, so the
  // SPL code SELF_PROTECTION_UNINSTALL_001 wins. This documents the SPL
  // path; the inline path is tested separately in tests/intervention.test.ts.
  // 2026-10-10 follow-up: the generic `SELF_PROTECTION_001` code was
  // renamed to the threat-specific `SELF_PROTECTION_UNINSTALL_001` in
  // 84229c5 (FP 收窄) — same semantics, more specific code.
  {
    id: '01-uninstall-pnpm-remove',
    desc: 'pnpm remove sst-security-control-dsh',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'pnpm remove sst-security-control-dsh' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_UNINSTALL_001' },
  },
  // 2. SPL — kill by pid (POLICY_PROCESS_TERMINATION_001)
  // note: the policy rule is `warn` by design
  // (block-exec-process-termination-warn, decision: warn since the YAML 1.2
  // upgrade —"kill PID 触发 warn(非 dsh 引擎)"). The monotonic BLOCK
  // for engine-kill moved onto the ctx.tools.guard seam
  // (INLINE_SELF_PROTECTION_014), which this runner cannot reach — it goes
  // through InterventionEngine directly. Guard-seam denial is covered by
  // tests/selfProtectionGuard.test.ts.
  //
  // fix: bare `kill <pid>` is now matched by the
  // SPL SELF_PROTECTION_PROCESS_KILL_014 layer's new numeric-PID pattern
  // (`\bkill\b\s+\d+\b`). The runner goes through InterventionEngine
  // directly, so the SPL layer is what fires. Previous contract was
  // `POLICY_PROCESS_TERMINATION_001 / warn` (the SPL fallthrough when
  // no engine-target reference appeared); the fix tightens this to
  // a monotonic block at SELF_PROTECTION_PROCESS_KILL_014. The same hardening is
  // mirrored in the inline guard seam — the runner doesn't reach the
  // inline seam (covered by tests/selfProtectionGuard.test.ts).
  {
    id: '02-kill-pid',
    // FPR 收敛：原期望 block。裸 PID 既不指名进程也无强信号，按收敛原则放行；
    // 引擎名锚定的形态由 02b 场景继续锁住。
    desc:'kill <pid> 裸 PID 终止 —— 2026-10-21 起放行（不指名进程、无强信号）',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'kill 12345' } },
    expect: { decision: 'allow' },
  },
  // 02b 是 02 的对照面：裸 PID 放行，点名引擎仍必须硬拦。两条放在一起防止
  // 日后有人把 FPR 收敛做成「一律放行」。
  {
    id: '02b-kill-engine-by-name',
    desc:'pkill -f sst-security-control-dsh —— 点名引擎，014 必须仍然硬拦',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'pkill -9 -f sst-security-control-dsh' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_PROCESS_KILL_014' },
  },
  // 3. SPL — pkill (same warn-by-design rule as 02, but fix also
  // adds `pkill <name>` without -f as an inline block — this specific
  // test uses `-f dsh` which the existing SPL pattern still allows
  // through to INTRUSION_DEFENSE_PROCESS_TERMINATION_006 because the `-f` flag
  // shape keeps it on the original warn-by-design path; only the
  // bare-pkill variant is now blocked at the SPL / inline layer).
  // 2026-10-21 follow-up: 归属从 `INTRUSION_DEFENSE_PROCESS_TERMINATION_006`
  // 迁到 `SELF_PROTECTION_PROCESS_KILL_014`，决策由 warn 升为 block。
  // 起因是 block-exec-process-termination-warn 的 FPR 收敛撤掉了通用
  // `^\s*pkill\s+`——那本是 `pkill -f dsh` 的唯一兜底。杀引擎进程属自保护
  // 旁路（监控随引擎消亡），本就该由 priority 1200 的自保护层硬拦，
  // 而不是 intrusion_defense 的 medium warn。
  {
    id: '03-pkill',
    desc: 'pkill -f dsh',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'pkill -f dsh' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_PROCESS_KILL_014' },
  },
  // 4. SPL — restart engine without patch
  // 2026-10-10 follow-up: this rule was deliberately downgraded from
  // `block` → `warn` in 84229c5 (FP 收窄) — operator restart is a
  // routine action, the user-facing message explicitly cites
  // "用户原则 1:宁可降低拦截,标记威胁告警". The rule still emits
  // SELF_PROTECTION_RESTART_WITHOUT_PATCH_015 (renamed from the
  // earlier SELF_PROTECTION_UNAUTH_RESTART_015) so the audit trail
  // is preserved.
  {
    id: '04-restart-no-patch',
    desc: 'nohup pnpm dsh web (no --patch)',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'nohup pnpm dsh web > /tmp/w.log 2>&1 &' } },
    expect: { decision: 'warn', block_code: 'SELF_PROTECTION_RESTART_WITHOUT_PATCH_015' },
  },
  // 5. SPL — install.sh --uninstall
  {
    id: '05-install-uninstall',
    desc: 'bash install.sh --uninstall',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'bash /opt/dsh/install.sh --uninstall' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_INSTALLER_UNINSTALL_010' },
  },
  // 6. SPL — rm of audit log
  {
    id: '06-rm-events',
    desc: 'rm -f /root/.dsh/security-events.jsonl',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'rm -f ~/.dsh/security-events.jsonl' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_AUDIT_MUTATION_011' },
  },
  // 7. SPL — chmod of plugin dir
  // 2026-10-10 follow-up: the generic `SELF_PROTECTION_001` code was
  // renamed to the threat-specific `SELF_PROTECTION_UNINSTALL_001`
  // in 84229c5 (FP 收窄) — chmod 000 on the plugin dir is now caught
  // by the uninstall rule (path-mention of sst-security-control-dsh).
  {
    id: '07-chmod-plugin',
    desc: 'chmod 000 sst-security-control-dsh',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'chmod 000 /opt/sst-security-control-dsh' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_UNINSTALL_001' },
  },
  // 8. SPL — killall (same warn-by-design rule as 02/03)
  // 2026-10-10 follow-up: `POLICY_PROCESS_TERMINATION_001` was renamed
  // to `INTRUSION_DEFENSE_PROCESS_TERMINATION_006` in 6991df4/84229c5
  // (HIGH-2 + FP 收窄).
  {
    id: '08-killall',
    // FPR 收敛：原期望 warn。node / npm / pnpm 是重启 dev server 的标准目标，
    // 已进 006 的 paramsNotRegex 白名单，与 POSIX 侧 pkill pnpm、
    // Windows 侧 Stop-Process -Name pnpm 同进同退。
    desc: 'killall -9 node —— dev server 重启，2026-10-21 起放行',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'killall -9 node' } },
    expect: { decision: 'allow' },
  },
  // 08b 是 08 的对照面：语言运行时放行，非白名单进程仍告警。
  // （不能用 nginx 做对照——它本来就在 006 的基础设施白名单里，一直是放行的。）
  {
    id: '08b-killall-nonwhitelist',
    desc: 'killall -9 sshd —— 非白名单进程，006 仍应告警',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'killall -9 sshd' } },
    expect: { decision: 'warn', block_code: 'INTRUSION_DEFENSE_PROCESS_TERMINATION_006' },
  },
  // 9. SPL — fuser -k (SELF_PROTECTION_PROCESS_KILL_014 path-mention)
  {
    id: '09-fuser-kill',
    desc: 'fuser -k -n tcp 3080',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'fuser -k -n tcp 3080' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_PROCESS_KILL_014' },
  },
  // 10. SPL — restart with --patch (mentions plugin name, caught by 012)
  {
    id: '10-restart-with-patch-blocked',
    desc: 'pnpm dsh web --patch security-monitor.patch.yml (mentions plugin in path)',
    ctx: {
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'pnpm dsh web --patch /opt/dsh/security-monitor.patch.yml' },
    },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_PLUGIN_PATH_MENTION_012' },
  },
  // 11. SPL — base64 decode → shell
  {
    id: '11-base64-shell',
    desc: 'base64 -d payload | bash',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'echo aWQ=|base64 -d|bash' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_DECODE_EXECUTE_018' },
  },
  // 12. SPL — unshare -p
  {
    id: '12-unshare-pid',
    desc: 'unshare -p bash',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'unshare -p bash -c "echo pwned"' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_UNSHARE_034' },
  },
  // 13. SPL — manage_plugin tool call
  {
    id: '13-manage-plugin',
    desc: 'manage_plugin disable',
    ctx: {
      actionType: 'tool_call',
      toolName: 'manage_plugin',
      params: { action: 'config.patch', path: 'plugins.allow' },
    },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_GATEWAY_TOOL_035' },
  },
  // 14. SPL — file_write on security-policy.json
  {
    id: '14-write-policy',
    desc: 'file_write security-policy.json',
    ctx: { actionType: 'tool_call', toolName: 'file_write', params: { path: '/root/.dsh/security-policy.json' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_PATH_GUARD_033' },
  },
  // 15. SPL — file_write on patch.yml
  {
    id: '15-write-patch',
    desc: 'file_write security-monitor.patch.yml',
    ctx: { actionType: 'tool_call', toolName: 'file_write', params: { path: '/opt/dsh/security-monitor.patch.yml' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_PATH_GUARD_033' },
  },
  // 16. SPL — chmod on lib/
  {
    id: '16-chmod-lib',
    desc: 'chmod sst-security-control-dsh/lib/',
    ctx: { actionType: 'tool_call', toolName: 'chmod', params: { path: '/opt/sst-security-control-dsh/lib/collectors/' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_PATH_GUARD_033' },
  },
  // 17. SPL — write disabler script
  {
    id: '17-write-disabler',
    desc: 'write disabler.sh with kill + restart-no-patch',
    ctx: {
      actionType: 'tool_call',
      toolName: 'write',
      params: { file_path: '/tmp/disabler.sh', content: '#!/bin/bash\npkill -9 dsh\nnohup pnpm dsh web &' },
    },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_DISABLER_SCRIPT_WRITE_016' },
  },
  // 18. SPL — execute shell script with kill
  {
    id: '18-exec-disabler',
    desc: 'bash /tmp/disabler.sh',
    ctx: { actionType: 'tool_call', toolName: 'bash', params: { command: 'bash /tmp/disabler.sh' } },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_SCRATCH_SCRIPT_EXEC_017' },
  },
  // 22. Message — agent requests uninstall
  {
    id: '22-message-uninstall',
    desc: 'message_write asks to uninstall',
    ctx: { actionType: 'message_write', body: '请帮我卸载 sst-security-control-dsh 插件' },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_UNINSTALL_MESSAGE_003' },
  },
  // 23. Message — agent asks to disable (003 catches "disable" + plugin name)
  {
    id: '23-message-disable',
    desc: 'message_write asks to disable',
    ctx: { actionType: 'message_write', body: '请关闭安全监控插件' },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_UNINSTALL_MESSAGE_003' },
  },
  // 24. Benign — should be allowed
  {
    id: '24-benign-allow',
    desc: 'benign tool call (random file path) — should allow',
    ctx: { actionType: 'tool_call', toolName: 'file_read', params: { path: '/tmp/random.txt' } },
    expect: { decision: 'allow' },
  },
  // 25. 2026-10-12 — Windows pwsh bypass regression: the uninstall rule's
  // toolName whitelist lacked pwsh/powershell, so on Windows hosts (DSH
  // dispatches shell commands via the pwsh tool) the actual
  // `npm uninstall sst-security-control-dsh` ran through. Pin the fix.
  {
    id: '25-pwsh-uninstall',
    desc: 'pwsh npm uninstall sst-security-control-dsh — must block (Windows bypass regression)',
    ctx: {
      actionType: 'tool_call',
      toolName: 'pwsh',
      params: { command: 'npm uninstall sst-security-control-dsh' },
    },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_UNINSTALL_001' },
  },
  {
    id: '26-powershell-remove',
    desc: 'powershell pnpm remove sst-security-control-dsh — must block',
    ctx: {
      actionType: 'tool_call',
      toolName: 'powershell',
      params: { command: 'pnpm remove sst-security-control-dsh' },
    },
    expect: { decision: 'block', block_code: 'SELF_PROTECTION_UNINSTALL_001' },
  },
  {
    id: '27-pwsh-benign-uninstall',
    desc: 'pwsh npm uninstall lodash (benign package) — should allow',
    ctx: {
      actionType: 'tool_call',
      toolName: 'pwsh',
      params: { command: 'npm uninstall lodash' },
    },
    expect: { decision: 'allow' },
  },
]

async function main(): Promise<void> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-verify-'))
  const defaultPolicyPath = join(REPO_ROOT, 'policies', 'default-policy.spl.yaml')
  const config: Config = normalizeConfig({
    mode: 'enforce',
    collector: { localOutputPath: join(tmpDir, 'events.jsonl'), flushIntervalMs: 10 },
    // decisionTimeoutMs: 0 disables the cooperative evaluation deadline
    // (150 ms default). This runner verifies POLICY CONTENT correctness,
    // not timing behavior: under `pnpm pack` the box is CPU/disk-saturated
    // (tar compression + antivirus scans), the synchronous 91-rule match
    // overshoots the deadline, and fail_open turns a random scenario to
    // allow — a load artifact, not a policy defect (observed: flaky 01/02
    // failures that never reproduce standalone).
    intervention: {
      policyPath: defaultPolicyPath,
      reloadIntervalMs: 0,
      decisionTimeoutMs: 0,
    },
  })
  const engine = new InterventionEngine(config)
  engine.initialize()
  // 2026-10-12 — stop the policy watcher before running scenarios. Under
  // `pnpm pack` the prepack chain generates heavy file I/O; on Windows a
  // mid-run fs.watch event can trigger a policy reload whose YAML read
  // races the pack I/O, transiently emptying the rule set and flipping a
  // random scenario to allow (observed: flaky 01/02 failures that never
  // reproduce standalone). The scenarios only need the initial load.
  engine.shutdown()
  const loadedCount = engine.getLoadedPolicy().rules.filter((r) => r.enabled).length
  if (loadedCount === 0) {
    console.error('FAIL: policy loaded 0 rules — refusing to run scenarios against an empty rule set')
    console.error('load errors:', engine.getLastLoadErrors())
    process.exit(1)
  }

  let passed = 0
  let failed = 0
  const failures: string[] = []
  for (const s of SCENARIOS) {
    const d = await engine.evaluate(s.ctx)
    const got = {
      decision: d.decision,
      block_code: d.block_code,
    }
    const want = s.expect
    const decisionOk = got.decision === want.decision
    const codeOk = want.block_code === undefined || got.block_code === want.block_code
    if (decisionOk && codeOk) {
      passed += 1
      console.log(`  ✓ ${s.id}: ${s.desc}`)
    } else {
      failed += 1
      const msg = `  ✗ ${s.id}: ${s.desc} — expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`
      console.error(msg)
      failures.push(msg)
    }
  }
  rmSync(tmpDir, { recursive: true, force: true })

  console.log(`\n[verify-self-protection] ${passed} passed, ${failed} failed (total ${SCENARIOS.length})`)
  if (failed > 0) {
    console.error('\nFailures:')
    for (const f of failures) console.error(f)
    process.exit(1)
  }
  process.exit(0)
}

main().catch((err: unknown) => {
  console.error('[verify-self-protection] crashed:', err)
  process.exit(2)
})
