/**
 * Gateway / manage_plugin tool-call blocking tests (a).
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

describe('SELF_PROTECTION_GATEWAY_TOOL_035 (a)', () => {
  let config: Config
  let interventionEngine: InterventionEngine
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-gw-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function withDefaultPolicy(): InterventionEngine {
    const defaultPolicyPath = fileURLToPath(new URL('../policies/default-policy.spl.yaml', import.meta.url))
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      intervention: { policyPath: defaultPolicyPath, reloadIntervalMs: 0, decisionTimeoutMs: 0 },
    })
    interventionEngine = new InterventionEngine(config)
    interventionEngine.initialize()
    return interventionEngine
  }

  it('blocks manage_plugin tool call', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'manage_plugin',
      params: { action: 'config.patch', path: 'plugins.allow' },
    })
    expect(d.decision).toBe('block')
    expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_TOOL_035')
  })

  it('blocks plugin_uninstall tool call', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'plugin_uninstall',
      params: { name: 'sst-security-control-dsh' },
    })
    expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_TOOL_036')
  })

  it('blocks extension_manager tool call', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'extension_manager',
      // Use the namespace-prefixed action form. Bare `action: 'remove'` is
      // explicitly out of scope per `self-protection-block-gateway-tool-call`
      // notes 2026-10-01 (FP-control: deleted bare-verb mode). Self-protection
      // targets under `extensions.<id>.remove` are caught by the priority-1100
      // SELF_PROTECTION_GATEWAY_SELF_HARM_004 rule (deeper field-level coverage).
      params: { action: 'extensions.sst-security-control-dsh.remove' },
    })
    expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_SELF_HARM_004')
  })

  it('blocks gateway tool call', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'gateway',
      params: { action: 'plugin.entries.disable', id: 'sst-security-control-dsh' },
    })
    expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_TOOL_035')
  })

  // 锚定后按寻址字段拆成两条规则（paramsRegex 字段间是 AND、缺失即不匹配，
  // 而 FIELD_ALIASES 不含 name/id），同一攻击会落在 036（name）或 055（id）。
  // 要锁住的不变量是「必须被拦」，故断言 decision + 编码属于锚定规则集合，
  // 而不是某一个具体编号。
  it('blocks plugin_patch tool call', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'plugin_patch',
      params: { id: 'sst-security-control-dsh', patch: { enabled: false } },
    })
    expect(d.decision).toBe('block')
    expect(['SELF_PROTECTION_GATEWAY_TOOL_036', 'SELF_PROTECTION_GATEWAY_TOOL_055']).toContain(
      d.block_code,
    )
  })

  // 收敛的另一面：指向第三方插件/扩展的操作必须放行，否则规则就退化成噪音源。
  it('ALLOWS plugin/extension calls targeting a third-party plugin', async () => {
    const engine = withDefaultPolicy()
    for (const toolName of ['plugin_patch', 'extension_uninstall', 'plugin_disable']) {
      const d = await engine.evaluate({
        actionType: 'tool_call',
        toolName,
        params: { name: 'dsh-plugin-code-review', id: 'dsh-plugin-code-review' },
      })
      expect(d.decision).toBe('allow')
    }
  })

  it('ALLOWS benign tool call (file_read)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { path: '/tmp/random-data.txt' },
    })
    expect(d.decision).toBe('allow')
  })

  it('ALLOWS gateway plugins.list query (POL-1)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'gateway',
      params: { action: 'plugins.list' },
    })
    expect(d.decision).toBe('allow')
  })

  it('ALLOWS plugin_manager skills.list query (POL-1)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'plugin_manager',
      params: { action: 'skills.list' },
    })
    expect(d.decision).toBe('allow')
  })

  it('ALLOWS extension_manager list query (POL-1)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'extension_manager',
      params: { action: 'extensions.list' },
    })
    expect(d.decision).toBe('allow')
  })
})
