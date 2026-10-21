/**
 * Reverse-tighten regression tests for SELF_PROTECTION_GATEWAY_TOOL_035
 * (priority 1500 — `self-protection-block-gateway-tool-call`).
 *
 * Background :
 *   The wide-net rule that blocks every `manage_plugin` / `gateway` /
 *   `extension_manager` change action regardless of the targeted plugin
 *   name. SELF_PROTECTION_GATEWAY_SELF_HARM_004 (priority 1100) is the narrow
 *   double-confirmation that only fires when the targeted plugin IS the
 *   security monitor — see `tests/reverseTighten004.test.ts`.
 *
 *   This test suite documents the design WHY:
 *
 *     The 4 verb-alternatives in the action: regex use slightly different
 *     verb lists — config.* has the widest (11 verbs: patch|set|update|
 *     put|write|delete|remove|unset|replace|merge|edit), while plugin.* /
 *     extension.* / bare have a 12-verb set that drops put|unset|replace|
 *     merge in favour of install|uninstall|disable|enable. A multi-segment
 *     `plugin.foo.put` therefore BYPASSES 1500 (the verb isn't in the
 *     plugin alt's list) — the rule is intentionally permissive here on
 *     the assumption that the targeted plugin name will be looked at by
 *     SELF_PROTECTION_GATEWAY_SELF_HARM_004, AND that the host DSH distribution's real
 *     mutation vocabulary is `install|uninstall|disable|enable|update`
 *     rather than the more general `put|unset|replace|merge`.
 *
 *   These tests lock down the *current* behaviour so any future regex
 *   edit that silently shifts the verb coverage between alternatives is
 *   caught at CI. The "must block" cases cover every verb in every alt's
 *   list; the "must allow" cases cover verbs that look mutating but
 *   aren't in the deny-list AND verbs that look benign but happen to be
 *   in one of the deny-list alternatives.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

describe('SELF_PROTECTION_GATEWAY_TOOL_035 wide-net', () => {
  let config: Config
  let interventionEngine: InterventionEngine
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-gw-rt-'))
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

  // -------------------------------------------------------------
  // The config.* alternative has the widest verb coverage
  // (patch|set|update|put|write|delete|remove|unset|replace|merge|edit).
  // Every one of those MUST fire through `gateway` tool calls.
  // -------------------------------------------------------------
  describe('config.<verb> blocks every verb in config alt', () => {
    const configVerbs = [
      'patch', 'set', 'update', 'put', 'write', 'delete',
      'remove', 'unset', 'replace', 'merge', 'edit',
    ]
    for (const verb of configVerbs) {
      it(`blocks config.foo.${verb} via gateway`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'gateway',
          params: { action: `config.foo.${verb}` },
        })
        expect(d.decision).toBe('block')
        expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_TOOL_035')
      })
    }
  })

  // -------------------------------------------------------------
  // The plugin.* / extension.* alternatives share a verb list
  // (install|uninstall|remove|disable|enable|update|patch|set|delete|
  //  write|edit) — note put/unset/replace/merge are NOT in this list.
  // -------------------------------------------------------------
  describe('plugin.<verb> blocks every verb in plugin alt', () => {
    const pluginVerbs = [
      'install', 'uninstall', 'remove', 'disable', 'enable',
      'update', 'patch', 'set', 'delete', 'write', 'edit',
    ]
    for (const verb of pluginVerbs) {
      it(`blocks plugin.foo.${verb} via manage_plugin`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'manage_plugin',
          params: { action: `plugin.foo.${verb}` },
        })
        expect(d.decision).toBe('block')
        expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_TOOL_035')
      })
      it(`blocks extension.foo.${verb} via extension_manager`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'extension_manager',
          params: { action: `extension.foo.${verb}` },
        })
        expect(d.decision).toBe('block')
        expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_TOOL_035')
      })
    }
  })

  // -------------------------------------------------------------
  // DOCUMENTED LIMITATION: the plugin/extension alternatives do NOT
  // include put/unset/replace/merge. Multi-segment actions using those
  // verbs BYPASS the wide net. This is intentional (the targeted
  // plugin-name check belongs in SELF_PROTECTION_GATEWAY_SELF_HARM_004) but the test
  // locks down the gap so any future widening is a deliberate change.
  // -------------------------------------------------------------
  describe('plugin/extension verbs OUTSIDE the deny-list (documented gap)', () => {
    const outsideVerbs = ['put', 'unset', 'replace', 'merge']
    for (const verb of outsideVerbs) {
      it(`allows plugin.foo.${verb} via manage_plugin (gap)`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'manage_plugin',
          params: { action: `plugin.foo.${verb}` },
        })
        // 1500 wide net does NOT fire here — the verb is not in the
        // plugin/extension alt's list. SELF_PROTECTION_GATEWAY_SELF_HARM_004 still
        // provides cover if the targeted plugin IS the security
        // monitor (its action regex explicitly includes put/unset/
        // replace/merge), and audit mode logs the call regardless.
        expect(d.decision).not.toBe('block')
      })
      it(`allows extension.foo.${verb} via extension_manager (gap)`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'extension_manager',
          params: { action: `extension.foo.${verb}` },
        })
        expect(d.decision).not.toBe('block')
      })
      // The config alt DOES include these verbs — the regex mismatch
      // only applies to the plugin/extension alts.
      it(`blocks config.foo.${verb} via gateway (config alt has it)`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'gateway',
          params: { action: `config.foo.${verb}` },
        })
        expect(d.decision).toBe('block')
        expect(d.block_code).toBe('SELF_PROTECTION_GATEWAY_TOOL_035')
      })
    }
  })

  // -------------------------------------------------------------
  // NEGATIVE: every "read-only" verb MUST pass through. Locks down
  // the verb deny-list from the OTHER side — if a future edit
  // accidentally adds e.g. 'show' to the deny-list, the
  // documentation page would say "wide net" but the behaviour
  // would be silently over-blocking benign queries.
  // -------------------------------------------------------------
  describe('read-only verbs are NEVER in the deny-list (must-not-match)', () => {
    const readOnlyVerbs = [
      'list', 'get', 'show', 'info', 'exists', 'help',
      'version', 'status', 'query', 'read', 'fetch',
    ]
    for (const verb of readOnlyVerbs) {
      it(`allows config.${verb} via gateway`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'gateway',
          params: { action: `config.foo.${verb}` },
        })
        expect(d.decision).not.toBe('block')
      })
      it(`allows plugins.${verb} via plugin_manager`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'plugin_manager',
          params: { action: `plugins.${verb}` },
        })
        expect(d.decision).not.toBe('block')
      })
      it(`allows extensions.${verb} via extension_manager`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'extension_manager',
          params: { action: `extensions.${verb}` },
        })
        expect(d.decision).not.toBe('block')
      })
    }
  })

  // -------------------------------------------------------------
  // P 收窄:删除 4th alternative `^(install...)$` bare verb 模式
  // 原模式 FP 0.1-1%(任何 bare 动词触发),改为:
  //   - bare verb 不再被 Rule 5 (1500) 拦截
  //   - 必须带 plugin.config. 前缀 (config.X.<verb> / plugins.X.<verb>) 才命中
  //   - 自保护插件名 (sst-security-control-dsh / dsh-security-monitor / dsh / self) 内联白名单
  // 设计意图:Rule 5 退化为更精确的安全网,Rule 4 (1100) 兜底非自身插件
  // -------------------------------------------------------------
  describe('bare verb (post-2026-10-01 narrowing): no longer blocks at Rule 5', () => {
    const bareMutating = [
      'install', 'uninstall', 'remove', 'disable', 'enable',
      'update', 'patch', 'set', 'delete', 'write', 'edit',
    ]
    const bareBenign = ['check', 'inspect', 'view', 'describe', 'lookup', 'search', 'ping', 'ready']

    // 原 4th alternative 删除后,bare mutating verb 不再被 Rule 5 拦截
    // 它们需要 plugin.config. 前缀才被 Rule 4 (1100) 拦截
    for (const verb of bareMutating) {
      it(`allows bare '${verb}' via manage_plugin (Rule 5 no longer matches bare verbs)`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'manage_plugin',
          params: { action: verb },
        })
        // Rule 5 (1500) 不再覆盖 bare verb;Rule 4 (1100) 需要 plugin.config. 前缀
        // bare verb 在两层规则下都不命中,允许放行(假定调用方会走 config.X.<verb> 形式)
        expect(d.decision).not.toBe('block')
      })
    }

    for (const verb of bareBenign) {
      it(`allows bare '${verb}' via manage_plugin`, async () => {
        const engine = withDefaultPolicy()
        const d = await engine.evaluate({
          actionType: 'tool_call',
          toolName: 'manage_plugin',
          params: { action: verb },
        })
        expect(d.decision).not.toBe('block')
      })
    }
  })
})