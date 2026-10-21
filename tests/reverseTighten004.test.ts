/**
 * Reverse-tighten regression tests for SELF_PROTECTION_GATEWAY_SELF_HARM_004
 * (priority 1100 — `self-protection-block-gateway-config-self-harm`).
 *
 * Background :
 *   The narrow SelfProtection rule that double-confirms an attack is
 *   targeting THIS plugin (rather than any other plugin on the host)
 *   previously over-fired — `^plugin(s)?\.(uninstall|...)` matched the
 *   plugin-mutation suffix on ANY plugin name, so an operator who
 *   legitimately uninstalled a third-party plugin still tripped the
 * SELF_PROTECTION_GATEWAY_SELF_HARM_004 rail. The 收紧 pass tightened
 *   every `action:` regex to require an explicit
 *   `sst-security-control-dsh` / `dsh-security-monitor` /
 *   `security-monitor` token. These tests lock down that targeting so
 *   any future regex edit that loosens the require-token clause is
 *   caught at CI.
 *
 * Note on layering:
 *     GATEWAY_TOOL_001 (priority 1500) is the wide net — it blocks
 *     every `manage_plugin` / `gateway` / `extension_manager` change
 *     action regardless of the targeted plugin name. That wide net is
 *     documented design (see `policies/default-policy.spl.yaml` line
 *     2027+). 004 is layered underneath specifically as a narrow
 *     double-confirmation: it ONLY fires when the targeted plugin IS
 *     the security monitor. The two rules are complementary — 1500
 *     catches the broad attempt, 1100 confirms the target.
 *
 * These tests load the default policy directly via `loadPolicy()` and
 * inspect the compiled regexes for SELF_PROTECTION_GATEWAY_SELF_HARM_004, without going
 * through `InterventionEngine.evaluate()` (which would always pick the
 * higher-priority 1500 rule and mask 004's behaviour).
 */
import { describe, expect, it } from 'vitest'
import { fileURLToPath } from 'node:url'
import { loadPolicy } from '../src/intervention/RuleLoader.js'
import type { CompiledRule, CompiledMatchClause } from '../src/intervention/InterventionEngine.js'

const DEFAULT_POLICY_PATH = fileURLToPath(
  new URL('../policies/default-policy.spl.yaml', import.meta.url),
)

function loadSelfProtection004(): CompiledRule {
  const result = loadPolicy(DEFAULT_POLICY_PATH)
  expect(result.error).toBeUndefined()
  expect(result.rules.length).toBeGreaterThan(0)
  const rule = result.rules.find((r) => r.id === 'self-protection-block-gateway-config-self-harm')
  if (!rule) throw new Error('self-protection-block-gateway-config-self-harm not found in default policy')
  expect(rule.priority).toBe(1100)
  expect(rule.action?.blockCode).toBe('SELF_PROTECTION_GATEWAY_SELF_HARM_004')
  return rule
}

function getActionRegexes(rule: CompiledRule): RegExp[] {
  const match: CompiledMatchClause | undefined = rule.match
  const regexes = match?.paramsRegex?.['action']
  if (!regexes || regexes.length === 0) {
    throw new Error('SELF_PROTECTION_GATEWAY_SELF_HARM_004 has no compiled action: regexes')
  }
  return regexes
}

describe('SELF_PROTECTION_GATEWAY_SELF_HARM_004 reverse tighten', () => {
  // ---------------------------------------------------------------
  // POSITIVE: action strings that MUST still trip 004 — locks down
  // the require-token clause so a future edit can't silently remove it.
  // ---------------------------------------------------------------
  describe('matches attack payloads (target = this plugin)', () => {
    const rule = loadSelfProtection004()
    const actionRegexes = getActionRegexes(rule)

    const mustMatch = [
      // config.* targeting this plugin (rule 1 + 6 — `config.<name>.<verb>`)
      'config.sst-security-control-dsh.patch',
      'config.sst-security-control-dsh.set',
      'config.dsh-security-monitor.unset',
      'config.security-monitor.edit',
      // plugins.* targeting this plugin (rule 2 — `plugin(s)?.name.<verb>`)
      'plugin.sst-security-control-dsh.uninstall',
      'plugins.sst-security-control-dsh.remove',
      'plugin.dsh-security-monitor.disable',
      'plugins.security-monitor.delete',
      // extensions.* targeting this plugin (rule 3 — `extension(s)?.name.<verb>`)
      'extension.sst-security-control-dsh.uninstall',
      'extensions.dsh-security-monitor.disable',
      // Mid-segment variants — config.foo.name.patch
      'config.foo.sst-security-control-dsh.patch',
      'plugins.bar.dsh-security-monitor.uninstall',
    ]

    for (const payload of mustMatch) {
      it(`MATCHES  ${payload}`, () => {
        const hit = actionRegexes.some((rx) => rx.test(payload))
        expect(hit).toBe(true)
      })
    }
  })

  // ---------------------------------------------------------------
  // NEGATIVE: action strings that MUST NOT trip 004 — locks down
  // the post-2026-09-24 收紧 fix so a future edit can't silently
  // re-introduce the over-blocking that trapped operators trying to
  // manage unrelated plugins.
  // ---------------------------------------------------------------
  describe('does NOT match benign operator payloads (target = other plugins)', () => {
    const rule = loadSelfProtection004()
    const actionRegexes = getActionRegexes(rule)

    const mustNotMatch = [
      // Manage / install / uninstall a third-party plugin — operator
      // action, NOT an attack on this plugin. 004 must NOT fire here.
      'plugin.other-tool.uninstall',
      'plugins.metrics-collector.disable',
      'plugin.code-formatter.remove',
      'plugins.web-search-plugin.install',
      'extension.theme-pack.delete',
      'extensions.grammar-checker.uninstall',
      // Config queries on the host config tree that don't target
      // security-monitor. These are not even blocked by the wide net
      // (1500) but 004 must also pass them through.
      'config.global.get',
      'config.foo-bar.update',
      // Unrelated tokens that LOOK similar to security-monitor but are
      // not the plugin name (substring traps).
      'config.monitor-watchdog.uninstall',
      'plugin.dashboard-monitor.remove',
      // Bare action strings without a target.
      'plugins.list',
      'extensions.list',
      // Bare verbs without any plugin prefix.
      'uninstall',
      'remove',
      'disable',
    ]

    for (const payload of mustNotMatch) {
      it(`DOES NOT MATCH  ${payload}`, () => {
        const hit = actionRegexes.some((rx) => rx.test(payload))
        expect(hit).toBe(false)
      })
    }
  })
})