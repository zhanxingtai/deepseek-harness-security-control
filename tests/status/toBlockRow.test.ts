/**
 * toBlockRow — wire-level normalization for Policy Hits rows.
 *
 * 2026-10-12 — 审计发现档(security_audit)行回归:无 intervention 的审计
 * 事件必须在工具/原因/策略列回退到顶层 target / reason /
 * audit_details.policy_id,否则 Policy Hits 整行只有 '—' / 'unknown',
 * 操作员无法解读。
 */
import { describe, expect, it } from 'vitest'
import { toBlockRow } from '../../src/status/overview.js'

describe('toBlockRow — audit-finding rows (security_audit)', () => {
  const rawAudit = {
    ts: 1_791_791_933_402,
    event_type: 'security_audit',
    audit_category: 'policy',
    audit_action: 'tamper',
    severity: 'high',
    reason:
      "security plugin 'security-monitor' unloaded at runtime (ctx.effect_dispose); matches plugin-manager HMR disable path",
    target: 'security-monitor',
    audit_details: {
      event_type_alias: 'plugin_runtime_unload',
      policy_id: 'self-unload-sentinel',
      detail: 'plugin scope disposed while the host process kept running',
    },
  }

  it('falls back to target / reason / audit_details.policy_id on every column', () => {
    const row = toBlockRow(rawAudit)
    expect(row.tool_name).toBe('security-monitor')
    expect(row.decision).toBe('unknown') // 客户端决策列回退显示 audit_action
    expect(row.audit_action).toBe('tamper')
    expect(row.severity).toBe('high')
    expect(row.policy_id).toBe('self-unload-sentinel')
    expect(row.block_reason).toContain('unloaded at runtime')
  })

  it('decision-hit rows keep intervention fields (audit fallbacks do not clobber)', () => {
    const row = toBlockRow({
      ts: 1,
      event_type: 'agent_tool_call',
      tool_name: 'pwsh',
      target: 'ignored-for-non-audit',
      reason: 'ignored-for-non-audit',
      audit_details: { policy_id: 'ignored' },
      intervention: {
        decision: 'deny',
        decision_internal: 'block',
        severity: 'critical',
        policy_id: 'self-protection-block-uninstall',
        block_reason: '该操作会禁用或卸载安全监控插件，已被安全策略阻断',
      },
    })
    expect(row.tool_name).toBe('pwsh')
    expect(row.policy_id).toBe('self-protection-block-uninstall')
    expect(row.block_reason).toContain('已被安全策略阻断')
  })

  it('audit row without target/reason/policy_id degrades to undefined (renders —)', () => {
    const row = toBlockRow({
      ts: 1,
      event_type: 'security_audit',
      audit_action: 'detect',
      severity: 'medium',
    })
    expect(row.tool_name).toBeUndefined()
    expect(row.policy_id).toBeUndefined()
    expect(row.block_reason).toBeUndefined()
    expect(row.audit_action).toBe('detect')
  })
})
