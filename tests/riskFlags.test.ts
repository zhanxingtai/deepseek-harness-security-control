/**
 * Risk flag vocabulary tests.
 */
import { describe, expect, it } from 'vitest'
import { RISK_FLAGS, DEFAULT_RISK_FLAGS, isKnownRiskFlag } from '../src/utils/riskFlags.js'

describe('RISK_FLAGS', () => {
  it('defines the canonical risk-flag vocabulary', () => {
    expect(RISK_FLAGS.reverse_shell).toBe('reverse_shell')
    expect(RISK_FLAGS.download_execute).toBe('download_execute')
    expect(RISK_FLAGS.mass_deletion).toBe('mass_deletion')
    expect(RISK_FLAGS.privilege_escalation).toBe('privilege_escalation')
    expect(RISK_FLAGS.credential_exposure).toBe('credential_exposure')
    expect(RISK_FLAGS.token_in_command).toBe('token_in_command')
    expect(RISK_FLAGS.sensitive_file_access).toBe('sensitive_file_access')
    expect(RISK_FLAGS.skill_binary_execution).toBe('skill_binary_execution')
    expect(RISK_FLAGS.self_protection_behavior).toBe('self_protection_behavior')
  })

  it('includes the data-leak vocabulary (数据泄露监测统一标准 v0.2.0 §5.2)', () => {
    // Active data-leak tags wired to emitters. Reserved-but-unused flags
    // (secret_in_content / pii_in_content / covert_channel /
    // third_party_upload / bulk_data_access) were dropped on 2026-09-25 —
    // they would mislead audit consumers into subscribing to tags no
    // collector emits. Tracked in .5 housekeeping batch.
    expect(RISK_FLAGS.data_exfiltration).toBe('data_exfiltration')
    expect(RISK_FLAGS.db_dump).toBe('db_dump')
  })

  it('does NOT collapse data_exfiltration into credential_exposure (2026-09-14 alias correction)', () => {
    // 数据泄露监测统一标准 v0.2.0 §5.2：两者为同级并存标签。回归保护——
    // 2026-08-28 版本的别名表曾把 data_exfiltration 折叠进 credential_exposure。
    // 2026-10-10：整个 `RISK_FLAG_ALIASES` + `normalizeRiskFlag` 已删除 —
    // const 内部就是事实源，const 的存在本身就是"不归一化"的保证。
    expect(RISK_FLAGS.data_exfiltration).toBe('data_exfiltration')
    expect(RISK_FLAGS.credential_exposure).toBe('credential_exposure')
    expect(RISK_FLAGS.data_exfiltration).not.toBe(RISK_FLAGS.credential_exposure)
  })

  it('preserves self_protection_bypass and self_protection_behavior as two distinct signals (2026-10-10 spec parity)', () => {
    // 删除 `self_protection_behavior -> self_protection_bypass` alias 后的回归保护。
    // 规范把这两个视为独立信号(bypass = 主动绕过插件,behavior = 异常访问插件自身),
    // 之前的 alias 在 runtime 偷偷把它们折叠成同一个,违反 spec 设计意图。
    expect(RISK_FLAGS.self_protection_bypass).toBe('self_protection_bypass')
    expect(RISK_FLAGS.self_protection_behavior).toBe('self_protection_behavior')
    expect(RISK_FLAGS.self_protection_bypass).not.toBe(RISK_FLAGS.self_protection_behavior)
  })

  it('DEFAULT_RISK_FLAGS includes all flags (including self_protection_behavior)', () => {
    expect(DEFAULT_RISK_FLAGS).toContain('reverse_shell')
    expect(DEFAULT_RISK_FLAGS).toContain('self_protection_behavior')
  })

  it('isKnownRiskFlag matches exactly the vocabulary', () => {
    expect(isKnownRiskFlag('reverse_shell')).toBe(true)
    expect(isKnownRiskFlag('self_protection_behavior')).toBe(true)
    expect(isKnownRiskFlag('unknown_flag')).toBe(false)
    expect(isKnownRiskFlag('REVERSE_SHELL')).toBe(false) // case-sensitive
  })
})
