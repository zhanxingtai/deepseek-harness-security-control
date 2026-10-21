/**
 * unified risk-flag vocabulary.
 *
 * The plugin uses a single `risk_flag` string array that flows through every
 * layer (runtime hook → plugin → SPL rule). Centralising the vocabulary
 * here keeps SPL rules and emit sites in sync:
 *
 *  1. Application-layer events (file_read, message_write, etc.) can be
 *     flagged with the same names the runtime hook surfaces.
 *  2. SPL rules can use `riskFlagsAny: ['token_in_command']` to react
 *     to patterns the RuntimeHook pre-spawn seam flags.
 *  3. The plugin's own event reports stay consistent with the platform's
 *     ingest schema (same names = same alerting).
 *
 * Names are mirrored from the pre-spawn seam's `deriveRiskFlags` set.
 * New flags can be added here without touching the SPL layer.
 */

export const RISK_FLAGS = {
  /** Reverse shell primitives: bash interactive redirect to /dev/tcp, nc -e, etc. */
  reverse_shell: 'reverse_shell',
  /** Download + execute in one command: curl … | bash */
  download_execute: 'download_execute',
  /** Mass deletion: rm -rf, find -delete */
  mass_deletion: 'mass_deletion',
  /** Privilege escalation: sudo, su -, chmod +s, setuid */
  privilege_escalation: 'privilege_escalation',
  /**
   * aligned with the platform's standardised risk-flag
   * vocabulary. The previous `data_exfiltration` was overloaded (it
   * covered both bulk-data egress and credential exfil); the platform
   * spec renamed it to `credential_exposure` to scope the tag tightly to
   * the credential-exfil threat class. Bulk-data egress (scp / rsync /
   * tar -c | nc) now sits under the platform-defined `data_egress` set
   * (a future extension — the current plugin only emits this single
   * flag for token-in-command style attacks; the SPL vocabulary still
   * has `riskFlagsAny: ['credential_exposure']` as the matching surface).
   */
  credential_exposure: 'credential_exposure',
  /**
   * 数据泄露监测统一标准 v0.2.0 §5.2 —— `data_exfiltration`
   * 与 `credential_exposure` 是同级并存标签（不按别名归一化）：
   * `credential_exposure` 覆盖凭据模式
   * 内容命中，`data_exfiltration` 覆盖传输工具特征（curl -T / scp / rsync /
   * rclone / git push 等 L1.1 变体）。由 RuntimeHook / 工具命令扫描注入。
   */
  data_exfiltration: 'data_exfiltration',
  /**
   * 数据泄露监测统一标准 v0.2.0 §5.2 —— 数据库/日志导出工具或导出语句
   * （mysqldump / pg_dump / mongoexport / bcp / redis-cli --rdb /
   * sqlite3 .dump / SELECT ... INTO OUTFILE）。检测标签，warn 级。
   */
  db_dump: 'db_dump',
  /** Token / credential in command line */
  token_in_command: 'token_in_command',
  /** Reading a sensitive system file via exec */
  sensitive_file_access: 'sensitive_file_access',
  /** Executable from a skill directory that isn't a script */
  skill_binary_execution: 'skill_binary_execution',
  /** Server-side request forgery: access to internal / metadata endpoints. */
  ssrf: 'ssrf',
  /** Known-malicious domain resolution or HTTP request. */
  malicious_domain: 'malicious_domain',
  /** Installing or executing packages from untrusted sources. */
  supply_chain: 'supply_chain',
  /** Suspicious encoding / obfuscation in command line or payload. */
  suspicious_encoding: 'suspicious_encoding',
  /**
   * canonical name for attempts to
   * bypass or disable security monitoring.
   */
  self_protection_bypass: 'self_protection_bypass',
  /**
   * the system layer terminated a NEW process that
   * matched a behaviorBlock class (watchdog_unit / kill_actor / etc.).
   * The SPL layer can subscribe to this to add an app-layer response
   * (e.g. escalate the host session).
   *
   * retained as a compatibility alias for
   * `self_protection_bypass`; new rules should use the canonical name.
   */
  self_protection_behavior: 'self_protection_behavior',
} as const

export type RiskFlagName = typeof RISK_FLAGS[keyof typeof RISK_FLAGS]

/**
 * Default set of risk flags. Used by system-layer risk heuristics and
 * exposed so the SPL can reference the same set.
 */
export const DEFAULT_RISK_FLAGS: readonly RiskFlagName[] = [
  RISK_FLAGS.reverse_shell,
  RISK_FLAGS.download_execute,
  RISK_FLAGS.mass_deletion,
  RISK_FLAGS.privilege_escalation,
  RISK_FLAGS.credential_exposure,
  RISK_FLAGS.token_in_command,
  RISK_FLAGS.sensitive_file_access,
  RISK_FLAGS.skill_binary_execution,
  RISK_FLAGS.ssrf,
  RISK_FLAGS.malicious_domain,
  RISK_FLAGS.supply_chain,
  RISK_FLAGS.suspicious_encoding,
  RISK_FLAGS.self_protection_bypass,
  RISK_FLAGS.self_protection_behavior,
]

/**
 * Type guard: a string is a known risk flag (case-sensitive match
 * against the constant set). Returns false for unknown flags rather
 * than throwing — callers should log unknown flags so the platform can
 * alert on vocabulary drift.
 */
export function isKnownRiskFlag(s: string): s is RiskFlagName {
  return (Object.values(RISK_FLAGS) as string[]).includes(s)
}
