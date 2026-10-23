/**
 * reasons.ts — localized text for the Reason column.
 *
 * WHY THIS FILE EXISTS
 *
 * `BlockRow.block_reason` is not authored prose. For SPL hits it is
 * composed at runtime by `DecisionComposer.buildReason`
 * (src/intervention/DecisionComposer.ts:505-519) as
 *
 *   `Block reason: {message} (rule: {name}). Aggregate risk: …`
 *
 * where `{message}` and `{name}` are Chinese — 98 of 98 rules in
 * policies/default-policy.spl.yaml carry a Chinese `name`. So the column
 * rendered an English wrapper sentence around Chinese content, in BOTH
 * languages. Mapping by `policy_id` (which DecisionComposer sets to
 * `rule.id`, DecisionComposer.ts:271) replaces the whole composed string
 * with one clean localized sentence.
 *
 * WHY KEYS LIVE HERE AND GET SPREAD INTO locales.ts
 *
 * 102 entries × 2 languages side by side is reviewable; split across two
 * 98-entry blocks it is not. `locales.ts` spreads REASON_EN / REASON_ZH
 * into its `en` / `zh` dicts, so `LocaleKey` derives from `en` and the
 * existing en↔zh parity test in tests/client/locales.test.ts covers
 * these keys with no extra wiring. The `import type` below is erased at
 * compile time — there is no runtime cycle.
 *
 * FALLBACK
 *
 * `localizeReason` returns the raw `block_reason` whenever no key
 * resolves, so an older plugin policy, a rule added after this table,
 * or an engine literal we have not seen degrades to exactly what the UI
 * shows today. Miss-detection relies on the host locale runtime
 * returning the key string itself for an unknown key —
 * `LocaleRuntime.translate` ends in `?? key`
 * (@deepseek-ai/dsh-client-locale lib/client.js:1294). Verified
 * against the real runtime, not assumed.
 *
 * GENERATED (zh column)
 *
 * zh values are lifted byte-exact from policies/default-policy.spl.yaml
 * by a one-shot generator, so they cannot drift from the policy text.
 * The generator is not committed — the DURABLE guard is the coverage
 * test in tests/client/locales.test.ts, which parses the SPL and fails
 * if any rule id lacks a `reason_<id>` key here (and vice versa). Add a
 * rule to the SPL without adding its key and CI goes red.
 */

import type { LocaleKey } from './locales.js'

/** Locale `t()` as the components declare it. */
export type Translate = (key: LocaleKey, params?: Record<string, string | number>) => string

/** One policy rule → its localized Reason text. */
export const REASON_EN = {
  'reason_self-protection-block-uninstall': 'Block uninstalling or disabling the security monitor plugin',
  'reason_self-protection-block-installer-uninstall': 'Block uninstall / cleanup executed by an installer script',
  'reason_self-protection-block-audit-file-mutation-command': 'Block deleting or truncating audit logs or policy files via a command',
  'reason_self-protection-allow-package-manager-mention': 'Allow package-manager calls that merely mention the sst-security-control-dsh path',
  'reason_self-protection-block-command-mentioning-plugin-path': 'Block commands mentioning the plugin asset paths (path-mention block)',
  'reason_self-protection-block-message-mentioning-plugin-path': 'Block messages asking to read / delete / tamper with the plugin asset paths (message-mention block)',
  'reason_self-protection-block-script-write-touching-plugin': 'Block writing scripts that uninstall or tamper with the plugin',
  'reason_self-protection-block-harness-process-kill': 'Block killing the dsh engine via kill / pkill (monitor-disabling bypass)',
  'reason_self-protection-block-restart-without-patch': 'Block restarting the dsh engine without the security-monitor --patch flag',
  'reason_self-protection-block-write-disabler-script': 'Block writing scripts that disable or restart the dsh engine (indirect script-execution bypass)',
  'reason_self-protection-block-execute-scratch-script': 'Block executing script files from temp directories (bash indirect-execution bypass; /tmp and /var/tmp vectors only, narrowed FP surface)',
  'reason_self-protection-block-decode-then-execute': 'Block piping base64 / openssl-decoded payloads straight to the shell (encoded-payload bypass)',
  'reason_self-protection-block-config-tamper': 'Block tampering with the security monitor config or data',
  'reason_self-protection-block-config-read': 'Block reading the security monitor config or data (read-file tools)',
  'reason_self-protection-block-config-read-exec': 'Block reading the security monitor config or data (exec commands)',
  'reason_self-protection-block-patch-file-delete': 'Block deleting the security monitor patch file',
  'reason_self-protection-block-profile-package-json': 'Block removing the security monitor dependency from the profile package.json',
  'reason_self-protection-block-gateway-config-self-harm': 'Block disabling or removing the security monitor via gateway / config_manager',
  'reason_self-protection-block-gateway-self-harm-path': 'Block disabling or removing the security monitor via the gateway path field',
  'reason_self-protection-block-gateway-self-harm-raw': 'Block disabling or removing the security monitor via the gateway raw field',
  'reason_self-protection-block-gateway-self-harm-value': 'Block disabling or removing the security monitor via the gateway value field',
  'reason_self-protection-block-gateway-self-harm-content': 'Block disabling or removing the security monitor via the gateway content field',
  'reason_self-protection-block-gateway-self-harm-data': 'Block disabling or removing the security monitor via the gateway data field',
  'reason_self-protection-block-gateway-self-harm-note': 'Block requests to uninstall the security monitor via the gateway note field',
  'reason_self-protection-block-gateway-action': 'Block uninstalling or disabling non-self plugins via a bare gateway action field (self-protection plugins whitelisted, narrowed FP surface)',
  'reason_self-protection-block-uninstall-message': 'Block user requests to uninstall or disable the security monitor',
  'reason_block-sensitive-system-files-critical': 'Block access to sensitive system files (critical)',
  'reason_block-sensitive-system-files-warn': 'Block access to sensitive system files (warn)',
  'reason_block-ssh-private-keys-critical': 'Block access to SSH private keys / authorized_keys files (critical)',
  'reason_block-ssh-private-keys-critical-ecdsa': 'Block access to SSH ECDSA private keys (id_ecdsa)',
  'reason_block-ssh-private-keys-critical-dsa': 'Block access to legacy DSA SSH private keys (id_dsa)',
  'reason_block-ssh-private-keys-warn': 'Block access to SSH private keys / authorized_keys files (warn)',
  'reason_block-read-credentials-critical': 'Block reading credential / key files (critical)',
  'reason_block-read-credentials-warn': 'Block reading credential / key files (warn)',
  'reason_block-exec-sensitive-file-critical': 'Block exec reads of SSH private key files and /etc/shadow (Tier-1)',
  'reason_block-exec-sensitive-file-warn': 'Block exec reads of sensitive system files (warn)',
  'reason_block-exec-reverse-shell': 'Block reverse shells via exec',
  'reason_block-exec-reverse-shell-multilang': 'Block multi-language reverse shells via exec',
  'reason_block-exec-download-pipe': 'Block download-and-execute via exec (whitelisted carve-outs)',
  'reason_block-exec-rm-root-critical': 'Block dangerous deletions via exec (critical)',
  'reason_block-exec-rm-root-warn': 'Block dangerous deletions via exec (warn)',
  'reason_block-exec-process-termination-warn': 'Block process termination via exec (warn)',
  'reason_block-exec-privilege-escalation': 'Block privilege escalation via exec',
  'reason_block-exec-capabilities-manipulation': 'Block Linux capabilities manipulation via exec',
  'reason_warn-capabilities-introspection': 'Warn on read-only capabilities introspection (getcap / getpcaps / pscap)',
  'reason_self-protection-block-privilege-escalation': 'Block tampering with the security monitor after gaining root / SUID / capabilities',
  'reason_warn-chroot-usage': 'Warn on chroot changing the root directory',
  'reason_block-exec-package-install-from-url': 'Block installing packages from untrusted sources via exec (public PyPI / npmjs / yarnpkg / rubygems / goproxy whitelisted, narrowed FP surface)',
  'reason_block-credential-in-command-critical': 'Command line contains plaintext credentials (critical commands, narrowed FP surface)',
  'reason_block-credential-in-command-warn': 'Command line contains plaintext credentials (warn)',
  'reason_block-delete-sensitive-files': 'Block deleting SSH private key files and other critical credential files (Tier-1)',
  'reason_block-write-system-backdoor-critical': 'Block writing system backdoors / startup entries (critical)',
  'reason_block-write-system-backdoor-warn': 'Block writing system backdoors / startup entries (warn)',
  'reason_block-write-sensitive-system-files': 'Block writes to sensitive system files (path dimension, Tier-1 list)',
  'reason_block-write-sensitive-system-files-command': 'Block writes to sensitive system files via shell redirection (command dimension, Tier-1)',
  'reason_block-internal-ssrf-command-critical': 'Block SSRF against internal addresses via exec (command dimension, critical)',
  'reason_block-internal-ssrf-command-warn': 'Block SSRF against internal addresses via exec (command dimension, warn)',
  'reason_redact-credentials-exfil': 'Redact outbound data matching credential / PII patterns (advisory)',
  'reason_block-cloud-upload': 'Monitor data transfers to external addresses (low-confidence warn, standard L1.1)',
  'reason_block-cloud-paste-service-pastebin': 'Block outbound data to known paste / upload services',
  'reason_block-cloud-paste-service-github-gist': 'Block outbound data to known paste / upload services (write body path)',
  'reason_block-data-exfil-db-live-connection': 'Block live database data exfiltration (live query / live monitor / live stream)',
  'reason_block-data-exfil-process-memory-dump': 'Block exfiltration of process memory / procfs / devmem',
  'reason_warn-procfs-credential-bearing': 'Warn on reads of credential-bearing procfs state files (status / cmdline / io / stack / auxv / exe / syscall / wchan)',
  'reason_block-data-exfil-db-dump': 'Monitor database / log export tool calls (low-confidence warn, standard L3.1)',
  'reason_block-cloud-metadata-imds': 'Monitor access to cloud metadata services (IMDS) — sensitive-source access, standard L1.5',
  'reason_self-protection-asset-tamper-patch': 'Asset layer: cordis.patch.yml modified or deleted (non-tool fallback)',
  'reason_self-protection-asset-soften-patch': 'Asset layer: cordis.patch.yml softened (enabled:false / mode:audit, etc., R4.13.3-a)',
  'reason_self-protection-asset-tamper-policy': 'Asset layer: security-policy.json / security-events.jsonl modified or deleted (path-based, R4.13.3-b; audit-log anchor)',
  'reason_self-protection-asset-soften-policy': 'Asset layer: security-policy.json softened (enabled:false / priority:0 / decision:allow, etc., R4.13.3-b)',
  'reason_self-protection-asset-tamper-state': 'Asset layer: asset-state.json tampered with (baseline forgery defense)',
  'reason_self-protection-asset-tamper-mcp': 'Asset layer: mcp.json modified (MCP registry hijack defense)',
  'reason_self-protection-path-guard-toolcall': 'Tool-stack layer: protect critical config / artifact paths from modification (path-based fallback, R4.13.1-b)',
  'reason_self-protection-block-unshare-namespace': 'Tool-stack layer: block unshare -p creating a new PID namespace (sandbox-escape defense, R4.7.3)',
  'reason_self-protection-block-gateway-tool-call': 'Tool-stack layer: block non-self-protecting mutating calls to gateway / manage_plugin / extension_manager (2026-09-01 POL-1; 2026-10-01 P2 narrowed FP surface, bare verbs removed, self-protection names whitelisted)',
  'reason_self-protection-block-mutating-plugin-tools': 'Tool-stack layer: block install / uninstall / enable / disable / update / patch plugin tools targeting the security monitor itself',
  'reason_self-protection-warn-mutating-extension-tools': 'Tool-stack layer: warn on extension tool operations targeting the security monitor itself',
  'reason_self-protection-block-mutating-plugin-tools-byid': 'Tool-stack layer: block plugin tool operations targeting the security monitor by id',
  'reason_self-protection-warn-mutating-extension-tools-byid': 'Tool-stack layer: warn on extension tool operations targeting the security monitor by id',
  'reason_self-protection-escalate-on-behavior-block': 'Application layer: escalate after a system-layer behaviorBlock fires',
  'reason_env-passthrough-block-bash-env': 'Block pre-execution command injection via BASH_ENV / ENV / PROMPT_COMMAND / SSH_AUTH_SOCK',
  'reason_env-passthrough-block-bash-funcs': 'Block shell function hijacking via exported BASH_FUNC_*',
  'reason_env-passthrough-block-ssh-auth-sock': 'Block forwarding SSH agent credentials via SSH_AUTH_SOCK',
  'reason_env-passthrough-block-gpg-agent': 'Block forwarding the GPG agent via GPG_AGENT_INFO',
  'reason_self-protection-block-scheduled-task-command': 'Block planting future-execution payloads via schedulers (systemd-timer / cron / at) — command layer',
  'reason_self-protection-warn-service-autostart': 'Warn on service autostart changes via systemctl enable / start / reload',
  'reason_self-protection-block-scheduled-task-body': 'Block planting scheduled task units by writing files (systemd-timer / cron file / OnCalendar) — script layer',
  'reason_self-protection-block-ptrace-attach': 'Block attaching to the dsh process via ptrace / gdb / strace',
  'reason_self-protection-block-disk-rewrite': 'Block modifying or erasing disks via dd / mkfs / bootloader',
  'reason_self-protection-block-cron-modify': 'Block modifying /etc/cron* system schedules via shell redirection',
  'reason_self-protection-block-write-cron-payload': 'Block writing files that reference /etc/cron* paths',
  'reason_self-protection-block-ld-so-preload': 'Block writes to /etc/ld.so.preload or ld.so.conf.d/ (glibc hijack channel)',
  'reason_self-protection-block-write-ld-so-payload': 'Block writing files that reference glibc hijack paths',
  'reason_self-protection-block-selinux-apparmor-disable': 'Block disabling SELinux / AppArmor (kernel mandatory access control)',
  'reason_self-protection-block-firewall-flush': 'Block flushing firewall rules (iptables / nft / ufw)',
  'reason_self-protection-block-write-firewall-flush-script': 'Block writing files that contain firewall-flush scripts',
  'reason_warn-unpatched-engine-relaunch': 'RuntimeHook detected the dsh engine restarting without --patch security-monitor (self-protection bypass warning)',
  'reason_warn-scratch-dir-spawn': 'RuntimeHook detected processes spawned from a temp directory (/tmp / var/tmp / dev/shm)',
} as const

/** zh side — rule `name` verbatim from policies/default-policy.spl.yaml. */
export const REASON_ZH = {
  'reason_self-protection-block-uninstall': '阻止卸载或禁用安全监控插件',
  'reason_self-protection-block-installer-uninstall': '阻止通过安装脚本执行卸载/清理',
  'reason_self-protection-block-audit-file-mutation-command': '阻止通过命令删除/截断审计日志或策略文件',
  'reason_self-protection-allow-package-manager-mention': '允许包管理工具调用中提及 sst-security-control-dsh 路径',
  'reason_self-protection-block-command-mentioning-plugin-path': '阻止命令中出现安全监控插件资产路径（路径提及式阻断）',
  'reason_self-protection-block-message-mentioning-plugin-path': '阻止消息中要求读取/删除/篡改安全监控插件资产路径（消息提及式阻断）',
  'reason_self-protection-block-script-write-touching-plugin': '阻止写入内容涉及卸载/篡改插件的脚本',
  'reason_self-protection-block-harness-process-kill': '阻止通过 kill/pkill 终止 dsh 引擎进程（禁用监控的旁路）',
  'reason_self-protection-block-restart-without-patch': '阻止不带 security-monitor --patch 参数重启 dsh 引擎',
  'reason_self-protection-block-write-disabler-script': '阻止写入含禁用/重启 dsh 引擎逻辑的脚本（脚本间接执行绕过）',
  'reason_self-protection-block-execute-scratch-script': '阻止执行临时目录下的脚本文件（bash 脚本间接执行绕过,仅 /tmp /var/tmp 攻击向量,FP 收窄）',
  'reason_self-protection-block-decode-then-execute': '阻止 base64/openssl 解码后直接交给 shell 执行（编码载荷绕过）',
  'reason_self-protection-block-config-tamper': '阻止篡改安全监控插件配置或数据',
  'reason_self-protection-block-config-read': '阻止读取安全监控插件配置或数据（读文件工具）',
  'reason_self-protection-block-config-read-exec': '阻止读取安全监控插件配置或数据（exec 命令）',
  'reason_self-protection-block-patch-file-delete': '阻止删除安全监控插件 patch 文件',
  'reason_self-protection-block-profile-package-json': '阻止从 profile package.json 移除安全监控插件依赖',
  'reason_self-protection-block-gateway-config-self-harm': '阻止通过 gateway/config_manager 禁用或移除安全监控插件',
  'reason_self-protection-block-gateway-self-harm-path': '阻止通过 gateway path 字段禁用或移除安全监控插件',
  'reason_self-protection-block-gateway-self-harm-raw': '阻止通过 gateway raw 字段禁用或移除安全监控插件',
  'reason_self-protection-block-gateway-self-harm-value': '阻止通过 gateway value 字段禁用或移除安全监控插件',
  'reason_self-protection-block-gateway-self-harm-content': '阻止通过 gateway content 字段禁用或移除安全监控插件',
  'reason_self-protection-block-gateway-self-harm-data': '阻止通过 gateway data 字段禁用或移除安全监控插件',
  'reason_self-protection-block-gateway-self-harm-note': '阻止通过 gateway note 字段要求卸载安全监控插件',
  'reason_self-protection-block-gateway-action': '阻止通过 gateway 单字段 action 卸载/禁用非自身插件（白名单自保护插件项,FP 收窄）',
  'reason_self-protection-block-uninstall-message': '阻止用户要求卸载或禁用安全监控插件',
  'reason_block-sensitive-system-files-critical': '阻断敏感系统文件访问',
  'reason_block-sensitive-system-files-warn': '阻断敏感系统文件访问',
  'reason_block-ssh-private-keys-critical': '阻断 SSH 私钥/授权文件访问',
  'reason_block-ssh-private-keys-critical-ecdsa': '阻断 SSH ECDSA 私钥访问（id_ecdsa，issue',
  'reason_block-ssh-private-keys-critical-dsa': '阻断 SSH 老 DSA 私钥访问（id_dsa，issue',
  'reason_block-ssh-private-keys-warn': '阻断 SSH 私钥/授权文件访问',
  'reason_block-read-credentials-critical': '阻断读取凭据/密钥文件',
  'reason_block-read-credentials-warn': '阻断读取凭据/密钥文件',
  'reason_block-exec-sensitive-file-critical': '阻断 exec 读取 SSH 私钥本体与 /etc/shadow（Tier-1）',
  'reason_block-exec-sensitive-file-warn': '阻断 exec 读取敏感系统文件',
  'reason_block-exec-reverse-shell': '阻断 exec 反弹 shell',
  'reason_block-exec-reverse-shell-multilang': '阻断多语言 exec 反弹 shell',
  'reason_block-exec-download-pipe': '阻断 exec 下载并执行（含白名单 carve-out）',
  'reason_block-exec-rm-root-critical': '阻断 exec 危险删除',
  'reason_block-exec-rm-root-warn': '阻断 exec 危险删除',
  'reason_block-exec-process-termination-warn': '阻断 exec 终止进程',
  'reason_block-exec-privilege-escalation': '阻断 exec 权限提升',
  'reason_block-exec-capabilities-manipulation': '阻断 exec Linux capabilities 操作',
  'reason_warn-capabilities-introspection': '警告 capabilities 只读查询（getcap / getpcaps / pscap）',
  'reason_self-protection-block-privilege-escalation': '阻止通过权限提升获得 root / SUID / capabilities 后篡改安全监控',
  'reason_warn-chroot-usage': 'chroot 改变根目录（告警级）',
  'reason_block-exec-package-install-from-url': '阻断 exec 从非受信来源安装包（白名单公共 PyPI/npmjs/yarnpkg/rubygems/goproxy,FP 收窄）',
  'reason_block-credential-in-command-critical': '命令行包含明文凭据（critical commands,FP 收窄）',
  'reason_block-credential-in-command-warn': '命令行包含明文凭据',
  'reason_block-delete-sensitive-files': '阻断删除 SSH 私钥本体与关键凭据文件（Tier-1）',
  'reason_block-write-system-backdoor-critical': '阻断写入系统后门/启动项',
  'reason_block-write-system-backdoor-warn': '阻断写入系统后门/启动项',
  'reason_block-write-sensitive-system-files': '阻断写入敏感系统文件（path 维度 · Tier-1 名单）',
  'reason_block-write-sensitive-system-files-command': '阻断通过 shell 重定向写入敏感系统文件（command 维度 · Tier-1）',
  'reason_block-internal-ssrf-command-critical': '阻断通过 exec 访问内网地址的 SSRF（command 维度）',
  'reason_block-internal-ssrf-command-warn': '阻断通过 exec 访问内网地址的 SSRF（command 维度）',
  'reason_redact-credentials-exfil': '外发数据脱敏（凭据/PII 模式，advisory）',
  'reason_block-cloud-upload': '监测向外部地址传输数据（低置信 warn，标准 L1.1）',
  'reason_block-cloud-paste-service-pastebin': '阻断向已知 paste/upload 服务外发数据',
  'reason_block-cloud-paste-service-github-gist': '阻断向已知 paste/upload 服务外发数据（write body 路径）',
  'reason_block-data-exfil-db-live-connection': '阻断数据库实时数据外发（live query / live monitor / live stream）',
  'reason_block-data-exfil-process-memory-dump': '阻断进程内存 / procfs / devmem 外发',
  'reason_warn-procfs-credential-bearing': '警告读取 procfs 凭据类状态文件（status/cmdline/io/stack/auxv/exe/syscall/wchan）',
  'reason_block-data-exfil-db-dump': '数据库/日志导出工具调用监测（低置信 warn，标准 L3.1）',
  'reason_block-cloud-metadata-imds': '监测访问云元数据服务（敏感来源访问，标准 L1.5）',
  'reason_self-protection-asset-tamper-patch': '资产层：cordis.patch.yml 被修改/删除（兜底非工具路径）',
  'reason_self-protection-asset-soften-patch': '资产层：cordis.patch.yml 内容软化（enabled:false / mode:audit 等，R4.13.3-a）',
  'reason_self-protection-asset-tamper-policy': '资产层：security-policy.json / security-events.jsonl 被改/删（路径型，R4.13.3-b;补审计日志锚）',
  'reason_self-protection-asset-soften-policy': '资产层：security-policy.json 软化（enabled:false / priority:0 / decision:allow 等，R4.13.3-b）',
  'reason_self-protection-asset-tamper-state': '资产层：asset-state.json 被篡改（防伪造基线）',
  'reason_self-protection-asset-tamper-mcp': '资产层：mcp.json 被修改（防 MCP 注册表被劫持）',
  'reason_self-protection-path-guard-toolcall': '工具栈层：保护关键配置文件/产物路径不被改（路径型兜底，R4.13.1-b）',
  'reason_self-protection-block-unshare-namespace': '工具栈层：阻断 unshare -p 创建新 PID namespace（防沙箱逃逸，R4.7.3）',
  'reason_self-protection-block-gateway-tool-call': '工具栈层：阻断 gateway/manage_plugin/extension_manager 的非自保护变更类工具调用（删除 bare verb,加自保护名白名单）',
  'reason_self-protection-block-mutating-plugin-tools': '工具栈层：阻断指向安全监控自身的 install/uninstall/enable/disable/update/patch 类插件工具',
  'reason_self-protection-warn-mutating-extension-tools': '工具栈层：告警指向安全监控自身的扩展类工具操作',
  'reason_self-protection-block-mutating-plugin-tools-byid': '工具栈层：按 id 指向安全监控自身的插件工具操作',
  'reason_self-protection-warn-mutating-extension-tools-byid': '工具栈层：按 id 指向安全监控自身的扩展类工具操作告警',
  'reason_self-protection-escalate-on-behavior-block': '应用层：system 层 behaviorBlock 触发后升级处理',
  'reason_env-passthrough-block-bash-env': '阻止通过 BASH_ENV / ENV / PROMPT_COMMAND / SSH_AUTH_SOCK 注入预执行命令',
  'reason_env-passthrough-block-bash-funcs': '阻止通过 BASH_FUNC_* 导出 shell 函数劫持',
  'reason_env-passthrough-block-ssh-auth-sock': '阻止通过 SSH_AUTH_SOCK 转发 SSH agent 凭据',
  'reason_env-passthrough-block-gpg-agent': '阻止通过 GPG_AGENT_INFO 转发 GPG agent',
  'reason_self-protection-block-scheduled-task-command': '阻止通过调度器（systemd-timer / cron / at）植入未来执行载荷（命令层）',
  'reason_self-protection-warn-service-autostart': '告警通过 systemctl enable/start/reload 修改服务自启动',
  'reason_self-protection-block-scheduled-task-body': '阻止通过写入文件植入定时任务单元（systemd-timer / cron file / OnCalendar）（脚本层）',
  'reason_self-protection-block-ptrace-attach': '阻止通过 ptrace / gdb / strace attach dsh 进程',
  'reason_self-protection-block-disk-rewrite': '阻止通过 dd / mkfs / bootloader 修改擦除磁盘',
  'reason_self-protection-block-cron-modify': '阻止通过 shell 重定向修改 /etc/cron* 系统定时任务',
  'reason_self-protection-block-write-cron-payload': '阻止写入含 /etc/cron* 路径的文件',
  'reason_self-protection-block-ld-so-preload': '阻止写入 /etc/ld.so.preload 或 ld.so.conf.d/（glibc 劫持通道）',
  'reason_self-protection-block-write-ld-so-payload': '阻止写入含 glibc 劫持路径的文件',
  'reason_self-protection-block-selinux-apparmor-disable': '阻止关闭 SELinux / AppArmor（内核强制访问控制）',
  'reason_self-protection-block-firewall-flush': '阻止清空防火墙规则（iptables / nft / ufw）',
  'reason_self-protection-block-write-firewall-flush-script': '阻止写入包含防火墙清空脚本的文件',
  'reason_warn-unpatched-engine-relaunch': 'RuntimeHook 检出 dsh 引擎无 --patch security-monitor 重启（自保护旁路告警）',
  'reason_warn-scratch-dir-spawn': 'RuntimeHook 检出在临时目录（/tmp /var/tmp /dev/shm）派生进程',
} as const

/**
 * Engine-produced literals that carry no rule id. Keyed by slug;
 * `LITERAL_ALIASES` maps the exact runtime string onto the slug.
 */
export const REASON_LITERAL_EN = {
  'reason_fail_closed_timeout': 'Intervention evaluation timed out; fail-closed per policy',
  'reason_high_risk_fail_open_only': 'High-risk activity blocked under fail_open_high_risk_only policy',
  'reason_inline_guard_exception': 'Inline guard exception caught',
  'reason_sensitive_header_denied': 'Inline sensitive-header guard denied the request',
} as const

export const REASON_LITERAL_ZH = {
  'reason_fail_closed_timeout': '策略评估超时;按策略 fail-closed 阻断',
  'reason_high_risk_fail_open_only': 'fail_open_high_risk_only 策略下高风险活动被阻断',
  'reason_inline_guard_exception': '内联守卫捕获异常',
  'reason_sensitive_header_denied': '出站敏感请求头守卫已阻断该请求',
} as const

/** Exact runtime `block_reason` string → locale key slug. */
export const LITERAL_ALIASES: Readonly<Record<string, string>> = {
  'Intervention evaluation timed out; fail-closed per policy': 'fail_closed_timeout',
  'High-risk activity blocked under fail_open_high_risk_only policy': 'high_risk_fail_open_only',
  'inline_guard_exception_caught': 'inline_guard_exception',
  'inline sensitive-header guard denied the request': 'sensitive_header_denied',
}

/**
 * Resolve a Reason cell for display.
 *
 * Miss-detection is deliberately broader than "t() returned the key".
 * The host runtime ends `translate()` in `?? key`
 * (@deepseek-ai/dsh-client-locale lib/client.js:1294), so a registered
 * key always yields a string and an unregistered one yields the key —
 * but `t` is a plain injected parameter, and not every implementation
 * honours that: `tests/client/recentBlocksRawDetail.test.tsx` stubs it
 * with `return en[key] as string`, which yields `undefined` for a miss.
 * Trusting only the `=== slug` check let that stub render an EMPTY cell
 * instead of the raw reason. A non-string, or a string equal to the key,
 * is both treated as a miss so the worst case degrades to "shows what
 * the UI showed before this table existed" rather than "shows nothing".
 *
 * @param policyId `BlockRow.policy_id` — the SPL rule `id`, or one of
 *   the inline pseudo-ids. Falls back to the literal table when absent.
 * @param raw `BlockRow.block_reason`, used verbatim when no key resolves.
 * @param t bound locale `t()`
 * @returns localized text, or `raw` when nothing is registered
 */
export function localizeReason(
  policyId: string | undefined,
  raw: string | undefined,
  t: Translate,
): string {
  const slug = policyId
    ? `reason_${policyId}`
    : raw && LITERAL_ALIASES[raw]
      ? `reason_${LITERAL_ALIASES[raw]}`
      : undefined
  const fallback = raw ?? ''
  if (slug === undefined) return fallback
  const out = t(slug as LocaleKey)
  if (typeof out !== 'string' || out.length === 0 || out === slug) return fallback
  return out
}
