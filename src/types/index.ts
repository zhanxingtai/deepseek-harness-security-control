export * from './external.js'

/**
 * Plugin operating mode — the authoritative union type.
 * All config / engine / sink / client / typert sites import this
 * instead of repeating inline `'audit' | 'enforce'` literals, so the
 * vocabulary cannot drift across modules.
 */
export type Mode = 'audit' | 'enforce'

/**
 */
export const DEFAULT_PLATFORM_ID = 'sst-security-control-dsh'

/**
 * Security event produced by collectors.  Field shape is documented inline
 * per the platform event-schema contract (see `src/utils/schema.ts` for the
 * required-field map and `validateEvent` for the runtime guard).
 */
export interface SecurityEvent {
  /**
   * Observer/emitter process name. Historically narrowed to the literal
   * 'sst-security-control-dsh', but the platform spec explicitly does not
   * constrain `comm` to a single value — system-layer events now report
   * the monitored process's own name (e.g. 'docker', 'bash').
   */
  comm: string
  event_id: string
  event_type: string
  /**
   * collapsed to the platform spec's 3-tier coarse
   * enum (`application | system | asset`). The previous 5-tier
   * (`network` and `runtime` as siblings) leaked plugin-internal
   * seams onto the wire. Fine-grained provenance now lives on
   * `source_layer` (which retains the 5 values for back-compat and
   * to keep the per-collector distinguishing signal available to
   * audit dashboards).
   */
  layer: 'application' | 'system' | 'asset'
  source_layer?: 'application' | 'network' | 'system' | 'asset' | 'runtime'
  ts: number
  /**
   * Wire format uses integer `schema_version: 1`. The platform event
   * schema (`common.json`) still declares the field as a string for
   * historical reasons; the validator accepts both shapes, but events
   * emitted to the platform must be integers.
   */
  schema_version?: number | string
  /** Derived policy evaluation block injected by EventCollector before persistence / upload. */
  policy_evaluation?: PolicyEvaluation
  collection_method?: string
  timestamp?: number
  pid?: number
  session_id?: string
  run_id?: string
  agent_id?: string
  /**
   * explicit task identifier. Surfaced on runtime_* events
   * (and any future event types that benefit from a stable per-task key)
   * so audit consumers can correlate a spawn to the agent task that
   * triggered it without parsing `run_id` themselves. Today equals
   * `session_id` (one session == one logical task in the harness runtime).
   */
  task_id?: string
  /**
   * monotonic turn identifier within a task. Mirrors the
   * `run_id` shape (`${session_id}-${turn}`) so consumers that key on
   * `run_id` keep working; the dedicated field lets dashboards that want
   * a short turn token (without the session prefix) avoid re-parsing.
   */
  turn_id?: string
  host_id?: string
  container_id?: string
  tool_call_id?: string
  tool_name?: string
  tool_kind?: string
  path?: string
  /** File operation encoding (file_* events), e.g. the tool name on file_privilege. */
  operation?: string
  params?: unknown
  /**
   * list of dotted-path keys that were masked by
   * `redactAndCollectKeys` while building this event. Present on
   * `agent_tool_call` and any other event that flowed through the
   * redaction helper; empty array (`[]`) when nothing matched.
   * Mirrors what the platform expects under the same field name.
   */
  redacted_keys?: string[]
  /**
   * subset of `redacted_keys` whose hits came from
   * the user_prompt side-channel (the user-typed prompt that initiated
   * the session, surfaced on every `agent_tool_call`). Operators see
   * `bearer_token` / `query.token` etc. on the union list and can tell
   * whether the leak originated in the prompt vs. the tool arguments by
   * diffing against this list. Present on `agent_tool_call`; empty
   * array (`[]`) when nothing matched.
   */
  user_prompt_redacted_keys?: string[]
  /**
   * JSON-string tool arguments. Carries the redacted object form when
   * `collector.redactRawParams: true` (marketplace default); with the
   * flag flipped off, the verbatim JSON lands here for forensic replay.
   * `params` is the same data as an object for callers that prefer
   * structural access. This is the canonical tool-args carrier.
   */
  tool_params?: string
  /**
   * side-channel describing how `tool_params` was
   * produced. `enabled` mirrors the live `collector.redactRawParams`
   * flag; `redacted` is true when the value passed through
   * `redactRawParams`. The sha256 + size of the original raw string are
   * always recorded so audit consumers can reconstruct whether masking
   * changed the carrier without having the original on disk.
   */
  params_redaction?: {
    enabled: boolean
    redacted: boolean
    raw_size_bytes: number
    raw_hash_sha256: string
  }
  params_hash?: string
  /**
   * MD5 hex digest of the meaningful content of this event. Pre-execute
   * events carry a hash of the *intent* (the content to be written or the
   * code to be executed); agent_tool_result events carry a hash of the
   * *result* (the content returned). Useful for tamper detection,
   * deduplication, and change fingerprinting — same hash on two reads of
   * the same path means the content did not change between them.
   */
  hash?: string
  /**
   * Post-hoc file operations derived from a shell / interpreter command
   * string (e.g. `bash -c "cat /etc/passwd"`) — emitted alongside the
   * tool's native event so audit dashboards can correlate shell-driven
   * file activity with native file_* events. Populated only when the
   * tool's args contain a command string and the parser recognizes at
   * least one file op; absent otherwise. See src/utils/shellFileOps.ts.
   */
  derived_file_ops?: DerivedFileOp[]
  user_prompt?: string
  assistant_message?: string
  system_prompt?: string
  agent_plan?: string[]
  previous_actions?: ActionRecord[]
  step_index?: number
  message_index?: number
  is_code_mode?: boolean
  code_content?: string
  code_content_length?: number
  code_language?: string
  model_provider?: string
  model_name?: string
  agent_config?: AgentConfig
  /**
   * Per the platform spec (§agent_start), `agents` is
   * the canonical descriptor array. Each entry follows the ebpf-shaped
   * schema `id / name / agentDir / config / skills / tools`. Cordis only
   * surfaces `id` + `options.{provider,model}` (no filesystem-shaped
   * fields), so `agentDir` / `config` / `skills` / `tools` are emitted as
   * `null` when unavailable. `name` mirrors `id` (the spec example also
   * uses identical values, and the harness does not distinguish the two
   * at the Cordis boundary). Loose `agent_id` / `agent_config` / `model_*`
   * keys remain alongside for backward compat.
   */
  agents?: AgentDescriptor[]
  skills?: string[]
  tools?: string[]
  role?: string
  content?: string
  content_length?: number
  /** Payload size limit flags. */
  content_truncated?: boolean
  content_original_length?: number
  user_prompt_truncated?: boolean
  user_prompt_original_length?: number
  reasoning?: string
  reasoning_length?: number
  message_id?: string
  parent_message_id?: string
  token_usage_prompt?: number
  token_usage_completion?: number
  token_usage_total?: number
  execution_duration_ms?: number
  duration?: number
  execution_status?: string
  status?: 'success' | 'failure'
  /** : process_exit coarse status, populated by the system
   *  layer. psutil cannot reap a process we did not terminate, so we
   *  cannot supply a real exit code; the field tells dashboards
   *  "we don't know" explicitly (`unknown`) vs "we killed it"
   *  (`self_protection_behavior`) vs future variants. */
  exit_status?: 'self_protection_behavior' | 'unknown' | 'normal'
  result?: string
  /** True when the full `result` exceeded the `toolResultMaxChars` cap and was
   *  dropped in favour of `result_preview` + full-length `hash`/`result_size`. */
  result_truncated?: boolean
  result_preview?: string
  result_size?: number
  result_preview_length?: number
  error_message?: string
  /**
   * real exit code for terminated processes, populated
   * by the system layer when it can reap the process via pidfd_open
   * (Linux 5.4+) on `process_exit`. Convention mirrors psutil:
   * non-negative integer for normal exits (the exit status code, 0..255),
   * negative integer when the process was killed by a signal (e.g. -9 for
   * SIGKILL). Optional because not every exit is reapable (kernels < 5.4
   * raise ENOSYS on pidfd_open; processes killed by a non-tracked parent
   * may vanish before we can attach). When absent, the coarse `exit_status`
   * field carries the resolution ("self_protection_behavior" / "unknown" /
   * "normal"). Windows WMI event tracing is a separate task.
   */
  exit_code?: number | null
  /**
   * emitted on agent_stop to indicate whether any tool_call
   * in the session was SPL-blocked. Surfaces policy enforcement correlation
   * without requiring the consumer to inspect `exit_code` semantics or
   * re-parse `previous_actions` (which does not store the decision field).
   */
  intervention_blocked?: boolean
  blocked?: boolean
  block_reason?: string
  intervention?: Intervention
  risk_assessment?: RiskAssessment
  /**
   * Sensitive-value obfuscation algorithm version marker. Required
   * by the platform spec whenever obfuscated values (e.g. `obf:v1`) appear in
   * the event payload.
   */
  obfuscation?: string
  /** 平台规范：source 为字符串标识，推荐格式 `<project>.<component>.<version>`。 */
  source?: string
  /** 结构化采集元数据（hook/中间件/采集器名），禁止把 `source` 同时当作 object。 */
  collector?: SourceMeta
  metadata?: Record<string, unknown>

  // System / network fields
  runtime?: string
  api?: string
  /** Platform v1.0.0: full command line as a single string. */
  cmdline?: string
  /** Platform v1.0.0: resolved executable path. */
  exe?: string
  /**
   * structured argv vector — optional metadata retained for
   * fragment-variable attack replay. The canonical string form is
   * `cmdline`; the canonical executable field is `exe`.
   */
  argv?: string[]
  shell_involved?: boolean
  shell?: string
  cwd?: string
  ppid?: number
  pgid?: number
  sid?: number
  target_pid?: number
  /**
   * child process id produced by a runtime spawn.
   * NO LONGER populated on `runtime_spawn_intent` — the
   * real harness `SubprocessHandle` exposes no `pid`
   * (subprocess/src/types.ts:169-196), and the earlier
   * `{ handle, pid }` stub shape was a fabrication. Only the stdio-mirror
   * wrapper (which knows its own child pid from `child_process.spawn`)
   * still emits this field. Correlation falls back to session_id /
   * run_id / cmdline.
   */
  child_pid?: number
  /**
   * §6.2 : stdio stream identifier on `runtime_stdio_mirror`
   * events emitted by the bundled `stdio-mirror` wrapper. The wrapper
   * always emits `stream: 'meta'` as a marker event when it spawns the
   * child, then `stream: 'stdin' | 'stdout' | 'stderr'` for each captured
   * chunk. The wrapper writes its own NDJSON file (separate from the
   * `LocalNdjsonSink` stream) so this field is informational.
   */
  stream?: 'stdin' | 'stdout' | 'stderr' | 'meta'
  /**
   * §6.2 : raw chunk size in bytes (UTF-8) on
   * `runtime_stdio_mirror` events. The persisted `content` may be smaller
   * after `limitPayloadSize` truncation; `bytes` carries the pre-truncation
   * size so audit consumers can reconstruct the original stream shape.
   */
  bytes?: number
  /**
   * §6.2 : pid of the bundled stdio-mirror wrapper process.
   * Stable for the lifetime of one wrapper invocation; combined with
   * `event_id` (`${wrapper_pid}-${seq}`) it lets audit consumers re-merge
   * wrapper events with the corresponding `runtime_spawn_intent` from the
   * host plugin (different `pid`, same `child_pid`).
   */
  wrapper_pid?: number
  /**
   * §6.2 : signal that killed the child (null on normal
   * exit). Populated by the wrapper on `runtime_stdio_mirror_exit` events
   * via Node's `ChildProcess 'exit'` event. Mirrors `exit_code` semantics:
   * when the signal is non-null, `exit_code` is `128` per POSIX convention.
   */
  exit_signal?: NodeJS.Signals | null
  process_name?: string
  username?: string
  uid?: number
  gid?: number
  euid?: number
  memory_rss?: number
  process_status?: string
  create_time?: number
  open_files_count?: number
  connections_count?: number
  child_pids?: number[]
  cpu_percent?: number
  caller?: { function?: string; file?: string; line?: number; column?: number }
  risk_flags?: string[]
  /**
   * standardised `process_change.changes` shape — an
   * array of `{key, old, new}` records describing the field-level diff
   * between the previous and current snapshot.
   */
  changes?: Array<{ key: string; old?: unknown; new?: unknown }>

  // Network fields
  request_id?: string
  service?: string
  direction?: 'send' | 'recv'
  method?: string
  url?: string
  /**
   * subset of `redacted_keys` whose hits came
   * from URL query-string scanning. Operators see `query.token` /
   * `query.api_key` on the union list and can tell whether the
   * leak originated in the URL vs. the headers / params / body
   * by diffing against this list. Present on `network_http`;
   * empty array (`[]`) when nothing matched.
   */
  url_redacted_keys?: string[]
  /**
   * D4 : subset of `redacted_keys` whose hits came
   * from HTTP body redaction (JSON / form-urlencoded / raw text).
   * Entries are prefixed with `body.` so an audit row can show
   * `body.headers.authorization` (JSON path) or `body.token`
   * (form-urlencoded path) or `body.bearer_token` (raw path).
   * Present on `network_http`; empty array when nothing matched.
   */
  body_redacted_keys?: string[]
  host?: string
  code?: number
  // Structured HTTP headers, required by the platform per-type validator
  // (see event-schema/network.json anyOf branch); used for both human
  // replay and structured access.
  headers?: Record<string, string | string[]>
  body?: string
  response_body?: string
  /** : SSE stream chunk counts when folding is applied. */
  response_body_chunks_total?: number
  response_body_chunks_kept?: number
  latency_ms?: number
  request_url?: string
  domain_name?: string
  dst_port?: number
  src_ip?: string
  dst_ip?: string
  src_port?: number
  /**
   * per-pid TCP connection surface for `network_connect` /
   * `network_disconnect` events emitted by the system layer (see
   * monitor/process_monitor.py §network-capture). Optional — only present
   * on network_* events. The schema is intentionally lenient: protocol is
   * a string ('tcp' today; 'udp' reserved for a later extension), the IP
   * strings accept either dotted-decimal IPv4 or colon-hex IPv6 (the
   * MVP only parses IPv4 from /proc/net/tcp; IPv6 is a passthrough).
   *
   * `duration_ms` is reserved for future per-connection age tracking;
   * today the system layer doesn't have a stable first-seen hook for
   * network_connect, so the field is always `null` on emission.
   */
  protocol?: string
  local_ip?: string
  local_port?: number
  remote_ip?: string
  remote_port?: number
  /** DNS query domain (network_dns). */
  query?: string
  /**
   * per-connection age in milliseconds. Reserved for a
   * future first-seen hook on network_connect (today the monitor does
   * not track when a connection was first observed — diffing against
   * `_network_seen` only knows the connection appeared since the last
   * scan tick, not the connection's true age). Optional — present but
   * null on emitted network_* events.
   */
  duration_ms?: number | null

  // Asset fields
  asset_id?: string
  asset_type?: 'agent_config' | 'skill' | 'mcp_server'
  /** : stable logical identity for the asset, decoupled
   *  from its on-disk path. Lets audit dashboards group events for the
   *  SAME logical entity across rename / move / different hosts.
   *    mcp_server  : `mcp_server:<server-name>` (the JSON key in mcp.json)
   *    skill       : `skill:<skill-bundle-basename>` (e.g. `skill:web-search`)
   *    agent_config: `agent_config:<file-basename>` (e.g. `agent_config:settings.yaml`)
   *  Two events with the same `class_id` describe the same asset even
   *  when their `asset_id` / `asset_path` differ — used by SelfProtection
   * rules and the asset_change_chain grouping. */
  class_id?: string
  asset_path?: string
  content_hash?: string
  prev_hash?: string
  parsed?: unknown
  file_size?: number
  file_mtime?: number
  // `asset_package` removed — AssetCollector (the only
  // emitter) was platform-deployment-private and is gone. The marketplace
  // surface does not ZIP agent config / skill / mcp_server payloads.
  // The AssetPackage interface below is also deleted.

  // cgroup fields (Linux only, optional on process_* events)
  cgroup_path?: string
  cgroup_version?: 'v1' | 'v2'
  memory_current?: number
  memory_max?: number
  cpu_usage_usec?: number
  /** Structured cgroup stats for cgroup_snapshot events. */
  cpu?: {
    usage_nanos?: number
    user_nanos?: number
    system_nanos?: number
    cfs_period_us?: number
    cfs_quota_us?: number
    usage_percent?: number
  }

  // fs/* event fields — the fs-mapped file_read / file_write complement of
  // `path` (ApplicationCollector.onFsObserved / onFsWriteIntent).
  /** Opaque key produced by the fs backend; do not parse. */
  target_key?: string
  /** Human-readable path from `FsTarget.displayPath`. */
  target_path?: string
  /** FsVersion token — present only when observation.kind === 'present'. */
  file_version?: string
  /** 'present' = file exists at observation time; 'absent' = missing. */
  observation_kind?: 'present' | 'absent'
  /** Audit-only echo of the FsWriteIntentPayload the waterfall produced. */
  fs_write_intent?: {
    kind: 'createIfAbsent' | 'replaceIfVersion'
    version?: string
  }
  /**
   * Integrity signal on `collector_integrity` events: the local NDJSON audit
   * log was deleted or truncated between two writes, meaning an audit hole
   * exists.  The event is recorded as the next line after the tamper so the
   * platform can surface it instead of the gap being silent.
   */
  integrity?: 'file_deleted' | 'file_truncated' | 'file_replaced'
  /** Byte size of the audit log before tampering (on `collector_integrity`). */
  prev_bytes?: number
  /** : inode of the audit log before file_replaced tamper. */
  prev_inode?: number
  current_inode?: number
  // policy tamper fields (on `policy_tamper` events).
  // The intervention engine compares the policy file's hash on each reload
  // against a baseline captured at first load; a divergence means an external
  // write happened between two reloads (a hostile policy edit), so the
  // reload is rejected and a `policy_tamper` event is emitted.
  policy_path?: string
  policy_baseline_hash?: string
  policy_current_hash?: string

  // security_audit event fields.
  //'sink'sink-local degradation signalling
  // (`security_audit/sink_disk_low` + recovery). The category is plugin-side
  // vocabulary; sibling collectors do not emit it.
  //'config'config livePatch audit trail
  // (applied keys + operator on success, refused self-protection-class
  // keys on rejection).
  audit_category?: 'policy' | 'integrity' | 'runtime' | 'behavior' | 'access' | 'sink' | 'config' | 'other'
  //'modify'config livePatch successfully
  // applied 🟢 keys at runtime (paired with audit_category 'config').
  audit_action?: 'block' | 'approve' | 'warn' | 'escalate' | 'guide' | 'detect' | 'tamper' | 'allow' | 'deny' | 'modify'
  audit_details?: Record<string, unknown>
  target?: string | object
  outcome?: 'success' | 'failure' | 'blocked' | 'ignored'
  /** Human-readable explanation for audit/integrity/security_audit events. */
  reason?: string
  /**
   * `audit_category` + `audit_action` are the two fields every
   * security_audit emitter must set. `summary` is the canonical one-line
   * description and is what audit consumers display.
   * `severity` uses the 5 tiers below; the 4 tiers the governance platform
   * accepts are a subset of them.
   */
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical'
  summary?: string
}

export interface ActionRecord {
  tool: string
  params?: unknown
  result_status?: string
  timestamp?: number
}

// AssetPackage interface deleted with AssetCollector. The
// marketplace plugin does not emit ZIP asset payloads.

export interface DerivedFileOp {
  op: 'read' | 'write' | 'delete' | 'privilege' | 'create'
  path: string
  mode?: string
  source?: 'shell' | 'python' | 'node'
}

export interface ModifyAction {
  redactFields?: string[]
  substitutePatterns?: Record<string, string>
  whitelistConstraint?: Record<string, string>
  setFields?: Record<string, unknown>
}

export interface Intervention {
  // marketplace wire vocabulary (allow / deny / ask). The
  // SPL internal 10-action vocabulary is preserved on `decision_internal`
  // so audit consumers can still see what the policy actually decided;
  // the wire-level `decision` is the lossy projection emitted to NDJSON
  // and to the marketplace event channel.
  decision?: 'allow' | 'deny' | 'ask'
  /**
   * the SPL internal decision preserved for audit consumers.
   * Distinct from `decision` which is the marketplace wire-format projection.
   * See `src/utils/decisionVocabulary.ts` for the mapping.
   *
   * added `'audit'` to the union. Audit is one of the four
   * core SPL v2 spec §5.1 values (block | watch | warn | allow | audit).
   * The previous 10-action union pre-dated and omitted audit, which
   * meant DecisionComposer.composeDecision (lines 211 / 243) could not
   * assign an audit verdict to `decision_internal` without TS2322. Audit
   * rules must reach the audit stream verbatim.
   */
  decision_internal?:
    | 'allow'
    | 'warn'
    | 'audit'
    | 'guide'
    | 'context_adjust'
    | 'modify'
    | 'substitute'
    | 'escalate'
    | 'degrade'
    | 'block'
    | 'approve'
  mode?: Mode
  policy_id?: string
  policy_name?: string
  policy_version?: string
  block_reason?: string
  block_code?: string
  appealable?: boolean
  reason?: string
  latency_ms?: number
  fail_strategy?: string
  modified_params?: Record<string, unknown>
  substituted_tool_name?: string
  param_mapping?: Record<string, string>
  /** : merged `modify` action detail from all matching modify rules. */
  modify?: ModifyAction
  guidance?: Guidance
  /** `decision: 'escalate'` detail (matches the SPL `escalate` action schema). */
  escalate?: EscalateDetail
  /** `decision: 'degrade'` detail (matches the SPL `degrade` action schema). */
  degrade?: DegradeDetail
  risk_assessment?: RiskAssessment
  /**
   * rule's effective severity driving the decision. Propagated
   * from `CompiledRule.severity` (which itself comes from the YAML's
   * `severity:` field). Absent on rules that haven't been migrated yet
   * — operators can read this field in NDJSON to tell "this block came
   * from a critical rule" vs "this block came from a high rule" without
   * re-reading the policy YAML.
   */
  severity?: 'critical' | 'extreme' | 'high' | 'medium' | 'low'
  /**
   * true when the rule's authored `block` decision was
   * downgraded to `warn` by the severity seam in
   * `DecisionComposer.composeDecision`. Set ONLY when the seam
   * actually flipped the verdict. Self-protection rules never set this
   * (they bypass the downgrade entirely). Audit consumers can use this
   * field to identify "this block the rule was authored as, but the
   * engine let it through anyway" cases without diffing the policy.
   */
  severity_downgraded?: boolean
  /**
   * id of the rule that triggered the downgrade (mirrors
   * how `policy_id` carries the deciding rule). Set together with
   * `severity_downgraded: true`; absent otherwise.
   */
  severity_rule_id?: string
  /**
   * True when a non-self_protection local
   * allow/warn rule was suppressed by a self_protection rule per the
   * SPL v2 spec §9.2 arbitration contract. Set ONLY when the
   * override seam in `DecisionComposer.composeDecision` actually
   * flipped the verdict — operators can grep `agent_tool_call`
   * events for `self_protection_override: true` to see override
   * attempts without needing a dedicated event type. Pairs with
   * `overridden_rule_id` which names the suppressed local rule.
   */
  self_protection_override?: boolean
  /**
   * id of the local allow/warn rule that would have won
   * the priority sort but was suppressed by the self_protection
   * arbitration seam. Set together with
   * `self_protection_override: true`; absent otherwise.
   */
  overridden_rule_id?: string
  /**
   * advisory marker for decisions the harness does NOT
   * honor in its current contract. Set to `true` for `modify` /
   * `substitute` (the plugin emits the event with the proposed change,
   * but the caller — not the harness — is expected to apply the
   * modification). See `the decision-vocabulary spec` §3.
   */
  advisory?: boolean
  /**
   * true when the engine flipped a `context_adjust`
   * decision into `escalate` because the per-(session, policy,
   * template) GuidanceStateMachine counter crossed the rule's
   * `max_attempts` / `escalate_threshold`. Lets audit consumers tell
   * "SPL author wrote escalate" from "engine auto-promoted after
   * repeated guidance". Pairs with `escalate.guidance_ref`.
   */
  escalate_promoted?: boolean
  /**
   * §6.2 第二项: audit-only detail emitted by inline
   * safety-net guards (InlineSelfProtection / SensitivePathGuard /
   * InlinePromptInjection). Carries the matched fingerprint id, the
   * kind label, a redacted sample excerpt of the offending text, and
   * the field name where the match was found. The field is set on the
   * inline-guard decisions so audit consumers can trace exactly why a
   * tool call was blocked without re-running the matcher. Stays out of
   * the SPL `Intervention.modify` shape because the SPL vocabulary does
   * not have an "audit" action.
   */
  audit_details?: {
    matched_pattern: string
    fingerprint_kind: string
    sample_excerpt: string
    field_source: string
    pattern_description: string
  }
}

/**
 * `escalate` decision detail — paired with `decision: 'escalate'`.
 * Field names match the SPL `escalate` action schema in
 * policies/default-policy.json.
 */
export interface EscalateDetail {
  /** Server-issued id for the approval request; populated when the decision is dispatched. */
  approval_request_id?: string
  /** Route / workflow identifier for the approval system to dispatch to. */
  approval_route?: string
  /** How long the request is allowed to wait for human response, in seconds. */
  timeout_seconds?: number
  /**
   * when the engine flipped `context_adjust` → `escalate`
   * because the per-(session, policy, template) guidance counter crossed
   * `max_attempts`/`escalate_threshold`, the original `Guidance` payload
   * is mirrored here so audit consumers see both the user-facing
   * guidance text and the promotion that pulled it out of the loop.
   * Unset when the SPL rule itself declared `decision: 'escalate'`.
   */
  guidance_ref?: Guidance
}

/**
 * `degrade` decision detail — paired with `decision: 'degrade'`.
 * Field names match the SPL `degrade` action schema.
 */
export interface DegradeDetail {
  // degraded-mode semantics.
  mode: 'readonly' | 'chat_only' | 'no_external' | 'sandbox' | 'limited_tools'
  /** Tools to remove from the active agent session after the degrade trigger. */
  removed_tools?: string[]
}

export interface Guidance {
  adjustment_id?: string
  template_id?: string
  template_version?: string
  rendered?: string
  allowed_scope?: string
  alternatives?: string[]
  /** Threshold at which repeated guidance upgrades to `escalate`. */
  escalate_threshold?: number
  /**
   * Cumulative count of guidance adjustments issued within the same session
   * for the same policy — used by the GuidanceStateMachine to detect
   * repeat-after-guidance patterns (mirrors the SPL `max_attempts` field
   * semantics on the `context_adjust` action).
   */
  guidance_count?: number
  /** Upper bound on repeats before upgrade to `escalate`; mirrors `max_attempts`. */
  max_attempts?: number
}

export interface RiskAssessment {
  risk_score?: number
  risk_level?: string
  reg_level?: string
  reg_clause?: string[]
  dimensions?: Record<string, number>
  matched_policies?: string[]
  evaluation_path?: string[]
  /**
   * stamped when the composed decision was promoted by
   * multi-rule aggregation rather than by the top-priority rule's own
   * action. `'medium_aggregation'` = several medium-risk rules fired
   * together and their summed score crossed the aggregation threshold,
   * so an `allow` verdict was raised to `escalate`. Audit consumers read
   * this to explain why the emitted decision differs from the matching
   * rule's declared action. Absent when no promotion happened.
   */
  promotion?: 'medium_aggregation'
}

export interface SourceMeta {
  hook_name?: string
  middleware_name?: string
  collector_name?: string
}

export interface SessionContext {
  sessionId: string
  runId: string
  agentId?: string
  userId?: string
  userPrompt?: string
  systemPrompt?: string
  agentPlan?: string[]
  previousActions: ActionRecord[]
  /**
   * count of tool_calls in this session whose SPL decision
   * was `block`. Surfaced on agent_stop as `intervention_blocked: boolean` so
   * the platform can correlate turn-stop with policy enforcement without
   * parsing `previousActions` (which does not store the decision field).
   * Zero on a clean turn; >=1 ⇒ at least one tool was policy-denied.
   */
  blockedToolCallCount?: number
  stepIndex: number
  messageIndex: number
  agentConfig?: AgentConfig
  skills?: string[]
  tools?: string[]
  lastUserMessageAt?: number
  /**
   * Wall-clock millisecond timestamp at which the session
   * was first seen. Set lazily in `getOrCreateSession` (only on first
   * creation; subsequent rehydrations keep the original). Consumed by
   * `onAgentTurnStopping` to compute `agent_stop.duration` (the
   * `agent/turn-stopping` Cordis payload does not surface a duration).
   */
  sessionStartTs?: number
  /**
   * Keyed by `ToolExecution.callId` (stable Cordis-provided
   * identifier for the same logical invocation) — NOT by the synthetic
   * `tool_call_id`. The previous synthetic key collided under concurrent tool
   * dispatch: read:9 / read:10 / read:11 each get a unique synthetic id on
   * pre-execute, but their post-executes rebuild `buildToolCallId` with the
   * CURRENT stepIndex, so all three post-executes looked up the LAST
   * synthetic id and clobbered / lost one another. The synthetic id is
   * preserved on emitted events (backward compatible with audit consumers
   * and existing schema); only the internal map key changes.
   * tool_call_id -> block reason for tool calls that were blocked in pre-execute.
   */
  blockedCalls?: Map<string, string>
  /**
   * Keyed by `ToolExecution.callId` (see blockedCalls
   * rationale). Value carries both the synthetic `tool_call_id` (so
   * post-execute emits the same id pre-execute stamped) and the
   * wall-clock `startTime` (so duration is computed against the right
   * pre-execute, not a sibling's). Entries are removed after post-execute
   * consumes them to keep the map bounded.
   */
  pendingToolStarts?: Map<string, { toolCallId: string; startTime: number }>
}

export interface AgentConfig {
  name?: string
  provider?: string
  model?: string
  tools?: string[]
  skills?: string[]
}

/**
 * Per-element shape for the `agents` array on
 * `agent_start`. Mirrors the spec table for the ebpf-style payload.
 * `agentDir` / `config` / `skills` / `tools` are nullable because the
 * Cordis plugin does not have filesystem access to resolve them — ebpf
 * collectors can populate them from /proc.
 */
export interface AgentDescriptor {
  id: string
  name: string
  agentDir: string | null
  config: string | null
  skills: string[] | null
  tools: string[] | null
}

/** Normalized intervention context passed to the policy engine. */
export interface InterventionContext {
  actionType: string
  toolName?: string
  params?: Record<string, unknown>
  body?: string
  headers?: Record<string, string | string[]>
  riskFlags?: string[]
  sessionId?: string
  runId?: string
  agentId?: string
  /** : platform identifier for policy scope filtering. */
  platformId?: string
  /** : tenant identifier for policy scope filtering. */
  tenantId?: string
  userPrompt?: string
  agentPlan?: string[]
  previousActions?: ActionRecord[]
  userAuthzState?: 'anonymous' | 'pending' | 'granted'
  userRoles?: string[]
  /**
   * Asset-layer fields (populated by the AssetCollector when an asset event
   * flows through the intervention engine).  When `actionType` starts with
   * `asset_`, callers should set these so policy rules can match by asset
   * class and path.
   */
  assetType?: 'agent_config' | 'skill' | 'mcp_server'
  assetPath?: string
  assetId?: string
}

/** Decision returned by the intervention engine. */
export interface SecurityDecision {
  // decision vocabulary.
  //
  // added `'audit'` to the union. Audit is one of the four
  // core SPL v2 spec §5.1 values;'s decision-enum narrowing exposed
  // a stale type definition here that excluded audit. The downstream
  // shape (NDJSON event, marketplace channel, audit row) consumes this
  // field, so the type must accept what DecisionComposer.composeDecision
  // can produce. Substitute / approve / guide / context_adjust / degrade
  // remain in the union for marketplace backward compat (still in the
  // 10-event toMarketplaceDecision map); audit rules now also flow through.
  decision: 'allow' | 'warn' | 'audit' | 'guide' | 'context_adjust' | 'modify' | 'substitute' | 'escalate' | 'degrade' | 'block' | 'approve'
  risk_signal?: RiskAssessment
  reason?: string
  block_reason?: string
  block_code?: string
  appealable?: boolean
  modified_params?: Record<string, unknown>
  substituted_tool_name?: string
  param_mapping?: Record<string, string>
  guidance?: Guidance
  /** `decision: 'escalate'` detail (mirror of `intervention.escalate`). */
  escalate?: EscalateDetail
  /** `decision: 'degrade'` detail (mirror of `intervention.degrade`). */
  degrade?: DegradeDetail
  policy_id?: string
  policy_name?: string
  policy_version?: string
  latency_ms?: number
  fail_strategy?: string
  mode?: Mode
  /**
   * advisory marker for decisions the harness does NOT
   * honor in its current contract. Set to `true` for `modify` /
   * `substitute` (the plugin emits the event with the proposed change,
   * but the caller — not the harness — is expected to apply the
   * modification). See `the decision-vocabulary spec` §3.
   */
  advisory?: boolean
  /**
   * cumulative count of guidance adjustments issued for
   * the same (session, policy, template). Stamped on every `context_adjust`
   * decision (even when not escalating) so audit consumers can see how
   * many times the rule fired before flipping. After the threshold, the
   * decision becomes `escalate` and the same number appears inside
   * `escalate.guidance_ref.guidance_count`.
   */
  guidance_count?: number
  /**
   * true when the engine flipped `context_adjust` →
   * `escalate` because the GuidanceStateMachine counter crossed the
   * rule's `max_attempts` / `escalate_threshold`. Lets audit consumers
   * distinguish "SPL author wrote escalate" from "engine auto-promoted
   * after repeated guidance". Pairs with `escalate.guidance_ref`.
   */
  escalate_promoted?: boolean
  /**
   * true iff at least one
   * matched rule fired on the CANONICAL form of the input (after
   * unicode normalisation + fragment-variable / env-carrier /
   * shell-function folding) rather than on the verbatim text.
   * Tells operators when an attack used obfuscation that the rail had
   * to rewrite before matching. Mirrored on the audit side via
   * `security_audit/canonicalization_applied`.
   */
  canonicalization_applied?: boolean
  /**
   * rule's effective severity driving the decision. Mirror of
   * `Intervention.severity` for callers that flatten the decision shape
   * and don't dig into `intervention.severity` directly.
   */
  severity?: 'critical' | 'extreme' | 'high' | 'medium' | 'low'
  /**
   * true iff the rule's authored `block` was downgraded to
   * `warn` by the severity seam. Mirror of `Intervention.severity_downgraded`.
   * Self-protection rules never set this (they bypass the downgrade).
   */
  severity_downgraded?: boolean
  /**
   * id of the rule that triggered the downgrade. Mirror of
   * `Intervention.severity_rule_id`. Set together with
   * `severity_downgraded: true`; absent otherwise.
   */
  severity_rule_id?: string
  /**
   * Mirror of
   * `Intervention.self_protection_override` for callers that read the
   * flat decision shape (Cordis `ctx.on('security/decision')` etc.).
   */
  self_protection_override?: boolean
  /**
   * mirror of `Intervention.overridden_rule_id`. Set
   * together with `self_protection_override: true`; absent otherwise.
   */
  overridden_rule_id?: string
  /**
   * §6.2 第二项: mirror of `intervention.audit_details`
   * exposed at the top-level SecurityDecision for audit consumers that
   * flatten the decision shape (e.g. Cordis `ctx.on('security/decision')`
   * listeners). See `Intervention.audit_details` for the schema.
   */
  audit_details?: {
    matched_pattern: string
    fingerprint_kind: string
    sample_excerpt: string
    field_source: string
    pattern_description: string
  }
  intervention?: Intervention
}

/**
 * Policy evaluation block required by the collector-access-spec v1 wire format.
 * Derived from the event's `intervention` field and injected by EventCollector
 * before local persistence and HTTP upload.
 *
 * The platform per-type validator requires every
 * `matches[]` element AND `final_match` to carry `priority`, `risk_level`,
 * `decision`, `policy_version` (string, not number). `final_match` may no
 * longer be `null` — the `no_match` / `not_applicable` branches now point
 * to a synthetic placeholder match so the wire shape stays uniform.
 */
export interface PolicyEvaluation {
  schema_version: number
  mode: Mode
  status: 'matched' | 'no_match' | 'not_applicable'
  policy_decision: 'allow' | 'block'
  matches: PolicyEvaluationMatch[]
  /**
   * Final matched rule. The field is ALWAYS present in the wire JSON.
   * The platform's `policy-evaluation-v1.schema.json` declares
   * `final_match` in `required: [...]` for all policy_evaluation
   * objects. Schema validation runs first, so omitting the field
   * produces a 400 "required" error regardless of business rules.
   * Conditional semantics:
   *   - status=matched       → non-null PolicyEvaluationMatch
   *   - status=no_match/     → JSON null literal
   *     not_applicable
   */
  final_match: PolicyEvaluationMatch | null
}

/**
 * Platform contract (collector-access-spec wire shape): the `decision` field on
 * `policy_evaluation.matches[*]` and `policy_evaluation.final_match` is
 * restricted to the two terminal states that match `policy_decision`. The
 * richer vocabulary (modify / substitute / context_adjust / escalate /
 * degrade / warn / guide / approve) lives on `event.intervention.decision`
 * and `event.policy_evaluation.policy_decision`-adjacent fields, but not on
 * individual matches. Wider enums here cause the platform server to return
 * `enum :: const` rejections per-event-type.
 */
export type PolicyEvaluationDecision = 'allow' | 'block'

export interface PolicyEvaluationMatch {
  policy_id: string
  /** Wire format is the integer version serialised as a string. */
  policy_version: string
  rule_id: string
  /** Priority from the matched rule (or `0` for placeholder). */
  priority: number
  /** `critical` | `high` | `medium` | `low` (SPL §4.2.1). */
  risk_level: 'critical' | 'high' | 'medium' | 'low'
  /**
   * Final decision this match contributes to. Platform contract restricts
   * this to `'allow' | 'block'` (matches `policy_decision`'s enum); richer
   * decisions live on `event.intervention.decision`.
   */
  decision: PolicyEvaluationDecision
}

/**
 * Risk-level inferred from the final decision when no rule carries
 * `evaluate.risk_level` (SPL安全策略统一规范.md §4.2.1 fallback table).
 * Moved here so types/index.ts remains the single source of truth for the
 * wire-shape types while also exporting the helpers that build them.
 */
export function inferRiskLevel(decision: string): 'critical' | 'high' | 'medium' | 'low' {
  switch (decision) {
    case 'block':
    case 'escalate':
      return 'high'
    case 'degrade':
    case 'modify':
      return 'medium'
    case 'context_adjust':
    case 'substitute':
    case 'allow':
      return 'low'
    default:
      return 'low'
  }
}
