/**
 * Minimal security event schema validation.
 *
 * The per-type required-field tables below MIRROR the platform's event
 * contract (`contracts/events/schemas/<event_type>/v1.schema.json` in the
 * platform repo, itself aligned with the shared standard under
 * `project_standards/governance/event-schema/`).
 *
 * This release ships without an upload channel — events land in the local
 * NDJSON only. The table still follows the platform contract, because the
 * two failure modes show up the moment an upload channel is added, and
 * both of them lose data:
 *
 *   - STRICTER than the platform → the plugin drops an event the platform
 *     would have accepted. The data never reaches the platform at all and
 *     nothing but a local "dropped invalid event" log records it.
 *   - LOOSER than the platform → the platform rejects the WHOLE batch
 *     (`invalid_event_schema` is a batch-level error), and the SDK then
 *     rewrites the offending event to `x_bridge_<type>` so the batch can
 *     be re-sent. The data survives, but the event type is degraded and
 *     the event leaves the platform's rule catalog.
 *
 * So the rule is: required == the platform's required, no more, no less.
 */
import type { SecurityEvent } from '../../types/index.js'

export interface ValidationIssue {
  path: string
  message: string
}

/** One per-type required-field rule.
 *
 *  - a plain string means "this field must be present";
 *  - an array of strings means "at least one of these fields must be
 *    present" — the platform's `anyOf` branch (used by the process
 *    contract, which accepts `cmdline` OR `exe`).
 */
export type EventTypeRule = string | readonly string[]

const EVENT_TYPE_RULES: Record<string, EventTypeRule[]> = {
  // ---- standard platform types ------------------------------------------
  // The platform requires `agent_id` on the session-start event; the
  // correlation handles (`session_id` / `run_id` / `tool_call_id`) are
  // optional in the contract and are therefore NOT required here.
  agent_session_start: ['agent_id'],
  agent_session_end: ['session_id'],
  // the platform's start/stop lifecycle branch requires `pid`
  agent_start: ['pid'],
  agent_stop: ['pid'],
  agent_message: ['role', 'content'],
  // `tool_params` is the JSON-string carrier for tool args (the redacted
  // JSON-string the platform ingest contract keys off); ApplicationCollector
  // emits it as the canonical tool-args carrier.
  agent_tool_call: ['tool_call_id', 'tool_name', 'tool_params'],
  // `status` ∈ {success, failure, blocked, error}; `execution_status` is an
  // internal alias retained as informational only.
  agent_tool_result: ['tool_call_id', 'status'],
  // file_* class: the platform requires `path` only. `session_id` /
  // `tool_call_id` stay optional because the fs/observed → file_read |
  // file_write path (see ApplicationCollector.onFsObserved /
  // flushExpiredIntents) emits OUTSIDE the tools/pre-execute contract,
  // where no tool_call_id exists and the actor may be anonymous.
  file_read: ['path'],
  file_write: ['path'],
  file_delete: ['path'],
  file_privilege: ['path'],
  // Asset layer (AssetCollector — historical pre-marketplace reference; the
  // marketplace form removed AssetCollector entirely). The platform requires
  // the four identity fields on every asset type; `prev_hash` / `parsed` /
  // `asset_package` are optional there, so they are optional here.
  asset_add: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  asset_change: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  asset_remove: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  asset_snapshot: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  // in-process TCP connection events. Emitted by the
  // NetworkHttpCollector (`networkCapture.enabled`) when it observes a
  // socket connect. `pid` is the owning process (not the plugin's pid) and
  // is already required by common-v1. `local_ip` / `local_port` describe
  // the socket's local end and are optional in the platform contract.
  network_connect: ['protocol', 'remote_ip', 'remote_port'],
  // DNS resolution events. The platform's network_dns contract requires the
  // resolved address — see NetworkHttpCollector.emitDnsEvent, which only
  // emits the event once an address is known.
  network_dns: ['protocol', 'remote_ip', 'remote_port', 'query'],
  // application-layer HTTP request events. Emitted by
  // NetworkHttpCollector inside the harness Node process. `method`/`url`/
  // `host`/`direction`/`service` are the minimal audit handle; the
  // response fields (code/response_body/latency_ms) and `headers` are
  // optional in the platform contract.
  network_http: ['service', 'direction', 'method', 'host', 'url'],
  // the platform's process contract is `anyOf [cmdline, exe]`
  process_start: [['cmdline', 'exe']],
  process_exit: [['cmdline', 'exe']],
  // security_audit event.
  security_audit: ['audit_category', 'audit_action'],
  // ---- extension types ---------------------------------------------------
  // The platform registers these as project extension events and validates
  // them with common-v1 plus the `event_type` const only — the payload is
  // the collector's own. The legacy names below are the ingest aliases the
  // SDK canonicalises before upload, so they carry the same (empty)
  // per-type requirement.
  //
  // The runtime layer keeps the marketplace-neutral names (no vendor
  // prefix); the platform resolves them through its ingest alias table.
  // The structured `argv` vector stays optional metadata for
  // fragment-variable attack replay.
  code_mode_exec: [],
  plugin_startup: [],
  runtime_spawn_intent: [],
  runtime_spawn_denied: [],
  runtime_resolve_intent: [],
  runtime_resolve_denied: [],
  runtime_terminal_intent: [],
  runtime_hook_error: [],
  runtime_stdio_mirror: [],
  runtime_stdio_mirror_exit: [],
  runtime_stdio_mirror_error: [],
  // ---- types the platform does not know ---------------------------------
  // Unregistered extension events are accepted as-is (common-v1 only), and
  // the registered-but-schema-less ones (`process_change`,
  // `process_snapshot`, `cgroup_*`) have no per-type contract at all — so
  // the local gate has no per-type opinion on any of them.
  process_change: [],
  process_snapshot: [],
  cgroup_snapshot: [],
  cgroup_anomaly: [],
  network_disconnect: [],
}

// mirrors the platform's common-v1 required set exactly: `comm` /
// `event_id` / `event_type` / `schema_version` / `ts` / `host_id` /
// `container_id` / `pid`. `layer` is optional in the contract (the
// platform defaults it to `system`), and `schema_version` is stamped by
// LocalNdjsonSink.buildTransportEvent before validation runs.
const COMMON_REQUIRED = ['comm', 'event_id', 'event_type', 'schema_version', 'ts', 'host_id', 'container_id', 'pid']

export function validateEvent(event: unknown): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  if (!event || typeof event !== 'object') {
    issues.push({ path: '', message: 'event must be an object' })
    return issues
  }

  const e = event as Partial<SecurityEvent>

  for (const field of COMMON_REQUIRED) {
    if ((e as Record<string, unknown>)[field] === undefined) {
      issues.push({ path: field, message: `missing required field: ${field}` })
    }
  }

  // the platform common schema 允许 `comm` 为任意来源标识
  // （如任意来源标识 / sst-security-control-dsh 等），不再限定单一值。
  if (typeof e.comm !== 'string' || e.comm.length === 0) {
    issues.push({ path: 'comm', message: 'comm must be a non-empty string' })
  }

  if (e.event_type && typeof e.event_type === 'string') {
    const rules = EVENT_TYPE_RULES[e.event_type] ?? []
    for (const rule of rules) {
      if (typeof rule === 'string') {
        if ((e as Record<string, unknown>)[rule] === undefined) {
          issues.push({ path: rule, message: `missing required field for ${e.event_type}: ${rule}` })
        }
        continue
      }
      // anyOf branch — the platform accepts the event when AT LEAST ONE of
      // the alternatives is present.
      const present = rule.some((field) => (e as Record<string, unknown>)[field] !== undefined)
      if (!present) {
        const alternatives = rule.join(' | ')
        issues.push({
          path: alternatives,
          message: `missing required field for ${e.event_type}: one of ${alternatives}`,
        })
      }
    }
  }

  if (e.ts !== undefined && typeof e.ts !== 'number') {
    issues.push({ path: 'ts', message: 'ts must be a number' })
  }

  if (e.schema_version !== undefined && typeof e.schema_version !== 'number' && typeof e.schema_version !== 'string') {
    issues.push({ path: 'schema_version', message: 'schema_version must be a number or string' })
  }

  return issues
}

export function assertValidEvent(event: unknown): void {
  const issues = validateEvent(event)
  if (issues.length > 0) {
    const summary = issues.map((i) => `${i.path}: ${i.message}`).join('; ')
    throw new Error(`invalid security event: ${summary}`)
  }
}
