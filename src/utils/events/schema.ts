/**
 * Minimal security event schema validation.
 *
 * This is intentionally dependency-free.  It validates the invariant fields
 * every event must carry, plus event-type-specific required fields.
 */
import type { SecurityEvent } from '../../types/index.js'

export interface ValidationIssue {
  path: string
  message: string
}

const EVENT_TYPE_RULES: Record<string, string[]> = {
  // agent_session_start carries `agent_id` as a required field per the
  // platform event-schema spec (§agent_session_start). Every other
  // application-layer event type uses `tool_call_id` / `session_id` for
  // correlation; reference data never carries `agent_id` on those types.
  agent_session_start: ['session_id', 'agent_id'],
  agent_start: ['session_id'],
  agent_message: ['session_id', 'role', 'content'],
  // tool_params is the JSON-string carrier for tool args (the redacted
  // JSON-string the platform ingest contract keys off); ApplicationCollector
  // emits it as the canonical tool-args carrier.
  agent_tool_call: ['session_id', 'tool_call_id', 'tool_name', 'tool_params'],
  // agent_tool_result carries `status` per the spec
  // (`event-schema/agent.json` anyOf branch — `status` ∈ {success, failure,
  // blocked, error}); `execution_status` was an internal alias retained as
  // informational only.
  agent_tool_result: ['session_id', 'tool_call_id', 'status'],
  // agent_stop requires `pid` per the platform schema
  // (`event-schema/agent.json` anyOf branch — `pid` is mandatory for
  // start/stop lifecycle events).
  agent_stop: ['session_id', 'pid'],
  // file_* class: `path` + `session_id` are the mandatory correlation handle.
  // tool_call_id / tool_name are optional because the fs/observed →
  // file_read|file_write path (see ApplicationCollector.onFsObserved /
  // flushExpiredIntents) emits OUTSIDE the tools/pre-execute contract, where
  // no tool_call_id exists and the actor may be anonymous.
  file_read: ['session_id', 'path'],
  file_write: ['session_id', 'path'],
  file_delete: ['session_id', 'path'],
  file_privilege: ['session_id', 'path'],
  code_mode_exec: ['session_id', 'tool_call_id', 'tool_name'],
  // Pre-spawn RuntimeHook seam (`ctx.subprocess.spawn`). Required
  // fields mirror the platform's process-event shape: pid +
  // process_name + cmdline + exe are the minimum correlation
  // handle. session_id / run_id / agent_id / tool_call_id stay
  // optional because events may fire outside any active tool call.
  process_start: ['pid', 'process_name', 'cmdline', 'exe'],
  process_change: ['pid', 'process_name', 'cmdline', 'exe'],
  // process_exit may be name-less (pid-only monitor line for unknown actors);
  // the platform process schema only requires cmdline or exe.
  process_exit: ['pid', 'cmdline', 'exe'],
  process_snapshot: ['pid', 'process_name'],
  cgroup_snapshot: [],
  cgroup_anomaly: [],
  // Asset layer (AssetCollector — historical pre-marketplace reference; the
  // marketplace form removed AssetCollector entirely). The structured `parsed` summary
  // is preserved for post-mortem event-decoder compatibility.
  // `parsed` is required per the platform schema
  // (event-schema/asset.json — describes the structured summary of the asset).
  // `prev_hash` is mandatory on change/remove/snapshot because the platform
  // uses it to correlate version transitions.
  // asset.json requires `content_hash` on all asset types;
  // `prev_hash` is additionally required on change / remove / snapshot.
  asset_add: ['asset_id', 'asset_type', 'asset_path', 'content_hash', 'parsed', 'pid'],
  asset_change: ['asset_id', 'asset_type', 'asset_path', 'content_hash', 'prev_hash', 'parsed', 'pid'],
  asset_remove: ['asset_id', 'asset_type', 'asset_path', 'content_hash', 'prev_hash', 'parsed', 'pid'],
  asset_snapshot: ['asset_id', 'asset_type', 'asset_path', 'content_hash', 'prev_hash', 'parsed', 'pid'],
  // Runtime layer : canonical fields `cmdline`
  // (string) + `exe`. The structured `argv` vector is retained as optional
  // metadata for fragment-variable attack replay.
  // dropped `x_dsh_` prefix for marketplace neutrality —
  // runtime_spawn_intent / runtime_spawn_denied / runtime_terminal_intent
  // already emit with neutral names; the schema is realigned here.
  runtime_spawn_intent: ['cmdline', 'exe'],
  runtime_spawn_denied: ['cmdline', 'exe'],
  runtime_terminal_intent: ['cmdline', 'exe'],
  // resolveExecutable audit seam — the harness
  // resolves PATH/LLD for a command BEFORE spawn; a
  // `node_modules/.bin/<safe-name>` symlink to a malicious bin looks
  // innocent at argv layer but resolves/realpaths to the deny-list target.
  // Same required-field shape as the spawn intent/denied siblings.
  runtime_resolve_intent: ['cmdline', 'exe'],
  runtime_resolve_denied: ['cmdline', 'exe'],
  // runtime_hook_error can fire before argv is known (e.g. spec.argv was
  // undefined); keep cmdline only as before.
  runtime_hook_error: ['cmdline'],
  // §6.2 : stdio pipe mirror events. The bundled
  // `stdio-mirror` wrapper writes these directly to its own NDJSON file
  // (separate from LocalNdjsonSink) so the schema is permissive (no
  // required fields). When the host plugin routes a wrapper event back
  // through `eventCollector.report` (future), the schema entry below
  // would gate validation. Today the only consumer is the audit-side
  // re-merge on (ts, child_pid, session_id, event_id).
  runtime_stdio_mirror: [],
  runtime_stdio_mirror_exit: [],
  runtime_stdio_mirror_error: [],
  // in-process TCP connection events. Emitted by the
  // NetworkHttpCollector (`networkCapture.enabled`) when it observes a
  // socket connect. `pid` is the owning process (not the plugin's pid)
  // and `protocol` / `remote_ip`
  // / `remote_port` are the minimum correlation handle. `local_ip` /
  // `local_port` describe the socket's local end. DNS resolution
  // arrives through the collector's `patchDns` hook gated on
  // `networkCapture.captureDns`; today the marketplace form does not
  // expose `domain_name` on this event, and `duration_ms` is reserved
  // for a future first-seen hook (currently always `null` on emission).
  // network_disconnect shares the same shape so a single consumer can
  // route both event classes.
  network_connect: ['pid', 'protocol', 'local_ip', 'local_port', 'remote_ip', 'remote_port'],
  network_disconnect: ['pid', 'protocol', 'local_ip', 'local_port', 'remote_ip', 'remote_port'],
  // application-layer HTTP request events. Emitted by
  // NetworkHttpCollector inside the harness Node process. `pid` is the
  // plugin/harness process; `method`/`url`/`host`/`direction` are the
  // minimal audit handle. Response fields (code/response_body/latency_ms)
  // are optional on the error path.
  //
  // `headers` is required by the platform per-type validator
  // (see event-schema/network.json anyOf branch — `service`,
  // `direction`, `method`, `host`, `url`, `headers` are all required);
  // NetworkHttpCollector emits only the structured `headers` (object).
  network_http: ['pid', 'method', 'url', 'host', 'direction', 'service', 'headers'],
  // plugin_startup is a one-shot diagnostic emitted by apply()
  // right after the RuntimeHook install attempt, so operators can verify in
  // events.jsonl whether the seam was actually wrapped. No required
  // fields — all diagnostics live in the payload.
  plugin_startup: [],
  // security_audit event.
  security_audit: ['audit_category', 'audit_action'],
}

// aligned with the platform common schema — host_id
// container_id, and pid are mandatory on every event.
const COMMON_REQUIRED = ['comm', 'event_id', 'event_type', 'layer', 'ts', 'host_id', 'container_id', 'pid']

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
    for (const field of rules) {
      if ((e as Record<string, unknown>)[field] === undefined) {
        issues.push({ path: field, message: `missing required field for ${e.event_type}: ${field}` })
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
