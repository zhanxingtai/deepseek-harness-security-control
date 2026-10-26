import { describe, expect, it } from 'vitest'
import { validateEvent, assertValidEvent } from '../src/utils/schema.js'

// the platform common schema (common-v1) requires comm / event_id /
// event_type / schema_version / ts / host_id / container_id / pid.
// `layer` is optional there — the platform defaults it to `system`.
const baseCommon = { host_id: 'host', container_id: 'host', pid: 1, schema_version: 1 }

/**
 * The per-type required sets of the platform's event contract
 * (contracts/events/schemas/<event_type>/v1.schema.json). The local gate
 * must mirror them EXACTLY: a stricter local gate drops events the
 * platform would have accepted, a looser one makes the platform reject the
 * whole batch and the SDK degrade the event to `x_bridge_<type>`.
 *
 * This table is the regression guard for that alignment.
 */
const PLATFORM_REQUIRED: Record<string, string[]> = {
  agent_session_start: ['agent_id'],
  agent_session_end: ['session_id'],
  agent_start: ['pid'],
  agent_stop: ['pid'],
  agent_message: ['role', 'content'],
  agent_tool_call: ['tool_call_id', 'tool_name', 'tool_params'],
  agent_tool_result: ['tool_call_id', 'status'],
  file_read: ['path'],
  file_write: ['path'],
  file_delete: ['path'],
  file_privilege: ['path'],
  asset_add: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  asset_change: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  asset_remove: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  asset_snapshot: ['asset_id', 'asset_type', 'asset_path', 'content_hash'],
  network_connect: ['protocol', 'remote_ip', 'remote_port'],
  network_dns: ['protocol', 'remote_ip', 'remote_port', 'query'],
  network_http: ['service', 'direction', 'method', 'host', 'url'],
  security_audit: ['audit_category', 'audit_action'],
  // the DSH extension types are validated by common-v1 + the event_type
  // const only — the payload is the collector's own
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
}

/** A payload that satisfies every per-type requirement of the table above. */
function payloadFor(eventType: string): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    agent_id: 'a1',
    session_id: 's1',
    pid: 4321,
    role: 'user',
    content: 'hello',
    tool_call_id: 'tc1',
    tool_name: 'bash',
    tool_params: '{"command":"ls"}',
    status: 'success',
    path: '/tmp/x.txt',
    asset_id: 'host:agent_config:/path',
    asset_type: 'agent_config',
    asset_path: '/path',
    content_hash: 'abc',
    protocol: 'udp',
    remote_ip: '10.0.0.1',
    remote_port: 53,
    query: 'example.com',
    service: 'https',
    direction: 'send',
    method: 'POST',
    host: 'example.com',
    url: '/api',
    audit_category: 'policy',
    audit_action: 'block',
  }
  const required = PLATFORM_REQUIRED[eventType] ?? []
  const out: Record<string, unknown> = {}
  for (const field of required) out[field] = payload[field]
  return out
}

describe('Event schema validation', () => {
  it('accepts a valid agent_session_start event', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-1',
      event_type: 'agent_session_start',
      layer: 'application',
      ts: 1,
      session_id: 's1',
      agent_id: 'a1',
    })
    expect(issues).toEqual([])
  })

  it('rejects missing common fields', () => {
    const issues = validateEvent({
      event_id: 'evt-1',
      event_type: 'agent_session_start',
      layer: 'application',
      ts: 1,
    } as any)
    const paths = issues.map((i) => i.path)
    expect(paths).toContain('comm')
    expect(paths).toContain('host_id')
    expect(paths).toContain('container_id')
    expect(paths).toContain('pid')
    expect(paths).toContain('schema_version')
    expect(paths).toContain('agent_id')
  })

  it('accepts an event without `layer` (optional in the platform contract)', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-1',
      event_type: 'agent_session_start',
      ts: 1,
      agent_id: 'a1',
    })
    expect(issues).toEqual([])
  })

  it('rejects non-string comm value', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 123 as any,
      event_id: 'evt-1',
      event_type: 'agent_session_start',
      layer: 'application',
      ts: 1,
      session_id: 's1',
      agent_id: 'a1',
    })
    expect(issues.some((i) => i.path === 'comm')).toBe(true)
  })

  it('accepts platform `comm` identifiers', () => {
    for (const comm of ['sst-security-control-dsh', 'other-agent-plugin']) {
      const issues = validateEvent({
        ...baseCommon,
        comm,
        event_id: 'evt-1',
        event_type: 'agent_session_start',
        layer: 'application',
        ts: 1,
        session_id: 's1',
        agent_id: 'a1',
      })
      expect(issues).toEqual([])
    }
  })

  it('rejects non-number ts', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-1',
      event_type: 'agent_session_start',
      layer: 'application',
      ts: 'now',
      session_id: 's1',
      agent_id: 'a1',
    } as any)
    expect(issues.some((i) => i.path === 'ts')).toBe(true)
  })

  it('accepts a valid agent_tool_call event', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-2',
      event_type: 'agent_tool_call',
      layer: 'application',
      ts: 2,
      session_id: 's1',
      agent_id: 'a1',
      tool_call_id: 'tc1',
      tool_name: 'bash',
      tool_params: '{"command":"ls"}',
    })
    expect(issues).toEqual([])
  })

  it('throws on assertValidEvent', () => {
    expect(() => assertValidEvent({})).toThrow(/invalid security event/)
  })

  it('accepts a valid network_http event', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-nh',
      event_type: 'network_http',
      //'layer'is the 3-tier spec enum; the
      // fine-grain 'network' tag moves to `source_layer`.
      layer: 'application',
      source_layer: 'network',
      ts: 4,
      pid: 1234,
      method: 'POST',
      url: '/api',
      host: 'example.com',
      direction: 'send',
      // the platform's network_http contract requires
      // service / direction / method / host / url — `headers` is
      // optional there and therefore optional here.
      service: 'https',
      headers: { Host: 'example.com' },
    })
    expect(issues).toEqual([])
  })

  it('rejects a network_http event missing direction', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-nh',
      event_type: 'network_http',
      layer: 'application',
      source_layer: 'network',
      ts: 4,
      pid: 1234,
      method: 'POST',
      url: '/api',
      host: 'example.com',
    } as any)
    expect(issues.some((i) => i.path === 'direction' && /network_http/.test(i.message))).toBe(true)
  })

  // —— DNS events ——
  // The platform's network_dns contract requires the resolved address
  // (`remote_ip`). The collector only emits the event once an address is
  // known, so the two sides agree.
  it('accepts a valid network_dns event', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-dns',
      event_type: 'network_dns',
      layer: 'application',
      source_layer: 'network',
      ts: 4,
      pid: 1234,
      protocol: 'udp',
      remote_ip: '10.0.0.53',
      remote_port: 53,
      service: 'dns',
      query: 'example.com',
    })
    expect(issues).toEqual([])
  })

  it('rejects a network_dns event missing remote_ip', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-dns',
      event_type: 'network_dns',
      layer: 'application',
      source_layer: 'network',
      ts: 4,
      pid: 1234,
      protocol: 'udp',
      remote_port: 53,
      service: 'dns',
      query: 'example.com',
    } as any)
    expect(issues.some((i) => i.path === 'remote_ip' && /network_dns/.test(i.message))).toBe(true)
  })

  // —— Asset-layer event coverage (Phase 5, M1) ——
  // Required-field table per the platform event-schemaasset.json:
  //   asset_add / asset_change / asset_remove / asset_snapshot:
  //     asset_id, asset_type, asset_path, content_hash
  // `prev_hash` / `parsed` are optional in the platform contract, so the
  // local gate must not require them (a stricter local gate would drop
  // events the platform would have accepted).
  // file_* events map onto the platform file classes; tool_call_id is
  // optional because the fs/observed → file_read|file_write path emits
  // OUTSIDE the tools/pre-execute contract (2026-08-17 alignment).
  it('accepts a file_write event without tool_call_id (fs-mapped path)', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-f',
      event_type: 'file_write',
      layer: 'application',
      ts: 3,
      session_id: 's1',
      path: '/tmp/x.txt',
    })
    expect(issues).toEqual([])
  })

  it('rejects a file_write event without path', () => {
    const issues = validateEvent({
      ...baseCommon,
      comm: 'sst-security-control-dsh',
      event_id: 'evt-f',
      event_type: 'file_write',
      layer: 'application',
      ts: 3,
      session_id: 's1',
    } as any)
    expect(issues.some((i) => i.path === 'path' && /file_write/.test(i.message))).toBe(true)
  })

  describe('asset_* events', () => {
    function baseAsset() {
      return {
        ...baseCommon,
        comm: 'sst-security-control-dsh',
        event_id: 'evt-a',
        layer: 'asset',
        ts: 1700000000000,
        // Spec §资产上报事件: `pid` is required on every asset event; the
        // collector always stamps its own process.pid (2026-08-17).
        pid: 1234,
      }
    }

    it('accepts a valid asset_add event', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_add',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'abc',
        parsed: { file_name: 'settings.yaml', format: 'yaml', keys: [] },
      })
      expect(issues).toEqual([])
    })

    it('accepts a valid asset_change event', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_change',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'new',
        prev_hash: 'old',
        parsed: { file_name: 'settings.yaml', format: 'yaml', keys: [] },
      })
      expect(issues).toEqual([])
    })

    it('accepts asset_change without prev_hash (optional in the platform contract)', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_change',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'new',
      } as any)
      expect(issues).toEqual([])
    })

    it('rejects asset_add without pid (2026-08-17)', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_add',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'abc',
        pid: undefined,
      } as any)
      expect(issues.some((i) => i.path === 'pid')).toBe(true)
    })

    it('rejects asset_remove without content_hash', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_remove',
        asset_id: 'host:skill:/path',
        asset_type: 'skill',
        asset_path: '/path',
        prev_hash: 'last',
      } as any)
      expect(issues.some((i) => i.path === 'content_hash' && /asset_remove/.test(i.message))).toBe(true)
    })

    it('rejects asset_snapshot missing content_hash', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_snapshot',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        // content_hash missing
        prev_hash: 'old',
      } as any)
      expect(issues.some((i) => i.path === 'content_hash')).toBe(true)
    })

    it('accepts asset events without optional fields (asset_package, file_size, file_mtime)', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_add',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'abc',
        parsed: { file_name: 'settings.yaml', format: 'yaml', keys: [] },
      })
      expect(issues).toEqual([])
    })

    it('accepts asset_add without parsed (optional in the platform contract)', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_add',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'abc',
      } as any)
      expect(issues).toEqual([])
    })

    it('rejects asset event with non-string comm value', () => {
      const issues = validateEvent({
        ...baseCommon,
        comm: 123 as any,
        event_id: 'evt-a',
        event_type: 'asset_add',
        layer: 'asset',
        ts: 1,
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'abc',
        parsed: { file_name: 'settings.yaml', format: 'yaml', keys: [] },
      } as any)
      expect(issues.some((i) => i.path === 'comm')).toBe(true)
    })

    it('rejects asset event with unknown asset_type', () => {
      // We intentionally do not constrain asset_type to the literal union
      // at the schema-validator level — the type union in src/types/index.ts
      // is the source of truth.  The validator must accept any string
      // and let downstream consumers decide.
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_add',
        asset_id: 'host:future_kind:/path',
        asset_type: 'future_kind' as any,
        asset_path: '/path',
        content_hash: 'abc',
        parsed: { file_name: 'settings.yaml', format: 'yaml', keys: [] },
      })
      expect(issues).toEqual([])
    })
  })

  // Runtime Hook events (standardized names) —
  // The platform registers these as `x_dsh_runtime_*` and validates them
  // with common-v1 + the event_type const only. The collector's own
  // payload (cmdline / exe / argv / cwd) is free-form, so the local gate
  // must NOT require it — a stricter local gate would drop events the
  // platform would have accepted.
  describe('runtime_* events', () => {
    function baseRuntime(overrides: Record<string, unknown> = {}) {
      return {
        ...baseCommon,
        comm: 'sst-security-control-dsh',
        event_id: 'evt-r',
        //'layer'is the 3-tier spec enum; the
        // pre-spawn seam tag 'runtime' moves to `source_layer`.
        layer: 'application',
        source_layer: 'runtime',
        ts: 1700000000000,
        pid: 4321,
        cmdline: 'bash -c echo hi',
        exe: 'bash',
        argv: ['bash', '-c', 'echo hi'],
        ...overrides,
      }
    }

    it('accepts a valid runtime_spawn_intent', () => {
      const issues = validateEvent({
        ...baseRuntime(),
        event_type: 'runtime_spawn_intent',
      })
      expect(issues).toEqual([])
    })

    it('accepts a valid runtime_spawn_denied', () => {
      const issues = validateEvent({
        ...baseRuntime(),
        event_type: 'runtime_spawn_denied',
        blocked: true,
      })
      expect(issues).toEqual([])
    })

    it('accepts a valid runtime_terminal_intent', () => {
      const issues = validateEvent({
        ...baseRuntime(),
        event_type: 'runtime_terminal_intent',
      })
      expect(issues).toEqual([])
    })

    it('accepts runtime_spawn_intent without cmdline / exe (collector-owned payload)', () => {
      const evt = baseRuntime({ cmdline: undefined, exe: undefined, argv: undefined }) as any
      const issues = validateEvent({ ...evt, event_type: 'runtime_spawn_intent' })
      expect(issues).toEqual([])
    })

    it('runtime_hook_error does NOT require argv (can fire before argv is known)', () => {
      const evt = baseRuntime({ argv: undefined, exe: undefined }) as any
      const issues = validateEvent({ ...evt, event_type: 'runtime_hook_error' })
      // argv/exe missing is fine for hook_error; the platform contract
      // does not constrain the collector's payload at all.
      expect(issues.some((i) => i.path === 'argv')).toBe(false)
      expect(issues.some((i) => i.path === 'exe')).toBe(false)
    })

    it('runtime_* events carry task_id / turn_id', () => {
      const issues = validateEvent({
        ...baseRuntime({ task_id: 'task-1', turn_id: 'turn-7' }),
        event_type: 'runtime_spawn_intent',
      })
      expect(issues).toEqual([])
    })

    // §6.2 : stdio pipe mirror emits three
    // event types directly to its own NDJSON file. The schema is
    // permissive (no required fields beyond the COMMON_REQUIRED set)
    // because the wrapper writes them outside LocalNdjsonSink's
    // validation path — see utils/schema.ts:90-92 comment.
    it('accepts runtime_stdio_mirror with no extra required fields', () => {
      const evt = baseRuntime()
      const issues = validateEvent({ ...evt, event_type: 'runtime_stdio_mirror' })
      expect(issues).toEqual([])
    })

    it('accepts runtime_stdio_mirror_exit with no extra required fields', () => {
      const evt = baseRuntime()
      const issues = validateEvent({ ...evt, event_type: 'runtime_stdio_mirror_exit' })
      expect(issues).toEqual([])
    })

    it('accepts runtime_stdio_mirror_error with no extra required fields', () => {
      const evt = baseRuntime()
      const issues = validateEvent({ ...evt, event_type: 'runtime_stdio_mirror_error' })
      expect(issues).toEqual([])
    })
  })

  // —— process_* : the platform contract is `anyOf [cmdline, exe]` ——
  describe('process_* events', () => {
    function baseProcess(overrides: Record<string, unknown> = {}) {
      return {
        ...baseCommon,
        comm: 'sst-security-control-dsh',
        event_id: 'evt-p',
        layer: 'system',
        ts: 1700000000000,
        pid: 4321,
        ...overrides,
      }
    }

    it('accepts process_start with cmdline only', () => {
      const issues = validateEvent({
        ...baseProcess({ cmdline: 'bash -c echo hi' }),
        event_type: 'process_start',
      })
      expect(issues).toEqual([])
    })

    it('accepts process_start with exe only', () => {
      const issues = validateEvent({
        ...baseProcess({ exe: 'bash' }),
        event_type: 'process_start',
      })
      expect(issues).toEqual([])
    })

    it('rejects process_start with neither cmdline nor exe', () => {
      const issues = validateEvent({
        ...baseProcess(),
        event_type: 'process_start',
      } as any)
      expect(issues.some((i) => /cmdline \| exe/.test(i.message))).toBe(true)
    })
  })

  // —— the local gate mirrors the platform's per-type required sets ——
  it('requires exactly the platform contract fields for every known type', () => {
    for (const [eventType, required] of Object.entries(PLATFORM_REQUIRED)) {
      const full = {
        ...baseCommon,
        comm: 'sst-security-control-dsh',
        event_id: `evt-${eventType}`,
        event_type: eventType,
        ts: 1,
        ...payloadFor(eventType),
      }
      // 1. the minimal compliant event passes
      const minimal = validateEvent(full)
      expect(minimal, `${eventType} minimal payload`).toEqual([])

      // 2. dropping any required field is caught locally, before the
      //    platform would reject the whole batch
      for (const field of required) {
        const broken: Record<string, unknown> = { ...full }
        delete broken[field]
        const issues = validateEvent(broken)
        expect(
          issues.some((i) => i.path === field),
          `${eventType} must require ${field}`,
        ).toBe(true)
      }
    }
  })
})
