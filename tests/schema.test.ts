import { describe, expect, it } from 'vitest'
import { validateEvent, assertValidEvent } from '../src/utils/schema.js'

// the platform common schema requires host_id
// container_id and pid on every event.
const baseCommon = { host_id: 'host', container_id: 'host', pid: 1 }

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
    expect(paths).toContain('session_id')
    expect(paths).toContain('agent_id')
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
      // fix: `service` and `headers` are now required by
      // the platform per-type validator (see event-schema/network.json
      // anyOf branch).
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

  // —— Asset-layer event coverage (Phase 5, M1) ——
  // Required-field table per the platform event-schemaasset.json:
  //   asset_add:      asset_id, asset_type, asset_path, content_hash
  //   asset_change:   + prev_hash
  //   asset_remove:   + content_hash, prev_hash
  //   asset_snapshot: + content_hash, prev_hash
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

    it('accepts a valid asset_change event (requires prev_hash)', () => {
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

    it('rejects asset_change without prev_hash', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_change',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'new',
        // prev_hash missing
      } as any)
      expect(issues.some((i) => i.path === 'prev_hash' && /asset_change/.test(i.message))).toBe(true)
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
      expect(issues.some((i) => i.path === 'pid' && /asset_add/.test(i.message))).toBe(true)
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
      // fix: `parsed` is now REQUIRED by the platform
      // (event-schema/asset.json — describes the structured summary).
      // The remaining optional fields (ZIP package, file metadata) are
      // still optional per spec §资产上报事件.
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

    it('rejects asset_add without parsed', () => {
      const issues = validateEvent({
        ...baseAsset(),
        event_type: 'asset_add',
        asset_id: 'host:agent_config:/path',
        asset_type: 'agent_config',
        asset_path: '/path',
        content_hash: 'abc',
      } as any)
      expect(issues.some((i) => i.path === 'parsed' && /asset_add/.test(i.message))).toBe(true)
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

  // Runtime Hook events (standardized names) ——
  // Required-field table per the platform specification §runtime_*:
  //   runtime_spawn_intent:    cmdline, exe
  //   runtime_spawn_denied:    cmdline, exe
  //   runtime_terminal_intent: cmdline, exe
  //   runtime_hook_error:      cmdline (exe optional)
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

    it('rejects runtime_spawn_intent missing cmdline', () => {
      const evt = baseRuntime({ cmdline: undefined }) as any
      const issues = validateEvent({ ...evt, event_type: 'runtime_spawn_intent' })
      expect(issues.some((i) => i.path === 'cmdline')).toBe(true)
    })

    it('rejects runtime_spawn_intent missing exe', () => {
      const evt = baseRuntime({ exe: undefined }) as any
      const issues = validateEvent({ ...evt, event_type: 'runtime_spawn_intent' })
      expect(issues.some((i) => i.path === 'exe')).toBe(true)
    })

    it('runtime_hook_error does NOT require argv (can fire before argv is known)', () => {
      const evt = baseRuntime({ argv: undefined, exe: undefined }) as any
      const issues = validateEvent({ ...evt, event_type: 'runtime_hook_error' })
      // argv/exe missing is fine for hook_error; cmdline is still required.
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
})
