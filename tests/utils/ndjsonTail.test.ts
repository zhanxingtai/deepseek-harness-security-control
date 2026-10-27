/**
 * Tests for the NDJSON tail reader.
 *
 * Coverage targets:
 *  - basic tail of last N parseable objects, newest-first
 *  - filter predicate (block-decision only)
 *  - empty / missing file → []
 *  - malformed lines are skipped without aborting the scan
 *  - partial-line write at the tail (the `appendFileSync` race) is tolerated
 *  - `fromLastBytes` hint shrinks the read window
 *  - `streamNdjson` walks the whole file in order
 */
import { appendFileSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { countNdjson, isBlockDecision, isRuleHit, streamNdjson, tailNdjson } from '../../src/utils/ndjsonTail.js'

let dir: string
let file: string

beforeEach(() => {
  dir = join(tmpdir(), `ndjson-tail-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
  mkdirSync(dir, { recursive: true })
  file = join(dir, 'events.jsonl')
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

function writeEvents(events: Array<Record<string, unknown>>): void {
  const text = events.map((e) => JSON.stringify(e)).join('\n') + (events.length ? '\n' : '')
  writeFileSync(file, text, 'utf8')
}

describe('tailNdjson', () => {
  it('returns [] for a missing file', async () => {
    expect(await tailNdjson(join(dir, 'missing.jsonl'), 10)).toEqual([])
  })

  it('returns [] for an empty file', async () => {
    writeEvents([])
    expect(await tailNdjson(file, 10)).toEqual([])
  })

  it('returns the last N parseable objects, newest first', async () => {
    const events = Array.from({ length: 25 }, (_, i) => ({
      ts: 1_000 + i,
      event_type: 'agent_tool_call',
      tool_name: `tool-${i}`,
    }))
    writeEvents(events)
    const tail = await tailNdjson(file, 5)
    expect(tail).toHaveLength(5)
    // newest-first: index 0 is the LAST written event.
    expect(tail[0]?.['tool_name']).toBe('tool-24')
    expect(tail[4]?.['tool_name']).toBe('tool-20')
  })

  it('applies the filter predicate', async () => {
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 10; i++) {
      events.push({ ts: 1_000 + i, event_type: 'agent_tool_call', intervention: { decision: i % 2 === 0 ? 'block' : 'allow' } })
    }
    writeEvents(events)
    const tail = await tailNdjson(file, 5, { filter: isBlockDecision })
    // half are block-decisions; newest-first, up to 5.
    expect(tail.length).toBeGreaterThan(0)
    for (const row of tail) {
      expect(isBlockDecision(row)).toBe(true)
    }
  })

  // 2026-09-28 regression — Policy Hits 与威胁计数对不上:初始字节窗口
  // (n*4096)按 ~4KB/事件标定,大体积事件(network_http SSE 等,实测
  // 平均 ~7KB)让窗口只覆盖文件末尾一小段,较早的命中被漏采。带
  // filter 时必须扩窗重扫直到凑满 n 条命中。
  it('grows the byte window until n filtered matches are found (large events)', async () => {
    const events: Array<Record<string, unknown>> = []
    // 40 条 ~16KB 的 filler 事件 → 初始窗口(n=10 → 40KB)只覆盖末尾 2-3 条
    const fillerBody = 'x'.repeat(16 * 1024)
    for (let i = 0; i < 40; i++) {
      events.push({ ts: 2_000 + i, event_type: 'network_http', body: fillerBody })
    }
    // 6 条命中散布在全文件:第 1 条在最前,其余穿插
    const hitAt = [0, 8, 16, 24, 32, 39]
    for (const idx of hitAt) {
      events.splice(idx, 0, {
        ts: 3_000 + idx,
        event_type: 'agent_tool_call',
        intervention: { decision: 'ask', decision_internal: 'warn' },
      })
    }
    writeEvents(events)
    const tail = await tailNdjson(file, 10, { filter: isRuleHit })
    expect(tail.length).toBe(6)
    for (const row of tail) {
      expect(isRuleHit(row)).toBe(true)
    }
    // newest-first
    const tss = tail.map((r) => r['ts'] as number)
    expect(tss).toEqual([...tss].sort((a, b) => b - a))
  })

  // 显式 fromLastBytes 的调用方(如增量 follow-up 扫描)维持单次扫描,
  // 不触发扩窗——返回窗口内的结果即可。
  it('explicit fromLastBytes keeps the single-window contract', async () => {
    const events: Array<Record<string, unknown>> = []
    const fillerBody = 'x'.repeat(16 * 1024)
    for (let i = 0; i < 40; i++) {
      events.push({ ts: 2_000 + i, event_type: 'network_http', body: fillerBody })
    }
    events.unshift({ ts: 9_999, event_type: 'agent_tool_call', intervention: { decision: 'ask', decision_internal: 'warn' } })
    writeEvents(events)
    const tail = await tailNdjson(file, 10, { filter: isRuleHit, fromLastBytes: 32 * 1024 })
    // 窗口只有 32KB,落在 filler 区;显式窗口不扩,返回空。
    expect(tail.length).toBe(0)
  })

  it('skips malformed lines without aborting the scan', async () => {
    const good1 = JSON.stringify({ ts: 1, event_type: 'agent_tool_call' })
    const good2 = JSON.stringify({ ts: 2, event_type: 'agent_tool_call' })
    const good3 = JSON.stringify({ ts: 3, event_type: 'agent_tool_call' })
    // Interleave a malformed line + a non-object JSON value.
    writeFileSync(file, [good1, '{not valid json', 'null', good2, '"a string"', good3].join('\n') + '\n', 'utf8')
    const tail = await tailNdjson(file, 10)
    expect(tail.map((r) => r['ts'])).toEqual([3, 2, 1])
  })

  it('tolerates a partial line at the tail (in-flight write)', async () => {
    // Good events + a half-written last line (the appendFileSync race).
    const good1 = JSON.stringify({ ts: 1, event_type: 'agent_tool_call' })
    const good2 = JSON.stringify({ ts: 2, event_type: 'agent_tool_call' })
    writeFileSync(file, `${good1}\n${good2}\n{"ts":3,"event_type":"agent_tool_`, 'utf8')
    const tail = await tailNdjson(file, 10)
    // The two complete lines parse; the half-written trailing line is dropped.
    expect(tail.map((r) => r['ts'])).toEqual([2, 1])
  })

  it('respects the fromLastBytes hint', async () => {
    // 100 lines, each ~80 bytes — well above the 64 KiB default scan
    // window for n=5 only when fromLastBytes is explicitly lowered.
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 100; i++) {
      events.push({ ts: 1_000 + i, event_type: 'agent_tool_call', tool_name: `tool-${String(i).padStart(4, '0')}` })
    }
    writeEvents(events)
    // 1 KiB tail window: only the last few lines are readable.
    const tail = await tailNdjson(file, 5, { fromLastBytes: 1024 })
    expect(tail.length).toBeGreaterThan(0)
    expect(tail.length).toBeLessThan(20)
    // Newest-first ordering preserved.
    if (tail.length >= 2) {
      const a = tail[0]?.['ts']
      const b = tail[tail.length - 1]?.['ts']
      expect(typeof a).toBe('number')
      expect(typeof b).toBe('number')
      expect(a!).toBeGreaterThan(b!)
    }
  })

  it('handles n=0 → [] without reading', async () => {
    writeEvents([{ ts: 1, event_type: 'x' }])
    expect(await tailNdjson(file, 0)).toEqual([])
  })

  // 2026-10-10 — Load more 真实 IO 回归: 150 条 ~7KB 事件
  // 模拟 production network_http 平均体积,分页 50/50/50 走
  // 50→100→150 必须拿到 disjoint 3 页。
  it('Load more: offset cursor paginates a 150-row log into disjoint 50-row pages', async () => {
    const fillerBody = 'x'.repeat(6 * 1024) // ~6KB payload → ~7KB per line
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 150; i++) {
      events.push({ ts: 1_700_000_000_000 + i, event_type: 'agent_tool_call', tool_name: `tool-${String(i).padStart(3, '0')}`, body: fillerBody })
    }
    writeEvents(events)
    // page 1: offset=0, limit=50 → 最新 50 条 (ts 1700000149..1700000100)
    const p1 = await tailNdjson(file, 50, { offset: 0 })
    expect(p1).toHaveLength(50)
    expect(p1[0]?.['tool_name']).toBe('tool-149')
    expect(p1[49]?.['tool_name']).toBe('tool-100')
    // page 2: offset=50, limit=50 → 接下来 50 条 (ts 1700000099..1700000050)
    const p2 = await tailNdjson(file, 50, { offset: 50 })
    expect(p2).toHaveLength(50)
    expect(p2[0]?.['tool_name']).toBe('tool-099')
    expect(p2[49]?.['tool_name']).toBe('tool-050')
    // page 3: offset=100, limit=50 → 最老 50 条 (ts 1700000049..1700000000)
    const p3 = await tailNdjson(file, 50, { offset: 100 })
    expect(p3).toHaveLength(50)
    expect(p3[0]?.['tool_name']).toBe('tool-049')
    expect(p3[49]?.['tool_name']).toBe('tool-000')
    // 三页 disjoint,合起来 = 全 150 条
    const all = [...p1, ...p2, ...p3]
    expect(all).toHaveLength(150)
    expect(new Set(all.map((r) => r['tool_name'])).size).toBe(150)
  })

  // offset 越界 → 返回空数组,客户端据此触发 end-of-results。
  it('offset beyond the file returns []', async () => {
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 80; i++) {
      events.push({ ts: 1_000 + i, event_type: 'agent_tool_call', tool_name: `t-${i}` })
    }
    writeEvents(events)
    const tail = await tailNdjson(file, 50, { offset: 80 })
    expect(tail).toEqual([])
    // 越界但 cap 内的负值 → clamped to 0
    const tail2 = await tailNdjson(file, 50, { offset: -5 })
    expect(tail2).toHaveLength(50)
    expect(tail2[0]?.['tool_name']).toBe('t-79')
  })
})

describe('countNdjson', () => {
  // 2026-10-10 — Load more "of N" total: the Events / Policy Hits
  // footer reads "Showing N of M events" — M comes from a full-file
  // filter-aware count. countNdjson streams the whole file (no
  // window) and tallies filter-passing lines.
  it('returns 0 for a missing / empty file', async () => {
    expect(await countNdjson(join(dir, 'missing.jsonl'))).toBe(0)
    writeEvents([])
    expect(await countNdjson(file)).toBe(0)
  })

  it('returns the total event count without a filter', async () => {
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 25; i++) {
      events.push({ ts: 1_000 + i, event_type: 'agent_tool_call' })
    }
    writeEvents(events)
    expect(await countNdjson(file)).toBe(25)
  })

  it('honours the filter predicate (filter-aware total)', async () => {
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 30; i++) {
      events.push({
        ts: 2_000 + i,
        event_type: 'agent_tool_call',
        intervention: { decision: i % 3 === 0 ? 'block' : 'allow' },
      })
    }
    writeEvents(events)
    // 30 events, every 3rd is a block → 10 blocks.
    expect(await countNdjson(file, isBlockDecision)).toBe(10)
  })

  it('survives malformed lines without aborting', async () => {
    writeFileSync(
      file,
      [
        JSON.stringify({ ts: 1, event_type: 'agent_tool_call' }),
        'this is not json',
        JSON.stringify({ ts: 2, event_type: 'agent_tool_call' }),
      ].join('\n') + '\n',
      'utf8',
    )
    expect(await countNdjson(file)).toBe(2)
  })
})

describe('streamNdjson', () => {
  it('walks every parseable object in file order', async () => {
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 5; i++) events.push({ ts: i, event_type: 'agent_tool_call', seq: i })
    writeEvents(events)
    const collected: number[] = []
    for await (const obj of streamNdjson(file)) {
      collected.push(obj['seq'] as number)
    }
    expect(collected).toEqual([0, 1, 2, 3, 4])
  })

  it('skips malformed lines', async () => {
    writeFileSync(file, `{"ts":1}\nnot json\n{"ts":2}\n`, 'utf8')
    const out: number[] = []
    for await (const obj of streamNdjson(file)) {
      out.push(obj['ts'] as number)
    }
    expect(out).toEqual([1, 2])
  })

  it('applies the filter predicate', async () => {
    const events: Array<Record<string, unknown>> = []
    for (let i = 0; i < 6; i++) {
      events.push({ ts: i, event_type: 'agent_tool_call', intervention: { decision: i % 2 === 0 ? 'block' : 'allow' } })
    }
    writeEvents(events)
    const out: unknown[] = []
    for await (const obj of streamNdjson(file, { filter: isBlockDecision })) {
      out.push(obj)
    }
    expect(out.length).toBe(3) // even i: 0, 2, 4
  })

  it('yields nothing for a missing file', async () => {
    const out: unknown[] = []
    for await (const obj of streamNdjson(join(dir, 'missing.jsonl'))) {
      out.push(obj)
    }
    expect(out).toEqual([])
  })
})

describe('isBlockDecision', () => {
  it('matches agent_tool_call + intervention.decision === block', () => {
    expect(isBlockDecision({ event_type: 'agent_tool_call', intervention: { decision: 'block' } })).toBe(true)
  })

  it('matches the marketplace deny vocabulary', () => {
    expect(isBlockDecision({ event_type: 'agent_tool_call', intervention: { decision: 'deny' } })).toBe(true)
  })

  it('prefers decision_internal over decision', () => {
    expect(
      isBlockDecision({
        event_type: 'agent_tool_call',
        intervention: { decision: 'deny', decision_internal: 'allow' },
      }),
    ).toBe(false)
    expect(
      isBlockDecision({
        event_type: 'agent_tool_call',
        intervention: { decision: 'allow', decision_internal: 'block' },
      }),
    ).toBe(true)
  })

  // 2026-10-12 — 纯决策谓词,与 event_type 解耦:任何层面的 block/deny
  // 决策(工具层 / 子进程层 / 消息层)都计入已拦截;无 intervention 的事件
  // (含 security_audit 的 blocked:true 审计行)仍被排除。
  it('matches block decisions on ANY event type (决策口径,不看 event_type)', () => {
    expect(isBlockDecision({ event_type: 'agent_tool_call', intervention: { decision: 'block' } })).toBe(true)
    // 消息层拦截(agent_message,blocked 标记但消息照送)——决策仍算拦截。
    expect(isBlockDecision({ event_type: 'agent_message', intervention: { decision: 'deny', decision_internal: 'block' } })).toBe(true)
    // 子进程层拦截(runtime_spawn_denied)。
    expect(isBlockDecision({ event_type: 'runtime_spawn_denied', intervention: { decision: 'deny', decision_internal: 'block' } })).toBe(true)
    // 无 intervention 的 security_audit(如 SelfProtectionGuard 审计行,
    // 顶层 blocked:true 但没有 intervention 块)——不计入。
    expect(isBlockDecision({ event_type: 'security_audit', blocked: true, audit_action: 'block', severity: 'high' })).toBe(false)
    expect(isBlockDecision({ event_type: 'agent_start' })).toBe(false)
  })

  it('rejects events without an intervention', () => {
    expect(isBlockDecision({ event_type: 'agent_tool_call' })).toBe(false)
  })

  it('rejects allow / non-blocking decisions', () => {
    expect(isBlockDecision({ event_type: 'agent_tool_call', intervention: { decision: 'allow' } })).toBe(false)
    expect(isBlockDecision({ event_type: 'agent_tool_call', intervention: { decision: 'warn' } })).toBe(false)
  })
})

// 2026-09-28 — 威胁事件口径(规则命中含 warn 标记未拦截;拦截是其子集)。
describe('isRuleHit', () => {
  it('matches warn-marked tool calls (命中 warn 级规则、标记未拦截)', () => {
    expect(
      isRuleHit({ event_type: 'agent_tool_call', intervention: { decision: 'ask', decision_internal: 'warn' } }),
    ).toBe(true)
  })

  it('matches blocks as well (threat ⊇ blocked)', () => {
    expect(isRuleHit({ event_type: 'agent_tool_call', intervention: { decision: 'deny', decision_internal: 'block' } })).toBe(true)
    expect(isRuleHit({ event_type: 'agent_tool_call', intervention: { decision: 'deny' } })).toBe(true)
  })

  it('matches runtime-layer hits (spawn_intent / spawn_denied)', () => {
    expect(
      isRuleHit({ event_type: 'runtime_spawn_intent', intervention: { decision: 'ask', decision_internal: 'warn' } }),
    ).toBe(true)
    expect(
      isRuleHit({ event_type: 'runtime_spawn_denied', intervention: { decision: 'deny', decision_internal: 'block' } }),
    ).toBe(true)
  })

  it('prefers decision_internal over decision', () => {
    expect(
      isRuleHit({ event_type: 'agent_tool_call', intervention: { decision: 'ask', decision_internal: 'allow' } }),
    ).toBe(false)
  })

  it('rejects allow decisions, non-evaluated event types, and missing intervention', () => {
    expect(isRuleHit({ event_type: 'agent_tool_call', intervention: { decision: 'allow' } })).toBe(false)
    expect(isRuleHit({ event_type: 'runtime_resolve_intent', intervention: { decision: 'allow' } })).toBe(false)
    expect(isRuleHit({ event_type: 'network_http' })).toBe(false)
    expect(isRuleHit({ event_type: 'agent_tool_call' })).toBe(false)
  })

  // 2026-10-12 — 纯决策谓词:消息层(agent_message)命中同样计入威胁。
  it('matches message-layer hits (agent_message 决策口径)', () => {
    expect(
      isRuleHit({ event_type: 'agent_message', intervention: { decision: 'deny', decision_internal: 'block' } }),
    ).toBe(true)
    expect(
      isRuleHit({ event_type: 'agent_message', intervention: { decision: 'ask', decision_internal: 'warn' } }),
    ).toBe(true)
    expect(isRuleHit({ event_type: 'agent_message', intervention: { decision: 'allow' } })).toBe(false)
  })

  // 2026-10-12 (rev 2) — 审计发现档:severity ∈ {medium, high, critical}
  // 的 security_audit 计入威胁(前端"风险"档);info/low(reload committed /
  // heartbeat 等生命周期审计)不计入,避免重载噪音淹没威胁统计。
  it('audit tier: security_audit counts by severity tier (审计发现档)', () => {
    // medium+ 计入——与事件页"风险"徽标同档。
    expect(
      isRuleHit({ event_type: 'security_audit', audit_category: 'policy', audit_action: 'tamper', severity: 'critical' }),
    ).toBe(true)
    expect(
      isRuleHit({ event_type: 'security_audit', audit_category: 'policy', audit_action: 'tamper', severity: 'high' }),
    ).toBe(true)
    expect(
      isRuleHit({ event_type: 'security_audit', audit_category: 'policy', audit_action: 'reload_failed', severity: 'medium' }),
    ).toBe(true)
    // 非 policy 类别的中高危发现(integrity detect 等)同样计入。
    expect(
      isRuleHit({ event_type: 'security_audit', audit_category: 'integrity', audit_action: 'detect', severity: 'high' }),
    ).toBe(true)
    // info/low 生命周期审计(reload committed / heartbeat)不计入。
    expect(
      isRuleHit({ event_type: 'security_audit', audit_category: 'policy', audit_action: 'reload_committed', severity: 'low' }),
    ).toBe(false)
    expect(
      isRuleHit({ event_type: 'security_audit', audit_category: 'policy', audit_action: 'reload_heartbeat', severity: 'info' }),
    ).toBe(false)
    // 无 severity 的 security_audit 也不计入。
    expect(isRuleHit({ event_type: 'security_audit', audit_category: 'policy' })).toBe(false)
  })
})

describe('concurrent append during read', () => {
  it('tolerates appendFileSync happening after streamNdjson starts', async () => {
    // Seed a few events.
    const seed: Array<Record<string, unknown>> = []
    for (let i = 0; i < 5; i++) seed.push({ ts: i, event_type: 'agent_tool_call', seq: i })
    writeEvents(seed)

    // Append 3 more lines AFTER the readline stream is open. This
    // simulates the plugin's `appendFileSync` racing with the reader.
    const out: number[] = []
    const consumer = (async () => {
      for await (const obj of streamNdjson(file)) {
        out.push(obj['seq'] as number)
        if (out.length === 5) {
          // First batch consumed; append more before draining.
          appendFileSync(file, JSON.stringify({ ts: 5, event_type: 'agent_tool_call', seq: 5 }) + '\n', 'utf8')
          appendFileSync(file, JSON.stringify({ ts: 6, event_type: 'agent_tool_call', seq: 6 }) + '\n', 'utf8')
          appendFileSync(file, JSON.stringify({ ts: 7, event_type: 'agent_tool_call', seq: 7 }) + '\n', 'utf8')
        }
      }
    })()
    await consumer
    expect(out).toContain(0)
    expect(out).toContain(4)
    // The appended lines may or may not be visible — what we care about
    // is that the reader did NOT throw on the in-flight writes. The
    // exact visibility depends on whether the OS-level read of the
    // tail chunk happened before or after the append landed.
    expect(out.length).toBeGreaterThanOrEqual(5)
  })
})
