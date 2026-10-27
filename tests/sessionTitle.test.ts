/** Session-title collection: the plugin subscribes to the host harness's
 *  `session/title` event (assigned on first user message, then LLM rename
 *  and user rename — last-wins) and stamps the title onto the session's
 *  subsequent events as the optional `session_title` field.
 */
import { describe, expect, it } from 'vitest'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizeConfig } from '../src/config.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../src/collectors/ApplicationCollector.js'
import type { Agent } from '../src/types/external.js'

function makeAgent(sessionId = 'session-title-1'): Agent {
  return {
    id: sessionId,
    session: { header: { id: sessionId } },
    options: { provider: 'test', model: 'test-model' },
  } as unknown as Agent
}

function readEvents(outputPath: string): Array<Record<string, unknown>> {
  return readFileSync(outputPath, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
}

describe('session_title collection', () => {
  it('stamps session_title on events emitted after the host assigns a title', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-session-title-'))
    const config = normalizeConfig({
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl') },
    })
    const sink = new LocalNdjsonSink(config)
    const app = new ApplicationCollector(config, sink)
    sink.initialize()
    app.initialize()
    try {
      const agent = makeAgent()
      // 1. Session start fires BEFORE any title exists — no field at all.
      app.onAgentSessionStart({ agent, source: 'test-source' })
      // 2. Host appends session/title (fallback on the first user message).
      app.onSessionTitleEvent({ header: { id: 'session-title-1' } }, { type: 'session/title', data: { title: 'fix the auth bug' } })
      // 3. Host renames (LLM provider title) — last-wins on the host side,
      //    so the plugin sees another session/title emission.
      app.onSessionTitleEvent({ header: { id: 'session-title-1' } }, { type: 'session/title', data: { title: 'Auth token refresh fix', source: { kind: 'provider' } } })
      // 4. Re-entry on the same session (resume / rehydration) emits events
      //    that must carry the LATEST title.
      app.onAgentSessionStart({ agent, source: 'test-source' })
    } finally {
      app.shutdown()
      sink.shutdown()
    }

    const rows = readEvents(config.collector.localOutputPath)
    const sessionStarts = rows.filter((row) => row['event_type'] === 'agent_session_start')
    expect(sessionStarts.length).toBeGreaterThanOrEqual(2)
    // First session_start predates the title → field absent, not empty.
    expect('session_title' in sessionStarts[0]).toBe(false)
    // Later session_start events carry the latest title.
    const later = sessionStarts[sessionStarts.length - 1]
    expect(later['session_title']).toBe('Auth token refresh fix')
  })

  it('ignores non-title session events, malformed sessions, and empty titles', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-session-title-'))
    const config = normalizeConfig({
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl') },
    })
    const sink = new LocalNdjsonSink(config)
    const app = new ApplicationCollector(config, sink)
    sink.initialize()
    app.initialize()
    try {
      const agent = makeAgent()
      app.onAgentSessionStart({ agent, source: 'test-source' })
      app.onSessionTitleEvent({ header: { id: 'session-title-1' } }, { type: 'session/state', data: { title: 'not a title event' } })
      app.onSessionTitleEvent({ header: {} }, { type: 'session/title', data: { title: 'no session id' } })
      app.onSessionTitleEvent({ header: { id: 'session-title-1' } }, { type: 'session/title', data: { title: '' } })
      app.onAgentSessionStart({ agent, source: 'test-source' })
    } finally {
      app.shutdown()
      sink.shutdown()
    }

    const rows = readEvents(config.collector.localOutputPath)
    const sessionStarts = rows.filter((row) => row['event_type'] === 'agent_session_start')
    expect(sessionStarts.every((row) => !('session_title' in row))).toBe(true)
  })

  it('carries a title observed before the session context exists (resumed session)', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-session-title-'))
    const config = normalizeConfig({
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl') },
    })
    const sink = new LocalNdjsonSink(config)
    const app = new ApplicationCollector(config, sink)
    sink.initialize()
    app.initialize()
    try {
      // Title event arrives BEFORE agent/created (cold-read backstop or a
      // host race) → queued in SessionStore, applied at first rehydration.
      app.onSessionTitleEvent({ header: { id: 'session-title-late' } }, { type: 'session/title', data: { title: 'resumed work session' } })
      app.onAgentSessionStart({ agent: makeAgent('session-title-late'), source: 'test-source' })
    } finally {
      app.shutdown()
      sink.shutdown()
    }

    const rows = readEvents(config.collector.localOutputPath)
    const sessionStart = rows.find((row) => row['event_type'] === 'agent_session_start' && row['session_id'] === 'session-title-late')
    expect(sessionStart?.['session_title']).toBe('resumed work session')
  })
})
