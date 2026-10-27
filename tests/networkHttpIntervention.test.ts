import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import http from 'node:http'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { NetworkHttpCollector } from '../src/collectors/NetworkHttpCollector.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import { httpRequestContext } from '../src/utils/httpContext.js'
import { normalizeConfig, type Config } from '../src/config.js'
import type { InterventionContext, SecurityEvent } from '../src/types/index.js'

function makeConfig(tmpDir: string, mode: 'audit' | 'enforce' = 'audit'): Config {
  return normalizeConfig({
    mode,
    collector: {
      localOutputPath: join(tmpDir, 'security-events.jsonl'),
      batchSize: 1,
      flushIntervalMs: 60_000,
      validateEvents: false,
    },
    application: {
      httpCapture: {
        enabled: true,
        redactBodies: true,
        captureResponseBody: true,
        maxBodyBytes: 1024 * 1024,
        maxRequestBodyBytes: 1024 * 1024,
        sseSummaryChunks: 5,
        sseSummaryLastChunks: 1,
        includeHosts: [],
        excludeHosts: [],
        excludeUrls: [],
        sensitiveKeyPatterns: [],
      },
    },
    intervention: {
      policyPath: join(tmpDir, 'policy.json'),
      reloadIntervalMs: 0,
    },
  })
}

function writePolicy(tmpDir: string, rules: unknown[]): void {
  const policy = {
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'test-policy' },
    rules,
  }
  writeFileSync(join(tmpDir, 'policy.json'), JSON.stringify(policy, null, 2))
}

function blockHostRule(hostPattern: string): Record<string, unknown> {
  return {
    id: 'block-test-host',
    category: 'intrusion_defense',
    enabled: true,
    priority: 1000,
    match: {
      actionType: ['http_request'],
      paramsRegex: { host: [hostPattern] },
    },
    action: {
      decision: 'block',
      blockReason: 'blocked test host',
      blockCode: 'INTRUSION_DEFENSE_TEST_HOST_BLOCK_001',
    },
  }
}

function makeHttpContext(overrides: Partial<InterventionContext> = {}): InterventionContext {
  return {
    actionType: 'http_request',
    params: {
      service: 'http',
      method: 'POST',
      host: 'api.example.com',
      url: 'http://api.example.com/v1/chat',
      path: '/v1/chat',
    },
    body: JSON.stringify({ model: 'test-model' }),
    sessionId: 'session-1',
    runId: 'run-1',
    agentId: 'agent-1',
    ...overrides,
  }
}

async function startTestServer() {
  const server = createServer((req, res) => {
    req.on('data', () => {})
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end('{"ok":true}')
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address() as AddressInfo
  return { server, url: `http://127.0.0.1:${address.port}` }
}

function waitForEvents(collector: LocalNdjsonSink, count: number, timeoutMs = 3000): Promise<SecurityEvent[]> {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now()
    const events: SecurityEvent[] = []
    const check = () => {
      if (events.length >= count) {
        resolve(events)
        return
      }
      if (Date.now() - startedAt > timeoutMs) {
        reject(new Error(`timed out waiting for ${count} events, got ${events.length}`))
        return
      }
      setTimeout(check, 20)
    }
    const originalReport = (collector as unknown as { report: (e: SecurityEvent) => void }).report
    ;(collector as unknown as { report: (e: SecurityEvent) => void }).report = function (event: SecurityEvent) {
      events.push(event)
      originalReport.call(this, event)
      check()
    }
    check()
  })
}

function getJson(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        res.on('data', () => {})
        res.on('end', () => resolve())
      })
      .on('error', reject)
  })
}

describe('network_http intervention gating + decision cache', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-http-gate-'))
  })

  afterEach(() => {
    if (existsSync(tmpDir)) rmSync(tmpDir, { recursive: true, force: true })
  })

  describe('InterventionEngine.evaluateHttp', () => {
    it('skips evaluation outside the tool-call window with an observable counter', async () => {
      const engine = new InterventionEngine(makeConfig(tmpDir))
      const decision = await engine.evaluateHttp(makeHttpContext(), { toolActive: false })
      expect(decision).toBeUndefined()
      const state = engine.getHttpEvaluationState()
      expect(state.skippedOutsideToolWindow).toBe(1)
      // No scan ran at all: neither a miss nor a hit.
      expect(state.cacheMisses).toBe(0)
      expect(state.cacheHits).toBe(0)
    })

    it('reduces evaluations by >=80% for 1000 homogeneous in-window requests', async () => {
      writePolicy(tmpDir, [])
      const config = makeConfig(tmpDir)
      const engine = new InterventionEngine(config)
      engine.initialize()

      const ctx = makeHttpContext()
      const REQUESTS = 1000
      for (let i = 0; i < REQUESTS; i++) {
        const decision = await engine.evaluateHttp(ctx, { toolActive: true })
        expect(decision?.decision).toBe('allow')
      }

      const state = engine.getHttpEvaluationState()
      // Baseline (pre-fix) behaviour: every request paid one full scan, i.e.
      // 1000 evaluations. Post-fix: one miss + 999 cache hits.
      expect(state.cacheMisses).toBe(1)
      expect(state.cacheHits).toBe(REQUESTS - 1)
      const reduction = 1 - state.cacheMisses / REQUESTS
      expect(reduction).toBeGreaterThanOrEqual(0.8)
      engine.shutdown()
    })

    it('re-evaluates (never caches) block decisions for in-window high-risk targets', async () => {
      writePolicy(tmpDir, [blockHostRule('^api\\.example\\.com$')])
      const engine = new InterventionEngine(makeConfig(tmpDir))
      engine.initialize()

      const ctx = makeHttpContext()
      const first = await engine.evaluateHttp(ctx, { toolActive: true })
      const second = await engine.evaluateHttp(ctx, { toolActive: true })
      expect(first?.decision).toBe('block')
      expect(second?.decision).toBe('block')

      const state = engine.getHttpEvaluationState()
      expect(state.cacheMisses).toBe(2)
      expect(state.cacheHits).toBe(0)
      expect(state.cacheSize).toBe(0)
      engine.shutdown()
    })

    it('bypasses the cached allow when the body matches a bodyRegex rule', async () => {
      writePolicy(tmpDir, [
        {
          id: 'block-leaked-token',
          category: 'data_leak_monitoring',
          enabled: true,
          priority: 1000,
          match: {
            actionType: ['http_request'],
            bodyRegex: ['secret-leak-TOKEN'],
          },
          action: {
            decision: 'block',
            blockReason: 'blocked leaked token in body',
            blockCode: 'DATA_LEAK_MONITORING_TEST_TOKEN_BODY_001',
          },
        },
      ])
      const engine = new InterventionEngine(makeConfig(tmpDir))
      engine.initialize()

      const benign = await engine.evaluateHttp(makeHttpContext(), { toolActive: true })
      expect(benign?.decision).toBe('allow')

      const malicious = await engine.evaluateHttp(
        makeHttpContext({ body: 'prefix secret-leak-TOKEN suffix' }),
        { toolActive: true },
      )
      // The cache must not replay the earlier allow over a body that now
      // matches a bodyRegex rule.
      expect(malicious?.decision).toBe('block')

      const state = engine.getHttpEvaluationState()
      expect(state.cacheHits).toBe(0)
      expect(state.cacheMisses).toBe(2)
      engine.shutdown()
    })

    it('expires cached decisions after the TTL', async () => {
      writePolicy(tmpDir, [])
      const engine = new InterventionEngine(makeConfig(tmpDir), {
        httpDecisionCache: { ttlMs: 40 },
      })
      engine.initialize()

      const ctx = makeHttpContext()
      await engine.evaluateHttp(ctx, { toolActive: true })
      await engine.evaluateHttp(ctx, { toolActive: true })
      expect(engine.getHttpEvaluationState().cacheMisses).toBe(1)
      expect(engine.getHttpEvaluationState().cacheHits).toBe(1)

      await new Promise((resolve) => setTimeout(resolve, 60))
      await engine.evaluateHttp(ctx, { toolActive: true })
      expect(engine.getHttpEvaluationState().cacheMisses).toBe(2)
      engine.shutdown()
    })

    it('clears the decision cache on policy reload', async () => {
      writePolicy(tmpDir, [])
      const config = makeConfig(tmpDir)
      const engine = new InterventionEngine(config)
      engine.initialize()

      const ctx = makeHttpContext()
      await engine.evaluateHttp(ctx, { toolActive: true })
      expect(engine.getHttpEvaluationState().cacheSize).toBe(1)

      // Same-content rewrite: hash unchanged, reloadPolicy still re-loads
      // and must drop cached verdicts.
      writePolicy(tmpDir, [])
      // @ts-expect-error -- private access for white-box reload assertion
      engine.reloadPolicy()
      expect(engine.getHttpEvaluationState().cacheSize).toBe(0)
      engine.shutdown()
    })
  })

  describe('NetworkHttpCollector wiring', () => {
    let collector: LocalNdjsonSink
    let httpCapture: NetworkHttpCollector
    let engine: InterventionEngine

    afterEach(() => {
      httpCapture?.uninstall()
      engine?.shutdown()
      collector?.shutdown()
    })

    it('collects events but skips evaluation outside the tool-call window', async () => {
      const { server, url } = await startTestServer()
      const config = makeConfig(tmpDir)
      collector = new LocalNdjsonSink(config, { logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() } })
      collector.initialize()
      engine = new InterventionEngine(config)
      httpCapture = new NetworkHttpCollector(config, { eventCollector: collector, interventionEngine: engine })
      httpCapture.install()

      const promise = waitForEvents(collector, 2)
      await getJson(`${url}/outside-window`)

      const events = await promise
      server.close()
      const httpEvents = events.filter((e) => e.event_type === 'network_http')
      expect(httpEvents).toHaveLength(2) // send + recv — collection unaffected
      expect(httpEvents.every((e) => e.blocked === false)).toBe(true)

      const state = engine.getHttpEvaluationState()
      expect(state.skippedOutsideToolWindow).toBe(1)
      expect(state.cacheMisses).toBe(0)
    })

    it('still evaluates and blocks high-risk targets inside the tool-call window', async () => {
      writePolicy(tmpDir, [blockHostRule('^127\\.0\\.0\\.1$')])
      const { server, url } = await startTestServer()
      const config = makeConfig(tmpDir, 'enforce')
      collector = new LocalNdjsonSink(config, { logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() } })
      collector.initialize()
      engine = new InterventionEngine(config)
      engine.initialize()
      httpCapture = new NetworkHttpCollector(config, { eventCollector: collector, interventionEngine: engine })
      httpCapture.install()

      const promise = waitForEvents(collector, 2)
      await httpRequestContext.run(
        { sessionId: 'session-1', runId: 'run-1', agentId: 'agent-1', toolCallId: 'call-1' },
        () => getJson(`${url}/inside-window`),
      )

      const events = await promise
      server.close()
      const send = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')
      expect(send).toBeDefined()
      expect(send?.blocked).toBe(true)
      expect(send?.block_reason).toContain('blocked test host')
      const recv = events.find((e) => e.event_type === 'network_http' && e.direction === 'recv')
      expect(recv?.blocked).toBe(true)

      const state = engine.getHttpEvaluationState()
      expect(state.skippedOutsideToolWindow).toBe(0)
      expect(state.cacheMisses).toBe(1)
    })

    it('serves repeat in-window requests from the decision cache end-to-end', async () => {
      writePolicy(tmpDir, [])
      const { server, url } = await startTestServer()
      const config = makeConfig(tmpDir)
      collector = new LocalNdjsonSink(config, { logger: { log: vi.fn(), warn: vi.fn(), error: vi.fn() } })
      collector.initialize()
      engine = new InterventionEngine(config)
      engine.initialize()
      httpCapture = new NetworkHttpCollector(config, { eventCollector: collector, interventionEngine: engine })
      httpCapture.install()

      const session = { sessionId: 'session-1', runId: 'run-1', agentId: 'agent-1', toolCallId: 'call-1' }
      const promise = waitForEvents(collector, 4)
      await httpRequestContext.run(session, () => getJson(`${url}/repeat`))
      await httpRequestContext.run(session, () => getJson(`${url}/repeat`))

      const events = await promise
      server.close()
      expect(events.filter((e) => e.event_type === 'network_http')).toHaveLength(4)

      const state = engine.getHttpEvaluationState()
      expect(state.cacheMisses).toBe(1)
      expect(state.cacheHits).toBe(1)
    })
  })
})
