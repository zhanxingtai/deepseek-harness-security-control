import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import http from 'node:http'
import { createServer } from 'node:http'
import dns from 'node:dns'
import { AddressInfo } from 'node:net'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { NetworkHttpCollector } from '../src/collectors/NetworkHttpCollector.js'
import { normalizeConfig, type Config } from '../src/config.js'
import { httpRequestContext } from '../src/utils/httpContext.js'
import type { SecurityEvent } from '../src/types/index.js'

function makeConfig(overrides: Partial<Config> = {}): Config {
  return normalizeConfig({
    mode: 'audit',
    collector: {
      localOutputPath: '/tmp/dsh-test-events.jsonl',
      batchSize: 1,
      flushIntervalMs: 60_000,
      validateEvents: false,
    },
    networkCapture: {
      enabled: true,
      redactBodies: true,
      captureResponseBody: true,
      maxBodyBytes: 1024 * 1024,
      sseSummaryChunks: 5,
      sseSummaryLastChunks: 1,
      includeHosts: [],
      excludeHosts: [],
      excludeUrls: [],
      sensitiveKeyPatterns: [],
    },
    ...overrides,
  })
}

function makeLogger() {
  return { log: vi.fn(), warn: vi.fn(), error: vi.fn() }
}

async function startTestServer(response?: { status?: number; body?: string; headers?: Record<string, string> }) {
  const { status = 200, body = '{"ok":true}', headers = { 'Content-Type': 'application/json' } } = response ?? {}
  const server = createServer((req, res) => {
    let received = ''
    req.on('data', (chunk) => {
      received += chunk.toString()
    })
    req.on('end', () => {
      res.writeHead(status, headers)
      res.end(body)
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
      const all = collector.getStats()
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
    // Abuse report() is internal; we read from the collector's queue indirectly by flushing.
    // Instead we inspect the collector's private queue via reflection for tests.
    const originalReport = (collector as unknown as { report: (e: SecurityEvent) => void }).report
    ;(collector as unknown as { report: (e: SecurityEvent) => void }).report = function (event: SecurityEvent) {
      events.push(event)
      originalReport.call(this, event)
      check()
    }
    check()
  })
}

describe('NetworkHttpCollector', () => {
  let collector: LocalNdjsonSink
  let httpCapture: NetworkHttpCollector
  let logger: ReturnType<typeof makeLogger>

  beforeEach(() => {
    logger = makeLogger()
    collector = new LocalNdjsonSink(makeConfig(), { logger })
    collector.initialize()
  })

  afterEach(() => {
    httpCapture?.uninstall()
    collector.shutdown()
  })

  it('emits a network_http event for http.request with body and response', async () => {
    const { server, url } = await startTestServer({ body: 'hello world' })
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    const req = http.request(
      `${url}/api/v1/chat`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' } },
      () => {},
    )
    req.write(JSON.stringify({ model: 'test-model' }))
    req.end()

    const events = await promise
    server.close()
    const event = events.find((e) => e.event_type === 'network_http')
    expect(event).toBeDefined()
    expect(event?.method).toBe('POST')
    expect(event?.url).toBe('/api/v1/chat')
    expect(event?.host).toBe('127.0.0.1')
    expect(event?.service).toBe('http')
    expect(event?.direction).toBe('send')
    expect(event?.code).toBe(200)
    expect(event?.response_body).toBe('hello world')
    expect(event?.body).toContain('test-model')
    expect(typeof event?.latency_ms).toBe('number')
  })

  it('emits structured `headers` on network_http', async () => {
    const { server, url } = await startTestServer()
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    const req = http.request(
      `${url}/api/headers`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Trace-Id': 'trace-abc-123',
        },
      },
      () => {},
    )
    req.write(JSON.stringify({ ok: true }))
    req.end()

    const events = await promise
    server.close()
    const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
    // fix: the platform per-type validator requires the
    // structured `headers` field. The legacy `header` (curl-style
    // string) form was removed in §十一 B4 —
    // emit only `headers` here.
    expect(event.headers).toBeDefined()
    expect(typeof event.headers).toBe('object')
    expect((event.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    expect((event.headers as Record<string, string>)['X-Trace-Id']).toBe('trace-abc-123')
  })

  it('redacts JSON body sensitive keys (Authorization header is now blocked by the inline guard)', async () => {
    const { server, url } = await startTestServer()
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    // E2-3: an Authorization header now triggers
    // SensitiveHeaderDeniedError BEFORE the request reaches the server
    // — see `sensitive-header guard denies http.request carrying Cookie`
    // below for the audit-side coverage. The pre-E2-3 "redact header value
    // and let it pass" behaviour is gone. The body-key redaction path is
    // orthogonal and still observable via a benign header carrier.
    const req = http.request(
      `${url}/api`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Custom-Auth': 'Bearer secret-token',
        },
      },
      () => {},
    )
    req.write(JSON.stringify({ api_key: 'super-secret', message: 'hi' }))
    req.end()

    const events = await promise
    server.close()
    const event = events.find((e) => e.event_type === 'network_http')!
    // §十一 B4 : only `headers` (structured object)
    // is emitted — the legacy `header` (curl-style string) form was
    // removed. The pre-E2-3 header-redaction assertion
    // (`Authorization: '***'`) is GONE — the inline guard now BLOCKS
    // before any header masking. The body-key redaction path is
    // orthogonal and still fires on `api_key` (default sensitive key).
    expect(event.body).toContain('"api_key":"***"')
    expect(event.body).toContain('"message":"hi"')
  })

  it('excludes hosts from capture', async () => {
    const { server, url } = await startTestServer()
    const config = makeConfig({
      networkCapture: {
        enabled: true,
        redactBodies: true,
        captureResponseBody: true,
        maxBodyBytes: 1024 * 1024,
        sseSummaryChunks: 5,
        sseSummaryLastChunks: 1,
        includeHosts: [],
        excludeHosts: ['127.0.0.1'],
        excludeUrls: [],
        sensitiveKeyPatterns: [],
      },
    })
    httpCapture = new NetworkHttpCollector(config, { eventCollector: collector })
    httpCapture.install()

    let eventFired = false
    const originalReport = (collector as unknown as { report: (e: SecurityEvent) => void }).report
    ;(collector as unknown as { report: (e: SecurityEvent) => void }).report = function (event: SecurityEvent) {
      if (event.event_type === 'network_http') eventFired = true
      originalReport.call(this, event)
    }

    await new Promise<void>((resolve, reject) => {
      const req = http.request(`${url}/skip`, (res) => {
        res.on('data', () => {})
        res.on('end', resolve)
      })
      req.on('error', reject)
      req.end()
    })

    server.close()
    expect(eventFired).toBe(false)
  })

  it('supports global.fetch wrapper', async () => {
    const { server, url } = await startTestServer({ body: 'fetch-response' })
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    await fetch(`${url}/fetch`, { method: 'POST', body: JSON.stringify({ query: 'x' }) })

    const events = await promise
    server.close()
    const event = events.find((e) => e.event_type === 'network_http')
    expect(event).toBeDefined()
    expect(event?.method).toBe('POST')
    expect(event?.url).toBe('/fetch')
    expect(event?.response_body).toBe('fetch-response')
    expect(event?.body).toContain('"query":"x"')
  })

  // ---------------------------------------------------------------------------
  // E2-3: inline sensitive-header guard integration. The guard
  // gates both `globalThis.fetch` and `http(s).request` BEFORE the outbound
  // socket opens. A hit throws SensitiveHeaderDeniedError synchronously and
  // emits one `security_audit/inline_sensitive_header_detect` row.
  //
  // 2026-09-28 fix: harness-internal planes (llm-pi-ai provider calls,
  // plugin telemetry) legitimately carry `Authorization: Bearer <key>` and
  // run outside the tool ALS frame — denying them broke every LLM request.
  //
  // 2026-10-10 fix (H5): the blanket out-of-frame exemption became an
  // explicit operator allow-list (`sensitiveHeaderGuard.harnessPlaneHosts`).
  // Out-of-frame requests to NON-exempt hosts are now guard-evaluated: on a
  // hit they are audited (`outcome: 'detected'`, guard_seam
  // 'network.http.out-of-frame') but NOT thrown unless
  // `enforceOutOfFrame: true`. Tests below cover all three postures.
  // ---------------------------------------------------------------------------

  const TOOL_FRAME = { sessionId: 's-test', runId: 'r-test', agentId: 'a-test', toolCallId: 'call-test' }

  it('sensitive-header guard denies fetch() carrying Authorization', async () => {
    const { server, url } = await startTestServer()
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    await expect(
      httpRequestContext.run(TOOL_FRAME, () =>
        fetch(`${url}/anything`, { headers: { Authorization: 'Bearer secret-token' } }),
      ),
    ).rejects.toMatchObject({
      name: 'SensitiveHeaderDeniedError',
      block_code: 'INLINE_SENSITIVE_HEADER_001',
      matchedKey: 'Authorization',
    })
    server.close()
  })

  it('sensitive-header guard denies http.request carrying Cookie', async () => {
    const { server, url } = await startTestServer()
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    await expect(
      httpRequestContext.run(TOOL_FRAME, () =>
        new Promise<void>((resolve, reject) => {
          const r = http.request(`${url}/anything`, { headers: { Cookie: 'session=abc' } }, () => {
            resolve()
          })
          r.on('error', (err: Error & { block_code?: string; matchedKey?: string }) => {
            if (err.name === 'SensitiveHeaderDeniedError' && err.block_code === 'INLINE_SENSITIVE_HEADER_001') {
              reject(err)
            } else {
              resolve()
            }
          })
          r.end()
        }),
      ),
    ).rejects.toMatchObject({
      name: 'SensitiveHeaderDeniedError',
      block_code: 'INLINE_SENSITIVE_HEADER_001',
      matchedKey: 'Cookie',
    })
    server.close()
  })

  it('sensitive-header guard emits a security_audit row on hit', async () => {
    const { server, url } = await startTestServer()
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    // Wait for 1 audit row + ignore the fact that fetch() throws.
    const auditPromise = waitForEvents(collector, 1)
    await httpRequestContext.run(TOOL_FRAME, () =>
      fetch(`${url}/anything`, { headers: { 'X-API-Key': 'sk-123' } }).catch(() => {}),
    )
    const events = await auditPromise
    server.close()

    const audit = events.find(
      (e) =>
        e.event_type === 'security_audit' &&
        e.audit_details?.['event_type_alias'] === 'inline_sensitive_header_detect',
    )
    expect(audit).toBeDefined()
    expect(audit?.blocked).toBe(true)
    expect(audit?.severity).toBe('high')
    expect(audit?.outcome).toBe('blocked')
    expect(audit?.block_reason).toContain('X-API-Key')
    expect(audit?.audit_details?.['matched_key']).toBe('X-API-Key')
    expect(audit?.audit_details?.['guard_seam']).toBe('network.http.fetch+https.request')
    // 2026-09-28 fix: the sink validator requires host_id/container_id —
    // the row must carry them so LocalNdjsonSink does not drop the block.
    expect(audit?.host_id).toBeDefined()
    expect(audit?.container_id).toBeDefined()
  })

  it('sensitive-header guard audits but does not block out-of-frame requests to non-exempt hosts (H5 default posture)', async () => {
    // 2026-10-10 (H5): the old blanket exemption let ANY out-of-frame
    // traffic (including agent fetches scheduled out of the tool frame)
    // skip the guard silently. Default posture now: the request proceeds
    // but a `detected` audit row lands so the attempt is operator-visible.
    const { server, url } = await startTestServer({ body: 'ok' })
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    const auditPromise = waitForEvents(collector, 1)
    const resp = await fetch(`${url}/out-of-frame`, { headers: { Authorization: 'Bearer sk-real-key' } })
    expect(resp.status).toBe(200)
    const events = await auditPromise
    server.close()

    const audit = events.find(
      (e) =>
        e.event_type === 'security_audit' &&
        e.audit_details?.['event_type_alias'] === 'inline_sensitive_header_detect',
    )
    expect(audit).toBeDefined()
    // Audit-only: the request was NOT denied. outcome follows the
    // audit-only detector vocabulary ('success' = host unaffected);
    // out_of_frame + guard_seam mark it as a detection.
    expect(audit?.outcome).toBe('success')
    expect(audit?.blocked).toBe(false)
    expect(audit?.audit_details?.['guard_seam']).toBe('network.http.out-of-frame')
    expect(audit?.audit_details?.['out_of_frame']).toBe(true)
    // Ops hook: the audit-only row names the host as a pending provider
    // exemption candidate so operators can filter "new provider" noise.
    expect(audit?.audit_details?.['suggested_provider_exemption']).toBe('127.0.0.1')
  })

  it('sensitive-header guard skips out-of-frame requests to seedHosts (operator seeds union marketplace baseline)', async () => {
    // 2026-10-20: seedHosts cover provider routes that inherit their
    // endpoint from the pi-ai catalog (nothing to discover in the settings
    // document). Operator entries UNION with the marketplace baseline in
    // normalizeConfig, so passing '127.0.0.1' here adds the test server
    // without stripping the default seeds.
    const { server, url } = await startTestServer({ body: 'ok' })
    httpCapture = new NetworkHttpCollector(
      makeConfig({
        sensitiveHeaderGuard: {
          enabled: true,
          keys: [],
          harnessPlaneHosts: [],
          enforceOutOfFrame: false,
          providerDiscovery: false,
          providerDiscoveryPath: '',
          seedHosts: ['127.0.0.1'],
        },
      }),
      { eventCollector: collector },
    )
    httpCapture.install()

    const reports: SecurityEvent[] = []
    const originalReport = (collector as unknown as { report: (e: SecurityEvent) => void }).report
    ;(collector as unknown as { report: (e: SecurityEvent) => void }).report = function (event: SecurityEvent) {
      reports.push(event)
      originalReport.call(this, event)
    }

    const resp = await fetch(`${url}/seed-provider-call`, { headers: { Authorization: 'Bearer sk-real-key' } })
    expect(resp.status).toBe(200)
    await new Promise((r) => setTimeout(r, 150))
    server.close()
    expect(reports.filter((e) => e.event_type === 'security_audit')).toHaveLength(0)
  })

  it('sensitive-header guard skips out-of-frame requests to hosts discovered from the settings document', async () => {
    // 2026-10-20: providerDiscovery reads llm-pi-ai route baseURLs from the
    // host settings document and exempts them — a customer adding/replacing
    // a model via the host's own configuration is covered without any
    // manual host list. The fixture points at 127.0.0.1 (hostname only;
    // the port in baseURL is stripped by URL parsing).
    const dir = mkdtempSync(join(tmpdir(), 'dsh-shg-discovery-'))
    try {
      const settingsPath = join(dir, 'settings.yaml')
      writeFileSync(
        settingsPath,
        'llm-pi-ai:\n  providers:\n    local-llm:\n      baseURL: http://127.0.0.1:43921/v1\n',
      )
      const { server, url } = await startTestServer({ body: 'ok' })
      httpCapture = new NetworkHttpCollector(
        makeConfig({
          sensitiveHeaderGuard: {
            enabled: true,
            keys: [],
            harnessPlaneHosts: [],
            enforceOutOfFrame: false,
            providerDiscovery: true,
            providerDiscoveryPath: settingsPath,
            seedHosts: [],
          },
        }),
        { eventCollector: collector },
      )
      httpCapture.install()

      const reports: SecurityEvent[] = []
      const originalReport = (collector as unknown as { report: (e: SecurityEvent) => void }).report
      ;(collector as unknown as { report: (e: SecurityEvent) => void }).report = function (event: SecurityEvent) {
        reports.push(event)
        originalReport.call(this, event)
      }

      const resp = await fetch(`${url}/discovered-provider-call`, { headers: { Authorization: 'Bearer sk-real-key' } })
      expect(resp.status).toBe(200)
      await new Promise((r) => setTimeout(r, 150))
      server.close()
      expect(reports.filter((e) => e.event_type === 'security_audit')).toHaveLength(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('sensitive-header guard skips out-of-frame requests to harnessPlaneHosts (operator allow-list)', async () => {
    // 2026-10-10 (H5): hosts in `sensitiveHeaderGuard.harnessPlaneHosts`
    // keep the old exemption — this is where the operator lists their LLM
    // provider / telemetry endpoints.
    const { server, url } = await startTestServer({ body: 'ok' })
    httpCapture = new NetworkHttpCollector(
      makeConfig({
        sensitiveHeaderGuard: {
          enabled: true,
          keys: [],
          harnessPlaneHosts: ['127.0.0.1'],
          enforceOutOfFrame: false,
        },
      }),
      { eventCollector: collector },
    )
    httpCapture.install()

    const reports: SecurityEvent[] = []
    const originalReport = (collector as unknown as { report: (e: SecurityEvent) => void }).report
    ;(collector as unknown as { report: (e: SecurityEvent) => void }).report = function (event: SecurityEvent) {
      reports.push(event)
      originalReport.call(this, event)
    }

    const resp = await fetch(`${url}/provider-call`, { headers: { Authorization: 'Bearer sk-real-key' } })
    expect(resp.status).toBe(200)
    await new Promise((r) => setTimeout(r, 150))
    server.close()
    expect(reports.filter((e) => e.event_type === 'security_audit')).toHaveLength(0)
  })

  it('sensitive-header guard hard-blocks out-of-frame requests when enforceOutOfFrame is true', async () => {
    // 2026-10-10 (H5): once the operator has populated harnessPlaneHosts
    // they can flip `enforceOutOfFrame: true` to upgrade out-of-frame hits
    // from audit-only to the same hard block in-frame requests get.
    const { server, url } = await startTestServer({ body: 'ok' })
    httpCapture = new NetworkHttpCollector(
      makeConfig({
        sensitiveHeaderGuard: {
          enabled: true,
          keys: [],
          harnessPlaneHosts: [],
          enforceOutOfFrame: true,
        },
      }),
      { eventCollector: collector },
    )
    httpCapture.install()

    await expect(
      fetch(`${url}/out-of-frame`, { headers: { Authorization: 'Bearer sk-real-key' } }),
    ).rejects.toMatchObject({
      name: 'SensitiveHeaderDeniedError',
      block_code: 'INLINE_SENSITIVE_HEADER_001',
      matchedKey: 'Authorization',
    })
    server.close()
  })

  it('sensitive-header guard passes benign headers through', async () => {
    const { server, url } = await startTestServer({ body: 'ok' })
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    const resp = await fetch(`${url}/anything`, {
      headers: {
        'User-Agent': 'test/1.0',
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    })
    expect(resp.status).toBe(200)
    await promise
    server.close()
  })

  it('truncates oversized response bodies', async () => {
    const bigBody = 'x'.repeat(2000)
    const { server, url } = await startTestServer({ body: bigBody })
    httpCapture = new NetworkHttpCollector(
      makeConfig({
        networkCapture: {
          enabled: true,
          redactBodies: true,
          captureResponseBody: true,
          maxBodyBytes: 100,
          sseSummaryChunks: 5,
          sseSummaryLastChunks: 1,
          includeHosts: [],
          excludeHosts: [],
          excludeUrls: [],
          sensitiveKeyPatterns: [],
        },
      }),
      { eventCollector: collector },
    )
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    await new Promise<void>((resolve, reject) => {
      http.get(`${url}/big`, (res) => {
        res.on('data', () => {})
        res.on('end', resolve)
      }).on('error', reject)
    })

    const events = await promise
    server.close()
    const event = events.find((e) => e.event_type === 'network_http')!
    expect(event.content_truncated).toBe(true)
    expect(event.content_original_length).toBeGreaterThan(100)
    expect(Buffer.byteLength(event.response_body ?? '', 'utf8')).toBeLessThanOrEqual(100 + 20) // marker budget
  })

  it('folds SSE streams to head + summary + tail chunks', async () => {
    const sseBody = [
      'data: {"chunk":1}',
      'data: {"chunk":2}',
      'data: {"chunk":3}',
      'data: {"chunk":4}',
      'data: {"chunk":5}',
      'data: {"chunk":6}',
      'data: {"chunk":7}',
      'data: {"chunk":8}',
      'data: {"chunk":9}',
    ].join('\n\n')
    const { server, url } = await startTestServer({
      body: sseBody,
      headers: { 'Content-Type': 'text/event-stream' },
    })
    httpCapture = new NetworkHttpCollector(
      makeConfig({
        networkCapture: {
          enabled: true,
          redactBodies: true,
          captureResponseBody: true,
          maxBodyBytes: 1024 * 1024,
          sseSummaryChunks: 3,
          sseSummaryLastChunks: 1,
          includeHosts: [],
          excludeHosts: [],
          excludeUrls: [],
          sensitiveKeyPatterns: [],
        },
      }),
      { eventCollector: collector },
    )
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    await new Promise<void>((resolve, reject) => {
      http.get(`${url}/sse`, (res) => {
        res.on('data', () => {})
        res.on('end', resolve)
      }).on('error', reject)
    })

    const events = await promise
    server.close()
    const event = events.find((e) => e.event_type === 'network_http')!
    expect(event.response_body).toContain('data: {"chunk":1}')
    expect(event.response_body).toContain('data: {"chunk":3}')
    expect(event.response_body).toContain('data: {"chunk":9}')
    expect(event.response_body).not.toContain('data: {"chunk":5}')
    expect(event.response_body).toContain('__dsh_sse_summary')
    expect(event.response_body_chunks_total).toBe(9)
    expect(event.response_body_chunks_kept).toBe(5) // 3 head + summary + 1 tail
    expect(event.content_truncated).toBe(true)
    expect(event.content_original_length).toBeGreaterThan(Buffer.byteLength(event.response_body ?? '', 'utf8'))
  })

  it('restores original http.request after uninstall', async () => {
    const original = http.request
    httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
    httpCapture.install()
    expect(http.request).not.toBe(original)
    httpCapture.uninstall()
    expect(http.request).toBe(original)
  })

  it('emits network_dns when captureDns is enabled', async () => {
    const config = makeConfig({
      networkCapture: {
        enabled: true,
        redactBodies: true,
        captureResponseBody: true,
        maxBodyBytes: 1024 * 1024,
        sseSummaryChunks: 5,
        sseSummaryLastChunks: 1,
        includeHosts: [],
        excludeHosts: [],
        excludeUrls: [],
        sensitiveKeyPatterns: [],
        captureDns: true,
      },
    })
    httpCapture = new NetworkHttpCollector(config, { eventCollector: collector })
    httpCapture.install()

    const promise = waitForEvents(collector, 1)
    dns.lookup('localhost', () => {})

    const events = await promise
    const dnsEvent = events.find((e) => e.event_type === 'network_dns')
    expect(dnsEvent).toBeDefined()
    expect(dnsEvent?.query).toBe('localhost')
    expect(dnsEvent?.service).toBe('dns')
    expect(dnsEvent?.protocol).toBe('udp')
    expect(dnsEvent?.remote_port).toBe(53)
    // the platform's network_dns contract requires the resolved address
    expect(dnsEvent?.remote_ip).toBeTruthy()
  })

  it('does not emit network_dns when the resolution yields no address', async () => {
    // A resolution with no address (a TXT/MX-only RRset, or a record
    // shape we cannot read) has no schema-valid network_dns
    // representation — the platform's contract requires `remote_ip`.
    // Emitting it anyway would make the platform reject the whole batch
    // and the SDK degrade the event to `x_bridge_network_dns`.
    const originalResolve = dns.resolve
    ;(dns as unknown as { resolve: unknown }).resolve = (
      _hostname: string,
      ...args: unknown[]
    ): void => {
      const cb = args.find((a) => typeof a === 'function') as
        | ((err: NodeJS.ErrnoException | null, records: unknown) => void)
        | undefined
      cb?.(null, [])
    }
    const seen: SecurityEvent[] = []
    const originalReport = (collector as unknown as { report: (e: SecurityEvent) => void }).report
    ;(collector as unknown as { report: (e: SecurityEvent) => void }).report = function (event: SecurityEvent) {
      seen.push(event)
      originalReport.call(this, event)
    }
    try {
      const config = makeConfig({
        networkCapture: {
          enabled: true,
          redactBodies: true,
          captureResponseBody: true,
          maxBodyBytes: 1024 * 1024,
          sseSummaryChunks: 5,
          sseSummaryLastChunks: 1,
          includeHosts: [],
          excludeHosts: [],
          excludeUrls: [],
          sensitiveKeyPatterns: [],
          captureDns: true,
        },
      })
      httpCapture = new NetworkHttpCollector(config, { eventCollector: collector })
      httpCapture.install()

      dns.resolve('example.com', 'TXT', () => {})
      await new Promise((resolve) => setTimeout(resolve, 100))

      expect(seen.filter((e) => e.event_type === 'network_dns')).toHaveLength(0)
    } finally {
      // uninstall() restores the stubbed `dns.resolve`; then the real one
      // goes back. `uninstall()` is idempotent, so afterEach is a no-op.
      httpCapture.uninstall()
      ;(dns as unknown as { resolve: unknown }).resolve = originalResolve
    }
  })

  describe('invariant #6 leak fix (URL query redact)', () => {
    it('redacts query-string secrets in url and request_url before emit', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      // Token-bearing query: lands on `url` (path + search) AND
      // `request_url` (full href). Both must be masked.
      const req = http.request(
        `${url}/api/data?token=secret-bearer-xyz&safe=ok`,
        { method: 'GET' },
        () => {},
      )
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.url).toBe('/api/data?token=***&safe=ok')
      expect(event.url).not.toContain('secret-bearer-xyz')
      expect(event.request_url).toBe(`${url}/api/data?token=***&safe=ok`)
      expect(event.request_url).not.toContain('secret-bearer-xyz')
      expect(event.url_redacted_keys).toEqual(['query.token'])
    })

    it('redacts multiple sensitive query keys (token + api_key + sid)', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      const req = http.request(
        `${url}/v1/users?token=xxx&api_key=yyy&sid=zzz&keep=vvv`,
        { method: 'GET' },
        () => {},
      )
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.url).not.toContain('xxx')
      expect(event.url).not.toContain('yyy')
      expect(event.url).not.toContain('zzz')
      expect(event.url).toContain('keep=vvv')
      expect(event.request_url).not.toContain('xxx')
      expect(event.request_url).not.toContain('yyy')
      expect(event.request_url).not.toContain('zzz')
      expect(event.request_url).toContain('keep=vvv')
      expect(event.url_redacted_keys).toEqual(['query.api_key', 'query.sid', 'query.token'])
    })

    it('leaves benign URLs untouched (clean control)', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      const req = http.request(`${url}/api/chat?model=foo&temp=0.7`, { method: 'GET' }, () => {})
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.url).toBe('/api/chat?model=foo&temp=0.7')
      expect(event.request_url).toBe(`${url}/api/chat?model=foo&temp=0.7`)
      // Clean control: no redaction markers at all.
      expect(event.url_redacted_keys).toBeUndefined()
    })

    it('preserves URL-encoded values in non-sensitive keys', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      // name carries %20 (URL-encoded space) — must round-trip
      // through the searchParams rebuild.
      const req = http.request(`${url}/api?token=secret&name=hello%20world`, { method: 'GET' }, () => {})
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.url).toContain('name=hello%20world')
      expect(event.url).toContain('token=***')
      expect(event.url_redacted_keys).toEqual(['query.token'])
    })
  })

  describe('D4 invariant #6 leak fix (HTTP body redact)', () => {
    it('redacts form-urlencoded sensitive keys before emit', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      const formBody = 'token=secret-xyz&user=alice&password=hunter2'
      const req = http.request(
        `${url}/login`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(formBody),
          },
        },
        () => {},
      )
      req.write(formBody)
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.body).toContain('token=***')
      expect(event.body).toContain('password=***')
      expect(event.body).toContain('user=alice')
      expect(event.body).not.toContain('secret-xyz')
      expect(event.body).not.toContain('hunter2')
      expect(event.body_redacted_keys).toEqual(['body.password', 'body.token'])
    })

    it('redacts Bearer tokens in raw (non-JSON) bodies before emit', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      const rawBody = 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz'
      const req = http.request(
        `${url}/api/raw`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'text/plain',
            'Content-Length': Buffer.byteLength(rawBody),
          },
        },
        () => {},
      )
      req.write(rawBody)
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.body).not.toContain('abcdefghijklmnopqrstuvwxyz')
      expect(event.body).toContain('Bearer ***')
      expect(event.body_redacted_keys).toContain('body.bearer_token')
    })

    it('still handles JSON bodies correctly (regression guard)', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      const jsonBody = JSON.stringify({ api_key: 'super-secret', user: 'alice' })
      const req = http.request(
        `${url}/api/json`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(jsonBody),
          },
        },
        () => {},
      )
      req.write(jsonBody)
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.body).toContain('"api_key":"***"')
      expect(event.body).toContain('"user":"alice"')
      expect(event.body_redacted_keys).toContain('body.api_key')
    })

    it('leaves benign JSON bodies without sensitive keys untouched (clean control)', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const promise = waitForEvents(collector, 1)
      const jsonBody = JSON.stringify({ user: 'alice', age: 30 })
      const req = http.request(
        `${url}/api/clean`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(jsonBody),
          },
        },
        () => {},
      )
      req.write(jsonBody)
      req.end()

      const events = await promise
      server.close()
      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event.body).toBe(jsonBody)
      // Clean control: no redaction markers.
      expect(event.body_redacted_keys).toBeUndefined()
    })
  })

  // ---------------------------------------------------------------------------
  // E2-7: progressive multipart/form-data summary. Replaces the
  // legacy `'[FormData body]'` opaque placeholder with a bounded, JSON-
  // serialisable summary that walks fields with progressive truncation so a
  // 50-MiB upload writes a small audit row, not 50 MiB to NDJSON.
  // ---------------------------------------------------------------------------

  describe('E2-7 progressive multipart payload truncation', () => {
    it('summarises a text-only FormData fetch with a JSON-serialisable body', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const fd = new FormData()
      fd.set('username', 'alice')
      fd.set('comment', 'hello world')
      const promise = waitForEvents(collector, 1)
      await fetch(`${url}/upload`, { method: 'POST', body: fd })
      const events = await promise
      server.close()

      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      expect(event).toBeDefined()
      const parsed = JSON.parse(event.body as string)
      expect(parsed.kind).toBe('multipart_summary')
      expect(parsed.field_count).toBe(2)
      expect(parsed.blob_count).toBe(0)
      expect(parsed.fields.map((f: { name: string }) => f.name)).toEqual(['username', 'comment'])
    })

    it('summarises an upload with a Blob field, applying progressive truncation', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const fd = new FormData()
      fd.set('caption', 'vacation photo')
      fd.set('photo', new Blob(['A'.repeat(8192)], { type: 'image/png' }))
      const promise = waitForEvents(collector, 1)
      await fetch(`${url}/upload`, { method: 'POST', body: fd })
      const events = await promise
      server.close()

      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      const parsed = JSON.parse(event.body as string)
      expect(parsed.field_count).toBe(2)
      expect(parsed.blob_count).toBe(1)
      expect(parsed.blob_truncated_count).toBe(1)
      const blobField = parsed.fields.find((f: { name: string }) => f.name === 'photo')
      expect(blobField.kind).toBe('blob')
      expect(blobField.content_type).toBe('image/png')
      expect(blobField.original_size).toBe(8192)
      expect(blobField.truncated).toBe(true)
      // Preview bounded — not the full 8 KiB.
      expect(blobField.preview.length).toBeLessThanOrEqual(4096)
    })

    it('records filename when the Blob is a File', async () => {
      const { server, url } = await startTestServer()
      httpCapture = new NetworkHttpCollector(makeConfig(), { eventCollector: collector })
      httpCapture.install()

      const fd = new FormData()
      fd.set('doc', new File(['report content'], 'q3-report.pdf', { type: 'application/pdf' }))
      const promise = waitForEvents(collector, 1)
      await fetch(`${url}/upload`, { method: 'POST', body: fd })
      const events = await promise
      server.close()

      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      const parsed = JSON.parse(event.body as string)
      const fileField = parsed.fields[0]
      expect(fileField.filename).toBe('q3-report.pdf')
      expect(fileField.content_type).toBe('application/pdf')
    })

    it('respects maxBodyBytes on the assembled summary (bounded row)', async () => {
      const { server, url } = await startTestServer()
      // Tiny cap (256 B) — the assembled JSON must still fit under it via
      // limitPayloadSize on the final body. The helper itself returns the
      // full summary; captureFetchBody applies the cap before write.
      const tinyConfig = makeConfig({
        networkCapture: {
          ...makeConfig().networkCapture,
          maxBodyBytes: 256,
        },
      })
      httpCapture = new NetworkHttpCollector(tinyConfig, { eventCollector: collector })
      httpCapture.install()

      const fd = new FormData()
      fd.set('text', 'x'.repeat(1024))
      const promise = waitForEvents(collector, 1)
      await fetch(`${url}/upload`, { method: 'POST', body: fd })
      const events = await promise
      server.close()

      const event = events.find((e) => e.event_type === 'network_http' && e.direction === 'send')!
      // The body was truncated to fit maxBodyBytes=256 + suffix.
      const bodyLength = Buffer.byteLength(event.body as string, 'utf8')
      expect(bodyLength).toBeLessThanOrEqual(256 + '…[truncated]'.length + 8)
    })
  })
})
