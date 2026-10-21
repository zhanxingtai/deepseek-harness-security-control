/**
 * config livePatch 测试.
 *
 * Coverage matrix (re-classified against the 2026-09-22 Config surface):
 *
 *  classifyPatchKeys
 *    - 🟢 safe-apply: representative fields × default / non-default values
 *    - 🟡 restart-required: mode / hostId / containerId / path-ish fields /
 *      watcher knobs — returned, never applied
 * 🔴 rejected: every block's `enabled`, inlineGuards.*, unknown
 *      keys — any single one refuses the WHOLE apply + high-severity audit
 *    - warnings: blockAtSubprocess under audit mode, rejected-carrying patch
 *  mergePatchForValidation
 * empty-list re-assertion (patterns / keys), numeric fallback
 *      (recoverMarginBytes), enum fallback (failStrategy)
 *  LivePatchManager.apply
 *    - garbage input never throws (invariant #3)
 *    - rejected-only / mixed rejected → refused, untouched, high-sev audit
 *    - 🟡-only / mixed 🟡 → ok, needsRestart, values untouched
 *    - safe-only → applied, exactly one modify audit, validateEvent clean
 *    - end-to-end: blockAtSubprocess false→true hot-enforces at the spawn
 *      seam WITHOUT reinstall (the ticket's core scenario)
 *    - end-to-end: loopedToolDetector threshold drives the live detector
 *    - timer rebuild: flushIntervalMs swap keeps events flowing
 *    - serialization: concurrent applies queue in order
 *    - component throw → folded into ok:false (invariant #3)
 *    - draft orthogonality: applyLivePatch never writes the draft file
 *  component livePatch() units
 *    - sink / engine / network / app / runtimeHook each apply their own
 *      🟢 fields and bounce their 🟡 fields to needsRestartKeys
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { normalizeConfig, type Config } from '../src/config.js'
import {
  classifyPatchKeys,
  LivePatchManager,
  mergePatchForValidation,
} from '../src/config/livePatch.js'
import { resolveDraftPath } from '../src/config/draft.js'
import { validateEvent } from '../src/utils/schema.js'
import { LocalNdjsonSink } from '../src/collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../src/collectors/ApplicationCollector.js'
import { NetworkHttpCollector } from '../src/collectors/NetworkHttpCollector.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import {
  RuntimeHook,
  type RuntimeHookSessionContext,
} from '../src/intervention/RuntimeHook.js'
import type { InterventionEngine as InterventionEngineType } from '../src/intervention/InterventionEngine.js'
import type { SecurityDecision, SecurityEvent } from '../src/types/index.js'
import type { SubprocessRuntimeLike, SubprocessSpawnSpec } from '../src/types/external.js'

/** Capture-everything sink used as the manager's audit target. */
class StubSink {
  events: SecurityEvent[] = []
  report(event: SecurityEvent): void {
    this.events.push(event)
  }
  audits(): SecurityEvent[] {
    return this.events.filter((e) => e.event_type === 'security_audit')
  }
}

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    comm: 'sst-security-control-dsh',
    event_id: `evt-test-${Math.random().toString(36).slice(2)}`,
    event_type: 'plugin_startup',
    layer: 'application',
    ts: Date.now(),
    timestamp: Date.now(),
    pid: process.pid,
    collection_method: 'agent_api',
    host_id: 'test-host',
    container_id: 'host',
    session_id: '__plugin__',
    agent_id: '__plugin__',
    ...overrides,
  } as SecurityEvent
}

function writePolicy(tmpDir: string): string {
  const path = join(tmpDir, 'policy.json')
  writeFileSync(
    path,
    JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'livepatch-test-policy' },
      rules: [],
    }),
  )
  return path
}

function baseConfig(tmpDir: string, overrides: Record<string, unknown> = {}): Config {
  return normalizeConfig({
    mode: 'audit',
    collector: { localOutputPath: join(tmpDir, 'events.jsonl'), flushIntervalMs: 10 },
    intervention: { policyPath: writePolicy(tmpDir), reloadIntervalMs: 0 },
    ...overrides,
  })
}

/* ------------------------------------------------------------------ *
 * classifyPatchKeys                                                   *
 * ------------------------------------------------------------------ */

describe('classifyPatchKeys', () => {
  const config = normalizeConfig({})

  it('classifies a non-default 🟢 scalar as safe-apply', () => {
    const preview = classifyPatchKeys({ collector: { batchSize: 42 } }, config)
    expect(preview.ok).toBe(true)
    expect(preview.safeKeys).toEqual(['collector.batchSize'])
    expect(preview.needsRestartKeys).toEqual([])
    expect(preview.rejectedKeys).toEqual([])
  })

  it('classifies a default-value 🟢 scalar as safe-apply (value-agnostic)', () => {
    const preview = classifyPatchKeys({ collector: { batchSize: 100 } }, config)
    expect(preview.safeKeys).toEqual(['collector.batchSize'])
  })

  it('classifies 🟢 booleans and thresholds across every safe block', () => {
    const preview = classifyPatchKeys(
      {
        collector: { validateEvents: false, maxFileBytes: 1024, diskLowWatermarkBytes: 4096 },
        application: { captureReasoning: false, toolResultMaxChars: 500, sessionTtlMs: 60_000 },
        networkCapture: { redactBodies: false, maxBodyBytes: 2048, captureDns: true },
        intervention: { decisionTimeoutMs: 10, failStrategy: 'fail_closed' },
        runtimeHooks: { failOpenOnError: false, networkEnabled: false },
        sensitivePathGuard: { paths: ['~/custom-secret'] },
        inlinePromptInjection: { patterns: ['custom-pattern'], excerptMaxChars: 40 },
        stdioMirror: { payloadLimitBytes: 512 },
        envPassthroughGuard: { keys: ['CUSTOM_ENV'] },
        // 2026-09-28 config review fix: the block was unclassifiable (🔴)
        // before sensitiveHeaderGuard entered SAFE_FIELDS.
        sensitiveHeaderGuard: { keys: ['X-Custom-Auth'] },
        loopedToolDetector: { windowMs: 30_000, thresholdPerWindow: 5 },
        tokenUsageDetector: { windowMs: 120_000, burstFactor: 5, minBaselineSamples: 2 },
        sinkDiskLow: { recoverMarginBytes: 1024 },
      },
      config,
    )
    expect(preview.rejectedKeys).toEqual([])
    expect(preview.needsRestartKeys).toEqual([])
    expect(preview.safeKeys).toEqual([
      'application.captureReasoning',
      'application.sessionTtlMs',
      'application.toolResultMaxChars',
      'collector.diskLowWatermarkBytes',
      'collector.maxFileBytes',
      'collector.validateEvents',
      'envPassthroughGuard.keys',
      'inlinePromptInjection.excerptMaxChars',
      'inlinePromptInjection.patterns',
      'intervention.decisionTimeoutMs',
      'intervention.failStrategy',
      'loopedToolDetector.thresholdPerWindow',
      'loopedToolDetector.windowMs',
      'networkCapture.captureDns',
      'networkCapture.maxBodyBytes',
      'networkCapture.redactBodies',
      'runtimeHooks.failOpenOnError',
      'runtimeHooks.networkEnabled',
      'sensitiveHeaderGuard.keys',
      'sensitivePathGuard.paths',
      'sinkDiskLow.recoverMarginBytes',
      'stdioMirror.payloadLimitBytes',
      'tokenUsageDetector.burstFactor',
      'tokenUsageDetector.minBaselineSamples',
      'tokenUsageDetector.windowMs',
    ])
  })

  it('classifies timer-interval fields (flushIntervalMs / reloadIntervalMs) as safe-apply', () => {
    const preview = classifyPatchKeys(
      { collector: { flushIntervalMs: 250 }, intervention: { reloadIntervalMs: 5000 } },
      config,
    )
    expect(preview.safeKeys).toEqual(['collector.flushIntervalMs', 'intervention.reloadIntervalMs'])
  })

  it('classifies runtimeHooks.blockAtSubprocess / enabledAtSubprocess as safe-apply', () => {
    const preview = classifyPatchKeys(
      { runtimeHooks: { blockAtSubprocess: true, enabledAtSubprocess: true, excludeCommandLines: ['--quiet'] } },
      config,
    )
    expect(preview.safeKeys).toEqual([
      'runtimeHooks.blockAtSubprocess',
      'runtimeHooks.enabledAtSubprocess',
      'runtimeHooks.excludeCommandLines',
    ])
  })

  it('classifies mode / hostId / containerId as restart-required', () => {
    const preview = classifyPatchKeys({ mode: 'enforce', hostId: 'h2', containerId: 'c2' }, config)
    expect(preview.safeKeys).toEqual([])
    expect(preview.needsRestartKeys).toEqual(['containerId', 'hostId', 'mode'])
  })

  it('classifies path-holding fields as restart-required', () => {
    const preview = classifyPatchKeys(
      {
        collector: { localOutputPath: '/tmp/x.jsonl', debugLogPath: '/tmp/d.log' },
        runtimeHooks: { logPath: '/tmp/r.jsonl', hookPath: '/tmp/h.js' },
        intervention: { policyPath: '/tmp/p.yaml', policyPaths: ['/tmp/a.yaml'] },
        stdioMirror: { outputPath: '/tmp/m.jsonl' },
      },
      config,
    )
    expect(preview.safeKeys).toEqual([])
    expect(preview.needsRestartKeys).toEqual([
      'collector.debugLogPath',
      'collector.localOutputPath',
      'intervention.policyPath',
      'intervention.policyPaths',
      'runtimeHooks.hookPath',
      'runtimeHooks.logPath',
      'stdioMirror.outputPath',
    ])
  })

  it('classifies watcher knobs (watchEnabled / watchDebounceMs) as restart-required', () => {
    const preview = classifyPatchKeys(
      { sensitivePathGuard: { watchEnabled: false, watchDebounceMs: 100 } },
      config,
    )
    expect(preview.needsRestartKeys).toEqual([
      'sensitivePathGuard.watchDebounceMs',
      'sensitivePathGuard.watchEnabled',
    ])
  })

  it('classifies intervention.mode as restart-required', () => {
    const preview = classifyPatchKeys({ intervention: { mode: 'enforce' } }, config)
    expect(preview.needsRestartKeys).toEqual(['intervention.mode'])
  })

  it.each([
    ['top-level enabled', { enabled: false }],
    ['intervention.enabled', { intervention: { enabled: false } }],
    ['runtimeHooks.enabled', { runtimeHooks: { enabled: false } }],
    ['networkCapture.enabled', { networkCapture: { enabled: false } }],
    ['sensitivePathGuard.enabled', { sensitivePathGuard: { enabled: false } }],
    ['inlinePromptInjection.enabled', { inlinePromptInjection: { enabled: false } }],
    ['stdioMirror.enabled', { stdioMirror: { enabled: false } }],
    ['envPassthroughGuard.enabled', { envPassthroughGuard: { enabled: false } }],
    ['loopedToolDetector.enabled', { loopedToolDetector: { enabled: false } }],
    ['tokenUsageDetector.enabled', { tokenUsageDetector: { enabled: false } }],
  ])('classifies %s as rejected (self-protection switch)', (_label, patch) => {
    const preview = classifyPatchKeys(patch, config)
    expect(preview.rejectedKeys.length).toBeGreaterThan(0)
    expect(preview.safeKeys).toEqual([])
  })

  it.each([
    ['engineLaunchers', { inlineGuards: { engineLaunchers: ['custom dsh'] } }],
    ['pluginPackageName', { inlineGuards: { pluginPackageName: 'evil-plugin' } }],
    ['patchMarkers', { inlineGuards: { patchMarkers: ['x.patch.yml'] } }],
  ])('classifies inlineGuards.%s as rejected ( safety net)', (_label, patch) => {
    const preview = classifyPatchKeys(patch, config)
    expect(preview.rejectedKeys).toHaveLength(1)
    expect(preview.rejectedKeys[0]).toMatch(/^inlineGuards\./)
  })

  it('classifies unknown top-level keys and unknown sub-fields as rejected', () => {
    const preview = classifyPatchKeys({ bogusBlock: { x: 1 }, collector: { bogusField: 1 } }, config)
    expect(preview.rejectedKeys).toEqual(['bogusBlock', 'collector.bogusField'])
  })

  it('warns when blockAtSubprocess=true is requested under audit mode', () => {
    // 2026-10-10: the shared `config` fixture is normalizeConfig({}),
    // which defaults to 'enforce' after the Plan A default flip
    // (src/config.schema.ts:381). Construct an explicit-audit config
    // for this case so the warning still fires — the warning is
    // about a runtime-config mismatch, not about a default-mode
    // mismatch.
    const auditConfig = normalizeConfig({ mode: 'audit' })
    const preview = classifyPatchKeys({ runtimeHooks: { blockAtSubprocess: true } }, auditConfig)
    expect(preview.warnings.some((w) => w.includes('mode=audit'))).toBe(true)
    expect(preview.safeKeys).toEqual(['runtimeHooks.blockAtSubprocess'])
  })

  it('does not warn about audit mode when the current config is enforce', () => {
    const enforce = normalizeConfig({ mode: 'enforce' })
    const preview = classifyPatchKeys({ runtimeHooks: { blockAtSubprocess: true } }, enforce)
    expect(preview.warnings).toEqual([])
  })

  it('warns when a rejected-carrying patch is previewed', () => {
    const preview = classifyPatchKeys({ enabled: false }, config)
    expect(preview.warnings.some((w) => w.includes('refuse the whole patch'))).toBe(true)
  })

  it('flags fail_closed as a warning-worthy failStrategy', () => {
    const preview = classifyPatchKeys({ intervention: { failStrategy: 'fail_closed' } }, config)
    expect(preview.warnings.some((w) => w.includes('fail_closed'))).toBe(true)
  })

  it('classifies a mixed patch into all three buckets', () => {
    const preview = classifyPatchKeys(
      {
        collector: { batchSize: 7 },
        mode: 'enforce',
        runtimeHooks: { enabled: false },
      },
      config,
    )
    expect(preview.safeKeys).toEqual(['collector.batchSize'])
    expect(preview.needsRestartKeys).toEqual(['mode'])
    expect(preview.rejectedKeys).toEqual(['runtimeHooks.enabled'])
  })

  it('returns an empty classification for an empty patch', () => {
    const preview = classifyPatchKeys({}, config)
    expect(preview.ok).toBe(true)
    expect(preview.safeKeys).toEqual([])
    expect(preview.needsRestartKeys).toEqual([])
    expect(preview.rejectedKeys).toEqual([])
  })
})

/* ------------------------------------------------------------------ *
 * mergePatchForValidation                                             *
 * ------------------------------------------------------------------ */

describe('mergePatchForValidation', () => {
  it('re-asserts the hardcoded inline-prompt-injection catalogue on patterns:[]', () => {
    const config = normalizeConfig({})
    const merged = mergePatchForValidation(config, { inlinePromptInjection: { patterns: [] } })
    expect(merged.inlinePromptInjection.patterns.length).toBeGreaterThan(20)
    expect(merged.inlinePromptInjection.patterns).toEqual(config.inlinePromptInjection.patterns)
  })

  it('re-asserts the hardcoded env-passthrough deny-list on keys:[]', () => {
    const config = normalizeConfig({})
    const merged = mergePatchForValidation(config, { envPassthroughGuard: { keys: [] } })
    expect(merged.envPassthroughGuard.keys).toContain('LD_PRELOAD')
    expect(merged.envPassthroughGuard.keys).toEqual(config.envPassthroughGuard.keys)
  })

  it('re-asserts sensitivePathGuard.paths on empty input', () => {
    const config = normalizeConfig({})
    const merged = mergePatchForValidation(config, { sensitivePathGuard: { paths: [] } })
    expect(merged.sensitivePathGuard.paths).toContain('~/.ssh/')
  })

  it('falls back to the default recoverMarginBytes on negative input', () => {
    const config = normalizeConfig({})
    const merged = mergePatchForValidation(config, { sinkDiskLow: { recoverMarginBytes: -5 } })
    expect(merged.sinkDiskLow.recoverMarginBytes).toBe(50 * 1024 * 1024)
  })

  it('falls back to fail_open on an unknown failStrategy', () => {
    const config = normalizeConfig({})
    const merged = mergePatchForValidation(config, {
      intervention: { failStrategy: 'bogus' as unknown as 'fail_open' },
    })
    expect(merged.intervention.failStrategy).toBe('fail_open')
  })

  it('derives stdioMirror.outputPath from collector.localOutputPath when emptied', () => {
    // 2026-09-26): the stdio mirror now writes to the SAME
    // NDJSON file as the host plugin — wrapper events are interleaved
    // with host events on the same ts axis. Empty `outputPath` falls
    // back to `collector.localOutputPath` verbatim, NOT the historical
    // sibling `${localOutputPath}.stdio-mirror.jsonl`.
    const config = normalizeConfig({ collector: { localOutputPath: '/tmp/base.jsonl' } })
    const merged = mergePatchForValidation(config, { stdioMirror: { outputPath: '' } })
    expect(merged.stdioMirror.outputPath).toBe('/tmp/base.jsonl')
  })

  it('does not mutate the input Config', () => {
    const config = normalizeConfig({ collector: { batchSize: 11 } })
    mergePatchForValidation(config, { collector: { batchSize: 99 } })
    expect(config.collector.batchSize).toBe(11)
  })
})

/* ------------------------------------------------------------------ *
 * LivePatchManager.apply — full-component harness                     *
 * ------------------------------------------------------------------ */

describe('LivePatchManager.apply', () => {
  let tmpDir: string
  let config: Config
  let sink: LocalNdjsonSink
  let engine: InterventionEngineType
  let app: ApplicationCollector
  let network: NetworkHttpCollector
  let hook: RuntimeHook
  let stub: StubSink
  let manager: LivePatchManager

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'livepatch-'))
    config = baseConfig(tmpDir)
    sink = new LocalNdjsonSink(config, { logger: { log: () => {}, warn: () => {}, error: () => {} } })
    sink.initialize()
    engine = new InterventionEngine(config, { builtinRulePaths: [] })
    engine.initialize()
    app = new ApplicationCollector(config, sink, engine, {
      logger: { warn: () => {}, error: () => {} },
    })
    app.initialize()
    network = new NetworkHttpCollector(config, { eventCollector: sink })
    hook = new RuntimeHook({
      eventCollector: sink,
      interventionEngine: engine,
      runtimeHookConfig: config.runtimeHooks,
      inlineGuards: config.inlineGuards,
      mode: config.mode,
      sessionResolve: () => undefined,
    })
    stub = new StubSink()
    manager = new LivePatchManager({
      config,
      sink: stub,
      components: [sink, engine, app, network, hook],
      operator: 'tester',
    })
  })

  afterEach(() => {
    app.shutdown()
    engine.shutdown()
    sink.shutdown()
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('refuses garbage input without throwing (invariant #3)', async () => {
    for (const garbage of [null, undefined, 42, 'patch', [1, 2]]) {
      const result = await manager.apply(garbage)
      expect(result.ok).toBe(false)
      expect(result.error).toBeTruthy()
    }
    expect(stub.events).toEqual([])
  })

  it('refuses a rejected-carrying patch as a whole and leaves config untouched', async () => {
    const before = config.runtimeHooks.blockAtSubprocess
    const result = await manager.apply({
      runtimeHooks: { blockAtSubprocess: true, enabled: false },
    })
    expect(result.ok).toBe(false)
    expect(result.rejectedKeys).toEqual(['runtimeHooks.enabled'])
    // The 🟢 sibling key in the SAME patch must not slip through.
    expect(result.appliedKeys).toEqual([])
    expect(config.runtimeHooks.blockAtSubprocess).toBe(before)
  })

  it('emits exactly one high-severity security_audit when a rejected key is attempted', async () => {
    const result = await manager.apply({ enabled: false })
    expect(result.ok).toBe(false)
    const audits = stub.audits()
    expect(audits).toHaveLength(1)
    const audit = audits[0]!
    expect(audit.audit_category).toBe('config')
    expect(audit.audit_action).toBe('deny')
    expect(audit.severity).toBe('high')
    expect(audit.outcome).toBe('blocked')
    expect(audit.reason).toBe('deny')
    expect(validateEvent(audit)).toEqual([])
    const details = audit.audit_details as Record<string, unknown>
    expect(details['rejected_keys']).toEqual(['enabled'])
    expect(details['operator']).toBe('tester')
  })

  it('emits a modify audit with applied keys + operator on success', async () => {
    const result = await manager.apply({ collector: { batchSize: 42 } })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual(['collector.batchSize'])
    expect(config.collector.batchSize).toBe(42)
    const audits = stub.audits()
    expect(audits).toHaveLength(1)
    const audit = audits[0]!
    expect(audit.audit_category).toBe('config')
    expect(audit.audit_action).toBe('modify')
    expect(audit.outcome).toBe('success')
    expect(validateEvent(audit)).toEqual([])
    const details = audit.audit_details as Record<string, unknown>
    expect(details['applied_keys']).toEqual(['collector.batchSize'])
    expect(details['operator']).toBe('tester')
  })

  it('applies 🟡-only patches as ok with needsRestart and leaves values untouched', async () => {
    const beforeMode = config.mode
    const beforePolicy = config.intervention.policyPath
    const result = await manager.apply({ mode: 'enforce', intervention: { policyPath: '/tmp/other.yaml' } })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual([])
    expect(result.needsRestartKeys).toEqual(['intervention.policyPath', 'mode'])
    expect(config.mode).toBe(beforeMode)
    expect(config.intervention.policyPath).toBe(beforePolicy)
  })

  it('applies the 🟢 subset of a mixed patch and reports the 🟡 remainder', async () => {
    const result = await manager.apply({
      collector: { batchSize: 77 },
      mode: 'enforce',
      sensitivePathGuard: { watchEnabled: false },
    })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual(['collector.batchSize'])
    expect(result.needsRestartKeys).toEqual(['mode', 'sensitivePathGuard.watchEnabled'])
    expect(config.collector.batchSize).toBe(77)
    expect(config.mode).toBe('audit')
    expect(config.sensitivePathGuard.watchEnabled).toBe(true)
  })

  it('fails cleanly when a sub-block is not an object (schema-shape error)', async () => {
    const result = await manager.apply({ collector: 'not-an-object' })
    expect(result.ok).toBe(false)
    expect(result.error).toMatch(/collector/)
    expect(stub.events).toEqual([])
  })

  it('folds a throwing component into ok:false instead of throwing (invariant #3)', async () => {
    const managerWithBadComponent = new LivePatchManager({
      config,
      sink: stub,
      components: [
        {
          livePatch: () => {
            throw new Error('component exploded')
          },
        },
      ],
      operator: 'tester',
    })
    const result = await managerWithBadComponent.apply({ collector: { batchSize: 5 } })
    expect(result.ok).toBe(false)
    expect(result.error).toMatch(/component exploded/)
  })

  it('serializes concurrent applies (promise-chain mutex)', async () => {
    const first = manager.apply({ collector: { batchSize: 42 } })
    const second = manager.apply({ collector: { batchSize: 77 } })
    const [r1, r2] = await Promise.all([first, second])
    expect(r1.ok).toBe(true)
    expect(r2.ok).toBe(true)
    expect(config.collector.batchSize).toBe(77)
    // Two successful applies → two modify audits, in invocation order.
    const audits = stub.audits()
    expect(audits).toHaveLength(2)
    expect((audits[0]!.audit_details as Record<string, unknown>)['applied_keys']).toEqual([
      'collector.batchSize',
    ])
  })

  it('preview is pure: no config mutation, no audit emission', () => {
    const before = config.collector.batchSize
    const preview = manager.preview({ collector: { batchSize: 4242 } })
    expect(preview.ok).toBe(true)
    expect(preview.safeKeys).toEqual(['collector.batchSize'])
    expect(config.collector.batchSize).toBe(before)
    expect(stub.events).toEqual([])
  })

  it('preview surfaces rejected keys with ok=false', () => {
    const preview = manager.preview({ loopedToolDetector: { enabled: false } })
    expect(preview.ok).toBe(false)
    expect(preview.rejectedKeys).toEqual(['loopedToolDetector.enabled'])
  })

  it('applies networkCapture arrays and rebuilds the derived host matcher state', async () => {
    const result = await manager.apply({ networkCapture: { includeHosts: ['Example.COM'] } })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual(['networkCapture.includeHosts'])
    const derived = network as unknown as { includeHosts: Set<string> }
    expect([...derived.includeHosts]).toEqual(['example.com'])
  })

  it('applies detector thresholds that the live loop detector then honours', async () => {
    const result = await manager.apply({ loopedToolDetector: { thresholdPerWindow: 3, windowMs: 10_000 } })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual([
      'loopedToolDetector.thresholdPerWindow',
      'loopedToolDetector.windowMs',
    ])
    const detector = app as unknown as {
      loopedToolDetector: { record: (tool: string, session: string, ts: number) => unknown }
    }
    // 3-threshold: the 4th call inside the window must fire.
    let hit: unknown = null
    for (let i = 1; i <= 4; i++) {
      const current = detector.loopedToolDetector.record('bash', 's1', 1_000 + i)
      if (current) hit = current
    }
    expect(hit).not.toBeNull()
  })

  it('applies tokenUsageDetector thresholds onto the live detector config', async () => {
    const result = await manager.apply({ tokenUsageDetector: { burstFactor: 9, minBaselineSamples: 1 } })
    expect(result.ok).toBe(true)
    const detector = app as unknown as { tokenUsageDetector: { config: { burstFactor: number; minBaselineSamples: number } } }
    expect(detector.tokenUsageDetector.config.burstFactor).toBe(9)
    expect(detector.tokenUsageDetector.config.minBaselineSamples).toBe(1)
  })

  it('applies intervention thresholds onto the live engine config', async () => {
    const result = await manager.apply({
      intervention: { decisionTimeoutMs: 5, failStrategy: 'fail_closed' },
    })
    expect(result.ok).toBe(true)
    expect(config.intervention.decisionTimeoutMs).toBe(5)
    expect(config.intervention.failStrategy).toBe('fail_closed')
  })

  it('applies inline-guard deny-list extensions on the shared config', async () => {
    const result = await manager.apply({
      sensitivePathGuard: { paths: ['~/custom-vault/'] },
      inlinePromptInjection: { excerptMaxChars: 33 },
      envPassthroughGuard: { keys: ['CUSTOM_DANGER'] },
      sensitiveHeaderGuard: { keys: ['X-Custom-Auth'] },
    })
    expect(result.ok).toBe(true)
    // deny-list is UNION — operator entries extend the
    // marketplace baseline. The shared config now carries BOTH the
    // baseline and the operator addition.
    expect(config.sensitivePathGuard.paths).toContain('~/custom-vault/')
    expect(config.sensitivePathGuard.paths).toContain('~/.ssh/')
    expect(config.inlinePromptInjection.excerptMaxChars).toBe(33)
    expect(config.envPassthroughGuard.keys).toContain('CUSTOM_DANGER')
    expect(config.envPassthroughGuard.keys).toContain('LD_PRELOAD')
    expect(config.sensitiveHeaderGuard.keys).toContain('X-Custom-Auth')
    expect(config.sensitiveHeaderGuard.keys).toContain('Authorization')
  })

  it('applies sinkDiskLow.recoverMarginBytes on the shared config', async () => {
    const result = await manager.apply({ sinkDiskLow: { recoverMarginBytes: 1234 } })
    expect(result.ok).toBe(true)
    expect(config.sinkDiskLow.recoverMarginBytes).toBe(1234)
  })

  it('applies application thresholds and rebuilds the session TTL timer', async () => {
    const timerBefore = (app as unknown as { ttlTimer: unknown }).ttlTimer
    const result = await manager.apply({ application: { sessionTtlMs: 120_000, toolResultMaxChars: 9 } })
    expect(result.ok).toBe(true)
    expect(config.application.sessionTtlMs).toBe(120_000)
    expect(config.application.toolResultMaxChars).toBe(9)
    expect((app as unknown as { ttlTimer: unknown }).ttlTimer).not.toBe(timerBefore)
  })

  it('rebuilds the sink flush timer on flushIntervalMs without losing events', async () => {
    sink.report(makeEvent({ event_id: 'evt-before-patch' }))
    const timerBefore = (sink as unknown as { flushTimer: unknown }).flushTimer
    const result = await manager.apply({ collector: { flushIntervalMs: 250 } })
    expect(result.ok).toBe(true)
    expect(config.collector.flushIntervalMs).toBe(250)
    expect((sink as unknown as { flushTimer: unknown }).flushTimer).not.toBe(timerBefore)
    sink.report(makeEvent({ event_id: 'evt-after-patch' }))
    const lines = readFileSync(join(tmpDir, 'events.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
    const ids = lines.map((l) => (JSON.parse(l) as { event_id?: string }).event_id)
    expect(ids).toContain('evt-before-patch')
    expect(ids).toContain('evt-after-patch')
  })

  it('rebuilds the engine watcher + GC cadence on reloadIntervalMs', async () => {
    const watcherBefore = (engine as unknown as { policyWatcher: unknown }).policyWatcher
    const result = await manager.apply({ intervention: { reloadIntervalMs: 60_000 } })
    expect(result.ok).toBe(true)
    expect(config.intervention.reloadIntervalMs).toBe(60_000)
    expect((engine as unknown as { policyWatcher: unknown }).policyWatcher).not.toBe(watcherBefore)
    // Engine still functional after the rebuild.
    expect(engine.requestReload().ok).toBe(true)
  })

  it('is orthogonal to the config draft: applyLivePatch never writes the draft file', async () => {
    const originalHome = process.env['HOME']
    process.env['HOME'] = tmpDir
    try {
      const result = await manager.apply({ collector: { batchSize: 55 } })
      expect(result.ok).toBe(true)
      expect(existsSync(resolveDraftPath())).toBe(false)
    } finally {
      if (originalHome === undefined) delete process.env['HOME']
      else process.env['HOME'] = originalHome
    }
  })
})

/* ------------------------------------------------------------------ *
 * Core scenario: blockAtSubprocess false → true WITHOUT restart       *
 * ------------------------------------------------------------------ */

describe('applyLivePatch: blockAtSubprocess hot-upgrade at the spawn seam', () => {
  let config: Config
  let tmpDir: string
  let hook: RuntimeHook
  let stub: StubSink
  let target: SubprocessRuntimeLike & { spawnCalls: SubprocessSpawnSpec[] }

  const sessionResolve = (): RuntimeHookSessionContext | undefined => undefined

  function makeRuntime(): SubprocessRuntimeLike & { spawnCalls: SubprocessSpawnSpec[]; terminated: number } {
    const calls: SubprocessSpawnSpec[] = []
    const extended = { spawnCalls: calls, terminated: 0 } as SubprocessRuntimeLike & {
      spawnCalls: SubprocessSpawnSpec[]
      terminated: number
    }
    const rt: SubprocessRuntimeLike = {
      // the real harness spawn returns a handle synchronously.
      spawn(spec) {
        calls.push(spec)
        return {
          done: Promise.resolve({ exitCode: 0, signal: null }),
          terminate: () => { extended.terminated++ },
          waitForExit: async () => true,
        }
      },
    }
    return Object.assign(extended, rt)
  }

  function blockEngine(): InterventionEngineType {
    const decision: SecurityDecision = {
      decision: 'block',
      mode: 'enforce',
      block_reason: 'blocked by test policy',
      block_code: 'TEST_042',
      latency_ms: 1,
    }
    return { evaluate: async () => decision } as unknown as InterventionEngineType
  }

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'livepatch-hook-'))
    config = baseConfig(tmpDir, { mode: 'enforce' })
    stub = new StubSink()
    target = makeRuntime()
    hook = new RuntimeHook({
      eventCollector: stub as unknown as LocalNdjsonSink,
      interventionEngine: blockEngine(),
      runtimeHookConfig: config.runtimeHooks,
      inlineGuards: config.inlineGuards,
      mode: config.mode,
      sessionResolve,
    })
    hook.install(target)
  })

  afterEach(() => {
    hook.uninstall()
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('audit posture before the patch: block decision does NOT abort the spawn', async () => {
    expect(config.runtimeHooks.blockAtSubprocess).toBe(false)
    const spec: SubprocessSpawnSpec = { argv: ['node', 'server.js'], cwd: tmpDir }
    await Promise.resolve(hook.wrap(spec))
    expect(target.spawnCalls).toHaveLength(1)
  })

  /**
   * an SPL `block` decision arrives after the synchronous
   * passthrough, so the hot-upgraded enforce posture shows up as
   * post-spawn enforcement (denied event + best-effort terminate) rather
   * than a pre-fork throw. The property under test is unchanged: the
   * SAME installed wrapper picks up `blockAtSubprocess: true` on the very
   * next wrap — no reinstall.
   */
  it('flipping blockAtSubprocess via applyLivePatch enforces on the very next wrap — no reinstall', async () => {
    const spec: SubprocessSpawnSpec = { argv: ['node', 'server.js'], cwd: tmpDir }
    const manager = new LivePatchManager({
      config,
      sink: stub,
      components: [hook],
      operator: 'tester',
    })
    const result = await manager.apply({ runtimeHooks: { blockAtSubprocess: true } })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual(['runtimeHooks.blockAtSubprocess'])
    expect(config.runtimeHooks.blockAtSubprocess).toBe(true)
    // Same installed wrapper, new behaviour: wrap still returns the handle
    // synchronously, and the background SPL block now terminates the child.
    const handle = hook.wrap(spec)
    expect(typeof (handle as { then?: unknown }).then).not.toBe('function')
    await new Promise<void>((r) => setImmediate(r))
    expect(target.spawnCalls).toHaveLength(1)
    expect(target.terminated).toBe(1)
    // And the denial is audited through the sink.
    expect(stub.events.some((e) => e.event_type === 'runtime_spawn_denied')).toBe(true)
  })

  it('flipping failOpenOnError via applyLivePatch is visible on the shared config', async () => {
    const manager = new LivePatchManager({
      config,
      sink: stub,
      components: [hook],
    })
    const result = await manager.apply({ runtimeHooks: { failOpenOnError: false } })
    expect(result.ok).toBe(true)
    expect(config.runtimeHooks.failOpenOnError).toBe(false)
  })

  it('a rejected key mixed into the blockAtSubprocess patch refuses the whole upgrade', async () => {
    const manager = new LivePatchManager({
      config,
      sink: stub,
      components: [hook],
    })
    const result = await manager.apply({
      runtimeHooks: { blockAtSubprocess: true, enabled: false },
    })
    expect(result.ok).toBe(false)
    expect(config.runtimeHooks.blockAtSubprocess).toBe(false)
    const spec: SubprocessSpawnSpec = { argv: ['node', 'server.js'], cwd: tmpDir }
    await Promise.resolve(hook.wrap(spec))
    expect(target.spawnCalls).toHaveLength(1)
  })
})

/* ------------------------------------------------------------------ *
 * Component-level livePatch() units                                   *
 * ------------------------------------------------------------------ */

describe('component livePatch units', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'livepatch-unit-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  it('LocalNdjsonSink.livePatch applies 🟢 fields, rebuilds the flush timer, bounces 🟡 keys', () => {
    const config = baseConfig(tmpDir)
    const sink = new LocalNdjsonSink(config, { logger: { log: () => {}, warn: () => {}, error: () => {} } })
    sink.initialize()
    try {
      const timerBefore = (sink as unknown as { flushTimer: unknown }).flushTimer
      const result = sink.livePatch({
        collector: {
          batchSize: 12,
          validateEvents: false,
          maxFileBytes: 2048,
          diskWarnWatermarkBytes: 111,
          diskLowWatermarkBytes: 222,
          redactRawParams: false,
          flushIntervalMs: 999,
          localOutputPath: '/tmp/elsewhere.jsonl',
          debugLogPath: '/tmp/dbg.log',
        },
        sinkDiskLow: { recoverMarginBytes: 4321 },
      })
      expect(result.ok).toBe(true)
      // `redactRawParams` is no longer in the
      // safe-apply set — the marketplace hardcodes it to true.
      expect(result.appliedKeys).toEqual([
        'collector.batchSize',
        'collector.diskLowWatermarkBytes',
        'collector.diskWarnWatermarkBytes',
        'collector.flushIntervalMs',
        'collector.maxFileBytes',
        'collector.validateEvents',
        'sinkDiskLow.recoverMarginBytes',
      ])
      expect(result.needsRestartKeys).toEqual([
        'collector.debugLogPath',
        'collector.localOutputPath',
      ])
      expect(config.collector.batchSize).toBe(12)
      expect(config.collector.flushIntervalMs).toBe(999)
      expect(config.sinkDiskLow.recoverMarginBytes).toBe(4321)
      // Path values untouched.
      expect(config.collector.localOutputPath).not.toBe('/tmp/elsewhere.jsonl')
      // Timer really rebuilt.
      expect((sink as unknown as { flushTimer: unknown }).flushTimer).not.toBe(timerBefore)
    } finally {
      sink.shutdown()
    }
  })

  it('InterventionEngine.livePatch applies thresholds, rebuilds watcher, bounces policyPath', () => {
    const config = baseConfig(tmpDir)
    const engine = new InterventionEngine(config, { builtinRulePaths: [] })
    engine.initialize()
    try {
      const watcherBefore = (engine as unknown as { policyWatcher: unknown }).policyWatcher
      const result = engine.livePatch({
        intervention: {
          decisionTimeoutMs: 3,
          failStrategy: 'fail_open_high_risk_only',
          reloadIntervalMs: 45_000,
          policyPath: '/tmp/other-policy.yaml',
          policyPaths: ['/tmp/a.yaml'],
        },
      })
      expect(result.ok).toBe(true)
      expect(result.appliedKeys).toEqual([
        'intervention.decisionTimeoutMs',
        'intervention.failStrategy',
        'intervention.reloadIntervalMs',
      ])
      expect(result.needsRestartKeys).toEqual(['intervention.policyPath', 'intervention.policyPaths'])
      expect(config.intervention.decisionTimeoutMs).toBe(3)
      expect(config.intervention.failStrategy).toBe('fail_open_high_risk_only')
      expect(config.intervention.reloadIntervalMs).toBe(45_000)
      expect((engine as unknown as { policyWatcher: unknown }).policyWatcher).not.toBe(watcherBefore)
      expect(engine.requestReload().ok).toBe(true)
    } finally {
      engine.shutdown()
    }
  })

  it('NetworkHttpCollector.livePatch rebuilds derived matcher state and ignores bad types', () => {
    const config = baseConfig(tmpDir)
    const collector = new NetworkHttpCollector(config, {
      eventCollector: new StubSink() as unknown as LocalNdjsonSink,
    })
    const result = collector.livePatch({
      networkCapture: {
        excludeHosts: ['Evil.EXAMPLE'],
        sensitiveKeyPatterns: ['secret_token'],
        maxBodyBytes: 4096,
        captureDns: true,
        redactBodies: false,
        captureResponseBody: false,
        sseSummaryChunks: 2,
        sseSummaryLastChunks: 0,
        includeHosts: ['api.internal'],
        excludeUrls: ['^/health'],
      },
    })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual([
      'networkCapture.captureDns',
      'networkCapture.captureResponseBody',
      'networkCapture.excludeHosts',
      'networkCapture.excludeUrls',
      'networkCapture.includeHosts',
      'networkCapture.maxBodyBytes',
      'networkCapture.redactBodies',
      'networkCapture.sensitiveKeyPatterns',
      'networkCapture.sseSummaryChunks',
      'networkCapture.sseSummaryLastChunks',
    ])
    const probe = collector as unknown as {
      excludeHosts: Set<string>
      includeHosts: Set<string>
      sensitiveKeyPatterns: string[]
      excludeUrlRegexps: RegExp[]
    }
    expect([...probe.excludeHosts]).toEqual(['evil.example'])
    expect([...probe.includeHosts]).toEqual(['api.internal'])
    expect(probe.sensitiveKeyPatterns).toContain('secret_token')
    expect(probe.excludeUrlRegexps[0]!.test('/health')).toBe(true)
    expect(config.networkCapture.maxBodyBytes).toBe(4096)
    // 2026-09-28 config review fix: sensitiveHeaderGuard.keys must be
    // applied by this component (classifier marks it 🟢).
    const shgResult = collector.livePatch({ sensitiveHeaderGuard: { keys: ['X-Custom-Auth'] } })
    expect(shgResult.ok).toBe(true)
    expect(shgResult.appliedKeys).toEqual(['sensitiveHeaderGuard.keys'])
    expect(config.sensitiveHeaderGuard.keys).toContain('X-Custom-Auth')
    // Bad-typed values are ignored, not coerced.
    const before = config.networkCapture.maxBodyBytes
    const ignored = collector.livePatch({ networkCapture: { maxBodyBytes: 'huge' as unknown as number } })
    expect(ignored.ok).toBe(true)
    expect(config.networkCapture.maxBodyBytes).toBe(before)
  })

  it('NetworkHttpCollector.livePatch rebuilds derived matcher state on subsequent array livePatch (   regression)', () => {
    // verify a SECOND livePatch that touches only one of the
    // array fields still rebuilds the derived matcher state, not just the
    // first one. The `appliedKeys.some(...)` branch in `livePatch()`
    // must re-fire on every patch that mutates a list field — a single
    // missed rebuild means the runtime matcher serves the OLD list.
    const config = baseConfig(tmpDir)
    const collector = new NetworkHttpCollector(config, {
      eventCollector: new StubSink() as unknown as LocalNdjsonSink,
    })
    // Pre-seed with a different excludeUrls so we can observe the rebuild.
    collector.livePatch({
      networkCapture: { excludeUrls: ['^/v1/health$'] },
    })
    const probe = collector as unknown as {
      excludeUrlRegexps: RegExp[]
    }
    expect(probe.excludeUrlRegexps).toHaveLength(1)
    expect(probe.excludeUrlRegexps[0]!.test('/v1/health')).toBe(true)
    expect(probe.excludeUrlRegexps[0]!.test('/v2/health')).toBe(false)
    // Second patch: only excludeUrls again, with a new pattern. Must
    // rebuild — a stale matcher would still match `/v1/health` and miss
    // the new `/v2/health` pattern.
    collector.livePatch({
      networkCapture: { excludeUrls: ['^/v2/health$'] },
    })
    expect(probe.excludeUrlRegexps).toHaveLength(1)
    expect(probe.excludeUrlRegexps[0]!.test('/v1/health')).toBe(false)
    expect(probe.excludeUrlRegexps[0]!.test('/v2/health')).toBe(true)
  })

  it('ApplicationCollector.livePatch applies thresholds + guard lists, ignores foreign blocks', () => {
    const config = baseConfig(tmpDir)
    const sink = new LocalNdjsonSink(config, { logger: { log: () => {}, warn: () => {}, error: () => {} } })
    const app = new ApplicationCollector(config, sink, undefined, {
      logger: { warn: () => {}, error: () => {} },
    })
    app.initialize()
    try {
      const timerBefore = (app as unknown as { ttlTimer: unknown }).ttlTimer
      const result = app.livePatch({
        application: { captureUserPrompt: false, sessionTtlMs: 90_000 },
        loopedToolDetector: { windowMs: 5000, thresholdPerWindow: 2 },
        tokenUsageDetector: { windowMs: 7000, burstFactor: 4, minBaselineSamples: 1 },
        sensitivePathGuard: { paths: ['~/vault/'] },
        inlinePromptInjection: { patterns: ['x'], excerptMaxChars: 11 },
        envPassthroughGuard: { keys: ['X_DANGER'] },
        // Foreign block: must be ignored (belongs to other components).
        runtimeHooks: { blockAtSubprocess: true },
      })
      expect(result.ok).toBe(true)
      expect(result.appliedKeys).toEqual([
        'application.captureUserPrompt',
        'application.sessionTtlMs',
        'envPassthroughGuard.keys',
        'inlinePromptInjection.excerptMaxChars',
        'inlinePromptInjection.patterns',
        'loopedToolDetector.thresholdPerWindow',
        'loopedToolDetector.windowMs',
        'sensitivePathGuard.paths',
        'tokenUsageDetector.burstFactor',
        'tokenUsageDetector.minBaselineSamples',
        'tokenUsageDetector.windowMs',
      ])
      expect(config.application.captureUserPrompt).toBe(false)
      expect(config.application.sessionTtlMs).toBe(90_000)
      expect(config.loopedToolDetector.thresholdPerWindow).toBe(2)
      expect(config.tokenUsageDetector.burstFactor).toBe(4)
      expect(config.sensitivePathGuard.paths).toEqual(['~/vault/'])
      expect(config.envPassthroughGuard.keys).toEqual(['X_DANGER'])
      expect((app as unknown as { ttlTimer: unknown }).ttlTimer).not.toBe(timerBefore)
    } finally {
      app.shutdown()
    }
  })

  /**
   * with the synchronous passthrough, deps.mode snapshot sync shows
   * up as post-spawn enforcement (denied event + best-effort terminate),
   * not a rejected Promise — wrap returns the handle synchronously.
   */
  it('RuntimeHook.livePatch syncs the deps.mode snapshot', async () => {
    const config = baseConfig(tmpDir)
    const sink = new StubSink()
    let terminated = 0
    const hook = new RuntimeHook({
      eventCollector: sink as unknown as LocalNdjsonSink,
      interventionEngine: {
        evaluate: async () => ({ decision: 'block', mode: 'enforce', latency_ms: 1 }) as SecurityDecision,
      } as unknown as InterventionEngineType,
      runtimeHookConfig: config.runtimeHooks,
      inlineGuards: config.inlineGuards,
      mode: config.mode,
      sessionResolve: () => undefined,
    })
    const result = hook.livePatch({ mode: 'enforce', runtimeHooks: { blockAtSubprocess: true } })
    expect(result.ok).toBe(true)
    expect(result.appliedKeys).toEqual(['mode', 'runtimeHooks.blockAtSubprocess'])
    // deps.mode was 'audit' at construction; the snapshot must now be
    // enforce — the block decision must produce post-spawn enforcement.
    const target: SubprocessRuntimeLike = {
      spawn: () => ({
        done: Promise.resolve({ exitCode: 0, signal: null }),
        terminate: () => { terminated++ },
        waitForExit: async () => true,
      }),
    }
    hook.install(target)
    try {
      const spec: SubprocessSpawnSpec = { argv: ['x'], cwd: tmpDir }
      const handle = hook.wrap(spec)
      expect(typeof (handle as { then?: unknown }).then).not.toBe('function')
      await new Promise<void>((r) => setImmediate(r))
      expect(terminated).toBe(1)
      expect(sink.events.some((e) => e.event_type === 'runtime_spawn_denied')).toBe(true)
    } finally {
      hook.uninstall()
    }
  })
})

/* ------------------------------------------------------------------ *
 * A-L3 (2026-09-25) — timer / watcher rebuild order                   *
 * ------------------------------------------------------------------ *
 * Closes two related defects:
 *   1. The three timer-interval fields (flushIntervalMs / sessionTtlMs
 *      / reloadIntervalMs) used to accept negative-or-zero values.
 *      Node's setInterval clamps non-positive intervals to 1ms — a
 *      re-applied 0/-1 would silently degrade the cadence to CPU-spin
 *      speed while the audit trail recorded "applied", making the
 *      regression invisible to operators. The fix tightens the
 *      guards to require `> 0` (reloadIntervalMs stays `>= 0` since
 *      0 is its explicit "disable GC timer" sentinel).
 *   2. InterventionEngine.reloadIntervalMs livePatch used to close
 *      the OLD watcher BEFORE building the new one — if the new
 *      build/start path threw, the engine was left with `policyWatcher
 *      === undefined` and silently lost policy reload detection until
 *      the next livePatch. The atomic-swap order (build-new →
 *      start-new → swap-reference → close-old) keeps the OLD watcher
 *      alive across any throw in the new path. */
describe('livePatch — timer / watcher rebuild order (A-L3, 2026-09-25)', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-l3-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function writePolicy(dir: string): string {
    const path = join(dir, 'p.yaml')
    writeFileSync(path, 'apiVersion: security.use/v2\nkind: Policy\nrules: []\n')
    return path
  }

  function baseConfig(): Config {
    return normalizeConfig({
      collector: {
        localOutputPath: join(tmpDir, 'events.jsonl'),
        flushIntervalMs: 200,
      },
      intervention: { policyPath: writePolicy(tmpDir), reloadIntervalMs: 5_000 },
    })
  }

  // No-op "no-op policy path" — engine.evaluate never invoked here.
  const stubPolicyPath = (): string => writePolicy(tmpDir)

  it('rejects negative-or-zero flushIntervalMs (CPU-spin clamp)', () => {
    const config = baseConfig()
    const sink = new LocalNdjsonSink(config)
    sink.initialize()
    try {
      const before = config.collector.flushIntervalMs
      for (const bad of [0, -1, -1000, Number.NEGATIVE_INFINITY]) {
        const result = sink.livePatch({ collector: { flushIntervalMs: bad } })
        // Config must NOT have been mutated by the bad value.
        expect(config.collector.flushIntervalMs).toBe(before)
        // Either the result rolled it back via needsRestart or it was
        // simply not applied; what matters is the field is unchanged.
        void result
      }
    } finally {
      sink.shutdown()
    }
  })

  it('rejects negative-or-zero sessionTtlMs', () => {
    const config = baseConfig()
    const collector = new ApplicationCollector(config, new LocalNdjsonSink(config))
    collector.initialize()
    try {
      const before = (config.application as unknown as { sessionTtlMs: number }).sessionTtlMs
      for (const bad of [0, -1, -1000]) {
        const result = collector.livePatch({ application: { sessionTtlMs: bad } })
        expect((config.application as unknown as { sessionTtlMs: number }).sessionTtlMs).toBe(before)
        // Negative Ttl never reaches the timer (the ttlTimer is built
        // with Math.max(value/2, 1000), but the livePatch guard now
        // rejects the bad value before either config or timer mutate).
        expect(result.appliedKeys).not.toContain('application.sessionTtlMs')
        void result
      }
    } finally {
      collector.shutdown()
    }
  })

  it('rejects negative reloadIntervalMs but accepts 0 (disable sentinel)', () => {
    const config = baseConfig()
    const engine = new InterventionEngine(config, { builtinRulePaths: [] })
    engine.initialize()
    try {
      // Negative is rejected outright.
      const negResult = engine.livePatch({ intervention: { reloadIntervalMs: -1 } })
      expect(config.intervention.reloadIntervalMs).toBe(5_000)
      expect(negResult.appliedKeys).not.toContain('intervention.reloadIntervalMs')
      // Zero is the explicit "disable GC timer" sentinel — must apply.
      const zeroResult = engine.livePatch({ intervention: { reloadIntervalMs: 0 } })
      expect(zeroResult.appliedKeys).toContain('intervention.reloadIntervalMs')
      expect(config.intervention.reloadIntervalMs).toBe(0)
    } finally {
      engine.shutdown()
    }
  })

  it('InterventionEngine watcher rebuild is atomic — old watcher survives a build throw', () => {
    const config = baseConfig()
    config.intervention.policyPath = stubPolicyPath()
    const engine = new InterventionEngine(config, { builtinRulePaths: [] })
    engine.initialize()
    try {
      const oldWatcher = (engine as unknown as { policyWatcher: { close: () => void } | undefined })
        .policyWatcher
      expect(oldWatcher).toBeDefined()
      // Flag-based stub: initialize ran with the original buildPolicyWatcher
      // and installed the real watcher. Right before the livePatch we flip
      // the flag so the next call throws — simulating a constructor failure
      // (e.g. malformed PolicyWatcher options, FS permission denied on the
      // first poll). The atomic-swap invariant is: the OLD watcher survives.
      const internal = engine as unknown as { buildPolicyWatcher: () => unknown }
      const originalBuilder = internal.buildPolicyWatcher.bind(engine)
      let shouldThrow = false
      internal.buildPolicyWatcher = () => {
        if (shouldThrow) throw new Error('simulated buildPolicyWatcher failure')
        return originalBuilder()
      }
      let oldClosed = false
      const origClose = oldWatcher!.close.bind(oldWatcher!)
      oldWatcher!.close = () => {
        oldClosed = true
        return origClose()
      }

      shouldThrow = true
      const result = engine.livePatch({ intervention: { reloadIntervalMs: 9_000 } })
      expect(result.ok).toBe(false)
      // OLD watcher is still the active reference — atomic swap rolled
      // back the failed rebuild.
      const afterWatcher = (engine as unknown as { policyWatcher: unknown }).policyWatcher
      expect(afterWatcher).toBe(oldWatcher)
      // OLD watcher's close() was NOT called (we'd have closed it only
      // after the new watcher was alive — and the build failed before
      // that point).
      expect(oldClosed).toBe(false)
      // Config still holds the unchanged reloadIntervalMs because the
      // try/catch in livePatch reverted appliedKeys but the config
      // assignment happens before the throw. That's the existing
      // contract — a successful config update + a failed rebuild is
      // surfaced via ok:false so operators can re-apply. The crucial
      // invariant is that the watcher reference is intact.
      expect(config.intervention.reloadIntervalMs).toBe(9_000)
    } finally {
      engine.shutdown()
    }
  })
})
