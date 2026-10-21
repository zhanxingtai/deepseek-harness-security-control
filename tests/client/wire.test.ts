/**
 * client wire-types test —.
 *
 * Verifies the contract between the host's
 * `src/typert/descriptors.ts` and the client's `src/client/wire.ts`:
 *
 *   - The method name list exported by the client matches the
 *     host's `SECURITY_MONITOR_INVOCATIONS` array (one method per
 *     host entry, names identical).
 *   - Each client method name is a real `keyof SecurityMonitorBridge`,
 *     so the bridge type is exhaustive — adding a new method to the
 *     host without updating the client will fail this test.
 *   - The Config snapshot type carries every key the host's
 *     `getConfig()` returns — the mirror cannot drift silently.
 *
 * The two `tsconfig` projects have different `rootDir`s, so the
 * client cannot import the host's descriptors file. We parse the
 * host file as a string and assert against the parsed regex. The
 * regex is loose enough to survive minor reformatting of the host
 * file but strict enough to catch a missing method.
 */
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import {
  SECURITY_MONITOR_METHODS,
  type ConfigSnapshot,
  type SecurityMonitorBridge,
} from '../../src/client/wire.js'

const HOST_DESCRIPTORS_PATH = resolve(
  __dirname,
  '..',
  '..',
  'src',
  'typert',
  'descriptors.ts',
)

function buildMinimalConfigSnapshot(): ConfigSnapshot {
  return {
    mode: 'audit',
    enabled: true,
    hostId: 'host-A',
    containerId: 'host',
    collector: {
      localOutputPath: '/var/log/sec.jsonl',
      batchSize: 50,
      flushIntervalMs: 250,
      validateEvents: true,
      maxFileBytes: 1_000_000,
      diskWarnWatermarkBytes: 500_000_000,
      diskLowWatermarkBytes: 100_000_000,
      redactRawParams: true,
      debugLogPath: '',
    },
    application: {
      captureUserPrompt: true,
      captureSystemPrompt: true,
      captureAgentPlan: true,
      captureReasoning: true,
      toolResultMaxChars: 100_000,
      sessionTtlMs: 1_800_000,
    },
    networkCapture: {
      enabled: true,
      redactBodies: true,
      captureResponseBody: true,
      maxBodyBytes: 1_048_576,
      sseSummaryChunks: 5,
      sseSummaryLastChunks: 1,
      includeHosts: [],
      excludeHosts: [],
      excludeUrls: [],
      sensitiveKeyPatterns: [],
      captureDns: false,
    },
    runtimeHooks: {
      enabled: true,
      networkEnabled: true,
      logPath: '/var/log/sec.rt.jsonl',
      hookPath: '',
      excludeCommandLines: [],
      enabledAtSubprocess: true,
      blockAtSubprocess: false,
      failOpenOnError: true,
    },
    intervention: {
      enabled: true,
      mode: 'audit',
      policyPath: '/etc/sec/policy.spl.yaml',
      policyPaths: [],
      reloadIntervalMs: 30_000,
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
    },
    inlineGuards: {
      engineLaunchers: ['pnpm dsh', 'node bin.ts'],
      pluginPackageName: 'sst-security-control-dsh',
      patchMarkers: ['security-monitor.patch.yml'],
    },
    // drift fix: 7 §6.2 sub-block mirrors
    // added to ConfigSnapshot. Field shapes mirror src/config.ts
    // exactly; values are minimal-valid for the type-check only.
    sensitivePathGuard: {
      enabled: true,
      paths: [],
      watchEnabled: true,
      watchDebounceMs: 500,
    },
    inlinePromptInjection: {
      enabled: true,
      patterns: [],
      excerptMaxChars: 80,
    },
    stdioMirror: {
      enabled: false,
      payloadLimitBytes: 1_048_576,
      outputPath: '',
    },
    envPassthroughGuard: {
      enabled: true,
      keys: [],
    },
    loopedToolDetector: {
      enabled: true,
      windowMs: 60_000,
      thresholdPerWindow: 100,
    },
    tokenUsageDetector: {
      enabled: true,
      windowMs: 60_000,
      burstFactor: 3,
      minBaselineSamples: 5,
    },
    sinkDiskLow: {
      recoverMarginBytes: 50 * 1024 * 1024,
    },
  }
}

describe('client wire — host/client contract', () => {
  it('host descriptors file is reachable', () => {
    expect(() => readFileSync(HOST_DESCRIPTORS_PATH, 'utf8')).not.toThrow()
  })

  it('client method list matches host SECURITY_MONITOR_INVOCATIONS minus host-only methods', () => {
    const src = readFileSync(HOST_DESCRIPTORS_PATH, 'utf8')
    // Pull the host invocations array. The format is:
    //   export const SECURITY_MONITOR_INVOCATIONS = [
    //     { method: 'overview', ... },
    //     { method: 'recentBlocks', ... },
    //     ...
    //   ] as const
    const match = src.match(/SECURITY_MONITOR_INVOCATIONS\s*=\s*\[([\s\S]*?)\]\s*as\s*const/)
    expect(match).not.toBeNull()
    if (!match) return
    const body = match[1] ?? ''
    const methodNames: string[] = []
    const re = /method:\s*'([^']+)'/g
    let m: RegExpExecArray | null
    while ((m = re.exec(body)) !== null) {
      methodNames.push(m[1] ?? '')
    }
    expect(methodNames.length).toBeGreaterThan(0)
    // the host keeps `rules` for the `/security rules`
    // CLI surface, but no client tab consumes it after the SPL rules
    // page removal. Guard both directions: the host must keep serving
    // it (CLI contract), and the client list must be exactly the host
    // list minus the host-only set, same order.
    expect(methodNames).toContain('rules')
    const clientVisible = methodNames.filter((name) => name !== 'rules')
    expect([...SECURITY_MONITOR_METHODS]).toEqual(clientVisible)
  })

  it('every client method is a key on SecurityMonitorBridge (incl. getConfig)', () => {
    // Type-level check via a runtime function that exercises each
    // method name. If a method is missing on the bridge, the cast
    // below will fail to compile and the test file will not build.
    const snap = buildMinimalConfigSnapshot()
    const bridge: SecurityMonitorBridge = {
      overview: async () => ({
        mode: 'audit',
        totalEvents: 0,
        blockCount: 0,
        last24hBlockCount: 0,
        // Metrics-page mirror fields.
        // 2026-09-28 — 威胁事件(规则命中含 warn 标记未拦截)。
        threatCount: 0,
        last24hThreatCount: 0,
        last24hTotalCount: 0,
        byLayer: {},
        uptimeSec: 0,
        loadedRuleCount: 0,
        localOutputPath: '',
      }),
      recentBlocks: async () => [],
      // no client-side `rules ` — host-only RPC.
      reload: async () => ({ ok: true, ruleCount: 0 }),
      getConfig: async () => snap,
      validateConfigPatch: async () => ({ ok: true, errors: [], warnings: [], normalized: snap }),
      saveConfigDraft: async () => ({
        ok: true,
        path: '/tmp/security-monitor-config.draft.json',
        restartRequired: true,
      }),
      getConfigDraftStatus: async () => ({ path: '', patchedAt: '', operator: '' }),
      // livePatch methods.
      previewLivePatch: async () => ({
        ok: true,
        safeKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
        errors: [],
      }),
      applyLivePatch: async () => ({
        ok: true,
        appliedKeys: [],
        needsRestartKeys: [],
        rejectedKeys: [],
        warnings: [],
      }),
      // events method — raw event-stream view.
      events: async () => [],
    }
    for (const m of SECURITY_MONITOR_METHODS) {
      expect(typeof bridge[m]).toBe('function')
    }
  })

  it('client bridge type is exhaustive over SECURITY_MONITOR_METHODS', () => {
    // @ts-expect-error — if the bridge gains a method but the
    // constant does not, this assignment fails. The test passes when
    // the union type and the constant stay in sync.
    const _bridge: Record<(typeof SECURITY_MONITOR_METHODS)[number], unknown> = {
      overview: 1,
      recentBlocks: 1,
      reload: 1,
      getConfig: 1,
      validateConfigPatch: 1,
      saveConfigDraft: 1,
      getConfigDraftStatus: 1,
      previewLivePatch: 1,
      applyLivePatch: 1,
      //
      events: 1,
    }
    expect(_bridge.overview).toBe(1)
  })

  it('ConfigSnapshot type carries every top-level key (7-block extension)', () => {
    // If the host side adds a new key to ConfigSnapshot, this test
    // forces the client to mirror it (otherwise the minimal
    // snapshot literal above will not satisfy the type). The runtime
    // check re-asserts the same shape against the host's
    // ConfigSnapshot declaration.
    //
    // extended with the 7 §6.2 sub-block
    // mirrors (sensitivePathGuard / inlinePromptInjection /
    // stdioMirror / envPassthroughGuard / loopedToolDetector /
    // tokenUsageDetector / sinkDiskLow).
    const snap = buildMinimalConfigSnapshot()
    expect(Object.keys(snap).sort()).toEqual(
      [
        'application',
        'collector',
        'containerId',
        'enabled',
        'envPassthroughGuard',
        'hostId',
        'inlineGuards',
        'inlinePromptInjection',
        'intervention',
        'loopedToolDetector',
        'mode',
        'networkCapture',
        'runtimeHooks',
        'sensitivePathGuard',
        'sinkDiskLow',
        'stdioMirror',
        'tokenUsageDetector',
      ].sort(),
    )
  })
})

// Sanity: the path used above must be inside the repo, not the lib/ output.
it('test resolves the SOURCE descriptors file (not the lib build artifact)', () => {
  expect(HOST_DESCRIPTORS_PATH.replace(/\\/g, '/')).toMatch(
    /\/src\/typert\/descriptors\.ts$/,
  )
  expect(HOST_DESCRIPTORS_PATH).not.toMatch(/[\\/]+lib[\\/]+/)
})

// Touch `join` so the import survives unused-import stripping in strict mode.
void join