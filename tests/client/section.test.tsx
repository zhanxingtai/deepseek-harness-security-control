/**
 * section component test — tab rename.
 *
 * Renders `SecurityMonitorSection` with a mocked bridge and asserts
 * the 4 tabs are present + clickable. Each tab is
 * exercised:
 *
 *   - Metrics (id 'overview'): stats render from the bridge's overview() snapshot
 *   - Top Blocks (id 'recent'): rows render from recentBlocks() + limit selector
 *   - Event Stream (id 'events'): rows render from events()
 *
 * Reload action is also tested: clicking the button calls
 * `bridge.reload()` and refreshes the Overview stats.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createElement } from 'react'

import { SecurityMonitorSection } from '../../src/client/section.js'
import * as hardReloadModule from '../../src/client/hardReload.js'
import type {
  SecurityMonitorBridge,
  OverviewSnapshot,
  BlockRow,
  ReloadResult,
  ConfigSnapshot,
} from '../../src/client/wire.js'
import { locales, type LocaleKey } from '../../src/client/locales.js'

/* ---------------------------------------------------------------- *
 * Mock bridge — every method returns a canned snapshot.            *
 * ---------------------------------------------------------------- */

function buildMockBridge(): {
  bridge: SecurityMonitorBridge
  calls: { method: string; args: unknown }[]
} {
  const calls: { method: string; args: unknown }[] = []
  const overview: OverviewSnapshot = {
    mode: 'audit',
    totalEvents: 1234,
    blockCount: 7,
    last24hBlockCount: 3,
    // 2026-09-28 — 威胁事件(含 warn 标记未拦截;7 拦截 + 5 warn 命中)。
    threatCount: 12,
    last24hThreatCount: 6,
    last24hTotalCount: 40,
    byLayer: { application: 30, network: 10 },
    uptimeSec: 3725,
    loadedRuleCount: 58,
    localOutputPath: '/home/me/.dsh/security-events.jsonl',
  }
  const recentBlocks: BlockRow[] = [
    {
      ts: 1_726_000_000_000,
      session_id: 'sess-A',
      tool_name: 'bash',
      tool_call_id: 'call-1',
      decision: 'block',
      decision_internal: 'block',
      block_reason: 'process kill attempt on harness',
      block_code: 'SELF_PROTECTION_PROCESS_KILL_014',
      policy_id: 'self-protection-block-harness-process-kill',
    },
    {
      ts: 1_725_999_000_000,
      session_id: 'sess-B',
      tool_name: 'write',
      decision: 'block',
      block_reason: 'restarter disabler script',
      block_code: 'SELF_PROTECTION_DISABLER_SCRIPT_WRITE_016',
      policy_id: 'self-protection-block-disabler-script',
    },
  ]
  const reload: ReloadResult = { ok: true, ruleCount: 58 }
  // minimal ConfigSnapshot so the new tab's getConfig
  // mock returns a well-typed value.
  const configSnapshot: ConfigSnapshot = {
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
      engineLaunchers: ['pnpm dsh'],
      pluginPackageName: 'sst-security-control-dsh',
      patchMarkers: ['security-monitor.patch.yml'],
    },
    // drift fix: 7 §6.2 sub-block mirrors.
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

  const bridge: SecurityMonitorBridge = {
    overview: vi.fn(async () => {
      calls.push({ method: 'overview', args: {} })
      return overview
    }),
    recentBlocks: vi.fn(async (args: { limit?: number } = {}) => {
      calls.push({ method: 'recentBlocks', args })
      const rows = recentBlocks.slice(0, args.limit ?? recentBlocks.length)
      // 2026-10-10 — wire contract: events() / recentBlocks()
      // return a {rows,total} envelope; the client footer uses
      // `total` to render "Showing N of M …".
      return { rows, total: rows.length }
    }),
    reload: vi.fn(async () => {
      calls.push({ method: 'reload', args: {} })
      return reload
    }),
    getConfig: vi.fn(async () => {
      calls.push({ method: 'getConfig', args: {} })
      return configSnapshot
    }),
    validateConfigPatch: vi.fn(async () => ({
      ok: true,
      errors: [],
      warnings: [],
      normalized: configSnapshot,
    })),
    saveConfigDraft: vi.fn(async () => ({
      ok: true,
      path: '/tmp/security-monitor-config.draft.json',
      restartRequired: true,
    })),
    getConfigDraftStatus: vi.fn(async () => ({ path: '', patchedAt: '', operator: '' })),
    // the Event Stream tab calls bridge.events on
    // mount; the wire contract requires the full method surface even
    // when a given test only exercises one tab.
    events: vi.fn(async () => ({ rows: [], total: 0 })),
    previewLivePatch: vi.fn(async () => {
      throw new Error('unused')
    }),
    applyLivePatch: vi.fn(async () => {
      throw new Error('unused')
    }),
  }
  return { bridge, calls }
}

function t(
  key: LocaleKey,
  params?: Record<string, string | number>,
): string {
  const raw = locales.en[key]
  if (typeof raw !== 'string') return String(key)
  if (!params) return raw
  return raw.replace(/\{(\w+)\}/g, (_m, name) => String(params[name] ?? `{${name}}`))
}

function renderSection(bridge: SecurityMonitorBridge): ReturnType<typeof render> {
  return render(createElement(SecurityMonitorSection, { bridge, t }))
}

/* ---------------------------------------------------------------- *
 * Tests                                                            *
 * ---------------------------------------------------------------- */

beforeEach(() => {
  // Each test gets a fresh DOM; happy-dom persists between tests
  // otherwise.
})

afterEach(() => {
  cleanup()
})

describe('SecurityMonitorSection', () => {
  it('renders the 4 tabs (Metrics / Event Stream / Top Blocks / Config)', async () => {
    const { bridge } = buildMockBridge()
    renderSection(bridge)
    // The Metrics tab is the default; it must call bridge.overview()
    // on mount. Wait for the async fetch to settle.
    await waitFor(() => {
      expect(bridge.overview).toHaveBeenCalled()
    })
    // SPL rules tab removed; display order is
    // Metrics / Event Stream / Policy Hits / Config.
    // (the"Top Blocks"tab was renamed to"Policy Hits"to align
    // with the marketplace presentation.)
    expect(screen.getByRole('tab', { name: /Metrics/ })).toBeTruthy()
    expect(screen.getByRole('tab', { name: /Event Stream/ })).toBeTruthy()
    expect(screen.getByRole('tab', { name: /Policy Hits/ })).toBeTruthy()
    expect(screen.getByRole('tab', { name: /Config/ })).toBeTruthy()
  })

  it('Metrics tab renders snapshot stats', async () => {
    const { bridge } = buildMockBridge()
    renderSection(bridge)
    await waitFor(() => {
      expect(screen.getByText('1234')).toBeTruthy()
    })
    expect(screen.getByText('7')).toBeTruthy() // blockCount (Blocked card, red)
    expect(screen.getByText('12')).toBeTruthy() // threatCount (Threat events card, accent 琥珀)
    expect(screen.getByText('40')).toBeTruthy() // last24hTotalCount (Last 24h)
    // No-regression meta line still carries mode / rules / uptime.
    expect(screen.getByText(/SPL rules loaded: 58/)).toBeTruthy()
    expect(screen.getByText(/Uptime: 1 h 2 m/)).toBeTruthy()
    // BY LAYER panel renders the wire buckets.
    expect(screen.getByText('application')).toBeTruthy()
    expect(screen.getByText('network')).toBeTruthy()
  })

  it('global header renders locale nav key + version + per-tab refresh interval', async () => {
    const { bridge } = buildMockBridge()
    renderSection(bridge)
    await waitFor(() => {
      expect(bridge.overview).toHaveBeenCalled()
    })
    // gap analysis): the page header title now reads
    // the same locale `nav` key as the sidebar panellist — the long
    // formal name (`sst-security-control-dsh-v0.5.3 安全监控插件`) was
    // bundled at build time via esbuild `define` and rendered very wide;
    // the version is now surfaced separately in `headerRight`. Left side:
    // `nav` (short locale label). Right side: version · refresh. See
    // the marketplace presentation spec §2.
    const body = document.body.textContent ?? ''
    expect(body).toContain(locales.en.nav)
    // 2026-10-12 — Metrics 与 Policy Hits 统一 10 s。
    expect(body).toContain('0.0.0-dev · auto-refresh 10s')
    // Switch tabs — the refresh hint follows the active tab's real
    // polling interval.
    fireEvent.click(screen.getByRole('tab', { name: /Event Stream/ }))
    expect(document.body.textContent ?? '').toContain('0.0.0-dev · auto-refresh 30s')
    fireEvent.click(screen.getByRole('tab', { name: /Policy Hits/ }))
    expect(document.body.textContent ?? '').toContain('0.0.0-dev · auto-refresh 10s')
    fireEvent.click(screen.getByRole('tab', { name: /Config/ }))
    expect(document.body.textContent ?? '').toContain('0.0.0-dev · manual refresh')
  })

  // 2026-10-12 — hard reload button (Ctrl+Shift+R equivalent). The
  // navigation itself is covered by hardReload.test.ts against a fake
  // Location; here we only assert the button wires to hardReload().
  // (A data-only "soft refresh" button was evaluated and rejected — the
  // hard reload strictly supersedes it.)
  it('header hard-reload button invokes hardReload()', async () => {
    const { bridge } = buildMockBridge()
    const spy = vi.spyOn(hardReloadModule, 'hardReload').mockImplementation(() => undefined)
    try {
      renderSection(bridge)
      await waitFor(() => {
        expect(bridge.overview).toHaveBeenCalled()
      })
      fireEvent.click(screen.getByRole('button', { name: locales.en.header_hard_reload }))
      expect(spy).toHaveBeenCalledTimes(1)
    } finally {
      vi.restoreAllMocks()
    }
  })

  it('Policy Hits tab loads rows on click', async () => {
    const { bridge } = buildMockBridge()
    renderSection(bridge)
    fireEvent.click(screen.getByRole('tab', { name: /Policy Hits/ }))
    await waitFor(() => {
      expect(bridge.recentBlocks).toHaveBeenCalled()
    })
    // columns: POLICY id (monospace) + REASON text + DECISION badge.
    expect(screen.getByText(/self-protection-block-harness-process-kill/)).toBeTruthy()
    expect(screen.getByText(/self-protection-block-disabler-script/)).toBeTruthy()
    expect(screen.getByText('process kill attempt on harness')).toBeTruthy()
    expect(screen.getByText('restarter disabler script')).toBeTruthy()
  })

  it('Config tab loads getConfig snapshot on click', async () => {
    const { bridge } = buildMockBridge()
    renderSection(bridge)
    fireEvent.click(screen.getByRole('tab', { name: /Config/ }))
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // The 7 section headers from the Config tab component.
    expect(screen.getByText(locales.en.config_section_top)).toBeTruthy()
    expect(screen.getByText(locales.en.config_section_inline)).toBeTruthy()
  })

  it('reload button calls bridge.reload() and refreshes the overview', async () => {
    const { bridge } = buildMockBridge()
    renderSection(bridge)
    // Wait for the initial overview to land.
    await waitFor(() => {
      expect(bridge.overview).toHaveBeenCalledTimes(1)
    })
    // Find the Reload button by its accessible name.
    const reloadButton = screen.getByRole('button', { name: /Reload policy/ })
    fireEvent.click(reloadButton)
    await waitFor(() => {
      expect(bridge.reload).toHaveBeenCalled()
    })
    // After reload, a second overview() call refreshes the stats.
    await waitFor(() => {
      expect(bridge.overview).toHaveBeenCalledTimes(2)
    })
  })

  it('renders error banner when bridge rejects', async () => {
    const { bridge } = buildMockBridge()
    ;(bridge.overview as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('host offline'),
    )
    renderSection(bridge)
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeTruthy()
    })
    expect(screen.getByText(/host offline/)).toBeTruthy()
  })
})
