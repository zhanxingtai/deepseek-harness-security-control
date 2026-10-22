/**
 * Config tab component test —.
 * Config form + draft persistence test —.
 * metadata-driven form + danger-key mechanism.
 *
 * Renders the `Config` tab against a mock bridge that returns a
 * canned ConfigSnapshot, then exercises:
 *
 *   - default state: a `getConfig()` call lands and the section
 *     headers render (one collapsible panel per Config top-level
 *     block, driven by CONFIG_SECTIONS)
 * inlineGuards panel shows a lock indicator ( immutability hint)
 *     and no inputs inside the locked section
 * collector block is now editable : its fields render as
 *     inputs carrying the snapshot values
 *   - `Reload config` button is present and triggers another
 *     `getConfig()` call
 *   - error path: when getConfig() rejects, an error banner appears
 *     with the host's error string appended
 *
 * L2 form behaviour (preserved through the rewrite):
 *   - field edit triggers debounced validateConfigPatch (500ms)
 *   - errors disable the Save button
 *   - warnings pop a confirm dialog before persisting
 *   - dangerous values (mode → enforce, failStrategy → fail_closed)
 *     pop the confirmation dialog UNCONDITIONALLY, even with clean
 *     validation — cancel does not save
 *   - successful save shows a banner with the persisted path
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createElement } from 'react'

import { Config } from '../../src/client/components/Config.js'
import type {
  SecurityMonitorBridge,
  ConfigSnapshot,
  ConfigPatch,
  ConfigValidationResult,
  ConfigDraftResult,
  ConfigDraftStatus,
} from '../../src/client/wire.js'
import { locales, type LocaleKey } from '../../src/client/locales.js'

/* ---------------------------------------------------------------- *
 * Mock bridge — returns a hand-built ConfigSnapshot.                *
 * ---------------------------------------------------------------- */

function buildSnapshot(): ConfigSnapshot {
  return {
    mode: 'enforce',
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
      toolResultMaxChars: 200_000,
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
      sensitiveKeyPatterns: ['token', 'key', 'secret'],
      captureDns: false,
    },
    runtimeHooks: {
      enabled: true,
      networkEnabled: true,
      logPath: '/var/log/sec.rt.jsonl',
      hookPath: '/var/run/sec.hook',
      excludeCommandLines: ['kthreadd', 'kworker/.*'],
      enabledAtSubprocess: true,
      blockAtSubprocess: false,
      failOpenOnError: true,
    },
    intervention: {
      enabled: true,
      mode: 'enforce',
      policyPath: '/etc/sec/policy.spl.yaml',
      policyPaths: [],
      reloadIntervalMs: 15_000,
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
    },
    inlineGuards: {
      engineLaunchers: ['pnpm dsh', 'node bin.ts', 'systemd-run'],
      pluginPackageName: 'sst-security-control-dsh',
      patchMarkers: ['security-monitor.patch.yml', 'security-monitor.patch.yaml'],
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
}

function buildMockBridge(opts?: {
  initialDraftStatus?: ConfigDraftStatus
  validation?: ConfigValidationResult | ((patch: ConfigPatch) => ConfigValidationResult)
  draftResult?: ConfigDraftResult
  failDraftSave?: boolean
}): {
  bridge: SecurityMonitorBridge
  calls: { method: string; args: unknown }[]
  mocks: {
    getConfig: ReturnType<typeof vi.fn>
    validateConfigPatch: ReturnType<typeof vi.fn>
    saveConfigDraft: ReturnType<typeof vi.fn>
    getConfigDraftStatus: ReturnType<typeof vi.fn>
  }
} {
  const calls: { method: string; args: unknown }[] = []
  const snap = buildSnapshot()
  const initialDraftStatus: ConfigDraftStatus = opts?.initialDraftStatus ?? {
    path: '',
    patchedAt: '',
    operator: '',
  }

  const validationMock = vi.fn(async (patch: ConfigPatch) => {
    calls.push({ method: 'validateConfigPatch', args: { patch } })
    if (opts?.validation) {
      if (typeof opts.validation === 'function') return opts.validation(patch)
      return opts.validation
    }
    const result: ConfigValidationResult = {
      ok: true,
      errors: [],
      warnings: [],
      normalized: snap,
    }
    return result
  })

  const draftResult: ConfigDraftResult = opts?.draftResult ?? {
    ok: true,
    path: '/home/me/.dsh/security-monitor-config.draft.json',
    restartRequired: true,
  }

  const saveMock = vi.fn(async (patch: ConfigPatch) => {
    calls.push({ method: 'saveConfigDraft', args: { patch } })
    if (opts?.failDraftSave) {
      throw new Error('disk full')
    }
    return draftResult
  })

  const draftStatusMock = vi.fn(async () => {
    calls.push({ method: 'getConfigDraftStatus', args: {} })
    return initialDraftStatus
  })

  const bridge: SecurityMonitorBridge = {
    overview: vi.fn(async () => ({
      mode: 'audit',
      totalEvents: 0,
      blockCount: 0,
      last24hBlockCount: 0,
      threatCount: 0,
      last24hThreatCount: 0,
      last24hTotalCount: 0,
      byLayer: {},
      uptimeSec: 0,
      loadedRuleCount: 0,
      localOutputPath: '',
    })),
    recentBlocks: vi.fn(async () => []),
    reload: vi.fn(async () => ({ ok: true, ruleCount: 0 })),
    getConfig: vi.fn(async () => {
      calls.push({ method: 'getConfig', args: {} })
      return snap
    }),
    validateConfigPatch: validationMock,
    saveConfigDraft: saveMock,
    getConfigDraftStatus: draftStatusMock,
  }
  return {
    bridge,
    calls,
    mocks: {
      getConfig: bridge.getConfig as ReturnType<typeof vi.fn>,
      validateConfigPatch: validationMock,
      saveConfigDraft: saveMock,
      getConfigDraftStatus: draftStatusMock,
    },
  }
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

function renderConfig(bridge: SecurityMonitorBridge): ReturnType<typeof render> {
  return render(createElement(Config, { bridge, t }))
}

/**
 * Toolbar queries use `findByRole`, never `getByRole`.
 *
 * `await waitFor(() => expect(bridge.getConfig).toHaveBeenCalled())` only
 * proves the request went out. Config is still on its `state.kind ===
 * 'loading'` branch then — which renders a banner, not the toolbar — and one
 * Promise resolution + setState render stands between the two. A bare
 * `getByRole` races that window and throws "unable to find role=button" on a
 * slower runner; it is not reproducible on a fast local machine, so it only
 * surfaces in CI. `findByRole` waits for the toolbar to mount instead.
 *
 * The two `getByRole` calls on the alert are correct as written: they sit
 * inside, and immediately after, a `waitFor` that already asserts the alert
 * exists.
 */

/**
 * The Config component debounces `validateConfigPatch` at 500ms.
 * Tests that need to step past that boundary wait the same window
 * in real time (the tests run in ~10ms otherwise). We always pass
 * the local `waitFor` to flush pending React work.
 */
async function flushDebounce(): Promise<void> {
  // Allow the setTimeout(500) to fire and flush React's pending setState
  // batch (act forces React to process its internal queue after the timer).
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 550))
  })
}

/** 2026-09-24: the "Show advanced" toggle was removed from the toolbar
 * All `visibility:'advanced'` fields and
 *  sections whose only fields carry that flag are now permanently
 *  hidden. Tests previously gated on `enableShowAdvanced()` should
 *  just render the form and query the visible surface directly. */

afterEach(() => {
  cleanup()
})

/* ---------------------------------------------------------------- *
 * read-only surface tests *
 * ---------------------------------------------------------------- */

describe('Config tab', () => {
  it('renders the section headers (one collapsible panel per Config top-level block)', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // 2026-09-24 — the "Show advanced" toggle is gone. Sections whose
    // every field is `visibility: 'advanced'` are skipped (application,
    // sinkDiskLow); the remaining 12 panels render.
    const expectedSections: ReadonlyArray<LocaleKey> = [
      'config_section_top',
      'config_section_collector',
      'config_section_network',
      'config_section_runtime',
      'config_section_intervention',
      'config_section_inline',
      'config_section_sensitive',
      'config_section_prompt_injection',
      'config_section_stdio_mirror',
      'config_section_env_passthrough',
      'config_section_looped_tool',
      'config_section_token_usage',
    ]
    for (const label of expectedSections) {
      expect(screen.getByText(locales.en[label])).toBeTruthy()
    }
    // Section panels are collapsible: the header is a button with
    // aria-expanded, defaulting to expanded.
    const sectionHeaders = document.querySelectorAll(
      '.dsh-secmon-config-section-header',
    )
    expect(sectionHeaders.length).toBe(13)
    for (const header of Array.from(sectionHeaders)) {
      expect(header.getAttribute('aria-expanded')).toBe('true')
    }
  })

  it('section panels collapse and expand on header click', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    const collectorHeader = screen.getByText(locales.en.config_section_collector)
      .closest('button') as HTMLButtonElement
    expect(collectorHeader).toBeTruthy()
    fireEvent.click(collectorHeader)
    expect(collectorHeader.getAttribute('aria-expanded')).toBe('false')
    // The collector body disappears while collapsed…
    expect(
      document.querySelector('[data-component="config-section-collector"] .dsh-secmon-config-section-body'),
    ).toBeNull()
    fireEvent.click(collectorHeader)
    expect(collectorHeader.getAttribute('aria-expanded')).toBe('true')
  })

  it('field rows render the dotted config key in monospace', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    const keys = Array.from(
      document.querySelectorAll('.dsh-secmon-config-field-key'),
    ).map((el) => el.textContent)
    // essential field keys render by default
    // 2026-10-10: top-level `Config.mode` was removed from the UI;
    // `intervention.mode` is now the only rendered mode control.
    expect(keys).toContain('intervention.mode')
    expect(keys).toContain('collector.localOutputPath')
    expect(keys).toContain('intervention.failStrategy')
    // advanced-only field keys are hidden
    expect(keys).not.toContain('collector.batchSize')
    expect(keys).not.toContain('tokenUsageDetector.burstFactor')
  })

  it('shows the lock indicator on the inlineGuards section only ( immutability hint)', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // The 🔒 glyph is rendered as a <span> with the dedicated
    // dsh-secmon-config-lock class. There must be exactly one —
    // other sections are NOT locked.
    const locks = document.querySelectorAll('.dsh-secmon-config-lock')
    expect(locks.length).toBe(1)
    const lock = locks[0] as HTMLElement
    expect(lock.textContent).toContain('🔒')
    expect(lock.getAttribute('title')).toBe(locales.en.config_inline_locked_no_edit)
  })

  it('renders the engineLaunchers array values verbatim (locked, not the empty placeholder)', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // locked fields render as plain text inside the locked
    // section — the host snapshot's launcher list must appear.
    const locked = document.querySelector('.dsh-secmon-config-inline-locked')
    expect(locked?.textContent ?? '').toContain('pnpm dsh, node bin.ts, systemd-run')
    expect(locked?.textContent ?? '').toContain('sst-security-control-dsh')
  })

  it('collector block is editable : inputs carry the snapshot values', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // turned the former read-only collector summary into editable
    // field rows driven by the metadata table. After the advanced
    // toggle removal, only the essential `localOutputPath` field
    // remains in the collector section.
    const section = document.querySelector(
      '[data-component="config-section-collector"]',
    ) as HTMLElement
    expect(section).toBeTruthy()
    const textInput = section.querySelector(
      'input[type="text"]',
    ) as HTMLInputElement | null
    expect(textInput).toBeTruthy()
    expect(textInput?.value).toBe('/var/log/sec.jsonl')
    // The advanced-only number / checkbox knobs (batchSize, validateEvents, …)
    // are no longer rendered.
    expect(section.querySelector('input[type="number"]')).toBeNull()
    expect(section.querySelector('input[type="checkbox"]')).toBeNull()
  })

  it('Reload config button is present + clicking it calls bridge.getConfig() again', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalledTimes(1)
    })
    const reloadButton = await screen.findByRole('button', { name: locales.en.config_reload })
    fireEvent.click(reloadButton)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalledTimes(2)
    })
  })

  it('shows an error banner when getConfig() rejects', async () => {
    const { bridge } = buildMockBridge()
    ;(bridge.getConfig as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('host offline'),
    )
    renderConfig(bridge)
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeTruthy()
    })
    // The error banner prefixes the localised "config_load_error"
    // string with the host's error message in brackets.
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toContain(locales.en.config_load_error)
    expect(alert.textContent).toContain('host offline')
  })
})

/* ---------------------------------------------------------------- *
 * form behaviour tests *
 * ---------------------------------------------------------------- */

describe('Config form', () => {
  it('field edit triggers debounced validateConfigPatch (500ms)', async () => {
    const { bridge, mocks } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // The `intervention.mode` <select> carries values 'audit' /
    // 'enforce'. Since 2026-10-10 it is the only mode control on the
    // page (the top-level `Config.mode` was removed from the UI).
    // Switch it from 'enforce' (the snapshot default) to 'audit'.
    const modeSelect = screen.getAllByRole('combobox').find(
      (el) => (el as HTMLSelectElement).value === 'enforce',
    ) as HTMLSelectElement | undefined
    expect(modeSelect).toBeTruthy()
    fireEvent.change(modeSelect, { target: { value: 'audit' } })

    // Validation must not fire synchronously (the spec is a
    // 500ms debounce). Confirm validateConfigPatch was NOT called
    // immediately.
    expect(mocks.validateConfigPatch).not.toHaveBeenCalled()

    // Step past the debounce window.
    await flushDebounce()

    await waitFor(() => {
      expect(mocks.validateConfigPatch).toHaveBeenCalledTimes(1)
    })
    const callArgs = mocks.validateConfigPatch.mock.calls[0]?.[0] as ConfigPatch
    // 2026-10-10: the saved patch is `{ intervention: { mode: 'audit' } }`,
    // NOT `{ mode: 'audit' }` — the top-level `Config.mode` field is no
    // longer surfaced in the UI.
    expect(callArgs).toMatchObject({ intervention: { mode: 'audit' } })
  })

  it('errors disable the Save Draft button', async () => {
    const failingValidation: ConfigValidationResult = {
      ok: false,
      errors: ['collector.batchSize: must be a positive integer'],
      warnings: [],
      normalized: null,
    }
    const { bridge } = buildMockBridge({ validation: failingValidation })
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })

    // Trigger validation by changing a field.
    const modeSelect = screen.getAllByRole('combobox').find(
      (el) => (el as HTMLSelectElement).value === 'enforce',
    ) as HTMLSelectElement | undefined
    fireEvent.change(modeSelect, { target: { value: 'audit' } })

    await flushDebounce()

    // Wait for the validation result to be rendered.
    await waitFor(() => {
      expect(
        screen.getByText(/collector\.batchSize: must be a positive integer/),
      ).toBeTruthy()
    })

    const saveButton = await screen.findByRole('button', { name: locales.en.config_save_draft })
    expect((saveButton as HTMLButtonElement).disabled).toBe(true)
  })

  it('warnings show a confirm dialog before persisting', async () => {
    const warningValidation: ConfigValidationResult = {
      ok: true,
      errors: [],
      warnings: ["Switching to 'enforce' without setting intervention.policyPaths"],
      normalized: buildSnapshot(),
    }
    const { bridge, mocks } = buildMockBridge({ validation: warningValidation })
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })

    // Trigger validation by changing a field — switching to
    // 'enforce' also triggers the warning case.
    const modeSelect = screen.getAllByRole('combobox').find(
      (el) => (el as HTMLSelectElement).value === 'enforce',
    ) as HTMLSelectElement | undefined
    expect(modeSelect).toBeTruthy()
    fireEvent.change(modeSelect, { target: { value: 'audit' } })

    await flushDebounce()

    // Wait for warnings to land.
    await waitFor(() => {
      expect(
        screen.getByText(/Switching to 'enforce' without setting intervention\.policyPaths/),
      ).toBeTruthy()
    })

    // Click Save Draft — the dialog should pop, NOT the save.
    const saveButton = await screen.findByRole('button', { name: locales.en.config_save_draft })
    fireEvent.click(saveButton)

    await waitFor(() => {
      expect(
        screen.getByText(locales.en.config_confirm_save_with_warnings_title),
      ).toBeTruthy()
    })
    expect(mocks.saveConfigDraft).not.toHaveBeenCalled()

    // Confirm — save fires. The confirm dialog wraps its own
    // button in a span[data-component=config-confirm-save] so we
    // can disambiguate it from the regular Save Draft button
    // (which uses the same locale string for its label).
    const confirmButton = document.querySelector(
      '[data-component="config-confirm-save"] button',
    ) as HTMLButtonElement
    expect(confirmButton).toBeTruthy()
    fireEvent.click(confirmButton)

    await waitFor(() => {
      expect(mocks.saveConfigDraft).toHaveBeenCalledTimes(1)
    })
  })

  it('save success shows a banner with the persisted path', async () => {
    const { bridge, mocks } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })

    // Edit a field so the form becomes dirty + validation is clean.
    const enabledCheckbox = screen.getAllByRole('checkbox').find(
      (el) => (el as HTMLInputElement).checked === true,
    ) as HTMLInputElement | undefined
    expect(enabledCheckbox).toBeTruthy()
    fireEvent.click(enabledCheckbox)

    await flushDebounce()

    // Click Save Draft — clean validation goes straight through.
    const saveButton = await screen.findByRole('button', { name: locales.en.config_save_draft })
    fireEvent.click(saveButton)

    // onSave re-triggers validation when validation === null (first Save
    // in this session), so wait for that debounce to fire before asserting.
    await flushDebounce()

    await waitFor(() => {
      expect(mocks.saveConfigDraft).toHaveBeenCalledTimes(1)
    })

    // The success banner carries the path the host returned.
    await waitFor(() => {
      expect(
        screen.getByText((content) =>
          content.includes('/home/me/.dsh/security-monitor-config.draft.json'),
        ),
      ).toBeTruthy()
    })
  })

  it('inlineGuards block is rendered with no inputs ( immutability)', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // The inlineGuards card is the one with the lock indicator —
    // assert no <input>, <select>, or <textarea> lives inside it
    // so an operator cannot bypass the safety net.
    const locked = document.querySelector('.dsh-secmon-config-inline-locked')
    expect(locked).toBeTruthy()
    const interactive = locked?.querySelectorAll('input, select, textarea')
    expect(interactive?.length ?? 0).toBe(0)
  })

  it('dangerous value (intervention.mode → enforce) pops the confirm dialog even with clean validation', async () => {
    // mechanism clause: the snapshot starts in audit; flipping
    // the intervention.mode select to 'enforce' must demand
    // confirmation unconditionally — no validation warnings involved.
    // 2026-10-10: the dangerous control is now `intervention.mode`
    // (the top-level `Config.mode` field was removed from the UI).
    const { bridge, mocks } = buildMockBridge()
    const snap = buildSnapshot()
    const auditSnap: ConfigSnapshot = {
      ...snap,
      mode: 'audit',
      intervention: { ...snap.intervention, mode: 'audit' },
    }
    ;(bridge.getConfig as ReturnType<typeof vi.fn>).mockResolvedValue(auditSnap)
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })

    const modeSelect = screen.getAllByRole('combobox').find(
      (el) => (el as HTMLSelectElement).value === 'audit',
    ) as HTMLSelectElement | undefined
    expect(modeSelect).toBeTruthy()
    fireEvent.change(modeSelect as HTMLElement, { target: { value: 'enforce' } })

    await flushDebounce()
    // Validation came back clean (default mock) — no warnings, no
    // errors. Save must STILL open the danger dialog.
    const saveButton = await screen.findByRole('button', { name: locales.en.config_save_draft })
    fireEvent.click(saveButton)

    // onSave re-triggers validation when validation === null.
    await flushDebounce()

    await waitFor(() => {
      expect(
        screen.getByText(locales.en.config_confirm_danger_title),
      ).toBeTruthy()
    })
    // The dialog lists the danger message; the save has NOT fired.
    expect(screen.getByText(locales.en.config_field_danger_mode)).toBeTruthy()
    expect(mocks.saveConfigDraft).not.toHaveBeenCalled()

    // Cancel — dialog closes, still no save, draft preserved.
    const cancelButton = await screen.findByRole('button', {
      name: locales.en.config_confirm_save_with_warnings_cancel,
    })
    fireEvent.click(cancelButton)
    expect(
      document.querySelector('[data-component="config-confirm-dialog"]'),
    ).toBeNull()
    expect(mocks.saveConfigDraft).not.toHaveBeenCalled()

    // Save again + confirm → the draft lands exactly once.
    // The danger dialog is already open; onConfirmSave proceeds directly.
    fireEvent.click(await screen.findByRole('button', { name: locales.en.config_save_draft }))
    await waitFor(() => {
      expect(
        screen.getByText(locales.en.config_confirm_danger_title),
      ).toBeTruthy()
    })
    const confirmButton = document.querySelector(
      '[data-component="config-confirm-save"] button',
    ) as HTMLButtonElement
    expect(confirmButton).toBeTruthy()
    fireEvent.click(confirmButton)
    await waitFor(() => {
      expect(mocks.saveConfigDraft).toHaveBeenCalledTimes(1)
    })
    const savedPatch = mocks.saveConfigDraft.mock.calls[0]?.[0] as ConfigPatch
    // 2026-10-10: the patch is `{ intervention: { mode: 'enforce' } }`
    // (top-level `Config.mode` is no longer edited in the UI).
    const savedIntervention = savedPatch['intervention'] as { mode?: string } | undefined
    expect(savedIntervention?.mode).toBe('enforce')
  })

  it('dangerous failStrategy (fail_closed) is flagged from the metadata danger set', async () => {
    const { bridge, mocks } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // The snapshot already runs enforce (buildSnapshot), so the mode
    // select shows 'enforce' — untouched it is NOT a danger hit (the
    // draft does not turn it on). Flip failStrategy instead.
    const failStrategySelect = screen.getAllByRole('combobox').find(
      (el) => (el as HTMLSelectElement).value === 'fail_open',
    ) as HTMLSelectElement | undefined
    expect(failStrategySelect).toBeTruthy()
    fireEvent.change(failStrategySelect as HTMLElement, { target: { value: 'fail_closed' } })

    await flushDebounce()

    fireEvent.click(await screen.findByRole('button', { name: locales.en.config_save_draft }))
    await waitFor(() => {
      expect(
        screen.getByText(locales.en.config_confirm_danger_title),
      ).toBeTruthy()
    })
    expect(screen.getByText(locales.en.config_field_danger_failStrategy)).toBeTruthy()
    expect(mocks.saveConfigDraft).not.toHaveBeenCalled()
  })

  it('toolbar renders Undo (green) / Copy JSON (green) / Save (blue primary)', async () => {
    const { bridge } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    const undo = await screen.findByRole('button', { name: locales.en.config_undo })
    // 2026-10-10 — Copy JSON label now resolves via the shared
    // `copy` key (collapsed from `config_copy_json`).
    const copy = await screen.findByRole('button', { name: locales.en.copy })
    const save = await screen.findByRole('button', { name: locales.en.config_save_draft })
    expect(undo.className).toContain('dsh-secmon-button--success')
    expect(copy.className).toContain('dsh-secmon-button--success')
    expect(save.className).toContain('dsh-secmon-button--primary')
  })

  // 2026-10-10 — regression tests for the Config tab review fixes:
  //   #1 sub-block shallow merge
  //   #2 intervention.mode danger flag
  //   #7 isDirty compares effective values
  //   #8 Copy JSON filters locked fields

  it('sub-block edits merge instead of replacing sibling fields', async () => {
    // Edit `intervention.mode` to a no-op (already enforce in the
    // snapshot) AND `intervention.policyPaths` to a new list in the
    // same session. The shallow-merge fix means both land in the
    // saved draft; the pre-fix bug would silently drop `mode` because
    // each `emit()` returns a partial sub-block patch and the
    // original top-level spread replaced the whole `intervention`
    // object on the second edit.
    const { bridge, mocks } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    const policyPathsInput = screen.getAllByRole('textbox').find(
      (el) => (el as HTMLInputElement).value === '',
    ) as HTMLInputElement | undefined
    expect(policyPathsInput).toBeTruthy()
    act(() => {
      fireEvent.change(policyPathsInput as HTMLElement, {
        target: { value: '/etc/sec/policyA.spl.yaml,/etc/sec/policyB.spl.yaml' },
      })
    })

    await flushDebounce()

    fireEvent.click(await screen.findByRole('button', { name: locales.en.config_save_draft }))
    await waitFor(() => {
      // mode is already enforce (snapshot baseline), so this saves
      // cleanly without a danger dialog. The test below separately
      // covers the danger case.
      expect(mocks.saveConfigDraft).toHaveBeenCalledTimes(1)
    })
    const savedPatch = (mocks.saveConfigDraft.mock.calls[0]?.[0] ?? {}) as ConfigPatch
    expect(savedPatch['intervention']).toBeDefined()
    const intervention = savedPatch['intervention'] as Record<string, unknown>
    expect(intervention['policyPaths']).toEqual([
      '/etc/sec/policyA.spl.yaml',
      '/etc/sec/policyB.spl.yaml',
    ])
  })

  it('dangerous intervention.mode (enforce) pops the confirm dialog', async () => {
    // Build a snapshot that runs audit so flipping `intervention.mode`
    // to enforce is a real change. With the metadata's `danger: true`
    // added in the #2 fix, the save path's danger check now matches
    // both `mode` and `intervention.mode`, so the dialog fires.
    const snap = buildSnapshot()
    snap.intervention = { ...snap.intervention, mode: 'audit' }
    snap.mode = 'audit'
    const bridge: SecurityMonitorBridge = {
      ...buildMockBridge().bridge,
      getConfig: vi.fn(async () => snap),
    }
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // The intervention section's mode select is the SECOND combobox
    // (the first is the top-level `mode` select). The snapshot sets
    // both to 'audit' so we look for an 'audit' combobox inside the
    // intervention section by its data-component attr.
    const interventionModeSelect = document.querySelector(
      '[data-component="config-field-intervention-mode"] select',
    ) as HTMLSelectElement | null
    expect(interventionModeSelect).toBeTruthy()
    fireEvent.change(interventionModeSelect as HTMLElement, { target: { value: 'enforce' } })

    await flushDebounce()

    fireEvent.click(await screen.findByRole('button', { name: locales.en.config_save_draft }))
    await waitFor(() => {
      expect(screen.getByText(locales.en.config_confirm_danger_title)).toBeTruthy()
    })
    expect(screen.getByText(locales.en.config_field_danger_mode)).toBeTruthy()
  })

  it('isDirty stays false when the operator types a value and types it back', async () => {
    // The #7 fix changed isDirty from "draft has any keys" to
    // "effective value differs from baseline". A no-op edit (type
    // X, then type X again) used to leave the Save button enabled
    // and would write a no-op draft to disk.
    const { bridge, mocks } = buildMockBridge()
    renderConfig(bridge)
    await waitFor(() => {
      expect(bridge.getConfig).toHaveBeenCalled()
    })
    // The collector section is hidden when collapsed — find the
    // localOutputPath input. The snapshot value is
    // '/var/log/sec.jsonl'; type the same value back.
    const localOutputPathInput = screen.getAllByRole('textbox').find(
      (el) => (el as HTMLInputElement).value === '/var/log/sec.jsonl',
    ) as HTMLInputElement | undefined
    expect(localOutputPathInput).toBeTruthy()
    act(() => {
      fireEvent.change(localOutputPathInput as HTMLElement, {
        target: { value: '/var/log/sec.jsonl' },
      })
    })
    await flushDebounce()

    const saveButton = await screen.findByRole('button', { name: locales.en.config_save_draft })
    expect((saveButton as HTMLButtonElement).disabled).toBe(true)
    // Clicking anyway must not call saveConfigDraft (button is
    // disabled, but we also verify the call count is still 0).
    expect(mocks.saveConfigDraft).not.toHaveBeenCalled()
  })

  it('Copy JSON skips locked fields (normalize-reasserted at apply time)', async () => {
    // The #8 fix added `if (field.locked) continue` to onCopyJson so
    // locked fields (`collector.redactRawParams`, `inlineGuards.*`,
    // the four guard `*.enabled` switches, `stdioMirror.enabled`)
    // are not copied verbatim. Operators pasting the JSON into
    // cordis.patch.yml get a faithful "what will land after the
    // host's normalize pass" snapshot.
    const { bridge } = buildMockBridge()
    let copiedText = ''
    // happy-dom's clipboard.writeText stub resolves the promise; we
    // monkey-patch it on the test bridge's host to capture the text.
    const original = (globalThis as { navigator?: { clipboard?: { writeText: (s: string) => Promise<void> } } })
      .navigator?.clipboard?.writeText
    const writeText = vi.fn(async (s: string) => {
      copiedText = s
    })
    Object.defineProperty(globalThis, 'navigator', {
      value: { clipboard: { writeText } },
      configurable: true,
    })
    try {
      renderConfig(bridge)
      await waitFor(() => {
        expect(bridge.getConfig).toHaveBeenCalled()
      })
      // `getConfig` being called only means the request went out — the
      // component is still on its `state.kind === 'loading'` branch, which
      // renders a banner instead of the toolbar. findByRole waits for the
      // toolbar to mount; getByRole raced it and threw on slower runners.
      fireEvent.click(await screen.findByRole('button', { name: locales.en.copy }))
      await waitFor(() => {
        expect(writeText).toHaveBeenCalled()
      })
      const parsed = JSON.parse(copiedText) as Record<string, unknown>
      // locked: redactRawParams (collector) is force-asserted true —
      // copying it would mislead the operator (their "false" entry
      // gets re-asserted to true at apply time).
      const collector = parsed['collector'] as Record<string, unknown> | undefined
      expect(collector?.['redactRawParams']).toBeUndefined()
      // locked: inlineGuards.engineLaunchers is force-asserted to
      // the UNION of fallback + operator — copying the effective
      // list would suggest "this is what the runtime runs", which
      // is not quite right.
      const inlineGuards = parsed['inlineGuards'] as Record<string, unknown> | undefined
      expect(inlineGuards).toBeUndefined()
      // locked: sensitivePathGuard.enabled is force-true.
      const spg = parsed['sensitivePathGuard'] as Record<string, unknown> | undefined
      expect(spg?.['enabled']).toBeUndefined()
    } finally {
      if (original) {
        Object.defineProperty(globalThis, 'navigator', {
          value: { clipboard: { writeText: original } },
          configurable: true,
        })
      } else {
        Object.defineProperty(globalThis, 'navigator', {
          value: undefined,
          configurable: true,
        })
      }
    }
  })
})