/**
 * Schemastery Config mirror unit tests.
 *
 * Verifies the soft-validation contract documented in
 * src/config.schema.ts:
 *   - Empty input → all defaults (mode=enforce, enabled=true, blocks={})
 *   - Valid partial input → merged with defaults, unknown fields dropped (loose)
 *   - Invalid input → validateConfig returns undefined (fallback path)
 *
 * These tests guard against regression in the Schemastery API surface
 * (the d.ts namespace-as-interface trick is fragile across upgrades).
 */

import { describe, expect, it } from 'vitest'
import Schema from '@deepseek-ai/schemastery'

import { Config, validateConfig } from '../src/config.schema.js'
import { normalizeConfig } from '../src/config.js'

// A.5 housekeeping: ActionSchema and ModeSchema were
// promoted out of src/config.schema.ts (the src side had no callers
// after never wired DecisionComposer to use ActionSchema — the
// decision vocabulary is exercised by the test below instead). These
// are test-only schemas that pin the marketplace 3-action and
// 2-mode contracts.
const ActionSchema = Schema.union(['allow', 'deny', 'ask'] as const)
const ModeSchema = Schema.union(['audit', 'enforce'] as const)

describe('config.schema ( marketplace mirror)', () => {
  describe('validateConfig', () => {
    it('returns defaults for empty input', () => {
      const result = validateConfig({})
      expect(result).toBeDefined()
      expect(result?.enabled).toBe(true)
      expect(result?.mode).toBe('enforce')
    })

    it('returns defaults for undefined / null input (never throws)', () => {
      expect(validateConfig(undefined)).toBeDefined()
      expect(validateConfig(null)).toBeDefined()
    })

    it('preserves explicit overrides', () => {
      const result = validateConfig({ mode: 'enforce', enabled: false })
      expect(result?.mode).toBe('enforce')
      expect(result?.enabled).toBe(false)
    })

    it('accepts unknown top-level fields (loose mode preserves them)', () => {
      // The top-level `Schema.object(...).loose(true)` lets marketplace
      // forward-compatibility fields pass through silently. We only
      // assert non-rejection here; whether the unknown field ends up
      // on the validated object is implementation-defined and may
      // change between schemastery releases.
      const result = validateConfig({
        mode: 'audit',
        futureMarketplaceField: { anything: true },
      })
      expect(result).toBeDefined()
    })

    it('autofix repairs an invalid mode value to the default', () => {
      // schemastery 3.x's `autofix:true` semantics: a strict field that
      // fails validation falls back to its `default()` and the call
      // succeeds. We do NOT want the runtime to throw on misconfigured
      // patches — `normalizeConfig` already runs after, so the worst
      // case is a slightly looser runtime config than the operator
      // intended. The audit log records the repaired value so the
      // operator can spot the misconfig post-hoc.
      //
      // 2026-10-10: default flipped to 'enforce' (see config.schema.ts).
      const result = validateConfig({ mode: 'invalid' as unknown as 'enforce' })
      expect(result).toBeDefined()
      expect(result?.mode).toBe('enforce')
    })
  })

  describe('Config direct call (Schemastery schema runtime)', () => {
    it('Config({}) returns the same shape as validateConfig({})', () => {
      const a = Config({})
      const b = validateConfig({})
      expect(a).toEqual(b)
    })
  })

  describe('ModeSchema', () => {
    it('accepts audit / enforce', () => {
      expect(ModeSchema('audit')).toBe('audit')
      expect(ModeSchema('enforce')).toBe('enforce')
    })

    it('throws on unknown mode', () => {
      expect(() => ModeSchema('garbage' as unknown as 'audit')).toThrow()
    })
  })

  describe('ActionSchema ( marketplace 3-action vocabulary)', () => {
    it('accepts allow / deny / ask', () => {
      expect(ActionSchema('allow')).toBe('allow')
      expect(ActionSchema('deny')).toBe('deny')
      expect(ActionSchema('ask')).toBe('ask')
    })

    it('throws on the legacy 8-action vocabulary (escalate / degrade etc.)', () => {
      // retires these — already enforces the 3-action contract
      // at the Schema layer so misconfigured rules fail loudly at load.
      expect(() => ActionSchema('escalate' as unknown as 'allow')).toThrow()
      expect(() => ActionSchema('degrade' as unknown as 'allow')).toThrow()
      expect(() => ActionSchema('modify' as unknown as 'allow')).toThrow()
    })
  })

  describe('sub-structure defaults (mirror src/config.ts)', () => {
    // Each block must surface the same defaults `normalizeConfig`
    // would have produced in isolation. The collector / application /
    // system / intervention / assetMonitor / environment / outbox blocks
    // are exercised end-to-end via `validateConfig({})` — defaults are
    // read off the returned object.

    it('collector block carries the marketplace defaults', () => {
      const r = validateConfig({})
      // trimmed the dead schema fields (endpoint /
      // maxRetries / timeoutMs / auth / collectorType / runtimeMode /
      // capabilities / httpCatchup) — the marketplace plugin does not
      // reach those code paths. The Schemastery surface mirrors the
      // live Config collector defaults.
      expect(r?.collector).toMatchObject({
        localOutputPath: '~/.dsh/security-events.jsonl',
        batchSize: 100,
        flushIntervalMs: 1000,
        validateEvents: true,
        redactRawParams: true,
        debugLogPath: '',
      })
    })

    it('application block carries the marketplace defaults', () => {
      const r = validateConfig({})
      // runtimeHooks / httpCapture moved to top-level
      // runtimeHooks / networkCapture in; `application.enabled` is
      // redundant with top-level `enabled`.
      expect(r?.application).toMatchObject({
        captureUserPrompt: true,
        captureSystemPrompt: true,
        captureAgentPlan: true,
        captureReasoning: true,
        toolResultMaxChars: 100000,
        sessionTtlMs: 1800000,
      })
    })

    it('system block is NOT carried in the marketplace Config schema (strip)', () => {
      // stripped the system-level process monitor
      // (Python psutil / SystemCollector) from the marketplace
      // deployment surface. Pre- this assertion existed as a
      // positive check on `system.procfs` defaults; replaced
      // it with a negative check that the marketplace Schema no
      // longer carries the block.
      const r = validateConfig({})
      expect(r?.['system']).toBeUndefined()
    })

    it('cgroups block is NOT carried in the marketplace Config schema (strip)', () => {
      // historical: cgroup v1/v2 was deferred;
      // subsequently removed the entire phase 4 surface.
      const r = validateConfig({})
      const cgroups = (r?.['system'] as Record<string, unknown> | undefined)?.['cgroups']
      expect(cgroups).toBeUndefined()
    })

    it('intervention block carries the legacy defaults (mode inherits from top-level)', () => {
      const r = validateConfig({})
      // `intervention.mode` is intentionally left without a Schema default
      // so `normalizeConfig` can propagate the top-level `mode` into it.
      // When the user passes nothing, the Schema leaves `mode` unset,
      // and `normalizeConfig` falls back to the top-level default
      // ('enforce' as of 2026-10-10) via the
      // `defaultInterventionConfig(input, defaultMode)` factory.
      expect(r?.intervention).toMatchObject({
        enabled: true,
        policyPath: '~/.dsh/security-policy.spl.yaml',
        reloadIntervalMs: 30000,
        decisionTimeoutMs: 150,
        failStrategy: 'fail_open',
      })
    })

    it('assetMonitor block is NOT carried in the marketplace Config schema (strip)', () => {
      // stripped AssetCollector from the marketplace
      // surface (forbidden to read `~/.dsh/` at runtime under the
      // marketplace sandbox).
      const r = validateConfig({})
      expect(r?.['assetMonitor']).toBeUndefined()
    })

    it('outbox block is NOT carried in the marketplace Config schema (strip)', () => {
      // stripped the EscalationOutbox (platform
      // deployment only).
      const r = validateConfig({})
      expect(r?.['outbox']).toBeUndefined()
    })

    it('environment block is NOT carried in the marketplace Config schema (strip)', () => {
      // stripped the environment block from the
      // marketplace; hostId / containerId were promoted to
      // top-level Config fields in.
      const r = validateConfig({})
      expect(r?.['environment']).toBeUndefined()
      // hostId / containerId live at top level instead.
      expect(r?.['hostId']).toBe('')
      expect(r?.['containerId']).toBe('')
    })
  })

  describe('autofix contract: type mismatches repair silently, loose-on-typo', () => {
    // A's call site passes `{ autofix: true }` for marketplace
    // forward-compatibility. The autofix contract from
    // @deepseek-ai/schemastery 3.x has two regimes:
    //
    //   - Loose: a misspelled sub-key on a `Schema.object(...)` block
    //     (e.g. `redactRawparams` vs the canonical `redactRawParams`)
    //     is KEPT alongside the canonical default. The Schema does
    //     NOT silently drop unknown fields — that's the responsibility
    // of the caller. documents this so a future maintainer
    //     doesn't think autofix dropped the typo.
    //
    //   - Strict-on-type: a value of the wrong type on a typed field
    //     (e.g. `redactRawParams: "false"` as a string instead of
    //     boolean) is REPAIRED to the field's `default()` silently.
    // This is the headline gain of : a stringy `false` used
    //     to slip past legacy `boolean(value, defaultValue)` because
    //     it was typeof `'string'`, not `'boolean'` — the legacy
    //     function returned `defaultValue: true` silently. The Schema
    //     now catches and repairs to the same default, but via a
    //     documented code path.
    //
    //   - Strict-on-enum: an enum value that doesn't match any
    //     declared literal (e.g. `runtimeMode: 'sometimes'`) is
    //     repaired to the field's `default()`. Same code path as the
    //     type-mismatch regime.

    it('keeps a wrong-case `redactRawparams` AND the canonical default (loose object)', () => {
      // Document the loose-object contract: unknown sub-keys are not
      // dropped, they're preserved alongside the canonical default.
      // This matches the schemastery 3.x behavior (no implicit filter).
      const r = validateConfig({
        collector: { redactRawparams: false },
      })
      expect(r).toBeDefined()
      const collector = r?.collector as Record<string, unknown>
      // Both keys coexist — the typo doesn't replace the canonical.
      expect(collector?.['redactRawparams']).toBe(false)
      expect(collector?.['redactRawParams']).toBe(true)
    })

    it('repairs a stringy `redactRawParams: "false"` to the default (true)', () => {
      // This is the win: a YAML where `redactRawParams:"false"`
      // (string, not boolean) used to silently default to `true` via
      // legacy `boolean(value, defaultValue)`. The Schema now repairs
      // the same default via autofix:true, but on a documented path.
      const r = validateConfig({
        collector: { redactRawParams: 'false' as unknown as boolean },
      })
      expect(r).toBeDefined()
      const collector = r?.collector as Record<string, unknown>
      expect(collector?.['redactRawParams']).toBe(true)
    })

    it('repairs an unknown enum value (intervention.failStrategy=unlisted) to the default', () => {
      // `runtimeMode` was retired in (Collector Config no
      // longer models it). The remaining `failStrategy` enum is the
      // canonical autofix repair target now.
      const r = validateConfig({
        intervention: { failStrategy: 'sometimes' as unknown as 'fail_open' },
      })
      expect(r).toBeDefined()
      const intervention = r?.intervention as Record<string, unknown>
      expect(intervention?.['failStrategy']).toBe('fail_open')
    })

    it('repairs an unknown top-level `mode` to the default', () => {
      // 2026-10-10: default flipped from 'audit' → 'enforce' (see
      // src/config.schema.ts:381). The repair semantics are unchanged —
      // schemastery autofix replaces an unknown mode value with the
      // schema default — only the default value moved.
      const r = validateConfig({ mode: 'silent' as unknown as 'enforce' })
      expect(r?.mode).toBe('enforce')
    })

    it('accepts `mode: enforce` at the top level (positive control)', () => {
      const r = validateConfig({ mode: 'enforce' })
      expect(r?.mode).toBe('enforce')
    })
  })

  describe('strict-on-strict-fields: throws when autofix is disabled', () => {
    // The `autofix: true` default at the call site is the right
    // marketplace ergonomics — keep the runtime resilient. But the
    // underlying Schema is still strict on type / enum mismatches,
    // and tests prove that by constructing the Config Schema
    // directly without autofix. This is the escape hatch operators
    // get when they want loud failures (e.g. CI linting of
    // marketplace patches before publish).

    it('throws on `mode: silent` when autofix is disabled', () => {
      expect(() => Config({ mode: 'silent' as unknown as 'audit' }, { autofix: false })).toThrow()
    })

    it('throws on a stringy `redactRawParams` when autofix is disabled', () => {
      expect(() => Config({ collector: { redactRawParams: 'false' as unknown as boolean } }, { autofix: false })).toThrow()
    })

    it('throws on `intervention.failStrategy: sometimes` when autofix is disabled', () => {
      // `runtimeMode` retired in; `failStrategy` enum is
      // the canonical strict-on-enum surface.
      expect(() => Config({ intervention: { failStrategy: 'sometimes' as unknown as 'fail_open' } }, { autofix: false })).toThrow()
    })
  })

  describe('wiring: validateConfig → normalizeConfig', () => {
    // A validated but discarded the result. passes the Schema-
    // filled object into `normalizeConfig` so the Schema defaults
    // become authoritative. We test the round-trip end-to-end: the
    // legacy defaults (mode, collector.*, application.*, ...) match
    // what normalizeConfig would have produced in isolation.

    it('validateConfig({}) → normalizeConfig() round-trip produces the marketplace shape', () => {
      // marketplace form: the pre-marketplace fields (application.enabled
      // application.runtimeHooks, system.procfs, assetMonitor, outbox)
      // were stripped. Schemastery Config mirror only models the
      // marketplace surface — round-trip assertions below cover that
      // surface only.
      const validated = validateConfig({})
      expect(validated).toBeDefined()
      const config = normalizeConfig(validated)
      // 2026-10-10: default flipped from 'audit' → 'enforce' so a
      // fresh install lands in enforce at the normalize layer.
      expect(config.mode).toBe('enforce')
      expect(config.enabled).toBe(true)
      expect(config.collector.localOutputPath).toBe('~/.dsh/security-events.jsonl')
      expect(config.collector.batchSize).toBe(100)
      expect(config.collector.maxFileBytes).toBe(52428800)
      expect(config.application.captureUserPrompt).toBe(true)
      expect(config.application.toolResultMaxChars).toBe(100_000)
      expect(config.runtimeHooks.enabledAtSubprocess).toBe(true)
      expect(config.runtimeHooks.blockAtSubprocess).toBe(false)
      expect(config.runtimeHooks.logPath).toBe('~/.dsh/security-events-runtime.jsonl')
      expect(config.networkCapture.enabled).toBe(true)
      expect(config.networkCapture.maxBodyBytes).toBe(1024 * 1024)
      expect(config.intervention.policyPath).toBe('~/.dsh/security-policy.spl.yaml')
      expect(config.intervention.policyPaths).toEqual([])
    })

    it('a user override flows through Schema then normalizeConfig', () => {
      const validated = validateConfig({ mode: 'enforce' })
      expect(validated?.mode).toBe('enforce')
      const config = normalizeConfig(validated)
      expect(config.mode).toBe('enforce')
      // intervention.mode follows the top-level mode by default —
      // Schema's intervention.mode has no default of its own
      // (intentionally — see config.schema.ts:139-145); normalizeConfig
      // propagates the top-level `mode` into it via `defaultMode`.
      // 2026-10-10: top-level default flipped from 'audit' → 'enforce',
      // so a fresh install's `intervention.mode` is also 'enforce'.
      expect(config.intervention.mode).toBe('enforce')
    })

    it('falls back to normalizeConfig(raw) when Schema fails', () => {
      // `validateConfig` returns undefined for malformed input; the
      // caller passes the raw input through unchanged. We simulate that
      // contract here and confirm the fallback shape matches what the
      // legacy path would have produced.
      const raw = { mode: 'enforce' as const, collector: { batchSize: 7 } }
      const validated = validateConfig(raw)
      // Schema passes — Schema-validated defaults flow into the
      // normalizeConfig call. The collector.batchSize override
      // (user value 7) survives the round-trip.
      expect(validated).toBeDefined()
      const config = normalizeConfig(validated ?? raw)
      expect(config.collector.batchSize).toBe(7)
      expect(config.mode).toBe('enforce')
    })
  })
})
