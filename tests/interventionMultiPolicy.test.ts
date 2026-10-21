/**
 * InterventionEngine multi-file policy loading.
 *
 * Verifies the append-after-user merge semantics introduced in
 * the new `intervention.policyPaths` config field:
 *
 *   - Legacy `policyPath` (single file) keeps working unchanged — the
 *     existing tamper-hash / single-file path is preserved verbatim.
 *   - `policyPaths: [...]` switches to multi-file mode. User paths load
 *     first; the constructor-supplied `builtinRulePaths` (or the env
 *     var fallback) append AFTER.
 *   - Combined hash covers every file so a write to any one of them
 *     trips tamper detection.
 *   - Per-file errors are isolated — a single bad file does not block
 *     the merge.
 *
 * These tests construct InterventionEngine directly with explicit
 * `builtinRulePaths: []` (or a temp-dir path list) so the engine is
 * fully decoupled from filesystem layout.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

function makeConfig(
  tmpDir: string,
  intervention: Record<string, unknown>,
): Config {
  return normalizeConfig({
    mode: 'audit',
    collector: {
      localOutputPath: join(tmpDir, 'security-events.jsonl'),
      flushIntervalMs: 10,
    },
    intervention,
  })
}

function writePolicy(tmpDir: string, fileName: string, rules: unknown[]): string {
  const policy = {
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: fileName.replace(/\..*$/, '') },
    rules,
  }
  const path = join(tmpDir, fileName)
  writeFileSync(path, JSON.stringify(policy, null, 2))
  return path
}

let tmpDir: string
beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 's3b-policy-'))
})
afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true })
})

describe('InterventionEngine multi-file policy loading', () => {
  describe('legacy single-file path (policyPath) keeps working', () => {
    it('loads a single policy.json and exposes the rules', () => {
      const path = writePolicy(tmpDir, 'policy.json', [
        { id: 'legacy.one', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const cfg = makeConfig(tmpDir, { policyPath: path, reloadIntervalMs: 0 })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [] })
      engine.initialize()
      const loaded = engine.getLoadedPolicy()
      expect(loaded.rules.map((r) => r.id)).toEqual(['legacy.one'])
      expect(loaded.error).toBeUndefined()
      engine.shutdown()
    })
  })

  describe('multi-file path (policyPaths)', () => {
    it('loads user paths in order, then appends builtin paths', () => {
      const userA = writePolicy(tmpDir, 'user-a.json', [
        { id: 'user.a', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const userB = writePolicy(tmpDir, 'user-b.json', [
        { id: 'user.b', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const builtin = writePolicy(tmpDir, 'builtin.json', [
        { id: 'builtin.high', priority: 1100, category: 'intrusion_defense', match: { tools: ['bash'] }, action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_TEST_HIGH_001' } },
      ])
      const cfg = makeConfig(tmpDir, {
        policyPath: '',
        policyPaths: [userA, userB],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [builtin] })
      engine.initialize()
      const loaded = engine.getLoadedPolicy()
      const ids = loaded.rules.map((r) => r.id)
      // Builtin (priority 1100) sorts ahead of user (100). Within each
      // group the input order is preserved: user.a → user.b, builtin.high
      // is alone.
      expect(ids).toEqual(['builtin.high', 'user.a', 'user.b'])
      engine.shutdown()
    })

    it('user rule at priority 800 vs builtin at 1000: builtin wins on priority', () => {
      const userPath = writePolicy(tmpDir, 'user.json', [
        { id: 'user.allow', priority: 800, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const builtinPath = writePolicy(tmpDir, 'builtin.json', [
        { id: 'builtin.block', priority: 1000, category: 'intrusion_defense', match: { tools: ['bash'] }, action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_TEST_BUILTIN_BLOCK_001' } },
      ])
      const cfg = makeConfig(tmpDir, {
        policyPaths: [userPath],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [builtinPath] })
      engine.initialize()
      const ids = engine.getLoadedPolicy().rules.map((r) => r.id)
      // builtin (1000) first, then user (800) — `composeDecision` picks
      // the highest-priority match. The verify below checks the priority
      // ordering, not the verdict composition.
      expect(ids).toEqual(['builtin.block', 'user.allow'])
      engine.shutdown()
    })

    it('user rule at priority 1100 vs builtin at 1000: user wins (priority wins, not origin)', () => {
      // The "append-after-user" semantic only applies when priorities
      // tie. A higher-priority user rule still beats a lower-priority
      // builtin — operators who need to override a builtin ship a
      // higher priority.
      const userPath = writePolicy(tmpDir, 'user.json', [
        { id: 'user.override', priority: 1100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const builtinPath = writePolicy(tmpDir, 'builtin.json', [
        { id: 'builtin.block', priority: 1000, category: 'intrusion_defense', match: { tools: ['bash'] }, action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_TEST_BUILTIN_BLOCK_001' } },
      ])
      const cfg = makeConfig(tmpDir, {
        policyPaths: [userPath],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [builtinPath] })
      engine.initialize()
      const ids = engine.getLoadedPolicy().rules.map((r) => r.id)
      expect(ids).toEqual(['user.override', 'builtin.block'])
      engine.shutdown()
    })

    it('tie-break at equal priority: user rule shadows builtin', () => {
      const userPath = writePolicy(tmpDir, 'user.json', [
        { id: 'user.tie', priority: 1000, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const builtinPath = writePolicy(tmpDir, 'builtin.json', [
        { id: 'builtin.tie', priority: 1000, category: 'intrusion_defense', match: { tools: ['bash'] }, action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_TEST_BUILTIN_TIE_001' } },
      ])
      const cfg = makeConfig(tmpDir, {
        policyPaths: [userPath],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [builtinPath] })
      engine.initialize()
      const ids = engine.getLoadedPolicy().rules.map((r) => r.id)
      // loadMultiplePolicies sorts priority desc + stable by input order;
      // user paths come first → user's rule ahead at equal priority.
      expect(ids).toEqual(['user.tie', 'builtin.tie'])
      engine.shutdown()
    })

    it('isolates per-file errors: bad user file does not break the merge', () => {
      const goodPath = writePolicy(tmpDir, 'good.json', [
        { id: 'good.one', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const badPath = join(tmpDir, 'bad.json')
      writeFileSync(badPath, 'rules:\n  - id: bad\n    match: { tools: [unclosed')
      const cfg = makeConfig(tmpDir, {
        policyPaths: [goodPath, badPath],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [] })
      engine.initialize()
      const loaded = engine.getLoadedPolicy()
      // The good rule still loaded; the error is surfaced via the
      // dedicated accessor, not silently dropped.
      expect(loaded.rules.map((r) => r.id)).toEqual(['good.one'])
      const errors = engine.getLastLoadErrors()
      expect(errors.length).toBe(1)
      expect(errors[0]?.path).toBe(badPath)
      engine.shutdown()
    })

    it('reports missing user paths via getLastLoadErrors without aborting the merge', () => {
      const goodPath = writePolicy(tmpDir, 'good.json', [
        { id: 'good.one', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const missingPath = join(tmpDir, 'does-not-exist.json')
      const cfg = makeConfig(tmpDir, {
        policyPaths: [goodPath, missingPath],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [] })
      engine.initialize()
      const loaded = engine.getLoadedPolicy()
      expect(loaded.rules.map((r) => r.id)).toEqual(['good.one'])
      const errors = engine.getLastLoadErrors()
      expect(errors.some((e) => e.path === missingPath)).toBe(true)
      engine.shutdown()
    })

    it('no-op when policyPaths is empty (legacy path)', () => {
      // Empty array falls back to single-file mode (`policyPath`). The
      // `policyPaths` field defaults to `[]` after normalizeConfig so
      // this is the post-migration default for operators who haven't
      // opted in.
      const path = writePolicy(tmpDir, 'policy.json', [
        { id: 'legacy.one', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const cfg = makeConfig(tmpDir, {
        policyPath: path,
        policyPaths: [],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [] })
      engine.initialize()
      expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['legacy.one'])
      engine.shutdown()
    })

    it('an empty builtinRulePaths list disables the append', () => {
      const userPath = writePolicy(tmpDir, 'user.json', [
        { id: 'user.one', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const cfg = makeConfig(tmpDir, {
        policyPaths: [userPath],
        reloadIntervalMs: 0,
      })
      const engine = new InterventionEngine(cfg, { builtinRulePaths: [] })
      engine.initialize()
      expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['user.one'])
      engine.shutdown()
    })
  })

  describe('multi-file tamper detection', () => {
    it('flags tamper when any one file in the merged set changes', () => {
      const userPath = writePolicy(tmpDir, 'user.json', [
        { id: 'user.one', priority: 100, category: 'behavior_guidance', match: { tools: ['bash'] }, action: { decision: 'allow' } },
      ])
      const builtinPath = writePolicy(tmpDir, 'builtin.json', [
        { id: 'builtin.one', priority: 1100, category: 'intrusion_defense', match: { tools: ['bash'] }, action: { decision: 'block', blockCode: 'INTRUSION_DEFENSE_TEST_BUILTIN_ONE_001' } },
      ])
      const cfg = makeConfig(tmpDir, {
        policyPaths: [userPath],
        reloadIntervalMs: 0,
      })
      const tamperEvents: unknown[] = []
      const engine = new InterventionEngine(cfg, {
        builtinRulePaths: [builtinPath],
        onTamper: (info) => tamperEvents.push(info),
      })
      engine.initialize()
      const before = engine.getLoadedPolicy().rules.map((r) => r.id)
      expect(before.length).toBe(2)

      // Mutate the builtin file. The next reload should detect the
      // hash divergence and reject the reload, keeping prior rules in
      // effect.
      writeFileSync(builtinPath, JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'builtin' },
        rules: [
          { id: 'builtin.tampered', priority: 999, category: 'intrusion_defense', match: { tools: ['bash'] }, action: { decision: 'allow' } },
        ],
      }))
      // Force a reload via initialize semantics — call the private
      // method through the public surface (the reload timer is
      // disabled in this test, so we trigger via a second engine
      // instance that re-reads the same baseline).
      // We simulate the reload by constructing a new engine against
      // the same paths and asserting the tamper counter increments.
      const engine2 = new InterventionEngine(cfg, {
        builtinRulePaths: [builtinPath],
      })
      engine2.initialize()
      // engine2 has its own baseline (just-initialized) — it loads the
      // tampered file cleanly. So tamper detection needs a re-load
      // against an existing baseline; we verify the *mechanism* by
      // reading the tamper counter on engine after a forced reload via
      // the timer (manual setInterval firing) — but the cleanest test
      // is to confirm that the engine records hash state on first load
      // and detects changes on reload. We exercise the reload path
      // manually below.
      engine2.shutdown()

      // Now exercise the same engine against the tampered file:
      // re-initialize triggers reloadPolicy which sees the divergence.
      // First call to engine.initialize() already loaded the baseline;
      // we need to force the reload timer to fire. Easiest: rebuild
      // engine with same config and exercise tamper via second engine.
      const tamperedEngine = new InterventionEngine(cfg, {
        builtinRulePaths: [builtinPath],
      })
      tamperedEngine.initialize()
      // At this point tamperedEngine's baseline is the tampered file
      // (it just loaded it). To test tamper detection, mutate again
      // and call reloadPolicy. We expose this via a second initialize
      // — which re-runs reloadPolicy() against the existing baseline.
      writeFileSync(builtinPath, JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'builtin' },
        rules: [
          { id: 'builtin.third', priority: 999, category: 'intrusion_defense', match: { tools: ['bash'] }, action: { decision: 'allow' } },
        ],
      }))
      // Calling initialize() again triggers reloadPolicy against the
      // existing baseline.
      tamperedEngine.initialize()
      const tamperState = tamperedEngine.getPolicyTamperState()
      expect(tamperState.tamperCount).toBeGreaterThanOrEqual(1)
      tamperedEngine.shutdown()
      engine.shutdown()
    })
  })
})