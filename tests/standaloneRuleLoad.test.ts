/**
 * A follow-up: InterventionEngine `builtinRulePaths` —
 * verifies that a marketplace install (no `~/.dsh/security-policy.spl.yaml`)
 * still loads the bundled `policies/default-policy.spl.yaml` (80 active
 * rules after, removed `policies/legacy.yaml`) via
 * the constructor option.
 *
 * Why this test exists:
 * Pre--follow-up, `resolveBuiltinPaths ` defaulted to `[]`, so a
 *   fresh marketplace install whose operator hadn't shipped their own
 *   policy file would compile 0 rules — the engine still loaded, but
 *   SPL was a no-op. The `src/index.ts` change now injects the bundled
 *   default via the constructor option, and this regression test pins
 *   that behaviour.
 *
 * Strategy:
 *   1. Construct InterventionEngine with ONLY the bundled default as
 *      `builtinRulePaths` and `policyPath: '<nonexistent>'` so the
 *      operator-side load contributes zero rules — proves the bundled
 *      default is the only source of rules in this scenario.
 *   2. Verify the count + a few known rule IDs are present.
 *   3. Confirm SELF_PROTECTION rules (the most important guarantee)
 *      survived the round-trip.
 *
 * Test environment notes:
 *   - Runs against `policies/default-policy.spl.yaml` via
 *     `import.meta.url`-relative resolution (NOT `process.cwd()`) so
 *     the test stays valid regardless of the runner's CWD.
 *   - Skipped when the bundled file is missing (e.g. someone ran the
 *     test from an install tarball that didn't ship policies/).
 */

import { describe, expect, it } from 'vitest'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { normalizeConfig } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

const SHIPPED_POLICY_PATH = fileURLToPath(
  new URL('../policies/default-policy.spl.yaml', import.meta.url),
)

describe('InterventionEngine — bundled default rule-file ( follow-up)', () => {
  it('the bundled default-policy.spl.yaml exists at the expected path', () => {
    // Sanity guard — the regression test below is meaningless if the
    // bundled file got moved/renamed.
    expect(existsSync(SHIPPED_POLICY_PATH)).toBe(true)
  })

  it('loads ≥58 enabled rules from the bundled default when no operator policy exists', () => {
    // Construct a minimal config that mirrors the marketplace defaults:
    //   - `policyPath` points at a nonexistent path so the operator-
    //     side load contributes nothing.
    // `policyPaths: []` so the layered loader skips.
    //   - `mode: 'audit'` so the engine loads rules without enforce
    //     bookkeeping.
    const config = normalizeConfig({
      collector: { localOutputPath: '/tmp/sec-events.jsonl' },
      intervention: {
        enabled: true,
        mode: 'audit',
        policyPath: '/nonexistent/operator-policy.spl.yaml',
        policyPaths: [],
        reloadIntervalMs: 60_000,
        decisionTimeoutMs: 50,
        failStrategy: 'fail_open',
      },
    })

    const engine = new InterventionEngine(config, {
      builtinRulePaths: [SHIPPED_POLICY_PATH],
    })
    engine.initialize()

    // The shipped policy declares 79 rules total, of which 21 are
    // intentionally `enabled: false` (they ship as documentation +
    // operator-on-demand toggles, never active by default). The
    // engine only compiles enabled rules, so we assert ≥58 (= 79
    // minus the 21 disabled). The 3 rules added during the
    // merge (`block-crypto-mining-binary` / `-pool` /
    // `block-kernel-module-load`) are all enabled and bring the
    // pre- baseline of 55 up to 58.
    //
    // Note: `loaded.error` is allowed to carry the "operator policy
    // file not found" warning because the legacy single-file path
    // (policyPath) failed — but the bundled builtins still load via
    // the follow-up path. The rules array is the source of
    // truth here.
    const loaded = engine.getLoadedPolicy()
    expect(loaded.rules.length).toBeGreaterThanOrEqual(58)

    // Spot-check that the known SelfProtection IDs survived the
    // round-trip — these are the rules whose presence an operator
    // can rely on even before they ship their own policy file.
    const ids = loaded.rules.map((r) => r.id)
    expect(ids).toContain('self-protection-block-uninstall')
    // 014/015/016/017/018 (kill/pkill/unpatched-restart/disabler-script/kernel-module-load
    // /decode-shell) are the highest-priority rules the marketplace
    // ships; any of them is sufficient evidence that the
    // SelfProtection block survived.
    const hasHighPriorityGuard = ids.some(
      (id) =>
        id === 'self-protection-block-harness-process-kill' ||
        id === 'self-protection-block-restart-without-patch' ||
        id === 'self-protection-block-write-disabler-script' ||
        id === 'self-protection-block-execute-scratch-script' ||
        id === 'self-protection-block-decode-then-execute',
    )
    expect(hasHighPriorityGuard).toBe(true)

    engine.shutdown()
  })

  it('an explicit empty array disables the bundled default (opt-out path)', () => {
    // Operators who explicitly want NO builtins (rare — usually only
    // custom deployments that ship their own curated policy) can pass
    // `builtinRulePaths: []`. The constructor branch treats an empty
    // array as "no append", distinct from `null` (which falls back to
    // the env var).
    const config = normalizeConfig({
      collector: { localOutputPath: '/tmp/sec-events.jsonl' },
      intervention: {
        enabled: true,
        mode: 'audit',
        policyPath: '/nonexistent/operator-policy.spl.yaml',
        policyPaths: [],
        reloadIntervalMs: 60_000,
        decisionTimeoutMs: 50,
        failStrategy: 'fail_open',
      },
    })

    const engine = new InterventionEngine(config, { builtinRulePaths: [] })
    engine.initialize()

    // 0 rules is the only possible outcome here — no operator policy,
    // no builtins. Behavioural confirmation: the kill command should
    // pass through (no rule to block it).
    const decision = engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'kill -9 12345' },
      riskFlags: [],
      session: { id: 'standalone-opt-out-test', agentId: 'test' },
    } as unknown as Parameters<typeof engine.evaluate>[0])
    expect(decision.decision).not.toBe('block')

    engine.shutdown()
  })
})