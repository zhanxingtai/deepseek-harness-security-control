/**
 * 2026-09-28: Regression pin for the bundled-policy `trustedBaselineHash`
 * seed inside `src/bootstrap.ts`.
 *
 * Background (the bug this test pins):
 * Bug fixed the bundled-policy PATH (was `./policies/...`, now
 *     `../policies/...`) so the bundled baseline loaded correctly.
 *   - With the path fixed, the engine's reload-time tamper detector
 *     still rejected EVERY reload with
 *     `policy tamper detected (count=N); reload rejected, prior rules
 *     remain in effect`.
 *   - Root cause: the format of `trustedBaselineHash` seeded from
 *     bootstrap did NOT match the format the engine computes for
 *     `bundledHashForTamper`. Bootstrap was seeding
 *     `sha256(content)` (a single hash of the raw file content). The
 *     engine computes
 *       sha256( map(e => `${e.path}:${e.hash}`).join('|') )
 *     where `e.hash` is `sha256(content)`. For the single bundled
 *     file this collapses to
 *       sha256( `${bundledPath}:${sha256(content)}` )
 *     — an OUTER hash over `path:contentHash`, not the inner
 *     `sha256(content)` the seed was producing.
 *   - Since the two formats never matched, every reload since
 *     startup tripped tamper (`tamperCount` grew by 1 per click; the
 *     operator reported count=3 after three reload attempts).
 *
 * This test pins three properties:
 *   1. `bootstrap.ts` includes the outer-shape seed
 *      `sha256( `${path}:${sha256(content)}` )`, NOT the inner
 *      `sha256(content)`.
 *   2. The compiled `lib/bootstrap.js` (what the marketplace runtime
 *      actually loads) computes the same outer-shape seed — the
 *      property survives `tsc`.
 *   3. The outer-shape seed, fed into a fresh InterventionEngine
 *      constructed with `builtinRulePaths: [bundledPath]`, does NOT
 *      trip tamper on the first reload (the test contract for the
 *      tamper-baseline option documented in
 *      `tests/policyReloadedAudit.test.ts`).
 *
 * Property (3) needs the InterventionEngine + the bundled policy
 * file — it pulls in cordis-free paths but does exercise the full
 * tamper pipeline. Property (1)+(2) are cheap source-text pins; we
 * run all three so a future refactor that drops the outer shape in
 * EITHER the source or the compiled output fails here, not in
 * production.
 */

import { describe, expect, it } from 'vitest'
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'

import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import { normalizeConfig } from '../src/config.js'

const BOOTSTRAP_TS = fileURLToPath(new URL('../src/bootstrap.ts', import.meta.url))
const LIB_BOOTSTRAP_JS = fileURLToPath(new URL('../lib/bootstrap.js', import.meta.url))
const PACKAGE_ROOT = dirname(dirname(LIB_BOOTSTRAP_JS))
const BUNDLED_POLICY = join(PACKAGE_ROOT, 'policies', 'default-policy.spl.yaml')

describe('bootstrap — trustedBaselineHash format', () => {
  it('bootstrap.ts seeds sha256(`${path}:${sha256(content)}`), NOT just sha256(content)', () => {
    const source = readFileSync(BOOTSTRAP_TS, 'utf8')
    // The bug: old code did
    //   trustedBaselineHash = createHash('sha256').update(content).digest('hex')
    // — the inner hash only. The engine's bundledHashForTamper is an
    // outer hash over `${path}:${contentHash}`, so the two never
    // matched and every reload tripped tamper.
    expect(source).not.toMatch(
      /trustedBaselineHash\s*=\s*createHash\(['"]sha256['"]\)\s*\.update\(content\)\s*\.digest\(['"]hex['"]\)/,
    )
    // The fix: build `${path}:${sha256(content)}` then sha256 that
    // joined string. Look for the outer-shape string-template form.
    expect(source).toMatch(/trustedBaselineHash\s*=\s*createHash\(['"]sha256['"]\)/)
    // The seeded input must include `${...}:${...}` (path:hash shape)
    // — the inner content-only form is the regression we're pinning.
    expect(source).toMatch(/`\$\{[^}]+\}:\$\{[^}]+\}`/)
  })

  it('compiled lib/bootstrap.js preserves the outer-shape seed (survives tsc)', () => {
    // The marketplace runtime loads the compiled bootstrap, not the
    // .ts source. We must verify the outer-shape string-template
    // form actually survived the build (a future tsc plugin or
    // minifier that destructures template literals could regress
    // this without changing the source).
    expect(readFileSync(LIB_BOOTSTRAP_JS, 'utf8')).toMatch(/`\$\{[^}]+\}:\$\{[^}]+\}`/)
    // And the inner-content-only DIRECT-ASSIGNMENT form must NOT
    // appear — the inner hash IS allowed as an intermediate step
    // (the outer-shape fix uses `sha256(content)` to build the
    // inner hash before re-hashing with the path). The regression
    // we're pinning is the direct `trustedBaselineHash =
    // createHash('sha256').update(content).digest('hex')` form,
    // which is what the pre-fix code did.
    expect(readFileSync(LIB_BOOTSTRAP_JS, 'utf8')).not.toMatch(
      /trustedBaselineHash\s*=\s*createHash\(['"]sha256['"]\)\s*\.update\(content\)\s*\.digest\(['"]hex['"]\)/,
    )
  })

  it('does not trip tamper on first reload (end-to-end engine contract)', async () => {
    // Property (3): run the full tamper pipeline against the actual
    // bundled policy. We compute the outer-shape seed the same way
    // the fixed bootstrap does, hand it to InterventionEngine via
    // the constructor option, and verify the first reload passes
    // tamper (i.e. tamperCount stays 0, rules load). If the seed
    // format drifts again, this assertion fires.
    expect(readFileSync(BUNDLED_POLICY, 'utf8').length, 'bundled policy must exist').toBeGreaterThan(0)
    const content = readFileSync(BUNDLED_POLICY, 'utf8')
    const contentHash = createHash('sha256').update(content).digest('hex')
    const seededBaseline = createHash('sha256')
      .update(`${BUNDLED_POLICY}:${contentHash}`)
      .digest('hex')

    // Build a config that points ONLY at the bundled path. policyPaths
    // empty, policyPath empty, builtinRulePaths resolves to the same
    // bundled file via the constructor option (so the engine doesn't
    // have to find it through env or filesystem guessing).
    const tmpDir = join(tmpdir(), `dsecmon-baseline-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
    mkdirSync(tmpDir, { recursive: true })
    writeFileSync(join(tmpDir, 'sink.jsonl'), '', 'utf8')
    try {
      const config = normalizeConfig({
        mode: 'enforce',
        collector: { localOutputPath: join(tmpDir, 'sink.jsonl'), flushIntervalMs: 0 },
        intervention: { policyPaths: [], reloadIntervalMs: 0 },
      })
      const tamperEvents: number[] = []
      const engine = new InterventionEngine(config, {
        builtinRulePaths: [BUNDLED_POLICY],
        trustedBaselineHash: seededBaseline,
        onTamper: () => tamperEvents.push(1),
      })
      engine.initialize()

      // First reload is the test contract: tamper MUST NOT fire
      // (the seeded baseline matches what the engine computes
      // for the unchanged bundled file).
      engine.triggerReload()
      expect(tamperEvents.length, 'tamper fired on unchanged bundled file — seed format drifted').toBe(0)
      const tamperState = engine.getPolicyTamperState()
      expect(tamperState.tamperCount).toBe(0)
      // And the bundled policy actually loaded — the engine reports
      // a non-zero rule count, so the UI's "0 rules" symptom (which
      // Bug also addressed) doesn't recur.
      expect(engine.getLoadedPolicy().rules.length, 'bundled policy did not load — the engine swallowed the rules').toBeGreaterThan(0)
    } finally {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })
})
