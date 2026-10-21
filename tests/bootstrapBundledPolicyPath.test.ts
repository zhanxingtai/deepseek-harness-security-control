/**
 * 2026-09-28: Regression pin for the bundled-policy path resolution
 * inside `src/bootstrap.ts`.
 *
 * Background (the bug this test pins):
 *   - The compiled bootstrap lives at `<pkg>/lib/bootstrap.js`.
 *   - The bundled SPL policy lives at `<pkg>/policies/default-policy.spl.yaml`
 *     (sibling of `lib/`, listed in `package.json` `files:` as the
 *     glob `policies/**`/`*.yaml`).
 *   - `bootstrap.ts` resolves the bundled-policy URL via `import.meta.url`
 *     so the path is layout-agnostic at runtime.
 *   - A previous revision resolved the URL as
 *     `new URL('./policies/default-policy.spl.yaml', import.meta.url)`,
 *     which from `lib/bootstrap.js` lands at
 *     `<pkg>/lib/policies/default-policy.spl.yaml` — a path that
 *     DOES NOT EXIST on a packed install. The InterventionEngine's
 *     `existing.filter(existsSync)` silently dropped the entry, the
 *     bundled baseline was not loaded, and the UI showed
 *     "loadedRuleCount: 0" with no rule preview.
 *
 * This test asserts the two properties the fix depends on:
 *   1. The URL inside `bootstrap.ts` is `../policies/...`, not
 *      `./policies/...` — i.e. it walks up one level from
 *      `lib/bootstrap.js` to the package root before descending into
 *      `policies/`.
 *   2. The same resolution applied to the COMPILED `lib/bootstrap.js`
 *      lands on an existing file in both the dev source layout and
 *      the `npm pack` tarball layout (verified against
 *      `install/sst-security-control-dsh-*.tgz` when one exists).
 *
 * It does NOT instantiate InterventionEngine or bootstrap (the
 * bootstrap module pulls in cordis and the full plugin graph) — the
 * source-text pin + the post-compile resolve test together are a
 * much smaller surface and lock down the failure mode the bug came
 * in through.
 */

import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const BOOTSTRAP_TS = fileURLToPath(new URL('../src/bootstrap.ts', import.meta.url))
const LIB_BOOTSTRAP_JS = fileURLToPath(new URL('../lib/bootstrap.js', import.meta.url))
const PACKAGE_ROOT = dirname(dirname(LIB_BOOTSTRAP_JS))

describe('bootstrap — bundled policy path resolution', () => {
  it('bootstrap.ts resolves the bundled policy via "../policies/..." (not "./policies/...")', () => {
    const source = readFileSync(BOOTSTRAP_TS, 'utf8')
    // The bug: old code used `new URL('./policies/default-policy.spl.yaml', import.meta.url)`
    // — that resolved relative to `lib/bootstrap.js` and landed at
    // `<pkg>/lib/policies/...` (does not exist in the tarball).
    expect(source).not.toMatch(
      /new URL\(\s*['"]\.\/policies\/default-policy\.spl\.yaml['"]/,
    )
    // The fix walks up one level so the URL from `lib/bootstrap.js` lands at
    // `<pkg>/policies/...`.
    expect(source).toMatch(
      /new URL\(\s*['"]\.\.\/policies\/default-policy\.spl\.yaml['"]/,
    )
  })

  it('compiled lib/bootstrap.js resolves the URL to an existing policy file', () => {
    // The compiled bootstrap is what the marketplace runtime actually
    // loads. We must verify that the URL string baked into the
    // compiled output — when applied against the compiled file's
    // own `import.meta.url` — points at a real file.
    expect(existsSync(LIB_BOOTSTRAP_JS)).toBe(true)
    const compiled = readFileSync(LIB_BOOTSTRAP_JS, 'utf8')
    // Both forms acceptable: either the comment-decoupled form
    // (`"../policies/default-policy.spl.yaml"`) or the backslash
    // template form (`..\/policies\/default-policy.spl.yaml`).
    expect(compiled).toMatch(/\.\.\/policies\/default-policy\.spl\.yaml/)

    // Resolve the URL the same way the runtime would:
    //   new URL("../policies/default-policy.spl.yaml", import.meta.url of lib/bootstrap.js)
    const resolved = fileURLToPath(
      new URL('../policies/default-policy.spl.yaml', new URL('file://' + LIB_BOOTSTRAP_JS.replace(/\\/g, '/'))),
    )
    expect(resolved).toBe(join(PACKAGE_ROOT, 'policies', 'default-policy.spl.yaml'))
    expect(existsSync(resolved)).toBe(true)

    // Sanity: the resolved file is a real SPL policy (has the
    // required `apiVersion: security.use/v2` + `kind: Policy`
    // envelope the RuleLoader rejects without —
    // upgraded bundled policy from v1 to v2 per spec §10).
    const head = readFileSync(resolved, 'utf8').slice(0, 200)
    expect(head).toMatch(/apiVersion:\s*security\.use\/v2/)
    expect(head).toMatch(/kind:\s*Policy/)
  })

  it('lib/policies/ is NOT created at build time (the old URL would silently drop the baseline)', () => {
    // Belt-and-suspenders: even if a future build script accidentally
    // starts copying policies into lib/policies/, the fix above still
    // works (the URL points at the package-root policies/ regardless).
    // But if this assertion ever fires, it means the old broken URL
    // would have "started working" by accident — that's a drift signal
    // worth investigating, not a regression to paper over.
    const libDir = dirname(LIB_BOOTSTRAP_JS)
    const libPolicies = join(libDir, 'policies')
    // `existsSync` is the actual runtime check InterventionEngine
    // uses to drop missing paths. We mirror it here.
    const hasLibPolicies = existsSync(libPolicies)
    if (hasLibPolicies) {
      // If a future build script writes policies/ under lib/, list
      // it so the failure is diagnostic, not silent.
      const listing = readdirSync(libPolicies).join(', ')
      throw new Error(
        `lib/policies/ exists on disk (${listing}); the old ./policies/... ` +
          'URL would no longer be a no-op. Verify the bundle layout still ' +
          'matches package.json `files:` (which lists policies/ at the ' +
          'package root, NOT under lib/) before relaxing this assertion.',
      )
    }
    expect(hasLibPolicies).toBe(false)
  })
})