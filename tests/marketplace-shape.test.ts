/**
 * marketplace form shape regression test.
 *
 * Pins three contracts observed in the v0.5.2-rc1 end-to-end install
 * against the remote DSH web profile:
 *
 *  1. `cordis.patch.yml` is a top-level YAML **array** of
 *     `@deepseek-ai/cordis-plugin-include` `PatchOptions` — DSH's
 *     `parsePatchList` (the host bootstrap)
 *     throws `must be a top-level YAML array of loader patch entries`
 *     otherwise.
 *
 *  2. `package.json#exports["./client"]` exists AND points at the same
 *     file as `dsh.client.entry` — DSH's
 *     `@deepseek-ai/dsh-client-modules` `ClientModuleRegistry` resolves
 *     the client bundle via Node.js exports lookup; without this
 *     export the registry throws `declares dsh.client but exports no
 *     "./client" bundle` and `pnpm dsh --profile web` fails to boot.
 *
 *  3. `verify-artifacts.mjs` itself rejects a deliberately broken
 *     cordis.patch.yml (single object instead of array). This proves
 *     the gate fails-closed rather than rubber-stamping.
 */
import { execFileSync } from 'node:child_process'
import {
  writeFileSync,
  existsSync,
  readFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
// js-yaml 5.x: under vitest's CJS interop the default export is the
// whole module namespace (load/dump/etc live on the namespace, not on
// `.default`). Importing the namespace directly keeps the call sites
// (`yaml.load`, `yaml.dump`) working in both vitest and Node ESM.
import * as yaml from 'js-yaml'

const repoRoot = join(import.meta.dirname, '..')

function readJson<T = unknown>(p: string): T {
  return JSON.parse(readFileSync(p, 'utf8')) as T
}

describe('marketplace form shape', () => {
  describe('cordis.patch.yml', () => {
    it('is a top-level YAML array of @deepseek-ai/cordis-plugin-include PatchOptions', () => {
      const text = readFileSync(join(repoRoot, 'cordis.patch.yml'), 'utf8')
      const parsed = yaml.load(text)

      // DSH parsePatchList requires Array.isArray(parsed); a non-array
      // throws `must be a top-level YAML array of loader patch entries`.
      expect(Array.isArray(parsed)).toBe(true)
      if (!Array.isArray(parsed)) return

      // We always ship exactly one marketplace layer; an empty array
      // would leave the bundle with no plugin entries to mount.
      expect(parsed.length).toBeGreaterThanOrEqual(1)

      // The first entry uses the `insert` form to add this plugin to
      // the host's service tree. The Cordis loader accepts other shapes
      // (id-targeted config overrides) but for a fresh marketplace
      // install `insert` is the documented path.
      const entry = parsed[0] as Record<string, unknown>
      expect(Array.isArray(entry.insert)).toBe(true)

      const insertList = entry.insert as Array<Record<string, unknown>>
      expect(insertList.length).toBeGreaterThanOrEqual(1)

      const pluginEntry = insertList[0]
      expect(pluginEntry.name).toBe('sst-security-control-dsh')
      // cordis-plugin-include PatchOptions
      // (vendor/loader EntryOptions) accepts only id/name/config/disabled/inject;
      // `plugin` is NOT a valid field. The plugin entry is resolved by Cordis
      // convention from the patch file's location — `<bundle>/lib/index.js`
      // after install (the `main` field in package.json + the loader's
      // `node_modules/<name>` resolution path).
      expect(pluginEntry.id).toBe('sst-security-control-dsh')
      expect(pluginEntry.plugin).toBeUndefined()

      // The original plugin config keys (mode, hostId, collector,
      // application, networkCapture, intervention, runtimeHooks) all
      // live under `config:` as a sub-mapping. Re-flattened, they
      // equal the pre-marketplace single-object shape.
      //
      // `mode` is `enforce` since commit 88921f4
      // (feat(policy): default mode = enforce via policy-file mode
      // declaration, 2026-10-10) — three-layer mode resolution so a
      // fresh marketplace install lands in `enforce` by default. The
      // cordis.patch.yml comment block (lines 37-38) documents the
      // three-way alignment with intervention.mode and the bundled
      // policy file's mode declaration.
      const config = pluginEntry.config as Record<string, unknown>
      expect(config.enabled).toBe(true)
      expect(config.mode).toBe('enforce')
      expect(config.hostId).toBeNull()
      expect(config.containerId).toBe('host')
      expect(typeof config.collector).toBe('object')
      expect(typeof config.application).toBe('object')
      expect(typeof config.networkCapture).toBe('object')
      expect(typeof config.intervention).toBe('object')
      expect(typeof config.runtimeHooks).toBe('object')
    })

    it('regression: single-object shape is rejected by verify-artifacts.mjs', () => {
      // Run the actual `verify-artifacts.mjs` JS module in-process by
      // importing it. To exercise the array-validation branch we
      // temporarily write a single-object copy of cordis.patch.yml,
      // then restore the array form. This avoids the xcopy/ENOTEMPTY
      // // Windows cleanup fragility of an out-of-process regression check.
      const patchFile = join(repoRoot, 'cordis.patch.yml')
      const original = readFileSync(patchFile, 'utf8')

      // Recover the inner plugin config from the array form, then
      // dump it as a single-object — the pre-marketplace shape that the
      // marketplace loader rejects.
      const parsed = yaml.load(original) as Array<Record<string, unknown>>
      const innerConfig = (parsed[0].insert as Array<Record<string, unknown>>)[0].config
      const brokenShape = yaml.dump(innerConfig)

      try {
        writeFileSync(patchFile, brokenShape, 'utf8')

        // Import the script module — it runs all checks at module
        // top level. We use a dynamic import so the module is fresh
        // (not cached from a prior test run). The script's
        // process.exit() call on failure will throw via the dynamic
        // import — capture the rejection rather than letting it
        // terminate vitest.
        let exitCode = 0
        let stderr = ''
        try {
          // Run as a child process so we can observe exit code +
          // stderr without the script taking down vitest itself.
          const result = execFileSync('node', ['scripts/verify-artifacts.mjs'], {
            cwd: repoRoot,
            stdio: 'pipe',
          })
          exitCode = 0
          stderr = result.toString()
        } catch (e: unknown) {
          const err = e as { status?: number; stdout?: Buffer; stderr?: Buffer }
          exitCode = err.status ?? 1
          stderr = (err.stderr ?? Buffer.from('')).toString()
        }

        expect(exitCode).not.toBe(0)
        expect(stderr).toMatch(/cordis\.patch\.yml.*YAML array/)
      } finally {
        // Restore the original array form so the suite's other tests
        // and the `pnpm verify` marketplace gate stay green.
        writeFileSync(patchFile, original, 'utf8')
      }
    })
  })

  describe('package.json#exports["./client"]', () => {
    it('exists and points at the same file as dsh.client.entry', () => {
      const pkg = readJson<{
        exports?: Record<string, unknown>
        dsh?: { client?: { entry?: string } }
      }>(join(repoRoot, 'package.json'))

      const clientExport = pkg.exports?.['./client']
      expect(clientExport).toBeDefined()

      // exports["./client"] can be a string OR a conditional mapping
      // with `default` / `import`. Normalize to the resolved string.
      const resolved =
        typeof clientExport === 'string'
          ? clientExport
          : ((clientExport as { default?: string; import?: string }).default ??
            (clientExport as { import?: string }).import ??
            null)
      expect(resolved).toBeTruthy()

      // Cross-check: dsh.client.entry is what the marketplace loader
      // expects; exports["./client"] is what DSH's registry actually
      // uses. They MUST point at the same file (relative spelling
      // differences are normalized).
      const stripDot = (p: string) => p.replace(/^\.\//, '')
      const a = stripDot(resolved as string)
      const b = pkg.dsh?.client?.entry ? stripDot(pkg.dsh.client.entry) : null
      expect(b).toBeTruthy()
      expect(a).toBe(b)
    })

    it('keeps the three documented exports keys (".", "./client", "./package.json")', () => {
      // Pin so a future cleanup that accidentally drops "./client"
      // (because nothing else uses it inside the plugin) fails this
      // test loudly rather than waiting for a remote install.
      const pkg = readJson<{ exports?: Record<string, unknown> }>(
        join(repoRoot, 'package.json'),
      )
      expect(pkg.exports?.['.']).toBeDefined()
      expect(pkg.exports?.['./client']).toBeDefined()
      expect(pkg.exports?.['./package.json']).toBeDefined()
    })
  })

  describe('package.json#dsh.bundle.patch', () => {
    // DSH CLI's `apps/cli/src/plugin.ts:34-37 exportsPatch()` does
    // `manifest.dsh?.bundle?.patch !== undefined` to decide whether a
    // dependency is a profile layer. Without `patch` DSH treats the
    // package as a plain dep and prints `declares no dsh.bundle —
    // installed as a plain dependency, not a profile layer`. The
    // missing field was the reason the v0.5.2-rc1 install on the
    // remote web profile shipped the plugin without activating it.
    it('is a string path that points at cordis.patch.yml on disk and in files[]', () => {
      const pkg = readJson<{
        dsh?: { bundle?: { patch?: unknown; entry?: unknown } }
        files?: string[]
      }>(join(repoRoot, 'package.json'))

      const patch = pkg.dsh?.bundle?.patch
      expect(typeof patch).toBe('string')

      const patchStr = patch as string
      // Convention is `./<path>` per
      // the host bootstrap JSDoc.
      expect(patchStr.startsWith('./')).toBe(true)

      // The patch file must exist on disk (would otherwise fail
      // `dsh.bundle.patch` resolution at install time) AND must be in
      // package.json#files (so the tarball carries it).
      const fullPath = join(repoRoot, patchStr)
      expect(existsSync(fullPath)).toBe(true)
      const normalized = patchStr.replace(/^\.\//, '')
      expect(pkg.files ?? []).toContain(normalized)
    })
  })
})