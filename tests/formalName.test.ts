/**
 * tests/formalName.test.ts — marketplace formal display-name
 * derivation (scripts/formalName.mjs).
 *
 * Covers:
 *  1. deriveFormalName() semver/prerelease trimming rules
 *     (`0.5.3` → `v0.5.3`, `0.5.2-rc2` → `v0.5.2`, `1.0.0-alpha.1` →
 *     `v1.0.0`) plus the non-throwing fallback for illegal versions.
 *  2. Generated artifacts stay in sync with package.json `version`:
 *     `lib/marketplace.manifest.json` `displayName` matches the
 *     `sst-security-control-dsh-v<major>.<minor>.<patch> <suffix>`
 *     contract, and the shipped `locale/en.json` / `locale/zh.json`
 *     `meta.title` (the real marketplace display-name contract read by
 *     dsh-app-boot readPluginMeta) equals the same derived name.
 *
 *     lib/ is gitignored, so a fresh clone won't have
 *     `lib/marketplace.manifest.json` until `pnpm prepare:marketplace`
 *     runs. `beforeAll` calls prepare.mjs iff the manifest is missing
 *     so contributors on a fresh clone can run `pnpm test` directly.
 */
import { readFileSync, existsSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { join } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
// No .d.ts for the .mjs script module (tsconfig excludes tests/ from
// tsc -b; vitest transpiles without typechecking).
// @ts-expect-error — untyped ESM script module
import { deriveFormalName, FORMAL_NAME_PREFIX } from '../scripts/formalName.mjs'

const repoRoot = join(import.meta.dirname, '..')
const manifestPath = join(repoRoot, 'lib', 'marketplace.manifest.json')

// Ensure the marketplace manifest exists before any test reads it.
// lib/ is gitignored, so a fresh clone won't have the manifest until
// `pnpm prepare:marketplace` has run. CI and `pnpm test` should be
// self-sufficient; calling prepare here is idempotent (it re-stamps but
// writes the same content if nothing has changed). The script writes
// both the manifest and the locale files (locale/en.json +
// locale/zh.json) — the latter are committed, so this is a no-op when
// the manifest already exists on disk.
beforeAll(() => {
  if (!existsSync(manifestPath)) {
    execSync('node scripts/prepare.mjs', {
      cwd: repoRoot,
      stdio: 'pipe',
    })
  }
})

function readJson<T = unknown>(p: string): T {
  return JSON.parse(readFileSync(p, 'utf8')) as T
}

const FALLBACK_NAME = `${FORMAL_NAME_PREFIX} 安全监控插件`
const DISPLAY_NAME_RE = /^sst-security-control-dsh-v\d+\.\d+\.\d+ .+/

describe('deriveFormalName', () => {
  it('derives v0.5.3 from a plain release version', () => {
    expect(deriveFormalName('0.5.3')).toBe(
      'sst-security-control-dsh-v0.5.3 安全监控插件',
    )
  })

  it('trims the -rcN prerelease suffix (0.5.2-rc2 → v0.5.2)', () => {
    expect(deriveFormalName('0.5.2-rc2')).toBe(
      'sst-security-control-dsh-v0.5.2 安全监控插件',
    )
  })

  it('trims dotted prerelease suffixes (1.0.0-alpha.1 → v1.0.0)', () => {
    expect(deriveFormalName('1.0.0-alpha.1')).toBe(
      'sst-security-control-dsh-v1.0.0 安全监控插件',
    )
  })

  it('is insensitive to the prerelease segment for the same core version', () => {
    expect(deriveFormalName('0.5.2-rc2')).toBe(deriveFormalName('0.5.2'))
  })

  it('tolerates a leading v in the source version', () => {
    expect(deriveFormalName('v0.5.3')).toBe(deriveFormalName('0.5.3'))
  })

  it('falls back to the unversioned name for illegal versions (never throws)', () => {
    for (const bad of ['', '   ', 'not-a-version', '1.2', '1.2.3.4', '0.5.x', null, undefined, 42]) {
      expect(() => deriveFormalName(bad)).not.toThrow()
      expect(deriveFormalName(bad)).toBe(FALLBACK_NAME)
    }
  })

  it('fallback still identifies the plugin (prefix + non-empty suffix)', () => {
    expect(FALLBACK_NAME.startsWith(FORMAL_NAME_PREFIX)).toBe(true)
    expect(FALLBACK_NAME.length).toBeGreaterThan(FORMAL_NAME_PREFIX.length)
  })
})

describe('generated naming artifacts', () => {
  const pkg = readJson<{ version: string; description: string }>(
    join(repoRoot, 'package.json'),
  )
  const expected = deriveFormalName(pkg.version)

  it('package.json version yields a contract-conformant display name', () => {
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+/)
    expect(expected).toMatch(DISPLAY_NAME_RE)
  })

  it('lib/marketplace.manifest.json displayName matches the naming contract', () => {
    // Re-read on every run; the file is gitignored, so a fresh clone
    // won't have it until `pnpm prepare:marketplace` ran — top-level
    // beforeAll ensures it exists, but this assertion is best-effort
    // re-verified each time so stale fixtures don't sneak through.
    const manifest = readJson<{ displayName?: string }>(
      join(repoRoot, 'lib', 'marketplace.manifest.json'),
    )
    expect(manifest.displayName).toMatch(DISPLAY_NAME_RE)
    expect(manifest.displayName).toBe(expected)
  })

  it.each(['en', 'zh'])('locale/%s.json meta.title matches the derived name', (lang) => {
    const locale = readJson<{ meta?: { title?: string; description?: string } }>(
      join(repoRoot, 'locale', `${lang}.json`),
    )
    expect(locale.meta?.title).toBe(expected)
    expect(locale.meta?.description).toBe(pkg.description)
  })

  it('locale files are listed in package.json#files (tarball ships them)', () => {
    const files = (pkg as unknown as { files: string[] }).files
    expect(files).toContain('locale/en.json')
    expect(files).toContain('locale/zh.json')
  })
})

/* ---------------------------------------------------------------- *
 * gap analysis) — marketplace presentation surface        *
 * 4-source sync.                                                    *
 *                                                                   *
 * The four sources are:                                              *
 *   1. package.json (npm registry single source of truth)            *
 *   2. lib/marketplace.manifest.json (generated, registry-side       *
 *      detail-page render surface)                                   *
 *   3. locale/en.json (host readPluginMeta anchor)                   *
 *   4. locale/zh.json (mirrors en for the formal-name contract)      *
 *                                                                   *
 * Each marketplace presentation field (description / icon /          *
 * homepage / keywords) must agree across all four sources — a        *
 * drift bug surfaces here, not in production.                        *
 * ---------------------------------------------------------------- */
describe('marketplace presentation 4-source sync', () => {
  // Source-loaded eagerly for the 3 committed sources (package.json +
  // locale/{en,zh}.json). The marketplace manifest is gitignored, so we
  // defer its load into the test bodies (via a `loadManifest()` helper)
  // to keep this describe() block buildable on a fresh clone.
  const pkg = readJson<Record<string, unknown>>(join(repoRoot, 'package.json'))
  const enLocale = readJson<{ meta?: Record<string, unknown> }>(
    join(repoRoot, 'locale', 'en.json'),
  )
  const zhLocale = readJson<{ meta?: Record<string, unknown> }>(
    join(repoRoot, 'locale', 'zh.json'),
  )

  function loadManifest(): Record<string, unknown> {
    return readJson<Record<string, unknown>>(
      join(repoRoot, 'lib', 'marketplace.manifest.json'),
    )
  }

  it('description is in sync across package.json, manifest, locale/en, locale/zh', () => {
    const fromPkg = (pkg as { description?: string }).description
    const fromManifest = (loadManifest() as { description?: string }).description
    const fromEn = enLocale.meta?.description
    const fromZh = zhLocale.meta?.description
    expect(fromPkg).toBeTypeOf('string')
    expect((fromPkg as string).length).toBeGreaterThan(0)
    expect(fromManifest).toBe(fromPkg)
    expect(fromEn).toBe(fromPkg)
    expect(fromZh).toBe(fromPkg)
  })

  it('icon is in sync across package.json, manifest, locale/en, locale/zh', () => {
    const fromPkg = (pkg as { icon?: string }).icon
    const fromManifest = (loadManifest() as { icon?: string }).icon
    const fromEn = enLocale.meta?.icon
    const fromZh = zhLocale.meta?.icon
    expect(fromPkg).toBeTypeOf('string')
    expect((fromPkg as string).length).toBeGreaterThan(0)
    expect(fromManifest).toBe(fromPkg)
    expect(fromEn).toBe(fromPkg)
    expect(fromZh).toBe(fromPkg)
  })

  it('homepage is in sync across package.json, manifest, locale/en, locale/zh', () => {
    const fromPkg = (pkg as { homepage?: string }).homepage
    const fromManifest = (loadManifest() as { homepage?: string }).homepage
    const fromEn = enLocale.meta?.homepage
    const fromZh = zhLocale.meta?.homepage
    expect(fromPkg).toBeTypeOf('string')
    expect(fromPkg).toMatch(/^https?:\/\//)
    expect(fromManifest).toBe(fromPkg)
    expect(fromEn).toBe(fromPkg)
    expect(fromZh).toBe(fromPkg)
  })

  it('keywords array is in sync across package.json, manifest, locale/en, locale/zh', () => {
    const fromPkg = (pkg as { keywords?: string[] }).keywords
    const fromManifest = (loadManifest() as { keywords?: string[] }).keywords
    const fromEn = enLocale.meta?.keywords as string[] | undefined
    const fromZh = zhLocale.meta?.keywords as string[] | undefined
    expect(Array.isArray(fromPkg)).toBe(true)
    expect((fromPkg as unknown as unknown[]).length).toBeGreaterThan(0)
    expect(fromManifest).toEqual(fromPkg)
    expect(fromEn).toEqual(fromPkg)
    expect(fromZh).toEqual(fromPkg)
  })

  it('icon file referenced in package.json#icon exists and is in tarball files[]', () => {
    const icon = (pkg as { icon?: string }).icon
    expect(icon).toBeTypeOf('string')
    expect(existsSync(join(repoRoot, icon as string))).toBe(true)
    const files = (pkg as { files?: string[] }).files
    expect(files).toContain((icon as string).replace(/^\.\//, ''))
  })

  // 2026-10-10: assets/wechat-mp-qr.jpg + QrModal were dropped for the
  // open-source release (private WeChat QR is not part of the
  // vendor-neutral marketplace contract). The QrModal component,
  // the "Follow WeChat official account" footer button, and the
  // qr_modal_* locale keys are all removed.

  it('manifest.capabilities is a non-empty array of strings', () => {
    const caps = (loadManifest() as { capabilities?: unknown }).capabilities
    expect(Array.isArray(caps)).toBe(true)
    expect((caps as unknown[]).length).toBeGreaterThan(0)
    for (const c of caps as unknown[]) {
      expect(typeof c).toBe('string')
      expect((c as string).length).toBeGreaterThan(0)
    }
  })
})
