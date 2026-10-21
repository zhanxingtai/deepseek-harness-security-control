#!/usr/bin/env node
/**
 * verify-artifacts.mjs — marketplace artifact completeness gate.
 *
 * ensure the built marketplace bundle is structurally
 * complete before publish. Catches:
 *  - lib/ missing entirely (build never ran)
 *  - lib/index.js missing (entry point never emitted)
 *  - lib/types/index.d.ts missing (declaration file missing — peers
 *    can't consume the package without .d.ts)
 *  - lib/marketplace.manifest.json missing or stale (prepare.mjs not
 *    run after source changes); `displayName` must equal the formal name
 * derived from package.json `version` ( naming)
 *  - locale/en.json | locale/zh.json missing, stale, or absent from
 * package.json#files (the marketplace display-name contract)
 *  - cordis.patch.yml missing at root (marketplace manifest gone)
 *  - package.json `files` block lists paths that don't exist on disk
 *  - peerDependencies references unknown packages
 *
 * Exits non-zero on any failure. Run after `pnpm build && pnpm prepare`.
 */
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')

const errors = []
function fail(msg) {
  errors.push(msg)
  console.error(`✗ ${msg}`)
}
function pass(msg) {
  console.log(`✓ ${msg}`)
}
function warn(msg) {
  console.warn(`⚠ ${msg}`)
}

function readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'))
}

// Read package.json once at the top so 5c/5d (cordis.patch.yml shape +
// exports["./client"] cross-ref) can use it before section 6.
const pkg = readJson(join(root, 'package.json'))

function exists(p) {
  try {
    return statSync(p).isFile() || statSync(p).isDirectory()
  } catch {
    return false
  }
}

// 1. lib/ exists
const libDir = join(root, 'lib')
if (!exists(libDir)) {
  fail('lib/ does not exist — run `pnpm build` first')
} else {
  pass('lib/ exists')
}

// 2. lib/index.js (entry)
const entry = join(libDir, 'index.js')
if (!exists(entry)) {
  fail(`${relative(root, entry)} missing — tsc did not emit an entry point`)
} else {
  pass('lib/index.js exists')
}

// 3. lib/types/index.d.ts
const types = join(root, 'lib', 'types', 'index.d.ts')
if (!exists(types)) {
  fail(`${relative(root, types)} missing — declaration file not emitted`)
} else {
  pass('lib/types/index.d.ts exists')
}

// 4. marketplace.manifest.json
const manifest = join(libDir, 'marketplace.manifest.json')
if (!exists(manifest)) {
  fail(`${relative(root, manifest)} missing — run \`node scripts/prepare.mjs\` to regenerate`)
} else {
  pass('lib/marketplace.manifest.json exists')
  const m = readJson(manifest)
  if (m.schemaVersion !== 1) fail(`manifest.schemaVersion expected 1, got ${m.schemaVersion}`)
  // manifest.name mirrors package.json#name (npm registry
  // identifier); the plugin id used by the marketplace install command
  // (`dsh plugin add sst-security-control-dsh`) lives in `cordis.patch.yml`
  // entry `id` and is checked separately below. Both must be internally
  // consistent — the npm name mirrors the plugin id in marketplace form.
  const npmName = pkg.name
  if (m.name !== npmName) fail(`manifest.name expected ${npmName}, got ${m.name}`)
  if (!m.gitSha) warn('manifest.gitSha is empty — git SHA stamp missing')
}

// 4b. Formal display name + marketplace locale files (
//     naming). The `dshWorkshop` block has NO harness validator (unknown
//     fields are ignored by the loader), so the real display-name
//     contract is the shipped `locale/<lang>.json` `meta.title`, read by
//     dsh-app-boot `readPluginMeta` (en.json is the anchor; package.json
//     name/description is only the fallback). Both the manifest
//     `displayName` and the locale `meta.title` MUST equal the formal
//     name derived from `package.json` `version` by
//     `scripts/formalName.mjs` — a hand-edited or stale display name is
//     a marketplace drift bug, not a cosmetic one.
const { deriveFormalName } = await import('./formalName.mjs')
const expectedFormalName = deriveFormalName(pkg.version)
const FORMAL_NAME_RE = /^sst-security-control-dsh-v\d+\.\d+\.\d+ .+/
if (exists(manifest)) {
  const m = readJson(manifest)
  if (m.displayName !== expectedFormalName) {
    fail(
      `manifest.displayName (${m.displayName ?? '(missing)'}) ≠ derived formal name (${expectedFormalName}) ` +
        '— run `node scripts/prepare.mjs` after a version bump; never hand-maintain',
    )
  } else if (!FORMAL_NAME_RE.test(m.displayName)) {
    fail(`manifest.displayName (${m.displayName}) does not match ${FORMAL_NAME_RE}`)
  } else {
    pass(`manifest.displayName → ${m.displayName}`)
  }
}
for (const lang of ['en', 'zh']) {
  const localeFile = join(root, 'locale', `${lang}.json`)
  const rel = relative(root, localeFile)
  if (!exists(localeFile)) {
    fail(`${rel} missing — run \`node scripts/prepare.mjs\` to generate the marketplace locale files`)
    continue
  }
  const doc = readJson(localeFile)
  if (doc?.meta?.title !== expectedFormalName) {
    fail(`${rel} meta.title (${doc?.meta?.title ?? '(missing)'}) ≠ derived formal name (${expectedFormalName})`)
  } else if (doc?.meta?.description !== pkg.description) {
    fail(`${rel} meta.description does not match package.json description`)
  } else {
    pass(`${rel} meta.title → ${doc.meta.title}`)
  }
  if (!(pkg.files ?? []).includes(`locale/${lang}.json`)) {
    fail(`locale/${lang}.json is not in package.json#files — the tarball would ship without the marketplace display name`)
  }
}

// 5. cordis.patch.yml at root (marketplace manifest)
const patchFile = join(root, 'cordis.patch.yml')
if (!exists(patchFile)) {
  fail('cordis.patch.yml missing — marketplace manifest not present at root')
} else {
  pass('cordis.patch.yml exists')

  // size sanity check. The marketplace
  // manifest is the entry point the host's parsePatchList reads first;
  // unbounded growth (a long comment block, a forgotten config sample)
  // makes install logs noisy and pushes the tgz payload for no
  // functional reason. Current size is 8.3 KB / 156 lines; warn at 12 KB
  // / 200 lines, fail at 16 KB / 250 lines.
  const patchStat = statSync(patchFile)
  const patchBytes = patchStat.size
  const patchLines = readFileSync(patchFile, 'utf8').split('\n').length
  const SOFT_BYTES = 12 * 1024
  const HARD_BYTES = 16 * 1024
  const SOFT_LINES = 200
  const HARD_LINES = 250
  if (patchBytes >= HARD_BYTES || patchLines >= HARD_LINES) {
    fail(
      `cordis.patch.yml too large: ${patchBytes}B / ${patchLines} lines ` +
      `(hard cap ${HARD_BYTES}B / ${HARD_LINES} lines — was 8284B / 156 lines on 2026-09-25)`,
    )
  } else if (patchBytes >= SOFT_BYTES || patchLines >= SOFT_LINES) {
    warn(
      `cordis.patch.yml nearing size cap: ${patchBytes}B / ${patchLines} lines ` +
      `(soft warn ${SOFT_BYTES}B / ${SOFT_LINES} lines; hard cap ${HARD_BYTES}B / ${HARD_LINES})`,
    )
  }
}

// 5b. Default SPL policy at root. The package.json
// `files` glob `policies/**/*.yaml` includes the default policy, but
// `glob` heads only verify the directory exists — a deleted/renamed
// policy file would slip through the files-existence check. Pin it
// here so a missing default policy fails the marketplace completeness
// gate before `npm pack` ships an empty SPL bundle.
const defaultPolicy = join(root, 'policies', 'default-policy.spl.yaml')
if (!exists(defaultPolicy)) {
  fail(`${relative(root, defaultPolicy)} missing — default SPL policy not present`)
} else {
  pass(`${relative(root, defaultPolicy)} exists`)
}

// 5d. stdio pipe mirror wrapper script. The
// bundled `lib/runtime/stdio-mirror.js` is the argv-sidecar process the
// harness spawns on a rewritten argv to capture child stdin/stdout/
// stderr bytes. Without it, `RuntimeHook.wrap()` rewrites the spec
// but the harness fails to spawn the wrapper and audit consumers see
// nothing. Pin both the script + its host helper so the marketplace
// tarball always ships a working mirror.
const stdioMirrorWrapper = join(root, 'lib', 'runtime', 'stdio-mirror.js')
if (!exists(stdioMirrorWrapper)) {
  fail(`${relative(root, stdioMirrorWrapper)} missing — stdio mirror wrapper not built`)
} else {
  pass(`${relative(root, stdioMirrorWrapper)} exists`)
}
const stdioMirrorEntry = join(root, 'lib', 'runtime', 'stdioMirrorEntry.js')
if (!exists(stdioMirrorEntry)) {
  fail(`${relative(root, stdioMirrorEntry)} missing — stdio mirror host helper not built`)
} else {
  pass(`${relative(root, stdioMirrorEntry)} exists`)
}

// 5c. cordis.patch.yml top-level shape. DSH's
//     the host bootstrap parsePatchList` requires
//     a top-level YAML **array** of `@deepseek-ai/cordis-plugin-include`
// `PatchOptions`. A single Cordis plugin config object (the pre-marketplace
//     shape) makes the loader throw `must be a top-level YAML array of
//     loader patch entries` and breaks every marketplace install.
//     Parse with js-yaml so this gate catches any future regression that
//     drops the array wrapper.
let cordisPatchEntries = null
if (exists(patchFile)) {
  try {
    // js-yaml 5.x ESM: `load` lives on the module namespace directly,
    // not on `.default` — accessing `.default.load` returns undefined
    // and the script aborts with "Cannot read properties of undefined".
    const yamlMod = await import('js-yaml')
    const parsed = yamlMod.load(readFileSync(patchFile, 'utf8'))
    if (!Array.isArray(parsed)) {
      fail(
        'cordis.patch.yml top-level must be a YAML array of ' +
          '@deepseek-ai/cordis-plugin-include PatchOptions (DSH parsePatchList) ' +
          `— got ${parsed === null ? 'null' : typeof parsed}`,
      )
    } else if (parsed.length === 0) {
      fail('cordis.patch.yml is an empty array — must contain at least one PatchOptions entry')
    } else {
      cordisPatchEntries = parsed
      pass(`cordis.patch.yml is a PatchOptions array (length=${parsed.length})`)
    }
  } catch (e) {
    fail(`cordis.patch.yml failed to parse as YAML: ${e.message}`)
  }
}

// 5e. package.json#dsh.bundle.patch. DSH
//     CLI's `apps/cli/src/plugin.ts:34-37 exportsPatch()` does
//     `manifest.dsh?.bundle?.patch !== undefined` — without a `patch`
//     field the loader treats the package as a plain dependency and
//     emits `declares no dsh.bundle — installed as a plain dependency`.
//     The path must (a) be a string, (b) point at a real file under
//     the repo root, and (c) be included in package.json#files so the
//     tarball actually carries it.
const bundlePatch = pkg.dsh?.bundle?.patch
if (!bundlePatch) {
  fail('package.json#dsh.bundle.patch missing — DSH exportsPatch() reads it (apps/cli/src/plugin.ts:34-37)')
} else if (typeof bundlePatch !== 'string') {
  fail(`package.json#dsh.bundle.patch must be a string, got ${typeof bundlePatch}`)
} else {
  const patchFull = join(root, bundlePatch)
  if (!exists(patchFull)) {
    fail(`package.json#dsh.bundle.patch points at missing file: ${bundlePatch}`)
  } else {
    // Strip leading `./` so we can cross-check against package.json#files
    // (the `files` block typically uses the bare relative form).
    const normalized = bundlePatch.replace(/^\.\//, '')
    if (!(pkg.files ?? []).includes(normalized)) {
      fail(
        `package.json#dsh.bundle.patch (${bundlePatch}) is not in package.json#files ` +
          `— the tarball would ship without it`,
      )
    } else {
      pass(`package.json#dsh.bundle.patch → ${bundlePatch}`)
    }
  }
}

// 5d. package.json#exports["./client"]. The DSH
//     `@deepseek-ai/dsh-client-modules` ClientModuleRegistry resolves
//     the client bundle via Node.js exports lookup
//     (`exports["./client"]`); the `dsh.client.entry` pointer alone is
//     not consulted at module-load time. Without this export the
//     registry throws `declares dsh.client but exports no "./client"
//     bundle` and `pnpm dsh --profile web` fails to boot. We pin both
//     that the key exists AND that it points at the same file as
//     `dsh.client.entry` so the two cannot drift.
const clientExport = pkg.exports?.['./client']
if (!clientExport) {
  fail('package.json#exports["./client"] missing — dsh-client-modules requires this lookup')
} else {
  // exports["./client"] can be a string OR a conditional object with
  // `default`. Normalize to the resolved string before comparing.
  const resolved =
    typeof clientExport === 'string'
      ? clientExport
      : (clientExport.default ?? clientExport.import ?? null)
  if (!resolved) {
    fail('package.json#exports["./client"] has no resolvable target (need string or {default,import})')
  } else {
    // Normalize `./foo` and `foo` to the same relative form so the
    // cross-check with dsh.client.entry (which uses no leading `./`)
    // does not false-positive on the trivial spelling difference.
    const stripDot = (p) => p.replace(/^\.\//, '')
    const a = stripDot(resolved)
    const b = pkg.dsh?.client?.entry ? stripDot(pkg.dsh.client.entry) : null
    if (b && a !== b) {
      fail(
        `package.json#exports["./client"] (${resolved}) disagrees with ` +
          `dsh.client.entry (${pkg.dsh.client.entry}) — pin them to the same path`,
      )
    } else {
      pass(`package.json#exports["./client"] → ${resolved}`)
    }
  }
}

// 6. Every path in package.json#files exists on disk (where local)
const files = pkg.files ?? []
let missing = 0
for (const pattern of files) {
  // 2026-10-10: npm `files[]` allows a leading `!` to deny a path
  // (e.g. `!lib/types/types/**` to exclude a dead-code sub-tree).
  // The marketplace validator only inspects the *include* entries,
  // so deny patterns are skipped here — the `npm pack` step is the
  // authoritative check that the deny rule actually fires.
  if (pattern.startsWith('!')) continue
  // Skip glob tails — only verify the literal head. Files listed are
  // exact paths in the marketplace tarball; if a glob tail is used we
  // check at least one match exists.
  if (/[\*\?\[]/.test(pattern)) {
    // glob: verify at least one matching file exists under root
    const head = pattern.split(/[\*\?\[]/)[0]
    const headFull = join(root, head)
    if (!exists(headFull)) {
      fail(`glob pattern ${pattern}: prefix ${head} does not exist on disk`)
      missing++
    }
    continue
  }
  const full = join(root, pattern)
  if (!exists(full)) {
    fail(`package.json#files entry missing on disk: ${pattern}`)
    missing++
  }
}
if (missing === 0 && files.length > 0) {
  pass(`all ${files.length} package.json#files entries exist on disk`)
}

// 7. peerDependencies — every declared peer name has a corresponding
//    section OR is a known marketplace runtime.
//
// B6 : trimmed the 13-entry whitelist down to the 8
// peers the marketplace plugin actually needs:
//   - `cordis` / `subprocess` — host runtime + subprocess seam type
//   - `schemastery` — direct `import Schema from '@deepseek-ai/schemastery'`
//     in src/config.schema.ts
// `yaml` + `js-yaml` — SPL policy parser
//   - `dsh-client-locale` + `dsh-client-ui-slots` — client runtime inject
//     (matches `src/client/index.ts` `inject = ['slots', 'locale']` and
//     `dsh.client.inject` in package.json)
// `dsh-commands` — `/security` slash-command runtime
//
// The previous 5 entries (`dsh-plugin-runtime`, `-ui-settings`,
// `-store`, `-connection`, `-agent`) were declared as peers but
// never imported AND never injected — they produced misleading
// "missing peer" warnings on marketplace nodes that did not install
// the full DSH Web stack. Removed in B6.
const peers = pkg.peerDependencies ?? {}
const KNOWN_RUNTIME_PEERS = new Set([
  '@deepseek-ai/cordis',
  '@deepseek-ai/schemastery',
  '@deepseek-ai/dsh-subprocess',
  // SPL YAML upgrade — both YAML libraries are optional peerDeps
  // (yaml is preferred, js-yaml is the legacy fallback per
  // src/intervention/RuleLoader.ts parseYaml).
  'yaml',
  'js-yaml',
  // DSH Web client slots/locale + commands runtime
  // all peer optional. The slots/locale entries match `dsh.client.inject`
  // (B5); `dsh-commands` powers the `/security` slash command.
  '@deepseek-ai/dsh-client-ui-slots',
  '@deepseek-ai/dsh-client-locale',
  '@deepseek-ai/dsh-commands',
  // 2026-09-22) — Typert Remote namespace protocol. Optional
  // peer because the host process never injects `ctx.remote` (it's
  // only registered in the gateway client process); the plugin still
  // declares it for forward-compatibility when future harnesses expose
  // `ctx.remote` on the host.
  '@deepseek-ai/dsh-typert-protocol',
])
for (const name of Object.keys(peers)) {
  if (!KNOWN_RUNTIME_PEERS.has(name)) {
    fail(`peerDependencies.${name} is not in the marketplace-known runtime set`)
  }
}
if (Object.keys(peers).length > 0) {
  pass(`peerDependencies known: ${Object.keys(peers).join(', ')}`)
}

// 7b. peerDependenciesMeta — every peer marked `optional: true` must be
//     declared in peerDependenciesMeta. Required peers (no meta entry)
//     are fine — only optional ones need the explicit declaration.
const peersMeta = pkg.peerDependenciesMeta ?? {}
for (const name of Object.keys(peersMeta)) {
  if (!peers[name]) {
    fail(`peerDependenciesMeta.${name} references peer not declared in peerDependencies`)
  }
  if (peersMeta[name]?.optional !== true) {
    fail(`peerDependenciesMeta.${name} must set optional: true (or remove the entry)`)
  }
}
const optionalPeers = Object.keys(peersMeta).filter(n => peersMeta[n]?.optional === true)
for (const name of Object.keys(peers)) {
  if (!optionalPeers.includes(name) && peers[name].startsWith('>=0.1')) {
    // lockstep peer range convention: >=0.1.x is a hint that
    // the peer is optional. Not strictly required, but warn so we don't
    // accidentally add a hard runtime dep on a DSH UI package.
    warn(`peerDependencies.${name} uses DSH-UI version range ${peers[name]} — verify this is optional via peerDependenciesMeta.${name} if the package may not be installed`)
  }
}
if (optionalPeers.length > 0) {
  pass(`peerDependenciesMeta.optional: ${optionalPeers.join(', ')}`)
}

// 8. lib/ has no platform-locked module compiled in (defense-in-depth
//    against a refactor that re-introduces one).
const PLATFORM_LOCKED = [
  'lib/auth',
  'lib/collectors/SystemCollector.js',
  'lib/collectors/AssetCollector.js',
  'lib/collectors/NodeActivityClient.js',
  'lib/collectors/EscalationOutbox.js',
  'lib/collectors/EventCollector.js',
  'lib/utils/pythonRunner.js',
  'lib/utils/pluginSelfCheck.js',
  'lib/utils/httpState.js',
]
let lockedHits = 0
for (const p of PLATFORM_LOCKED) {
  const full = join(root, p)
  if (exists(full)) {
    fail(`platform-locked module present in build: ${p}`)
    lockedHits++
  }
}
if (lockedHits === 0) {
  pass('no platform-locked modules in lib/ (auth / system / asset / outbox / EventCollector)')
}

// 9. lib/index.js smoke-import
try {
  // 2026-09-18 Windows: Node 24 ESM requires absolute paths to be
  // `file://` URLs — passing `e:/...` directly throws
  // "Only URLs with a scheme in: file, data, and node are supported".
  // `pathToFileURL` normalizes the OS path to the correct URL form.
  await import(pathToFileURL(entry).href)
  pass('lib/index.js imports cleanly')
} catch (e) {
  fail(`lib/index.js failed to import: ${e.message}`)
}

// 10. lib/client/ bundle — present iff `dsh.client` block is declared in
// package.json ( settings page — see /).
if (pkg.dsh?.client) {
  const clientEntry = pkg.dsh.client.entry
  if (!clientEntry) {
    fail('dsh.client block present but entry field missing')
  } else {
    const full = join(root, clientEntry)
    if (!exists(full)) {
      fail(`dsh.client.entry ${clientEntry} missing on disk — run \`pnpm build:client\``)
    } else {
      pass(`${clientEntry} exists (dsh.client bundle)`)
    }
  }
} else {
  pass('dsh.client block absent — settings page UI not enabled')
}

// 11. Marketplace presentation surface. The icon /
//     homepage / author fields are the marketplace detail page's
//     primary read surface — a missing icon means the detail page
//     renders a placeholder; a missing homepage means the "visit site"
//     button has nowhere to point. (2026-10-10: the WeChat-OA
//     social surface was dropped for the open-source release; a
//     private WeChat QR is not part of the vendor-neutral
//     marketplace contract.)
//     This section mirrors the marketplace install spec
//     .clawhubSpec), so the same checks apply to both shapes.
if (pkg.icon) {
  const iconFull = join(root, pkg.icon)
  if (!exists(iconFull)) {
    fail(`package.json#icon (${pkg.icon}) points at missing file`)
  } else if (!(pkg.files ?? []).includes(pkg.icon.replace(/^\.\//, ''))) {
    fail(
      `package.json#icon (${pkg.icon}) is not in package.json#files — ` +
        'the tarball would ship without the marketplace detail-page icon',
    )
  } else {
    pass(`package.json#icon → ${pkg.icon}`)
  }
} else {
  fail('package.json#icon missing — marketplace detail page renders without an icon')
}

if (pkg.homepage) {
  if (!/^https?:\/\//.test(pkg.homepage)) {
    fail(`package.json#homepage (${pkg.homepage}) is not an http(s) URL`)
  } else {
    pass(`package.json#homepage → ${pkg.homepage}`)
  }
} else {
  fail('package.json#homepage missing — marketplace detail page has no "visit site" target')
}

if (pkg.author) {
  const authorName = typeof pkg.author === 'string' ? pkg.author : pkg.author?.name
  if (!authorName) {
    fail('package.json#author present but name is empty')
  } else {
    pass(`package.json#author.name → ${authorName}`)
  }
} else {
  fail('package.json#author missing — marketplace detail page has no author')
}

if (exists(manifest)) {
  const m = readJson(manifest)
  if (m.icon !== pkg.icon) {
    fail(`manifest.icon (${m.icon ?? '(missing)'}) ≠ package.json#icon (${pkg.icon ?? '(missing)'})`)
  }
  if (m.homepage !== pkg.homepage) {
    fail(
      `manifest.homepage (${m.homepage ?? '(missing)'}) ≠ package.json#homepage (${pkg.homepage ?? '(missing)'})`,
    )
  }
  if (!Array.isArray(m.capabilities) || m.capabilities.length === 0) {
    fail('manifest.capabilities missing or empty — marketplace detail page has no capability list')
  } else {
    pass(`manifest.capabilities → ${m.capabilities.length} entries`)
  }
}

for (const lang of ['en', 'zh']) {
  const localeFile = join(root, 'locale', `${lang}.json`)
  if (!exists(localeFile)) continue
  const doc = readJson(localeFile)
  if (doc?.meta?.icon !== pkg.icon) {
    fail(
      `locale/${lang}.json meta.icon (${doc?.meta?.icon ?? '(missing)'}) ≠ package.json#icon (${pkg.icon ?? '(missing)'})`,
    )
  }
  if (doc?.meta?.homepage !== pkg.homepage) {
    fail(
      `locale/${lang}.json meta.homepage (${doc?.meta?.homepage ?? '(missing)'}) ≠ package.json#homepage (${pkg.homepage ?? '(missing)'})`,
    )
  }
  if (!Array.isArray(doc?.meta?.keywords) || doc.meta.keywords.length === 0) {
    fail(`locale/${lang}.json meta.keywords missing or empty`)
  }
}

// ───────────────────────────────────────────────────────────────────────
// §12 — marketplace protocol blocks
// (uiHints / contracts / configSchema / activation).
//
// These 4 blocks are siblings of `displayName / capabilities / supportChannels`
// at the manifest top level (NOT nested inside dshWorkshop or
// the install spec — see §3 option A). Missing blocks cause
// marketplace UI to fall back to displayName for everything, hide the
// capability list, and refuse to render the settings page.
// ───────────────────────────────────────────────────────────────────────
if (exists(manifest)) {
  const m = readJson(manifest)

  // activation block
  if (!m.activation || typeof m.activation !== 'object') {
    fail('manifest.activation missing — marketplace cannot tell when this plugin activates')
  } else if (m.activation.onStartup !== true) {
    fail(`manifest.activation.onStartup must be true (got ${m.activation.onStartup})`)
  } else {
    pass('manifest.activation.onStartup → true')
  }

  // uiHints block (tab labels + advanced flags + panel integration)
  if (!m.uiHints || typeof m.uiHints !== 'object') {
    fail('manifest.uiHints missing — marketplace detail page has no Tab labels')
  } else {
    const tabKeys = Object.keys(m.uiHints.tabs ?? {})
    if (tabKeys.length === 0) {
      fail('manifest.uiHints.tabs is empty — DSH Web settings page has no Tab labels')
    } else {
      for (const id of tabKeys) {
        const tab = m.uiHints.tabs[id]
        if (!tab?.label) {
          fail(`manifest.uiHints.tabs.${id}.label missing`)
        }
      }
      pass(`manifest.uiHints.tabs → ${tabKeys.length} entries (${tabKeys.join(', ')})`)
    }
    if (m.uiHints.panelIntegration !== 'dsh-client-ui-slots') {
      fail(
        `manifest.uiHints.panelIntegration must be 'dsh-client-ui-slots' (DSH marketplace sandbox network:none forbids panelUrl HTTP routes)`,
      )
    } else {
      pass("manifest.uiHints.panelIntegration → 'dsh-client-ui-slots'")
    }
  }

  // contracts block (Cordis event hooks + Typert RPC + HTTP routes)
  if (!m.contracts || typeof m.contracts !== 'object') {
    fail('manifest.contracts missing — marketplace UI capability list is empty')
  } else {
    if (!Array.isArray(m.contracts.hooks) || m.contracts.hooks.length === 0) {
      fail('manifest.contracts.hooks missing or empty — no Cordis event subscriptions declared')
    } else {
      pass(`manifest.contracts.hooks → ${m.contracts.hooks.length} entries`)
    }
    if (!Array.isArray(m.contracts.gatewayMethods) || m.contracts.gatewayMethods.length === 0) {
      fail('manifest.contracts.gatewayMethods missing or empty — no Typert RPC declared')
    } else {
      pass(`manifest.contracts.gatewayMethods → ${m.contracts.gatewayMethods.length} entries`)
    }
    // HTTP routes: DSH marketplace sandbox `network:none` forbids plugin-owned
    // routes. Empty array is the correct DSH shape.
    // see §1.1 cross-marketplace difference).
    if (!Array.isArray(m.contracts.httpRoutes)) {
      fail('manifest.contracts.httpRoutes must be an array (empty is OK — DSH sandbox network:none)')
    } else if (m.contracts.httpRoutes.length > 0) {
      fail(
        `manifest.contracts.httpRoutes must be empty for DSH marketplace (got ${m.contracts.httpRoutes.length} entries; plugin-owned HTTP routes violate network:none sandbox)`,
      )
    } else {
      pass('manifest.contracts.httpRoutes → [] (DSH sandbox network:none compliance)')
    }
  }

  // configSchema block (loose top-level shape, additionalProperties:true)
  if (!m.configSchema || typeof m.configSchema !== 'object') {
    fail('manifest.configSchema missing — marketplace cannot render the settings page')
  } else if (m.configSchema.type !== 'object') {
    fail(`manifest.configSchema.type must be 'object' (got '${m.configSchema.type}')`)
  } else if (!m.configSchema.properties || typeof m.configSchema.properties !== 'object') {
    fail('manifest.configSchema.properties missing — settings page has no block list')
  } else {
    const blockKeys = Object.keys(m.configSchema.properties)
    // Required top-level blocks (mirror src/config.ts normalizeConfig)
    const required = ['collector', 'intervention', 'runtimeHooks']
    const missing = required.filter((k) => !blockKeys.includes(k))
    if (missing.length > 0) {
      fail(`manifest.configSchema.properties missing required blocks: ${missing.join(', ')}`)
    } else {
      pass(`manifest.configSchema.properties → ${blockKeys.length} blocks (incl. required: ${required.join(', ')})`)
    }
  }
}

// Summary
console.log()
if (errors.length === 0) {
  console.log(`✓ verify-artifacts.mjs: PASS`)
  process.exit(0)
} else {
  console.error(`✗ verify-artifacts.mjs: FAIL (${errors.length} errors)`)
  process.exit(1)
}
