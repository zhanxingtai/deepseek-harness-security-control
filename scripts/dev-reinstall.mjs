#!/usr/bin/env node
/**
 * dev-reinstall.mjs — fully-automated local iteration cycle.
 *
 * Runs the full marketplace install path so a single command (after
 * each source change) yields a freshly-built, freshly-installed,
 * freshly-verified plugin in the target DSH profile. No manual file
 * copying, no `pnpm link` symlink juggling, no manual peer-dep setup.
 *
 *   1. `npm pack --pack-destination install` in THIS repo
 *      - npm lifecycle `prepack` auto-chains:
 *          node scripts/prepare.mjs          # tsc -b + build-client.mjs +
 *                                            #   stamp gitSha / buildTimestamp /
 *                                            #   write lib/marketplace.manifest.json
 *          node scripts/verify-self-contained.mjs   # dependencies: {} + no remote imports
 *          node scripts/verify-artifacts.mjs       # lib/ + lib/types/ + manifest + patch file
 *      - then `npm pack` writes `install/sst-security-control-dsh-<version>.tgz`
 *
 *   2. Auto-link peer packages from the HARNESS workspace
 *      - The plugin declares 4 private `@deepseek-ai/*` peer packages
 *        (`dsh-client-ui-slots` / `dsh-client-locale` / `dsh-commands`
 *        / `dsh-typert-protocol`). They live as workspace packages
 *        under `../dsh-harness/packages/*` and are not
 *        reachable from the public npm registry.
 *      - On a personal dev box without an internal registry, we add
 *        `link:<absolute-path>` references to the profile's
 *        `package.json#dependencies` and run `pnpm install`. pnpm
 *        creates the directory symlinks for us; subsequent edits to
 *        the harness workspace sources are picked up automatically.
 *      - Step is a no-op when the peers are already linked
 *        (subsequent `pnpm dev:reinstall` calls don't churn the lockfile).
 *
 *   3. `pnpm dsh plugin remove sst-security-control-dsh` in the HARNESS repo
 *      - tears down the previously-installed plugin copy cleanly
 *
 *   4. `pnpm dsh plugin add sst-security-control-dsh <tarball-path>`
 *      - extracts the tarball into the profile's
 *        `~/.dsh/profiles/<profile>/node_modules/sst-security-control-dsh/`
 *      - DSH's plugin loader picks up the new `lib/index.js` on the
 *        next `pnpm dsh --profile <profile>` startup
 *
 *   5. Post-install smoke check — read the installed `lib/index.js`
 *      and assert it carries the expected `inject` entries. Catches
 *      the "tarball looks fine but extract gave us stale files"
 * regression that bit in the first place.
 *
 * Why `npm pack` instead of `pnpm pack`:
 *   - `pnpm pack` runs a pre-flight lockfile check before executing the
 *     prepack chain. On Windows + pnpm 10/11 + this repo's `.npmrc`
 *     (auto-install-peers=false + strict-peer-dependencies=false +
 *     private `@deepseek-ai/*` peer deps that don't exist on the public
 *     npm registry), the check sometimes fails with
 *     `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH` and aborts the cycle before
 *     `prepack` ever runs.
 *   - `npm pack` honors the same `prepack` lifecycle hook (so the
 *     prepare.mjs → verify-* chain still executes), but skips pnpm's
 *     pre-flight check. On Windows it requires `--pack-destination
 *     <dir>` to point at an *existing* directory — npm does NOT
 *     create the destination dir itself; we `mkdir -p install`
 *     before invoking it.
 *
 * Why this exists: the previous flow required manual `cp lib/index.js
 * ~/.dsh/profiles/<profile>/node_modules/sst-security-control-dsh/lib/`
 * after every rebuild. Easy to forget, easy to typo, easy to forget to
 * restart dsh, easy to land on the wrong node_modules. This wrapper
 * makes the cycle one command and verifies the install actually
 * landed.
 *
 * Usage:
 *   node scripts/dev-reinstall.mjs                            # uses default profile 'web'
 *   node scripts/dev-reinstall.mjs --profile headless         # override profile
 *   node scripts/dev-reinstall.mjs --harness ../dsh-harness    # override harness dir
 *   node scripts/dev-reinstall.mjs --skip-pack                # reuse existing install/<tgz>
 *
 * IMPORTANT: invoke via `node`, NOT `pnpm dev:reinstall`. pnpm v11
 * auto-runs `pnpm install --frozen-lockfile` before every script,
 * which then hits ERR_PNPM_FETCH_404 on the 3 host-side private
 * `@deepseek-ai/*` peer deps (`cordis` / `subprocess` / `schemastery`)
 * even with `auto-install-peers=false` (pnpm/pnpm#9490). The plugin's
 * own `node_modules/` is dev-only (TypeScript / vitest / esbuild) and
 * already populated after the bootstrap step below — there is no need
 * to run pnpm inside this script at all.
 *
 * Bootstrap (one-time, per fresh checkout):
 *   corepack pnpm@10.14.0 install --ignore-scripts   # populate node_modules/
 *                                                   # with pnpm 10.x (peer-safe)
 *
 * Per-change cycle:
 *   node scripts/dev-reinstall.mjs                   # build → pack → reinstall
 *
 * Exits 0 only if every step succeeds AND the post-install smoke
 * check passes.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const PLUGIN_ROOT = join(__dirname, '..')

// ---- argv ----------------------------------------------------------------
function defaultHarnessCandidates(pluginRoot) {
  // Try a handful of common layouts in priority order. First hit wins.
  // Each entry is resolved relative to pluginRoot (or absolute).
  const candidates = [
    process.env.DSH_HARNESS_DIR,
    resolve(pluginRoot, '..', '..', 'dsh-harness'),     // <root>/code/<plugin> + <root>/dsh-harness
    resolve(pluginRoot, '..', '..', '..', 'dsh-harness'), // <root>/<plugin> + <root>/../dsh-harness
    resolve(pluginRoot, '..', 'dsh-harness'),            // <plugin>/dsh-harness (rare)
  ].filter(Boolean)
  for (const c of candidates) {
    if (existsSync(join(c, 'package.json'))) return c
  }
  return candidates[0] // fall through to error path with the highest-priority candidate
}

function parseArgs(argv, pluginRoot) {
  const out = {
    profile: 'web',
    harness: defaultHarnessCandidates(pluginRoot),
    skipPack: false,
  }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--profile') out.profile = argv[++i]
    else if (a === '--harness') out.harness = resolve(argv[++i])
    else if (a === '--skip-pack') out.skipPack = true
    else if (a === '--help' || a === '-h') {
      console.log(
        'Usage: node scripts/dev-reinstall.mjs ' +
          '[--profile <name>] [--harness <dir>] [--skip-pack]\n' +
          '\n' +
          'Env: DSH_HARNESS_DIR=<dir>   override the harness checkout location\n' +
          '                            (highest priority; wins over --harness)\n',
      )
      process.exit(0)
    }
  }
  return out
}

const args = parseArgs(process.argv.slice(2), PLUGIN_ROOT)

// ---- helpers -------------------------------------------------------------
function step(label) {
  console.log(`\n▶ ${label}`)
}
function ok(label) {
  console.log(`✓ ${label}`)
}
function fail(label, detail) {
  console.error(`✗ ${label}`)
  if (detail) console.error(`  ${detail}`)
  process.exit(1)
}
function run(cmd, cwd) {
  // Use spawnSync with stdio inherit so the user sees all output and any
  // TTY prompts (e.g. pnpm install confirmModulesPurge on Windows) go
  // to the same terminal.
  const result = spawnSync(cmd, { cwd, stdio: 'inherit', shell: true })
  if (result.status !== 0) {
    fail(`command failed: ${cmd}`, `exit ${result.status}`)
  }
}

// ---- 1. Build + package (npm pack auto-chains prepack + verify-* + tar) -
const pkg = JSON.parse(readFileSync(join(PLUGIN_ROOT, 'package.json'), 'utf8'))
const version = pkg.version
// derive tarball name from `pkg.name` so a scoped package
// produces a `<scope>-<name>-<version>.tgz` automatically.
// npm pack internally computes the same name from package.json; matching it here
// keeps dev-reinstall idempotent with the publish pipeline.
const tarballName = `${pkg.name.replace(/^@/, '').replace(/\//g, '-')}-${version}.tgz`
const tarballPath = join(PLUGIN_ROOT, 'install', tarballName)

if (!args.skipPack) {
  step(`Building + packaging v${version} (npm pack → prepack chain)`)
  // npm pack refuses to create the destination dir itself on Windows;
  // pre-create it so the cycle is hermetic.
  mkdirSync(join(PLUGIN_ROOT, 'install'), { recursive: true })
  // `CI=true` keeps pnpm's downstream install hooks (transitively
  // invoked by prepare.mjs) from prompting for confirmModulesPurge on
  // a TTY-less bash.
  run('npm pack --pack-destination install', PLUGIN_ROOT)
} else {
  step(`--skip-pack set; expecting existing install/${tarballName}`)
}

if (!existsSync(tarballPath)) {
  fail(`tarball not found`, tarballPath)
}
const tarballStat = statSync(tarballPath)
ok(`tarball ready: install/${tarballName} (${tarballStat.size} bytes)`)

// ---- 2. Validate harness dir -------------------------------------------
if (!existsSync(join(args.harness, 'package.json'))) {
  fail(
    `harness dir does not look like a DSH checkout (no package.json)`,
    args.harness,
  )
}

// ---- 3. Auto-link private @deepseek-ai/* peers from harness workspace -
// The plugin's peerDependencies block declares 4 private packages that
// live as workspace members inside the harness monorepo. On a personal
// dev box without an internal registry they cannot be fetched from npm,
// so we link them from the harness's own `packages/*` source via pnpm
// `link:` references. Each entry below maps a peer name to its
// workspace-relative path; we verify the workspace source exists and
// its `package.json#name` matches the peer name before linking.
const PEER_LINKS = [
  // Host-side runtime services — provided by the harness's own
  // workspace (vendor/* + packages/*/*). pnpm cannot fetch them from
  // the public npm registry (private packages), so we link them from
  // the harness checkout. These are what the plugin's `inject` array
  // (`subprocess` / `tools` / `commands` / `remote`) resolves against
  // at the Cordis service layer. Without the links the loader reports
  // `rowPhasePending: '等待依赖'` because the registry-driven resolve
  // fails to find them.
  {
    name: '@deepseek-ai/cordis',
    wsRel: 'vendor/cordis',
  },
  {
    name: '@deepseek-ai/schemastery',
    wsRel: 'vendor/schemastery',
  },
  {
    name: '@deepseek-ai/dsh-subprocess',
    wsRel: 'packages/subprocess/subprocess',
  },
  // Client-side UI / RPC peers — needed for the plugin's web
  // surfaces (Events tab / config form / typert mount). Same pattern:
  // private workspace packages, link from the harness checkout.
  {
    name: '@deepseek-ai/dsh-client-ui-slots',
    wsRel: 'packages/client/ui-slots',
  },
  {
    name: '@deepseek-ai/dsh-client-locale',
    wsRel: 'packages/client/locale',
  },
  {
    name: '@deepseek-ai/dsh-commands',
    wsRel: 'packages/interaction/commands',
  },
  {
    name: '@deepseek-ai/dsh-typert-protocol',
    wsRel: 'packages/typert/protocol',
  },
]
const profileHome = join(
  process.env.USERPROFILE ?? process.env.HOME ?? '',
  '.dsh',
  'profiles',
  args.profile,
)
const profilePkgPath = join(profileHome, 'package.json')
const profileNodeModules = join(profileHome, 'node_modules', '@deepseek-ai')
{
  step(`Auto-linking private @deepseek-ai/* peers from harness workspace`)
  // Read the profile's package.json (we mutate the dependencies block
  // only when at least one peer is missing on disk).
  const profilePkg = JSON.parse(readFileSync(profilePkgPath, 'utf8'))
  profilePkg.dependencies = profilePkg.dependencies ?? {}
  const linksToAdd = []
  for (const peer of PEER_LINKS) {
    const shortName = peer.name.split('/')[1]
    const installedPath = join(profileNodeModules, shortName)
    if (existsSync(installedPath)) {
      // Already linked (or otherwise installed) — skip; the next
      // `pnpm dev:reinstall` call must not churn the lockfile.
      continue
    }
    const wsSrc = join(args.harness, peer.wsRel)
    if (!existsSync(join(wsSrc, 'package.json'))) {
      fail(
        `peer ${peer.name} not installed AND not found at expected workspace path`,
        `expected ${wsSrc} (does the harness repo still have this layout?)`,
      )
    }
    const wsPkg = JSON.parse(readFileSync(join(wsSrc, 'package.json'), 'utf8'))
    if (wsPkg.name !== peer.name) {
      fail(
        `peer ${peer.name} workspace source has unexpected name`,
        `${wsSrc}/package.json#name = ${wsPkg.name}`,
      )
    }
    linksToAdd.push({ peer, wsSrc, wsPkg })
  }
  if (linksToAdd.length === 0) {
    ok(`all ${PEER_LINKS.length} peers already linked (no-op)`)
  } else {
    for (const { peer, wsSrc } of linksToAdd) {
      // pnpm `link:` with an absolute path creates a directory symlink
      // in `node_modules/@deepseek-ai/<short>`. Subsequent edits to the
      // harness workspace source are picked up automatically — just
      // restart dsh.
      profilePkg.dependencies[peer.name] = `link:${wsSrc}`
      console.log(
        `  + ${peer.name} → link:${wsSrc}`,
      )
    }
    writeFileSync(profilePkgPath, JSON.stringify(profilePkg, null, 2) + '\n')
    // Direct deps (the link: refs we just added) install regardless of
    // the `autoInstallPeers` setting. We deliberately do NOT pass
    // `--config.auto-install-peers=true`: the plugin's other 3 peer
    // deps (`@deepseek-ai/cordis` / `@deepseek-ai/subprocess` /
    // `@deepseek-ai/schemastery`) are private and unreachable from the
    // public npm registry, AND they are provided by the host DSH
    // process at runtime (Cordis's plugin loader resolves them via the
    // harness's own workspace symlinks) — fetching them at the profile
    // level would only fail with ERR_PNPM_FETCH_404 and abort the cycle.
    run('pnpm install', profileHome)
    ok(`linked ${linksToAdd.length} peer(s) from harness workspace`)
  }
}

// ---- 4. pnpm dsh plugin remove -----------------------------------------
step(`Removing previous install from profile '${args.profile}'`)
// dsh CLI signature: `dsh plugin --profile <name> <pnpm-args...>`
// (`plugin` is a subcommand of dsh; `--profile` is one of its flags.)
// The remove step is idempotent — when the previous install was
// already removed by hand or by a partial prior cycle, pnpm exits
// non-zero with `ERR_PNPM_CANNOT_REMOVE_MISSING_DEPS`. We probe the
// installed copy directly first and skip the remove if there's
// nothing on disk; otherwise we let the remove run and ignore the
// same specific pnpm error code if it surfaces.
{
  // scope-aware path (scoped packages land under
  // `node_modules/<scope>/<name>/`). Mirrors the dev-reinstall §1 derivation.
  const installedPkg = pkg.name.startsWith('@')
    ? join(profileHome, 'node_modules', ...pkg.name.split('/'))
    : join(profileHome, 'node_modules', pkg.name)
  if (!existsSync(installedPkg)) {
    ok('no previous install to remove (already clean)')
  } else {
    const result = spawnSync(
      `pnpm dsh plugin --profile ${args.profile} remove sst-security-control-dsh`,
      { cwd: args.harness, stdio: 'pipe', shell: true },
    )
    // Forward the captured output so the user sees the pnpm result.
    if (result.stdout) process.stdout.write(result.stdout)
    if (result.stderr) process.stderr.write(result.stderr)
    if (result.status !== 0) {
      const combined = `${result.stdout ?? ''}\n${result.stderr ?? ''}`
      if (/ERR_PNPM_CANNOT_REMOVE_MISSING_DEPS|Cannot remove.*no dependencies/i.test(combined)) {
        ok('remove step no-op (pnpm dep record clean, files already gone)')
      } else {
        fail(
          `command failed: pnpm dsh plugin --profile ${args.profile} remove sst-security-control-dsh`,
          `exit ${result.status}`,
        )
      }
    }
  }
}

// ---- 5. pnpm dsh plugin add <tarball-path> -----------------------------
step(
  `Installing fresh tarball into profile '${args.profile}' ` +
    `(source = install/${tarballName})`,
)
// Newer pnpm (10+/11) takes the tarball path as a positional argument,
// not via a `--source` flag (the latter is npm-pack syntax; pnpm's
// `add` has never honored it). Passing both `<pkg-name>` and the
// tarball confuses pnpm — it tries to fetch the package from the
// public registry (404, since `@deepseek-ai/*` is private). Pass
// only the tarball; pnpm derives the package name from the tarball's
// `package.json#name`.
run(
  `pnpm dsh plugin --profile ${args.profile} add "${tarballPath}"`,
  args.harness,
)

// ---- 6. Post-install smoke check ---------------------------------------
step('Verifying installed copy has the fix (lib/index.js inject entries)')
// scope-aware install path. Scoped packages land at
// `node_modules/@<scope>/<name>/...`; unscoped at `node_modules/<name>/...`.
const installDirName = pkg.name.startsWith('@')
  ? join(...pkg.name.split('/'))
  : pkg.name
const installedIndex = join(
  profileHome,
  'node_modules',
  installDirName,
  'lib',
  'index.js',
)
if (!existsSync(installedIndex)) {
  fail(
    `installed lib/index.js not found — extract may have failed silently`,
    installedIndex,
  )
}
const installedSrc = readFileSync(installedIndex, 'utf8')
const injectMatch = installedSrc.match(/export\s+const\s+inject\s*=\s*\[([^\]]*)\]/)
if (!injectMatch) {
  fail('could not find `export const inject = [...]` in installed lib/index.js')
}
const installedInject = injectMatch[1]
  .split(',')
  .map((s) => s.trim().replace(/^['"]|['"]$/g, ''))
  .filter(Boolean)
//'remote'is intentionally NOT in this
// list — it's a client-only service registered by
// `@deepseek-ai/dsh-cordis-client-runner` on the browser cordis ctx.
// Adding it to the host fiber's `inject` would pin the loader
// entry in FIBER_PENDING forever and surface as `rowPhasePending:
// '等待依赖'` in the marketplace UI
// (the plugin inventory service →
// the plugin manager UI).
// The settings bridge reads it via `ctx.reflect.get('remote')`
// instead.
const requiredInject = ['subprocess', 'tools', 'commands']
const missing = requiredInject.filter((dep) => !installedInject.includes(dep))
if (missing.length > 0) {
  fail(
    `installed lib/index.js is missing required inject entries`,
    `missing: ${missing.join(', ')}; full list: ${installedInject.join(', ')}`,
  )
}
ok(
  `installed lib/index.js declares inject = [${installedInject.join(', ')}] ` +
    `(all 4 present)`,
)

// ---- 7. Optional peer-installed check ---------------------------------
step(`Verifying ${PEER_LINKS.length} private peers are linked into profile/node_modules`)
const missingPeers = PEER_LINKS.filter((peer) => {
  const shortName = peer.name.split('/')[1]
  return !existsSync(join(profileNodeModules, shortName, 'package.json'))
})
if (missingPeers.length > 0) {
  fail(
    'profile is still missing some peer packages',
    `missing: ${missingPeers.map((p) => p.name).join(', ')}`,
  )
}
ok(
  `all ${PEER_LINKS.length} peers present in ${profileNodeModules}: ` +
    PEER_LINKS.map((p) => p.name.split('/')[1]).join(', '),
)

console.log(
  `\n✓ dev-reinstall complete — run \`pnpm dsh --profile ${args.profile}\` from the harness repo to start the engine`,
)
console.log(
  '\n⚠ A DSH CLIENT RESTART IS REQUIRED after every reinstall. The in-app "重新加载页面"' +
    '\n  button re-runs the host web boot against the plugin directory, which was just' +
    '\n  deleted + re-extracted on disk; the running client still holds the startup-time' +
    '\n  module graph, so the re-import fails and DSH shows the crash dialog ("web boot:' +
    '\n  1 entry did not activate"). The host-side plugin code is likewise only picked up' +
    '\n  on the next startup — reloading the page without restarting would still run the' +
    '\n  OLD code even if the import succeeded.',
)