#!/usr/bin/env node
/**
 * build-client.mjs — bundle `src/client/` for the DSH marketplace webserver.
 *
 * follow-up — switched from IIFE to CJS + factory wrap.
 *
 * Background (root cause of the persistent "loaded without registering" error):
 *   The host's `client-modules` loader
 *   (the host client loader) expects every
 *   plugin bundle to call `window.__ModuleLoader__.load({ id, factory })`
 *   during script evaluation. The factory is invoked lazily by the host's
 *   `materialize(id)`, at which point the host's `makeRequire` function
 *   resolves `require("react")` etc. against its `seed` table
 *   (platform-provided modules) and registered peer plugins.
 *
 *   Earlier deploys used `--format=iife` with the registration at the
 *   bottom of the IIFE. esbuild placed the `import { ... } from 'react'`
 *   lines at the TOP of the IIFE, where they executed at script load
 *   time as `__require("react")` — and threw "Dynamic require of
 *   'react' is not supported" before the registration call ever ran.
 *   The host's `arrive()` then observed
 *   `factories.has("sst-security-control-dsh") === false` and rejected the
 *   bundle with "loaded without registering …".
 *
 *   The reference impl `lib/client.js` (~19KB,
 *   no React bundled) solves this by emitting the entire bundle body
 *   INSIDE the factory function:
 *
 *     window.__ModuleLoader__.load({
 *       id: "...",
 *       factory: (require) => {
 *         var module = { exports: {} };
 *         var exports = module.exports;
 *         Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
 *         let react = require("react");
 *         // ... all bundle code lives here ...
 *         exports.apply = apply;
 *         exports.inject = inject;
 *         return module.exports;
 *       }
 *     });
 *
 *   esbuild's `--format=cjs` emits top-level `require("react")` calls.
 *   When the CJS body is wrapped inside the factory body, those calls
 *   resolve via lexical scoping to the factory's `require` parameter
 *   (the host's makeRequire) and execute lazily at materialize time.
 *
 * Build pipeline:
 *   1. esbuild bundles `src/client/index.ts` to CJS (lib/.client.cjs.tmp.js)
 *      with all peer-dep modules marked `external` so they emit as plain
 *      `require("react")` etc. instead of being inlined.
 *   2. Strip esbuild's `"use strict";` preamble and the trailing
 *      `0 && (module.exports = {...});` dead-code marker.
 *   3. Wrap the CJS body inside the `window.__ModuleLoader__.load(...)`
 *      factory form above. Write to lib/client.js.
 *
 * React / ReactDOM / dsh-client-* peer deps are NOT bundled. The bundle
 * stays small (~6-20KB range) and relies on the host's `seed` table for
 * resolution.
 */
import { build } from 'esbuild'
import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')

// inject the raw package version as a compile-time text
// constant. The client cannot read package.json at runtime (marketplace
// bundle), so build-client stamps it into the bundle via esbuild `define`.
// The client source references the `__SECURITY_MONITOR_VERSION__`
// identifier and declares it in `src/client/buildInfo.ts` (with a runtime
// fallback for unit tests, where the define is absent).
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const buildDefines = {
  __SECURITY_MONITOR_VERSION__: JSON.stringify(pkg.version),
}
const outFile = join(root, 'lib', 'client.js')
const tmpFile = join(root, 'lib', '.client.cjs.tmp.js')
const outDir = dirname(outFile)
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true })

// 1. Bundle to CJS. Top-level require() calls go here; they execute lazily
//    when the host invokes the factory (not at script load).
const result = await build({
  entryPoints: [join(root, 'src', 'client', 'index.ts')],
  bundle: true,
  format: 'cjs',
  platform: 'browser',
  target: 'es2022',
  jsx: 'automatic',
  outfile: tmpFile,
  // 2026-10-10: stop emitting client.js.map. The marketplace bundle
  // is shipped to consumer DSH hosts; the map leaks `src/client/*`
  // paths and is ~374 KB of pure weight. Stack traces for the
  // browser-side code are nice-to-have, not worth the source-path
  // disclosure + 15% of the tgz budget.
  sourcemap: false,
  logLevel: 'info',
  // image asset loader so `import qrUrl from
  // '../assets/wechat-mp-qr.jpg'` inlines the JPEG as a base64 data
  // URL at bundle time. marketplace sandbox forbids new HTTP routes
  // (`network:none`), so the QR image cannot be served by the host;
  // inlining via esbuild's `dataurl` loader keeps the bundle
  // self-contained and the QR survives rotate/restart. Bundle weight
  // delta: +38 KiB for the 28 KiB JPEG (the data URL is ~37% larger).
  loader: {
    '.jpg': 'dataurl',
    '.jpeg': 'dataurl',
    '.png': 'dataurl',
    '.svg': 'dataurl',
    '.ico': 'dataurl',
  },
  // Externalize all peer deps — the host's `seed` table resolves them at
  // factory-invocation time. See the host client loader
  // for the resolution order: seed → statics → loadCache → factories.
  external: [
    'react',
    'react-dom',
    'react/jsx-runtime',
    '@deepseek-ai/dsh-client-ui-primitives',
    '@deepseek-ai/dsh-client-runtime/client',
    '@deepseek-ai/dsh-client-schema-form',
    '@deepseek-ai/dsh-client-store',
    '@deepseek-ai/dsh-client-locale',
    '@deepseek-ai/dsh-client-connection',
    '@deepseek-ai/dsh-client-ui-settings',
    '@deepseek-ai/dsh-client-ui-slots',
    '@deepseek-ai/dsh-commands',
    '@deepseek-ai/dsh-agent',
  ],
  // formal name / version text constants (see above).
  define: buildDefines,
})

if (result.errors.length > 0) {
  console.error('✗ build-client.mjs: esbuild reported errors:')
  for (const e of result.errors) console.error('  ' + e.text)
  process.exit(1)
}

// 2. Read CJS bundle, strip esbuild's preamble / trailing marker, wrap in factory.
const cjs = readFileSync(tmpFile, 'utf8')

let stripped = cjs
// esbuild prepends "use strict"; — strip (the factory body supplies its own).
stripped = stripped.replace(/^"use strict";\s*/, '')
// esbuild appends a `0 && (module.exports = {...});` line at the very end as
// a tree-shaking hint. We manage module.exports in the wrapper, so strip it.
stripped = stripped.replace(
  /\n*0\s*&&\s*\(\s*module\.exports\s*=[^;]+;?\s*\)\s*;?\s*$/,
  '',
)
// Trim trailing blank lines / whitespace so the wrapped output stays clean.
stripped = stripped.replace(/\s+$/, '') + '\n'

const wrapped = `window.__ModuleLoader__.load({
  id: 'sst-security-control-dsh',
  factory: function (require) {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
${stripped}
    return module.exports;
  }
});
`

writeFileSync(outFile, wrapped)
// Clean up the intermediate CJS bundle — it was only ever a
// staging area for the wrapper rewrite.
for (const tmp of [tmpFile]) {
  if (existsSync(tmp)) unlinkSync(tmp)
}
console.log(`✓ build-client.mjs complete — wrote ${outFile}`)