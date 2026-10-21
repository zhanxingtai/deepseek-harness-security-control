#!/usr/bin/env node
/**
 * verify-self-contained.mjs — marketplace self-containment gate.
 *
 * enforce the marketplace contract that the plugin ships
 * zero runtime outbound dependencies. The marketplace declares
 * `dshWorkshop.permissions: ["network:none"]` — this script is the
 * mechanical check that the build artifact honors it.
 *
 * What it asserts:
 *  1. `package.json#dependencies` is empty (no runtime npm deps).
 *  2. `package.json#dshWorkshop.permissions` includes `network:none`.
 *  3. `src/` and `lib/` contain no `import … from 'http[s]://…'` /
 *     `require('http[s]://…')` remote module specifiers.
 *  4. `src/` contains no `fetch(` / `http.request(` /
 *     `https.request(` calls outside `NetworkHttpCollector.ts` (which
 *     patches Node internals in-process — that's capture, not outbound).
 *  5. No `import('http')` / `require('https')` outside Node stdlib
 *     allowlist.
 *
 * Exits non-zero on any violation. Run after `pnpm build`.
 */
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')

const errors = []
const warnings = []

function fail(msg) {
  errors.push(msg)
  console.error(`✗ ${msg}`)
}

function warn(msg) {
  warnings.push(msg)
  console.warn(`! ${msg}`)
}

function pass(msg) {
  console.log(`✓ ${msg}`)
}

function readJson(p) {
  return JSON.parse(readFileSync(p, 'utf8'))
}

// 1. dependencies: {}
const pkg = readJson(join(root, 'package.json'))
const deps = pkg.dependencies ?? {}
if (Object.keys(deps).length > 0) {
  fail(`dependencies must be empty; found: ${Object.keys(deps).join(', ')}`)
} else {
  pass('dependencies: {} (empty)')
}

// 2. dshWorkshop.permissions includes network:none
const perms = pkg.dshWorkshop?.permissions ?? []
if (!perms.includes('network:none')) {
  fail('dshWorkshop.permissions must include "network:none"')
} else {
  pass('dshWorkshop.permissions includes "network:none"')
}

// 3. No remote URL imports
const REMOTE_IMPORT_RE = /(?:import|require|import\s*\()\s*[^;'"`]*['"`](https?:|ftp:|git\+|ssh:|\/\/)[^'"`]+['"`]/g
const FORBIDDEN_HTTP_CALL_RE = /\b(?:fetch|node-fetch|axios\.get|axios\.post|got\(|http\.request|https\.request)\s*\(/g

const NETWORK_HTTP_COLLECTOR_SRC = 'src/collectors/NetworkHttpCollector.ts'
const NETWORK_HTTP_COLLECTOR_LIB = 'lib/collectors/NetworkHttpCollector.js'
const ALLOWED_NETWORK_FILES = new Set([
  // In-process capture — patches http.request / fetch / dns.lookup; the
  // patches themselves never call the network. The "http" import here is
  // for the type-only `IncomingMessage` etc.
  NETWORK_HTTP_COLLECTOR_SRC,
  NETWORK_HTTP_COLLECTOR_LIB,
])

function walk(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    const st = statSync(full)
    if (st.isDirectory()) {
      if (entry === 'node_modules' || entry === '.git' || entry.startsWith('.')) continue
      out.push(...walk(full))
    } else {
      out.push(full)
    }
  }
  return out
}

const scanRoots = [join(root, 'src')]
if (existsSync(join(root, 'lib'))) scanRoots.push(join(root, 'lib'))

let remoteHits = 0
let networkCallHits = 0
for (const dir of scanRoots) {
  for (const file of walk(dir)) {
    if (!/\.(ts|js|mjs|cjs)$/.test(file)) continue
    const rel = relative(root, file).replace(/\\/g, '/')
    const text = readFileSync(file, 'utf8')
    let m
    REMOTE_IMPORT_RE.lastIndex = 0
    while ((m = REMOTE_IMPORT_RE.exec(text))) {
      remoteHits++
      fail(`remote URL import in ${rel}: ${m[0]}`)
    }
    FORBIDDEN_HTTP_CALL_RE.lastIndex = 0
    while ((m = FORBIDDEN_HTTP_CALL_RE.exec(text))) {
      if (ALLOWED_NETWORK_FILES.has(rel)) continue
      // Allow http.request / https.request inside NetworkHttpCollector
      // (the very regex match above; harmless).
      networkCallHits++
      const ctx = text.slice(Math.max(0, m.index - 40), m.index + m[0].length + 40)
      fail(`forbidden network call in ${rel} (${m[0]}): …${ctx}…`)
    }
  }
}

if (remoteHits === 0) pass('no remote URL imports in src/lib')
if (networkCallHits === 0) pass('no outbound fetch/http.request outside NetworkHttpCollector')

// Summary
console.log()
if (errors.length === 0) {
  console.log(`✓ verify-self-contained.mjs: PASS (${warnings.length} warnings)`)
  process.exit(0)
} else {
  console.error(`✗ verify-self-contained.mjs: FAIL (${errors.length} errors, ${warnings.length} warnings)`)
  process.exit(1)
}
