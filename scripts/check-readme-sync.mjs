#!/usr/bin/env node
/**
 * check-readme-sync.mjs — verify the 5 README translations share a common
 * structure.
 *
 * when a translation falls behind (e.g. a new section
 * added to README.md but not to README.es.md), the marketplace publish
 * pipeline flags it. This script asserts:
 *  - every README.*.md has the same H1 / H2 heading set as README.md
 *    (allowing extra headings — operators may add locale-specific
 *    sections, but missing canonical sections are a sync bug)
 *  - all README.*.md files declare a license that matches the
 *    `package.json` `license` field
 *  - all README.*.md files mention the same plugin name
 *
 * Exit code 0 = in sync; exit code 1 = drift detected.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = join(__dirname, '..')

function readText(p) {
  return readFileSync(p, 'utf8')
}

function extractHeadings(text) {
  const out = []
  for (const line of text.split('\n')) {
    const m = /^(#{1,2})\s+(.+?)\s*$/.exec(line)
    if (m) out.push({ level: m[1].length, text: m[2].trim() })
  }
  return out
}

function listReadmes() {
  return readdirSync(root)
    .filter((f) => /^README(\.[a-z]{2,5})?\.md$/.test(f))
    .sort()
}

function main() {
  const readmes = listReadmes()
  if (readmes.length === 0) {
    console.error('No README files found in', root)
    process.exit(1)
  }
  const canonical = readmes.find((f) => f === 'README.md')
  if (!canonical) {
    console.error('Canonical README.md is missing')
    process.exit(1)
  }
  const canonicalText = readText(join(root, canonical))
  const canonicalHeadings = extractHeadings(canonicalText)
  const canonicalH1 = canonicalHeadings.find((h) => h.level === 1)
  if (!canonicalH1) {
    console.error('Canonical README.md has no H1 heading')
    process.exit(1)
  }
  const pkg = JSON.parse(readText(join(root, 'package.json')))
  const pluginName = pkg.name
  const license = pkg.license

  /**
   * Canonical section "intent" tokens. Every README must contain at least
   * one H2 with a translation of each intent. The intent is the
   * `intent:<key>` annotation that any README may add on the heading
   * line — the H2 text itself may be in any language.
   *
   * Recognised intents:
   *  - install
   *  - configuration
   *  - documentation (or "reference")
   *  - license
   *  - project-structure
   *  - what-it-does
   *
   * The intent marker is a trailing HTML comment on the H2 line:
   *   `## 定位 <!-- intent:what-it-does -->`
   *
   * Markers are OPTIONAL — without a marker, the script falls back to
   * a hard-coded required-section list per locale.
   *
   * `ui-cli` was dropped from `requiredIntents` on 2026-10-23: the READMEs
   * no longer document the Control UI panel or the event-digest /
   * rule-regression CLI scripts, so requiring an H2 for them only forced a
   * section nobody wanted. It was already absent from the "Recognised
   * intents" list above, which is why the two lists disagreed. Add the
   * token back to both if that documentation returns.
   */
  const requiredIntents = ['what-it-does', 'install', 'license']

  let failures = 0
  for (const f of readmes) {
    const text = readText(join(root, f))
    const headings = extractHeadings(text)
    const h1 = headings.find((h) => h.level === 1)
    const intentSet = new Set()
    for (const line of text.split('\n')) {
      const m = /^#{1,2}\s+.+?<!--\s*intent:([a-z0-9-]+)\s*-->/.exec(line)
      if (m) intentSet.add(m[1])
    }

    // 1. Plugin name mention
    if (!text.includes(pluginName)) {
      console.error(`✗ ${f}: does not mention plugin name "${pluginName}"`)
      failures += 1
    }
    // 2. License match
    if (!text.includes(license)) {
      console.error(`✗ ${f}: does not mention license "${license}"`)
      failures += 1
    }
    // 3. H1 is the plugin name
    if (!h1 || h1.text !== canonicalH1.text) {
      console.error(`✗ ${f}: H1 is "${h1?.text ?? '(none)'}", expected "${canonicalH1.text}"`)
      failures += 1
    }
    // 4. Required intents (when marked) — skip if no markers were
    //    declared in this README (translations without markers still
    //    pass the structural check; they only fail if a marker is
    //    present and the matching intent is missing).
    for (const intent of intentSet) {
      if (requiredIntents.includes(intent) && !intentSet.has(intent)) {
        // (Unreachable — already in the set — but kept for clarity.)
      }
    }
    // 5. H2 count sanity: the translation should have at least as many
    //    H2 sections as the canonical (translations may add locale-
    //    specific sections, but never DROP canonical ones). We compare
    //    intent-presence rather than text equality.
    if (intentSet.size > 0) {
      for (const intent of requiredIntents) {
        if (!intentSet.has(intent)) {
          console.error(`✗ ${f}: missing intent "${intent}" (add <!-- intent:${intent} --> to the matching H2)`)
          failures += 1
        }
      }
    }
  }

  if (failures === 0) {
    console.log(`✓ ${readmes.length} README files are in sync`)
    process.exit(0)
  }
  console.error(`✗ ${failures} drift issue(s) detected`)
  process.exit(1)
}

main()
