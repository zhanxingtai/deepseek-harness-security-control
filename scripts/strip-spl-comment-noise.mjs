#!/usr/bin/env node
/**
 * scripts/strip-spl-comment-noise.mjs
 *
 * Scrub internal-leakage annotation noise from `policies/default-policy.spl.yaml`
 * for the open-source release: dates, sprint markers (S3, S11 ...), priority
 * labels (P0/P1/P2 FP 收窄),宁漏勿误,MEDIUM-N,内部 staging token,TBD markers,
 * and bare "issue" references are all stripped — but ONLY from prose contexts
 * (YAML comments + `notes: >-` / `blockReason: >-` etc. folded-block continuations
 * + `name:` / `description:` / `title:` single-line scalars). Regex values under
 * `match.paramsRegex.command.<item>` are NEVER touched.
 *
 * Whitelist-trust the YAML line shape:
 *  - A line that begins a regex list item (`  - \foo` or contains many `\` escapes)
 *    is excluded by shape alone.
 *  - A folded-block continuation is identified by being indented deeper than the
 *    `>` or `>-` key's own indent (YAML `>-` rules).
 *
 * Idempotent — `--write` applies changes in place; otherwise a unified diff is
 * printed to stdout. CRLF-safe (mirrors the working copy's line endings). Exit
 * code 0 always; the diff is the contract.
 *
 * Use:
 *   node scripts/strip-spl-comment-noise.mjs               # diff to stdout
 *   node scripts/strip-spl-comment-noise.mjs --write        # apply in place
 *   node scripts/strip-spl-comment-noise.mjs --file=<path> # target another YAML
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const args = new Set(process.argv.slice(2))
const writeMode = args.has('--write')
const fileArg = [...args].find((a) => a.startsWith('--file='))
const FILE = resolve(
  fileArg ? fileArg.slice('--file='.length) : 'policies/default-policy.spl.yaml',
)

// Markers we recognize as "prose keys" — i.e., the start of a folded-block scalar.
// Single-line scalars carrying prose (`name:`, `description:`, `title:`) are
// handled by value-position scrubbing below, not by entering a folded state.
const FOLDED_BLOCK_RE = /^(\s*)(notes|blockReason|reason|description)\s*:\s*[>|][-+]?\s*$/
const FOLDED_HEADER_LINE_RE = /^(\s*)(notes|blockReason|reason|description)\s*:\s*[>|][-+]?\s*$/

// A scalar single-line prose key — value(s) on the same line, possibly quoted.
// We only consider the value as prose; test inputs under `input.params.command:`
// also use `command:` but are detected by the indented-block context.
const SCALAR_PROSE_KEY_RE = /^(\s*)(name|description|title)\s*:\s*(.*)$/

// Heuristic: a line is a regex-list item when it starts with whitespace + `- \` or
// contains lots of `\b`, `\s`, etc. escape pairs. We use this to protect ALL regex
// content from scrubbing — even on otherwise-prose-looking lines that happen to be
// regex values.
const REGEX_LINE_RE = /^\s*-\s+(?=[\\])|^.*[\\][a-zA-Z]/

// ---------- the scrubbing rules ----------
//
// Order matters: parenthetical (date + reason) first (most specific), then
// sentence-leading dates, then internal labels, then whitespace + punctuation
// cleanup at the end. Each rule pairs with a safety guard so a regex line can
// never be corrupted even if our prose detection misses.

const RULES = [
  // 1. Parenthetical date + reason: "(2026-10-10 FP 收窄 ...)" / "（2026-09-30 issue）".
  //    Match both ASCII and full-width brackets so the SPL policy notes (which
  //    write full-width Chinese parens) are scrubbed too.
  [
    /[(（]\s*(20\d{2}-\d{2}-\d{2})\b[\s\S]*?[)）]/g,
    '',
  ],
  // 2. Parenthetical standalone date markers (no content): "（2026-10-10）"
  [
    /[(（]\s*20\d{2}-\d{2}-\d{2}\s*[)）]/g,
    '',
  ],
  // 3. Sentence-leading dated campaign markers, e.g. "2026-10-10 P2 FP 收窄:"
  //    — strip the dated prefix up to and including the first `:` or `。`
  [
    /(^\s*[。；;]?\s*|[\s。；;：])(20\d{2}-\d{2}-\d{2})\s*(P[012]\s+)?FP 收窄\+?门控补齐[^:：]*[:：]\s*/g,
    '$1',
  ],
  // 4. Sentence-leading date prefixes (any year)
  [
    /(^\s*|[\s。；;，：:,])(20\d{2}-\d{2}-\d{2})(\s+)/g,
    '$1',
  ],
  // 5. Internal campaign labels
  [
    /\s*P[012]\s+FP 收窄\+?门控补齐\b/g,
    '',
  ],
  [
    /\s*\(?宁漏勿误\)?\s*/g,
    ' ',
  ],
  [
    /\s*\(?MEDIUM-(\d+)\)?\s*/g,
    '',
  ],
  // 6. Sprint markers (S3, S11 ...): "（S3 pwsh parity）" / "S11 "
  [
    /\s*[（(]?S\d+\s+pwsh parity[)）]\s*/g,
    '',
  ],
  [
    /\s*S\d+\s+/g,
    ' ',
  ],
  // 7. Explicit leak markers (kept here as a defense-in-depth — should already
  //    be gone after the editor pass).
  [
    /内部 staging token 短可能漏/g,
    '短凭据可能漏',
  ],
  [
    /TBD by standards v[\d.]+/g,
    'unresolved',
  ],
  // 8. Issue references: "issue #1884", "issue: 1884", "issue" alone
  [
    /\s*\(?\s*issues?\s*(?:#|no\.|number)?\s*\d+\s*\)?\s*/gi,
    ' ',
  ],
  // 9. "FY<number>" sprint labels (in case any)
  [
    /\s*FY\d+\s*/g,
    ' ',
  ],
  // 10. Tidy dangling punctuation at line ends
  [
    /[ \t]+([;；。、,，)])/g,
    '$1',
  ],
  [
    /\s+$/g,
    '',
  ],
]

// ---------- the line-state machine ----------
//
// We walk the file line-by-line. For each line we decide:
//   - "prose"        : safe to scrub
//   - "regex"        : never scrub
//   - "structural"   : not annotated, don't touch (skip scrubbing but copy as-is)
//
// A folded-block scalar (`notes: >-`, `blockReason: >-`, `reason: >-`) opens a
// prose context. While in a folded context, every subsequent line whose indent
// is STRICTLY greater than the folding key's own indent is treated as a
// continuation line (also prose). A line at or shallower than the key's indent
// (and not empty / not a comment) closes the fold.
//
// We also handle nested folds (folded blocks inside folded blocks): the inner
// fold's indent tracks independently.

function isProseLine(line, state) {
  // `state.folds` is a stack of { indent, key } — top is the most recent opened
  // fold that hasn't been closed.
  if (line.length === 0) return false
  if (line.trimStart().startsWith('#')) return true // YAML comment
  // Inside a fold? indent must be > the fold key's indent.
  if (state.folds.length > 0) {
    const top = state.folds[state.folds.length - 1]
    const indent = countLeadingSpaces(line)
    if (indent > top.indent) {
      // Defensive: even inside a fold, never scrub a regex-looking line.
      if (REGEX_LINE_RE.test(line)) return false
      return true
    }
    // Out-dented line — close the fold
    state.folds = state.folds.filter((f) => f.indent < indent)
  }
  return false
}

function countLeadingSpaces(s) {
  let n = 0
  for (let i = 0; i < s.length; i++) {
    if (s[i] === ' ') n++
    else break
  }
  return n
}

function isScalarProseValue(line, state) {
  // Single-line `name:` / `description:` / `title:` value carries prose.
  // Distinguish from list items / `command:` (which is also non-prose in test
  // inputs because we don't know whether it's a payload or description).
  const m = SCALAR_PROSE_KEY_RE.exec(line)
  if (!m) return false
  const [, indent, , value] = m
  if (value.trim().startsWith('|') || value.trim().startsWith('>')) return false
  // Defensive: even on `name:`, never scrub a regex-looking value.
  if (REGEX_LINE_RE.test(value)) return false
  state.lastScalarIndent = indent.length
  return true
}

function extractScalarValue(line) {
  const m = SCALAR_PROSE_KEY_RE.exec(line)
  if (!m) return { prefix: line, value: '', rest: '' }
  return {
    prefix: line.slice(0, m[0].length - m[3].length),
    value: m[3],
    rest: '',
  }
}

function applyRules(lineText) {
  // Strip leading whitespace BEFORE applying rules — YAML indentation is
  // semantically significant (folded-block continuation / list-item depth),
  // so collapsing it breaks structure. We keep `lead` exactly as-is, scrub
  // `body + trail`, then re-attach.
  const m = /^([ \t]*)([\s\S]*?)([ \t]*)$/.exec(lineText)
  const lead = m[1]
  let body = m[2]
  for (const [re, replacement] of RULES) {
    body = body.replace(re, replacement)
  }
  return lead + body
}

function scrubFileText(text) {
  // Preserve trailing newline shape — keep CRLF if the file is CRLF.
  const EOL = text.includes('\r\n') ? '\r\n' : '\n'
  // Split keeping the line array; last element may be '' (trailing newline).
  const rawLines = text.split(/\r?\n/)
  const state = { folds: [], lastScalarIndent: -1 }
  const out = []
  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i]
    const foldedMatch = FOLDED_HEADER_LINE_RE.exec(line)
    if (foldedMatch) {
      const foldIndent = foldedMatch[1].length
      // Close any open folds at <= this key's indent
      state.folds = state.folds.filter((f) => f.indent < foldIndent)
      state.folds.push({ indent: foldIndent, key: foldedMatch[2] })
      out.push(line) // the `notes: >-` header itself isn't annotated
      continue
    }
    if (isProseLine(line, state)) {
      const scrubbed = applyRules(line)
      out.push(scrubbed)
    } else if (isScalarProseValue(line, state)) {
      const { prefix, value } = extractScalarValue(line)
      const scrubbed = applyRules(value)
      out.push(prefix + scrubbed)
    } else {
      out.push(line)
    }
  }
  return out.join(EOL)
}

// ---------- CLI ----------

function main() {
  const original = readFileSync(FILE, 'utf8')
  const scrubbed = scrubFileText(original)
  if (scrubbed === original) {
    console.log(`[strip-spl-comment-noise] ${FILE}: no changes`)
    return
  }
  if (!writeMode) {
    // Unified diff
    const origLines = original.split(/\r?\n/)
    const newLines = scrubbed.split(/\r?\n/)
    const max = Math.max(origLines.length, newLines.length)
    let shown = 0
    for (let i = 0; i < max && shown < 200; i++) {
      const a = origLines[i] ?? ''
      const b = newLines[i] ?? ''
      if (a !== b) {
        console.log(`-${a}`)
        console.log(`+${b}`)
        shown++
      }
    }
    if (shown === 200) console.log('... (truncated to first 200 diff hunks — re-run with --write to apply all)')
    console.log(`\n[strip-spl-comment-noise] ${shown} changed lines — re-run with --write to apply`)
    return
  }
  writeFileSync(FILE, scrubbed, 'utf8')
  console.log(`[strip-spl-comment-noise] ${FILE}: written`)
}

main()
