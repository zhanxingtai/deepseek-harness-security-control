import type { InterventionContext } from '../types/index.js'
import type { CompiledMatchClause, CompiledRule } from './InterventionEngine.js'
import { stripZeroWidthAndRtl } from './InlinePromptInjection.js'

/**
 * Match an intervention context against a compiled rule.
 *
 * Semantics:
 * - actionType: any listed value matches (or absent = match all).
 * - toolName: any listed value matches; '*' is a wildcard.
 * - riskFlagsAny: at least one listed flag must be present.
 * - riskFlagsAll: all listed flags must be present.
 * - paramsRegex: for every configured field, at least one regex must match the
 *   stringified value of that field. If a field is absent the rule does not match.
 * - bodyRegex: at least one regex must match the body string.
 *
 * Every command/body string is also matched in its CANONICAL (fragment-folded)
 * form — see `canonicalizeCommand`. This is the behavioural half of SPL
 * matching: "no banned contiguous substring" stops being a usable evasion once
 * a fragment-assembled command is folded back into its assembled form before
 * the existing self-protection patterns run.
 */
export function matchRule(
  ctx: InterventionContext,
  rule: CompiledRule,
  /**
   * optional observer that
   * receives canonicalization signals during this rule's evaluation.
   * `canonicalizationUsed` flips to `true` if the rule matched via
   * the canonical (folded / normalised) form of any input rather
   * than the verbatim text. `undefined` = no observability (the
   * default call sites — tests, debug — don't care).
   */
  traceSink?: { canonicalizationUsed?: boolean },
): boolean {
  // every MatchClause sub-clause is independently optional
  // and an empty / absent `match` clause means "matches everything". This
  // mirrors the SPL spec vocabulary — riskFlags-only rules (a pure "if the
  // event carries flag X" rule, no actionType / toolName constraint) are a
  // legitimate simplification of pure "always-on" guards and were previously
  // impossible to express. The previous `!rule.match` early-return forced
  // every rule to enumerate at least one sub-clause.
  if (!rule.enabled) return false
  const m = rule.match
  if (!m) return true

  if (!matchActionType(ctx, m)) return false
  if (!matchToolName(ctx, m)) return false
  if (!matchAssetType(ctx, m)) return false
  if (!matchRiskFlags(ctx, m)) return false
  if (!matchParamsRegex(ctx, m, traceSink)) return false
  if (!matchParamsNotRegex(ctx, m)) return false
  if (!matchBodyRegex(ctx, m, traceSink)) return false

  return true
}

function matchActionType(ctx: InterventionContext, m: CompiledMatchClause): boolean {
  if (!m.actionType || m.actionType.size === 0) return true
  return ctx.actionType ? m.actionType.has(ctx.actionType) : false
}

function matchAssetType(ctx: InterventionContext, m: CompiledMatchClause): boolean {
  if (!m.assetType || m.assetType.size === 0) return true
  const assetType = ctx.assetType
  if (!assetType) return false
  return m.assetType.has(assetType)
}

function matchToolName(ctx: InterventionContext, m: CompiledMatchClause): boolean {
  if (!m.toolName || m.toolName.size === 0) return true
  const toolName = ctx.toolName
  if (!toolName) return false
  if (m.toolName.has('*')) return true
  return m.toolName.has(toolName)
}

function matchRiskFlags(ctx: InterventionContext, m: CompiledMatchClause): boolean {
  const flags = new Set(ctx.riskFlags ?? [])

  if (m.riskFlagsAll && m.riskFlagsAll.size > 0) {
    for (const flag of m.riskFlagsAll) {
      if (!flags.has(flag)) return false
    }
  }

  if (m.riskFlagsAny && m.riskFlagsAny.size > 0) {
    for (const flag of m.riskFlagsAny) {
      if (flags.has(flag)) return true
    }
    return false
  }

  return true
}

function matchParamsRegex(
  ctx: InterventionContext,
  m: CompiledMatchClause,
  traceSink?: { canonicalizationUsed?: boolean },
): boolean {
  if (!m.paramsRegex) return true
  const params = ctx.params ?? {}
  for (const [field, regexes] of Object.entries(m.paramsRegex)) {
    const value = stringifyField(getFieldValue(params, field))
    if (value === undefined) return false
    if (!matchesRegexList(value, regexes, traceSink)) return false
  }
  return true
}

/**
 * Negative form of `matchParamsRegex`. When `paramsNotRegex` is declared,
 * the rule must NOT match any of the listed patterns for the rule to
 * still be considered a hit — typical use is "block kill PID commands
 * unless the target is a dev server process name". If a field is declared
 * here but the corresponding `ctx.params[field]` is absent, the rule is
 * excluded (defensive: do not silently let missing-field samples through;
 * matches the strict semantics of `paramsRegex`).
 */
function matchParamsNotRegex(
  ctx: InterventionContext,
  m: CompiledMatchClause,
  traceSink?: { canonicalizationUsed?: boolean },
): boolean {
  if (!m.paramsNotRegex) return true
  const params = ctx.params ?? {}
  for (const [field, regexes] of Object.entries(m.paramsNotRegex)) {
    const value = stringifyField(getFieldValue(params, field))
    if (value === undefined) return false
    if (matchesRegexList(value, regexes, traceSink)) return false
  }
  return true
}

function matchBodyRegex(
  ctx: InterventionContext,
  m: CompiledMatchClause,
  traceSink?: { canonicalizationUsed?: boolean },
): boolean {
  if (!m.bodyRegex || m.bodyRegex.length === 0) return true
  // bodyRegex is a STRICT gate: when the rule declares bodyRegex it
  // expects a body to evaluate against. A tool call that doesn't
  // carry a body (e.g. `params.command` only) MUST fail this clause
  // so the rule does not match vacuously and over-block — see
  // intervention.test.ts SELF_PROTECTION_PLUGIN_SCRIPT_WRITE_013/016 negative tests.
  // Rules that need to evaluate write-tool content should reach the
  // content via `paramsRegex.body` (FIELD_ALIASES includes
  // `content`/`text`/`data`).
  const body = ctx.body
  if (typeof body !== 'string' || body.length === 0) return false
  return matchesRegexList(body, m.bodyRegex, traceSink)
}

// --- Fragment-variable folding (behavioural matching) ------------------------

/**
 * Test a string against a list of regexes, first verbatim, then in its
 * canonical (fragment-folded) form, then once more with zero-width / RTL
 * codepoints replaced by literal spaces. A rule therefore matches if ANY of
 * the three views — literal text, shell-assembled text, or
 * whitespace-injected text — carries the pattern.
 *
 * the third pass closes the between-token ZWSP
 * bypass class. The first pass keeps the within-token ZWSP collapse to a
 * contiguous word (so the `\bpnpm\b` anchor fires on `pnpm`), and the
 * first-pass `stripZeroWidthAndRtl(...)` inside `unicodeNormalizeCached`
 * preserves that. But the second pass cannot manufacture a SPACE — the
 * attacker who removed every space and replaced them with U+200B made the
 * `\s+` anchor unreachable even after canonicalisation. The third pass
 * substitutes a literal space for each stripped codepoint, restoring the
 * token boundary the SPL patterns expect.
 */
function matchesRegexList(
  value: string,
  regexes: RegExp[],
  /**
   * optional observer that
   * flips to `true` if the rule matched via a non-verbatim view
   * (canonical folded form, or zero-width-replaced-spaced form).
   * Stamps the audit-side `canonicalization_applied` flag on the
   * decision so operators can see when the rail had to rewrite
   * obfuscated text before matching. Distinct from "canonical form
   * existed" — only sets when a non-verbatim view actually matched.
   */
  traceSink?: { canonicalizationUsed?: boolean },
): boolean {
  if (regexes.some((rx) => rx.test(value))) return true
  const canonical = canonicalizeCommandCached(value)
  if (canonical !== value && regexes.some((rx) => rx.test(canonical))) {
    if (traceSink) traceSink.canonicalizationUsed = true
    return true
  }
  const spaced = stripZeroWidthAndRtl(value, ' ')
  if (spaced !== value && regexes.some((rx) => rx.test(spaced))) {
    // Spacing replacement is a canonicalization-adjacent pass too —
    // if the rule fired only because we substituted a literal space
    // for each ZWSP, surface that. Operators want to know the attack
    // used invisible separators, not just generic obfuscation.
    if (traceSink) traceSink.canonicalizationUsed = true
    return true
  }
  return false
}

/**
 * Memoized `canonicalizeCommand`. Folding is a pure function of
 * the input string, and without a cache every paramsRegex/bodyRegex rule
 * re-folds the same command once per rule — O(N) folds per evaluation for
 * an N-rule policy. The cache is process-wide (not per-evaluation) because
 * identical command strings recur across evaluations (e.g. repeated tool
 * calls). Bounded LRU: values can be up to 16 KiB each, so the cap keeps
 * worst-case footprint at ~4 MiB.
 */
const CANONICAL_CACHE_MAX = 256
const canonicalCache = new Map<string, string>()

function canonicalizeCommandCached(value: string): string {
  const hit = canonicalCache.get(value)
  if (hit !== undefined) {
    // Refresh LRU order.
    canonicalCache.delete(value)
    canonicalCache.set(value, hit)
    return hit
  }
  const canonical = canonicalizeCommand(value)
  if (canonical !== value) {
    if (canonicalCache.size >= CANONICAL_CACHE_MAX) {
      const oldest = canonicalCache.keys().next().value
      if (oldest !== undefined) canonicalCache.delete(oldest)
    }
    canonicalCache.set(value, canonical)
  }
  return canonical
}

const MAX_CANONICAL_INPUT = 16 * 1024
// Fresh instance per use — a shared /g regex would carry lastIndex state.
const VAR_REF_SOURCE = '\\$\\{([A-Za-z_][A-Za-z0-9_]*)\\}|\\$([A-Za-z_][A-Za-z0-9_]*)'
const VAR_REF_RE = () => new RegExp(VAR_REF_SOURCE, 'g')
// (defence-in-depth): accept bash assignment prefixes
// `declare [-flags]`, `typeset [-flags]`, `local`, `readonly` in addition to
// `export` / bare `VAR=…`. Without these the fragment-variable fold silently
// skips the whole "declare the fragments, then reference them" class of
// attacks (the existing SPL rules fire on the assembled
// text but `foldAssignment` never recorded the variables, so the references
// stayed unresolved). The optional flag group on `declare` / `typeset` matches one
// or more `-x` / `-i` / `-a` / `-A` / `-r` / `--` flags separated by
// whitespace; the closing `\s+` requires at least one separator before the
// variable name. `local` only makes sense inside a function body, but the
// fold is conservative — accepting it at top-level costs nothing.
const ASSIGN_RE =
  /^(?:(?:export|(?:declare|typeset)(?:\s+-[a-zA-Z]+)*|local|readonly)\s+)*([A-Za-z_][A-Za-z0-9_]*)=(.*)$/

// Unicode normalisation (FEAT) -----------------
//
// `canonicalizeCommand` runs BEFORE the fragment-variable / env-carrier fold
// regexes so that the banned behaviour written with
// full-width Latin letters or zero-width separators
// cannot slip past the ASCII-only fold patterns.
// Normalisation is a single regex sweep and never throws; pathological inputs
// (unpaired surrogates) fall back to the zero-width strip alone.
const UNICODE_NORMALIZE_CACHE_MAX = 256
const unicodeNormalizeCache = new Map<string, string>()

function unicodeNormalizeCached(text: string): string {
  if (!text || text.length > MAX_CANONICAL_INPUT) return text
  const hit = unicodeNormalizeCache.get(text)
  if (hit !== undefined) {
    unicodeNormalizeCache.delete(text)
    unicodeNormalizeCache.set(text, hit)
    return hit
  }
  let normalised: string
  try {
    // NFKD = compatibility decomposition (full-width → ASCII), more permissive
    // than NFKC for shell canonicalisation because it also splits ligatures
    // (`ﬁre` → `fire`). Identical to NFKC for the full-width Latin range.
    //
    // keep the default `''` replacement so within-
    // token ZWSP obfuscations (`pnpm` → `pnpm`) still collapse to the
    // contiguous launcher word. The between-token bypass class
    // (`pnpmdshweb` with ZWSP replacing the SPACES between words) is
    // closed separately in `matchesRegexList` via a third pass that checks
    // each regex against the value with ZWSP replaced by literal space —
    // that's the only shape the SPL `\bpnpm\s+dsh\b` /\s+ anchors can
    // observe, and a within-token collapse (default `''`) can't manufacture
    // a space where the attacker removed one.
    normalised = stripZeroWidthAndRtl(text.normalize('NFKD'))
  } catch {
    // Unpaired-surrogate fallback: skip NFKD (would throw) but still strip
    // the invisible codepoints so the second pass has something to scan.
    normalised = stripZeroWidthAndRtl(text)
  }
  if (normalised !== text) {
    if (unicodeNormalizeCache.size >= UNICODE_NORMALIZE_CACHE_MAX) {
      const oldest = unicodeNormalizeCache.keys().next().value
      if (oldest !== undefined) unicodeNormalizeCache.delete(oldest)
    }
    unicodeNormalizeCache.set(text, normalised)
  }
  return normalised
}
// Env-carriers (`systemd-run --setenv=…`, `--env …`, `Environment=…` /
// `--property=Environment=…`). Hiding a deployment string behind a variable
// that only the service runtime expands keeps it out of the scanned text
// entirely: the command line carries NO contiguous banned substring and no
// shell assignment, so every literal rule passes. These carriers are
// constant-foldable exactly like shell assignments — if the injected value is
// a safe literal, the `$VAR` reference can be substituted and the assembled
// command reaches the existing rules.
const ENV_CARRIER_SOURCE =
  '(?:--setenv|--env|--environment|(?:--property=)?Environment)' +
  '[=:\\s]+([A-Za-z_][A-Za-z0-9_]*)[=:\\s]+' +
  '("(?:[^"\\\\]|\\\\.)*"|\'(?:[^\'\\\\]|\\\\.)*\'|[^\\s\'"]+)'
const ENV_CARRIER_RE = () => new RegExp(ENV_CARRIER_SOURCE, 'g')

/**
 * Expand fragment-variable encodings inside a command string so the
 * self-protection patterns can see the *assembled* behaviour instead of the
 * fragments the agent textually submitted.
 *
 * A watchdog-style bypass works by making the banned behaviour exist only
 * after shell variable expansion — the text submitted is a handful of short
 * assignments plus a reference, never the command itself. No contiguous banned
 * substring exists in the scanned text, so every literal SPL rule passes. This
 * function performs a best-effort shell *constant folding*: statement by
 * statement it records literal assignments and substitutes `$VAR` / `${VAR}`
 * references with those values.
 *
 * Safety (why folding cannot manufacture a false positive):
 *  - Only values that are themselves *safe literals* are folded — the value
 *    must contain no remaining `$`, backtick, `(`, or `)` after reference
 *    substitution, i.e. nothing runtime-dependent. `LPID=$(ss -tlnp ...)` is
 *    left untouched.
 *  - References to undefined variables are left as-is (`$LPID` stays `$LPID`).
 *  - Folding only ever turns the text INTO the same bytes the rules already
 *    block when written plainly, so it cannot broaden the block set beyond
 *    what the plaintext form already covers — it only closes the encoding gap.
 */
export function canonicalizeCommand(text: string): string {
  if (!text || text.length > MAX_CANONICAL_INPUT) return text
  // FEAT : normalise unicode (NFKD + zero-width/RTL strip) BEFORE the
  // fragment-variable / env-carrier fold regexes so that full-width letters
  // (`ｐｍｐｍ ｄｓｈ ｗｅｂ`) and zero-width separators (`pnpm dsh web`) become
  // ASCII and reach the existing patterns.
  text = unicodeNormalizeCached(text)
  // FEAT : pre-scan for shell-function definitions (`name { … }` or
  // `function name { … }`) so a function body carrying the banned behaviour
  // is unfolded into the call site. The function bodies are recorded in the
  // same `vars` map as fragment assignments; later `$NAME` references
  // substitute to the body. The function definition lines are stripped from
  // the text so they don't reach the statement-walk as executable lines
  // (otherwise the body would be re-evaluated on the original side).
  const { text: stripped, fnVars } = foldShellFunctions(text)
  text = stripped
  const vars = new Map<string, string>(fnVars)
  const folded: string[] = []
  // Statement boundary = newline or `;` ONLY. `&&`/`||`/`&` are flow control —
  // splitting on them would tear apart `2>&1 < /dev/null &` and destroy the
  // very adjacency ($X$Y) the attacker relies on.
  for (const statement of text.split(/[\n;]/)) {
    const stmt = statement.trim()
    if (!stmt) continue
    const value = foldAssignment(stmt, vars)
    if (value !== null) {
      // Assignment statements contribute nothing executable; they only feed
      // the variable map for subsequent statements.
      continue
    }
    foldEnvCarriers(stmt, vars)
    folded.push(substituteRefs(stmt, vars, 0))
  }
  const out = folded.join(' ; ')
  // FEAT : curl/wget pipe-shape canonicalisation. A remote payload is
  // fetched then piped to a shell (`curl URL | bash`, `wget URL | sh`,
  // `curl URL | xargs bash -c`). The URL body is opaque to us — we can't
  // constant-fold a remote resource — but the SHAPE is a known attack
  // vector. Insert a synthetic marker after the shell endpoint so the
  // canonical form is auditable (post-hoc `pnpm inspect-events` can grep
  // for the marker to list all fetched-payload candidates) and so future
  // SPL rules with a marker-prefix clause can match without re-parsing
  // the URL. The marker is a no-op comment-shaped token (preceded by `#`
  // so the shell would treat it as a comment if it were ever re-executed
  // — it isn't, we only fold for evaluation).
  const marked = annotateFetchedPayloads(out)
  return marked === text ? text : marked
}

/**
 * Detect `curl URL | bash/sh/zsh/...` and `wget URL | bash` pipe shapes
 * and append a synthetic marker `# dsh-fetched-payload:<URL>` after the
 * shell endpoint. The marker is shell-comment-shaped (the original argv
 * is NEVER re-executed; canonicalization is read-only on the SPL side),
 * but it shows up in `canonicalizeCommand` output for post-hoc audit.
 *
 * Safety: no eval, no recursion, no `$` substitution inside the URL.
 * Already-folded text (variable assignments before the pipe, fragment
 * variables in the URL via the prior fold) is left alone — the marker
 * captures the LITERAL URL substring that survived folding.
 */
const FETCHED_PIPE_RE = () =>
  new RegExp(
    // `curl/wget <url>` (any non-`|` text up to 1 KiB) `|` optional spaces
    // `bash|sh|zsh|python|perl|ruby` optional command. We attach the
    // marker to the WHOLE pipe line so future SPL rules with a marker
    // clause match without scanning the URL.
    '(\\b(?:curl|wget)\\b[^|\\n]{0,1024}\\|\\s*\\b(?:bash|sh|zsh|python|perl|ruby)\\b[^\\n]{0,256})',
    'g',
  )

function annotateFetchedPayloads(text: string): string {
  const re = FETCHED_PIPE_RE()
  let out = ''
  let cursor = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    out += text.slice(cursor, m.index)
    // The URL portion is whatever precedes the first `|` inside the match.
    const matchStr = m[1]
    const pipeIdx = matchStr.indexOf('|')
    const urlPart = pipeIdx >= 0 ? matchStr.slice(0, pipeIdx).trim() : matchStr.trim()
    // Extract a rough URL token from the fetch command.
    const urlMatch = /\bhttps?:\/\/\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2}[^\s|]*/i.exec(urlPart)
    const url = urlMatch ? urlMatch[0].replace(/[)\]}>.,]+$/, '') : '<unparsed>'
    out += m[1] + '   # dsh-fetched-payload:' + url
    cursor = m.index + m[1].length
    re.lastIndex = cursor
  }
  out += text.slice(cursor)
  return out
}

// Shell-function folding (FEAT) ------------------------
//
// The fragment-variable class folds into the
// contiguous banned form, but the same trick can hide a body inside a
// shell function definition:
//
//   ban() { <banned command>; }
//   ban
//
// No contiguous banned substring exists in `ban` alone (it's a 3-letter
// identifier); the body never appears inline. `foldShellFunctions` matches
// the two POSIX forms (`name() { body }` / `function name { body }`) via a
// brace walker (the body can span multiple lines and contain its own
// `;`-separated statements), records each body under the function name, and
// strips the definition lines from the returned text. The downstream
// `substituteRefs` step then expands `$ban` to the body, which the existing
// SELF_PROTECTION_PROCESS_KILL_014 command pattern (`\bfuser\b.*-(k|--kill)\b.*\d+`)
// catches.
//
// Safety (mirrors `foldAssignment`):
//   - Body must be a SAFE LITERAL after reference substitution: no remaining
//     `$`, backtick, `(`, `)` (parens would mean command substitution inside
//     the body, which we cannot evaluate). A function whose body cannot be
//     constant-folded is left untouched in the text — the call site stays
//     `$name`, the existing rules don't fire, and the operator sees a
//     runtime-detected event rather than a folded false positive.
//   - A function definition whose body contains ITSELF a function
//     definition is REJECTED (defensive: prevents recursive folding that
//     could blow the depth limit).
//   - The walker is bounded by `MAX_CANONICAL_INPUT` — already enforced by
//     the caller — so pathological inputs are short-circuited upstream.
const FN_DEF_NAME = '[A-Za-z_][A-Za-z0-9_]*'
const FN_DEF_RE = () =>
  new RegExp(
    // `name() {` or `function name {` (the `function` keyword form allows a
    // space between name and `{`); the opening `{` may be preceded by
    // whitespace and newlines.
    `(?:(?:${FN_DEF_NAME})\\s*\\(\\s*\\)\\s*\\{|\\bfunction\\s+${FN_DEF_NAME}\\s*\\{)`,
    'g',
  )

/**
 * Scan `text` for shell-function definitions, record each foldable body in
 * the returned `fnVars` map (keyed by function name), and return the text
 * with all definition lines stripped. Unfoldable bodies are NOT recorded —
 * the corresponding call site will not substitute, and the original
 * definition lines remain in the returned text (the existing patterns stay
 * unaware of the function, which is the desired conservative behaviour).
 */
function foldShellFunctions(
  text: string,
): { text: string; fnVars: Map<string, string> } {
  const fnVars = new Map<string, string>()
  // Walk through the text finding definition headers, then brace-match the
  // body. Single-pass is sufficient because definitions don't nest in
  // POSIX shell (a function body containing another function definition is
  // not legal, and even if it were, the inner def is silently dropped by
  // the runtime).
  const re = FN_DEF_RE()
  let cursor = 0
  // Collect ranges to strip AFTER the walk (don't mutate `text` during scan).
  const stripRanges: Array<[number, number]> = []
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const headerStart = m.index
    const headerEnd = re.lastIndex // right after the `{`
    // Extract the function name from the matched form.
    // Two forms:
    //   `name() {`     → captured as `${FN_DEF_NAME}\s*\(\s*\)\s*\{`
    //   `function name {` → captured as `\bfunction\s+${FN_DEF_NAME}\s*\{`
    // The shared suffix is `{`, so the name is whatever precedes it.
    const openBrace = text.indexOf('{', headerStart)
    // Find the function name: scan back from `{` over whitespace to the
    // first identifier char, then read the identifier.
    let nameEnd = openBrace
    while (nameEnd > headerStart && /\s/.test(text[nameEnd - 1])) nameEnd--
    let nameStart = nameEnd
    while (nameStart > headerStart && /[A-Za-z0-9_]/.test(text[nameStart - 1])) nameStart--
    const fnName = text.slice(nameStart, nameEnd)
    // Now brace-match the body. Track `{` / `}` so nested compound
    // statements (`if … then { … } fi`) inside the body don't terminate
    // the body prematurely.
    let depth = 1
    let bodyEnd = headerEnd
    while (bodyEnd < text.length && depth > 0) {
      const ch = text[bodyEnd]
      if (ch === '{') depth++
      else if (ch === '}') depth--
      bodyEnd++
    }
    if (depth !== 0) {
      // Unterminated body — leave it alone, advance past the match.
      continue
    }
    // The body lives between `headerEnd` (right after `{`) and the matching
    // `}` at `bodyEnd - 1`.
    const body = text.slice(headerEnd, bodyEnd - 1)
    // Reject nested function definitions inside the body (would re-enter
    // the walker with overlapping ranges — the defensive check below).
    if (/\bfunction\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/.test(body) ||
        new RegExp(`${FN_DEF_NAME}\\s*\\(\\s*\\)\\s*\\{`).test(body)) {
      continue
    }
    // Substitute any `$VAR` references against an empty map (we're
    // recording before the main walk, so no fragment assignments are
    // available yet — references stay as-is, which is the safe default).
    const substituted = body
    // Safety: body must be a SAFE LITERAL — no `$`, backtick, or parens.
    if (/\$|`|\(|\)/.test(substituted)) continue
    // Foldable: record.
    if (!fnVars.has(fnName)) fnVars.set(fnName, substituted)
    // Strip the entire definition (including the body and trailing newline
    // if present) from the text. Range = [headerStart, bodyEnd].
    stripRanges.push([headerStart, bodyEnd])
    // Resume the regex scan AFTER the body — anything inside the body is
    // part of the definition, not a separate top-level statement.
    re.lastIndex = bodyEnd
    // Guard against infinite loop on zero-width matches.
    if (headerEnd <= cursor) {
      cursor = bodyEnd
    } else {
      cursor = bodyEnd
    }
  }
  // Apply strips back-to-front so earlier offsets stay valid.
  if (stripRanges.length === 0) return { text, fnVars }
  let stripped = text
  for (let i = stripRanges.length - 1; i >= 0; i--) {
    const [s, e] = stripRanges[i]
    stripped = stripped.slice(0, s) + stripped.slice(e)
  }
  return { text: stripped, fnVars }
}

/**
 * If `stmt` is a shell assignment (`VAR=...` / `export VAR=...` /
 * `declare [-flags] VAR=...` / `typeset [-flags] VAR=...` /
 * `local VAR=...` / `readonly VAR=...`) whose value is a foldable literal,
 * records it and returns the variable name. Returns null when the statement
 * is NOT an assignment (caller treats it as executable). Unsafe RHS values
 * (containing `$`, backtick, or parens after reference substitution) are
 * swallowed WITHOUT being recorded — they are still assignment lines, they
 * just cannot be constant-folded.
 */
function foldAssignment(stmt: string, vars: Map<string, string>): string | null {
  const m = ASSIGN_RE.exec(stmt)
  if (!m) return null
  const name = m[1]
  const rhs = m[2].trim()
  const substituted = substituteRefs(rhs, vars, 1)
  // NOTE: no .trim() on the unquoted value — `R3=" -k"` has a significant
  // leading space; trimming it turns $R1$R2$R3$R4$R5 into `fuser-k...` instead
  // of `fuser -k ...`.
  const unquoted = unquote(substituted)
  if (/\$|`|\(|\)/.test(unquoted)) return name // assignment, but not foldable
  vars.set(name, unquoted)
  return name
}

/**
 * Record `--setenv=VAR='lit'` / `--env VAR='lit'` / `Environment=VAR="lit"`
 * values into the variable map so later `$VAR` references fold to the literal.
 * Same safety rule as `foldAssignment`: only safe literals are recorded — a
 * value containing `$`, backtick, or parens after substitution is runtime
 * dependent and is left unknown (the reference stays `$VAR`).
 */
function foldEnvCarriers(stmt: string, vars: Map<string, string>): void {
  const re = ENV_CARRIER_RE()
  let m: RegExpExecArray | null
  while ((m = re.exec(stmt)) !== null) {
    if (vars.has(m[1])) continue // later assignment already wins
    const substituted = substituteRefs(m[2], vars, 1)
    const unquoted = unquote(substituted)
    if (/\$|`|\(|\)/.test(unquoted)) continue
    vars.set(m[1], unquoted)
  }
}

function substituteRefs(stmt: string, vars: Map<string, string>, depth: number): string {
  if (depth > 4) return stmt
  return stmt.replace(VAR_REF_RE(), (full, braced: string | undefined, bare: string | undefined) => {
    const name = (braced ?? bare) ?? ''
    const value = vars.get(name)
    return value !== undefined ? value : full
  })
}

function unquote(s: string): string {
  if (s.length >= 2) {
    const quote = s[0]
    if ((quote === '"' || quote === "'") && s.endsWith(quote)) return s.slice(1, -1)
  }
  return s
}

/**
 * Look up a parameter value, supporting common field aliases used by
 * different tool conventions. The primary field is checked first; if absent
 * we fall back to aliases. This lets a single `paramsRegex.path` rule match
 * both `path` and `file_path` / `src` / `target` (DSH native tool style)
 * without duplicating every rule.
 */
function getFieldValue(params: Record<string, unknown>, field: string): unknown {
  if (params[field] !== undefined) return params[field]
  const aliases = FIELD_ALIASES[field]
  if (!aliases) return undefined
  for (const alias of aliases) {
    if (params[alias] !== undefined) return params[alias]
  }
  return undefined
}

/**
 * 参数字段别名表。
 *
 * 导出而非模块私有：外部策略评测工具用本地镜像复刻本引擎的匹配语义来评测策略，
 * 它必须读到同一份别名表，否则会把「语料用 file_path、规则 key 在 path」这种
 * **实际能命中**的样本误判成漏报——实测会让诊断凭空多出上百条假缺陷。镜像侧经
 * loadHarnessHelpers() 注入，与 canonicalizeCommand / stripZeroWidthAndRtl 同一套机制。
 *
 * 改动本表即改变引擎匹配行为；新增别名请同步镜像侧的兜底表。
 */
export const FIELD_ALIASES: Record<string, string[]> = {
  path: ['file_path', 'file', 'src', 'source', 'target', 'destination', 'dest', 'destination_path'],
  command: ['cmd', 'shell', 'script', 'exec'],
  body: ['content', 'text', 'data'],
}

function stringifyField(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}
