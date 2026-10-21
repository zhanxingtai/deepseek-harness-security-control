/**
 * Post-hoc parser that recovers file operations embedded inside a tool's
 * `command` / `code` / `script` string.
 *
 * Why this exists
 * ----------------
 * Tools like `bash`, `python -c`, `node -e` accept a free-form string. When the
 * agent invokes `bash -c "cat /etc/passwd"`, our normal tool-name classifier
 * only sees `agent_tool_call` — the file semantics are lost. This parser
 * derives a `derived_file_ops`
 * array on the existing event so audit dashboards can filter shell-driven
 * file activity alongside native file_* events.
 *
 * Scope (intentional)
 * -------------------
 *  - Shell commands: cat/head/tail/tee/cp/mv/rm/chmod/chown/chgrp/dd/sed -i/awk
 *    plus shell redirects `>` / `>>` / `<`.
 *  - Inline scripts: `python -c '...'`, `python3 -c "..."`, `node -e '...'`
 *    detected by regex against the script body (`open(...)`, `fs.X(...)`).
 *
 * Known limitations (documented; not blocking)
 * ---------------------------------------------
 *  - No variable expansion: `$file`, `${file}` are skipped.
 *  - No glob expansion: `*`, `?`, `[...]` are kept as literal paths.
 *  - No command substitution recursion: `$(cmd)` is treated as opaque text.
 *  - No absolute-path resolution: paths are preserved verbatim from the
 * command. (Normalization is; see gap analysis.)
 *  - No argv flag handling: `-rf`, `--`, etc. are filtered heuristically
 *    by skipping tokens that start with `-`.
 *
 * The output is best-effort and intended for observability — it is NOT a
 * sandbox, and missing a file op here does NOT mean the op is safe.
 */

export type DerivedFileOpKind = 'read' | 'write' | 'delete' | 'privilege' | 'create'

export interface DerivedFileOp {
  /** Operation kind inferred from the verb (cat -> read, rm -> delete, ...). */
  op: DerivedFileOpKind
  /** Path as it appeared in the command string. Not resolved / normalized. */
  path: string
  /** Privilege ops only: the mode string (e.g. "777", "u+x"). */
  mode?: string
  /** Which interpreter produced this op (for debugging). */
  source?: 'shell' | 'python' | 'node'
}

const READ_VERBS = new Set(['cat', 'head', 'tail', 'less', 'more', 'sort', 'wc', 'file', 'bat'])
const WRITE_VERBS = new Set(['tee'])
const DELETE_VERBS = new Set(['rm', 'unlink'])

/**
 * Per-verb sets of flags whose argument is supplied as a SEPARATE token
 * (e.g. `head -n 5 file`). When we see one of these flags in the token
 * stream, we skip the next token so it is not mistaken for a positional
 * (file) argument. Verbs not listed here use the default "flags are bool"
 * rule, which is correct for the vast majority of short flags.
 */
const FLAGS_WITH_VALUE: Record<string, ReadonlySet<string>> = {
  head: new Set(['-n', '-c']),
  tail: new Set(['-n', '-c', '-q', '--lines', '--bytes']),
  sort: new Set(['-k', '-t', '-o', '--key', '--field-separator', '--output']),
  wc: new Set(['-w', '-l', '-c', '-m', '--words', '--lines', '--bytes', '--chars']),
  cut: new Set(['-f', '-c', '-d', '-b', '-n', '--fields', '--bytes', '--delimiter']),
}

/**
 * Tokenize a shell segment, respecting single/double quotes and backslash
 * escapes (outside single quotes). Returns the verbatim tokens — quote
 * stripping happens during parsing, not here, so we can detect quoted forms.
 */
function tokenize(seg: string): string[] {
  const tokens: string[] = []
  let buf = ''
  let quote: '"' | "'" | null = null
  let escape = false
  for (let i = 0; i < seg.length; i++) {
    const ch = seg[i]
    if (escape) {
      buf += ch
      escape = false
      continue
    }
    if (ch === '\\' && quote !== "'") {
      escape = true
      continue
    }
    if (quote) {
      if (ch === quote) {
        quote = null
        continue
      }
      buf += ch
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === ' ' || ch === '\t' || ch === '\n') {
      if (buf) {
        tokens.push(buf)
        buf = ''
      }
      continue
    }
    buf += ch
  }
  if (buf) tokens.push(buf)
  return tokens
}

function isFlag(tok: string): boolean {
  return tok.length > 1 && tok[0] === '-' && /^[A-Za-z0-9=]/.test(tok.slice(1))
}

function isRedirectOp(tok: string): boolean {
  return tok === '>' || tok === '>>' || tok === '<' || tok === '>&' || tok === '<&' || tok === '>|'
}

/**
 * File-descriptor redirections (`2>&1`, `1>&2`, `&>`, `&>>`, `n<&m`).
 * These redirect one fd to another — they do not name a path and MUST
 * never be classified as one. Without this filter, `cat /etc/passwd
 * 2>&1 | head` would produce a spurious `[{read,/etc/passwd}, {read,2>&1}]`
 * pair.
 */
function isFdRedirectOp(tok: string): boolean {
  // `2>&1`, `1<&2`, `12>&34`, etc. — leading digits, then >& or <&,
  // then more digits. Also `&>` / `&>>` (close-all-and-write forms).
  return /^\d*&>+$/.test(tok) || /^\d*&>>$/.test(tok) || /^\d+[><]&?\d+$/.test(tok) || tok === '&>' || tok === '&>>'
}

/**
 * Filter out flag tokens, redirect operators, AND any tokens that appear
 * after a redirect operator. Returns positional arguments in order.
 *
 * `cat /tmp/b > /tmp/c` -> ['/tmp/b']   (the destination is captured by
 * the redirect loop, so it must not be re-classified as a read here).
 * `echo leaked >> /tmp/leak.txt` -> ['leaked']
 * `head -n 5 file` -> ['file']            (with `verb='head'`, the value
 *                                          following the value-taking flag
 *                                          `-n` is consumed).
 * `rm -rf -- /tmp/foo` -> ['/tmp/foo']    (the `--` end-of-options marker
 *                                          is consumed but never classified
 *                                          as a positional; probe).
 * `cat -- /etc/hosts` -> ['/etc/hosts']   (same).
 */
function positionalArgs(tokens: string[], verb: string): string[] {
  const valueFlags = FLAGS_WITH_VALUE[verb]
  const out: string[] = []
  let afterRedirect = false
  let skipNext = false
  for (const t of tokens) {
    if (skipNext) { skipNext = false; continue }
    if (t === '--') {
      // End-of-options marker. Subsequent tokens are always positionals
      // regardless of shape — but `--` itself is never a path.
      continue
    }
    if (isRedirectOp(t) || isFdRedirectOp(t)) {
      afterRedirect = true
      continue
    }
    if (isFlag(t)) {
      if (valueFlags?.has(t)) skipNext = true
      continue
    }
    if (afterRedirect) continue
    out.push(t)
  }
  return out
}

/**
 * Pull the inline-script body out of `python -c '...'` / `node -e "..."`.
 * Returns undefined if the segment is not in `-c` / `-e` form, or if the
 * script body cannot be located.
 */
function extractInlineScript(seg: string): { script: string; lang: 'python' | 'node' } | undefined {
  const tokens = tokenize(seg)
  if (tokens.length < 3) return undefined
  const head = tokens[0].toLowerCase()
  const lang: 'python' | 'node' | undefined =
    head === 'python' || head === 'python3'
      ? 'python'
      : head === 'node' || head === 'nodejs'
        ? 'node'
        : undefined
  if (!lang) return undefined
  for (let i = 1; i < tokens.length - 1; i++) {
    if (tokens[i] === '-c' || tokens[i] === '-e') {
      return { script: tokens[i + 1] ?? '', lang }
    }
  }
  return undefined
}

function parseInlineScript(script: string, lang: 'python' | 'node'): DerivedFileOp[] {
  const out: DerivedFileOp[] = []
  if (lang === 'python') {
    // open(path, mode) — mode defaults to 'r' (read). Track per-call mode.
    const re = /open\(\s*(['"])([^'"]+)\1\s*(?:,\s*(['"])([^'"]*)\3)?\s*\)/g
    let m: RegExpExecArray | null
    while ((m = re.exec(script)) !== null) {
      const path = m[2]
      const mode = m[4] ?? 'r'
      let op: DerivedFileOpKind = 'read'
      if (/w|a|x|\+/.test(mode)) op = 'write'
      out.push({ op, path, source: 'python' })
    }
    // os.unlink / os.remove / pathlib.Path.unlink
    const delRe = /(?:os\.(?:unlink|remove)|pathlib\.Path\([^)]*\)\.unlink)\(\s*(['"])([^'"]+)\1\s*\)/g
    while ((m = delRe.exec(script)) !== null) {
      out.push({ op: 'delete', path: m[2], source: 'python' })
    }
    // os.chmod / os.chown
    const privRe = /os\.(chmod|chown)\(\s*(['"])([^'"]+)\2\s*,\s*([^)]+)\)/g
    while ((m = privRe.exec(script)) !== null) {
      out.push({ op: 'privilege', path: m[3], mode: m[4], source: 'python' })
    }
  } else {
    // node: fs.X(Sync)?(path[, ...])
    const re = /fs\.(readFile|writeFile|appendFile|unlink|chmod|chown)(Sync)?\s*\(\s*(['"])([^'"]+)\3/g
    let m: RegExpExecArray | null
    while ((m = re.exec(script)) !== null) {
      const verb = m[1]
      const path = m[4]
      let op: DerivedFileOpKind = 'read'
      if (verb === 'writeFile' || verb === 'appendFile') op = 'write'
      else if (verb === 'unlink') op = 'delete'
      else if (verb === 'chmod' || verb === 'chown') op = 'privilege'
      out.push({ op, path, source: 'node' })
    }
  }
  return out
}

function parseShellSegment(seg: string): DerivedFileOp[] {
  const out: DerivedFileOp[] = []
  const tokens = tokenize(seg)
  if (tokens.length === 0) return out

  // Run verb-specific logic FIRST so reads appear before redirect-driven
  // writes in the output (the natural semantic order: source files are
  // consumed before the result is written). Verb logic skips tokens that
  // appear after a redirect operator, so the redirect loop below is the
  // sole writer of the destination path.
  const verb = tokens[0]
  const args = positionalArgs(tokens.slice(1), verb)

  if (READ_VERBS.has(verb)) {
    // cat|head|tail <file> [more files...]
    for (const a of args) out.push({ op: 'read', path: a, source: 'shell' })
  }
  else if (verb === 'awk') {
    // awk ['script'] file [file...]
    // First positional may be a script in single quotes; heuristic: skip if
    // it contains awk operators (no path-like slashes or has '=' patterns).
    // Simple rule: skip the first arg if it doesn't look like a path.
    for (const a of args) {
      if (a.includes('/') || a.startsWith('.') || a.startsWith('/') || a.startsWith('~')) {
        out.push({ op: 'read', path: a, source: 'shell' })
      }
    }
  }
  else if (verb === 'sed') {
    // sed -i 'script' file [file...]
    // Heuristic: the FIRST arg is the sed script; subsequent are files. The
    // `-i` flag distinguishes in-place writes from streaming reads.
    const inPlace = tokens.some((t) => t === '-i' || t.startsWith('-i'))
    let scriptConsumed = false
    for (const a of args) {
      if (!scriptConsumed && !isFlag(a)) {
        scriptConsumed = true
        continue
      }
      out.push({ op: inPlace ? 'write' : 'read', path: a, source: 'shell' })
    }
  }
  else if (WRITE_VERBS.has(verb)) {
    for (const a of args) out.push({ op: 'write', path: a, source: 'shell' })
  }
  else if (verb === 'cp') {
    // cp src dst [more pairs]
    if (args.length >= 2) {
      out.push({ op: 'read', path: args[0], source: 'shell' })
      for (let i = 1; i < args.length; i++) {
        out.push({ op: 'write', path: args[i], source: 'shell' })
      }
    }
  }
  else if (verb === 'mv') {
    // mv src dst — `mv` renames: src is removed (delete), dst is created
    // (write). Classifying src as `read` (the prior behaviour) muddies the
    // audit signal — a `derived_file_ops` of [read, write] suggests a copy
    // when the file actually disappears from its origin. The op list
    // is re-spelled to [delete, write] to reflect the rename semantics; SPL
    // policy continues to fire on the underlying command line, so a
    // self-protection rule against `mv /etc/shadow /tmp/leak.txt` is
    // unaffected.
    if (args.length >= 2) {
      for (let i = 0; i < args.length - 1; i++) {
        out.push({ op: 'delete', path: args[i], source: 'shell' })
      }
      const dst = args[args.length - 1]
      out.push({ op: 'write', path: dst, source: 'shell' })
    }
  }
  else if (verb === 'find') {
    // `find ... -delete` — the find verb itself reads every starting path
    // it descends into (this is its semantics), and `-delete` unlinks each
    // match. The probe showed this was previously silent: the `find` body
    // is treated as opaque. We surface BOTH the read of every starting
    // path AND a delete at the same scope.
    //
    // Note: we walk the raw `tokens` (not positionalArgs) because find's
    // grammar is `[paths...] [predicates...]` — `-delete` is a predicate,
    // not a flag, so positionalArgs' isFlag filter would strip it (its
    // valueFlags lookup for `find` is undefined, so `-delete` was being
    // silently dropped before this branch ran).
    if (tokens.includes('-delete')) {
      // Collect paths: the consecutive tokens AFTER the verb and BEFORE
      // the first predicate (`-foo` or `name=value` form).
      for (let i = 1; i < tokens.length; i++) {
        const t = tokens[i]
        if (t.startsWith('-') || t.includes('=')) break
        out.push({ op: 'read', path: t, source: 'shell' })
        out.push({ op: 'delete', path: t, source: 'shell' })
      }
    }
  }
  else if (verb === 'tar') {
    // `tar -c[z|j]f <archive> <files...>` — archive creation writes the
    // archive AND reads every named source. `tar -x... -f <archive>
    // [-C dir]` — extraction reads the archive AND writes to the
    // destination (or cwd when -C is absent). Without this, the
    // probe surfaced nothing for `tar -czf /tmp/a.tar.gz /etc` even
    // though both halves of the I/O are interesting audit data.
    //
    // Note: we walk the raw `tokens` (not positionalArgs) because tar's
    // grammar combines mode + compressor + `-f` into a single concatenated
    // flag (`-czf`, `-cjf`). positionalArgs strips every `-` token as a
    // bool flag, leaving an empty arg list — so we read the token stream
    // directly here.
    const modeTok = tokens.find((t) => /^-[a-zA-Z]*[cxt]/.test(t)) ?? ''
    const isCreate = /c/.test(modeTok)
    const isExtract = /x/.test(modeTok)
    let archive: string | undefined
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      // `-f` may be standalone (`-f archive`) or concatenated into the
      // mode flag (`-czf`, `-cjf`). The archive path is the next token
      // after whichever form is in use.
      const isFFlag =
        t === '-f' || t === '--file' ||
        // Concatenated `-?f` form (e.g. `-cf`, `-czf`, `-cjf`, `-xf`).
        // Matches `-` followed by zero+ mode letters then `f` at the end
        // — `-czf`, `-cf`, `-xf` all qualify.
        /^-[a-zA-Z]*f$/.test(t)
      if (isFFlag) {
        const next = tokens[i + 1]
        if (next && !/^-/.test(next) && !isFdRedirectOp(next)) {
          archive = next
        }
        break
      }
    }
    if (isCreate) {
      if (archive) out.push({ op: 'write', path: archive, source: 'shell' })
      // Sources to read: every token AFTER the archive, excluding the
      // archive itself.
      for (let i = 1; i < tokens.length; i++) {
        const t = tokens[i]
        if (t === archive) continue
        if (/^-/.test(t)) continue // skip other flags
        // Filter the archive path again (handles --file variants).
        if (archive && t === archive) continue
        out.push({ op: 'read', path: t, source: 'shell' })
      }
    } else if (isExtract) {
      if (archive) out.push({ op: 'read', path: archive, source: 'shell' })
      // `-C dir` selects the extract destination (write target).
      for (let i = 1; i < tokens.length - 1; i++) {
        if (tokens[i] === '-C' || tokens[i] === '--directory') {
          const dir = tokens[i + 1]
          if (dir && !/^-/.test(dir)) {
            out.push({ op: 'write', path: dir, source: 'shell' })
          }
        }
      }
    }
  }
  else if (verb === 'unzip') {
    // `unzip [-opts] <archive> [-d dest] [files...]` — reads the archive,
    // writes to dest (or cwd when absent). Without this the probe
    // surfaced nothing for `unzip -o evil.zip -d /tmp/`.
    //
    // Same walk-the-raw-tokens pattern as `tar`: positionalArgs would
    // strip `-o` etc. as bool flags and lose the archive too. We read
    // tokens directly so the first non-flag token is the archive.
    //
    // unzip has value-taking flags (`-d <dir>`, `-x <exclude>`,
    // `-p <password>`, ...). The naive "first non-flag token is the
    // archive" heuristic breaks when `-d` precedes the archive on the
    // command line (`unzip -d /tmp loot.zip`): without flag-value
    // awareness, `/tmp` was classified as the archive. We list the
    // value-taking unzip flags explicitly so the heuristic stays tight.
    const UNZIP_VALUE_FLAGS = new Set([
      '-d', '--directory',
      '-x', '--exclude',
      '-p', '--password',
      '-P', '--extract-password',
    ])
    const positionals: string[] = []
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i]
      if (UNZIP_VALUE_FLAGS.has(t)) {
        // Skip this flag AND its value — neither is the archive.
        i++
        continue
      }
      if (!/^-/.test(t)) positionals.push(t)
    }
    if (positionals.length >= 1) {
      out.push({ op: 'read', path: positionals[0], source: 'shell' })
    }
    for (let i = 1; i < tokens.length - 1; i++) {
      if (tokens[i] === '-d' || tokens[i] === '--directory') {
        const dir = tokens[i + 1]
        if (dir && !/^-/.test(dir)) {
          out.push({ op: 'write', path: dir, source: 'shell' })
        }
      }
    }
  }
  else if (DELETE_VERBS.has(verb)) {
    for (const a of args) out.push({ op: 'delete', path: a, source: 'shell' })
  }
  else if (verb === 'chmod') {
    // chmod [opts] mode path [path...]
    const mode = args[0]
    for (let i = 1; i < args.length; i++) {
      out.push({ op: 'privilege', path: args[i], mode, source: 'shell' })
    }
  }
  else if (verb === 'chown' || verb === 'chgrp') {
    // chown [opts] user[:group] path [path...]
    // First positional is the ownership spec; rest are paths.
    for (let i = 1; i < args.length; i++) {
      out.push({ op: 'privilege', path: args[i], mode: args[0], source: 'shell' })
    }
  }
  else if (verb === 'dd') {
    // dd if=path of=path [bs=N]
    for (const t of tokens) {
      if (t.startsWith('if=')) {
        out.push({ op: 'read', path: t.slice(3), source: 'shell' })
      } else if (t.startsWith('of=')) {
        out.push({ op: 'write', path: t.slice(3), source: 'shell' })
      }
    }
  }

  // Shell redirects — appended LAST so reads from verb logic appear before
  // redirect-driven writes (the natural source-then-destination order).
  // Runs unconditionally so verbs not explicitly recognized above (e.g.
  // `grep foo > /tmp/x`) still surface their write target.
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]
    if (t.startsWith('>>') || t.startsWith('>')) {
      const rest = t.slice(t.startsWith('>>') ? 2 : 1)
      const path = rest || tokens[i + 1]
      if (path && !isFlag(path)) out.push({ op: 'write', path, source: 'shell' })
    } else if (t.startsWith('<')) {
      const rest = t.slice(1)
      const path = rest || tokens[i + 1]
      if (path && !isFlag(path)) out.push({ op: 'read', path, source: 'shell' })
    }
  }

  return out
}

/**
 * Deduplicate operations while preserving first-occurrence order. Two ops are
 * considered the same when `(op, path)` match. Useful because many commands
 * emit the same op multiple times via different rules (e.g. `rm` and a
 * matching redirect pattern); collapsing these keeps the audit payload tight.
 */
function dedupeAndPreserveOrder(ops: DerivedFileOp[]): DerivedFileOp[] {
  const seen = new Set<string>()
  const out: DerivedFileOp[] = []
  for (const op of ops) {
    const key = `${op.op}:${op.path}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(op)
  }
  return out
}

/**
 * Public entry point. Returns an empty array for any input that does not
 * contain a recognizable file operation. Order reflects the order in which
 * operations appear in the command string.
 *
 * @example
 * parseShellFileOps('cat /etc/passwd | grep root > /tmp/leak.txt')
 * // [
 * //   { op: 'read',    path: '/etc/passwd', source: 'shell' },
 * //   { op: 'write',   path: '/tmp/leak.txt', source: 'shell' },
 * // ]
 *
 * parseShellFileOps('python -c "open(\'/etc/shadow\').read()"')
 * // [{ op: 'read', path: '/etc/shadow', source: 'python' }]
 */
export function parseShellFileOps(command: string): DerivedFileOp[] {
  if (!command || typeof command !== 'string') return []
  // Inline-script fast path: if the command starts with python/node -c/-e,
  // parse the script body as a single block. We deliberately do NOT split on
  // `;` first, because semicolons inside the quoted script (e.g.
  // `python -c "import os; os.unlink('/etc/secret')"`) would shred the
  // script body and the inner os.unlink call would never be seen.
  const inline = extractInlineScript(command)
  if (inline) {
    return dedupeAndPreserveOrder(parseInlineScript(inline.script, inline.lang))
  }
  // Multi-segment shell command. `|` (without `||`) is a pipeline operator;
  // `||`, `&&`, `;` are control operators. We don't try to preserve quotes
  // across splits — each segment is tokenized independently.
  const segments = command.split(/\s*(?:\|\||&&|;|\|)\s*/).filter(s => s.trim().length > 0)
  const out: DerivedFileOp[] = []
  for (const seg of segments) {
    out.push(...parseShellSegment(seg))
  }
  return dedupeAndPreserveOrder(out)
}

/**
 * Decide whether a tool name looks like a shell / interpreter whose args
 * may contain embedded file operations. Conservative: false negatives are
 * preferable to false positives (we miss a derived_file_op rather than
 * attaching garbage to an unrelated event).
 */
export function isShellLikeTool(toolName: string): boolean {
  if (!toolName || typeof toolName !== 'string') return false
  const lower = toolName.toLowerCase().replace(/[_-]/g, '')
  // Short shell interpreters — matched as whole words (the regex enforces
  // word boundaries, so 'push' / 'short' / 'cash' do NOT match).
  //   sh, bash, zsh, fish, dash, ksh, csh, tcsh, ash
  const SHORT_SHELLS = ['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh', 'csh', 'tcsh', 'ash']
  for (const name of SHORT_SHELLS) {
    if (new RegExp(`\\b${name}\\b`).test(lower)) return true
  }
  // Distinctive substrings (long enough that substring match is safe).
  // For compound names like 'run_shell_command' (after _ stripping:
  // 'runshellcommand'), the 'shell' substring is what surfaces it.
  const SUBSTRING_HINTS = [
    'shell',
    'python', 'python3', 'py',
    'node', 'nodejs', 'deno', 'bun',
    'ruby', 'perl', 'php',
    'powershell', 'cmd',
  ]
  for (const hint of SUBSTRING_HINTS) {
    if (lower.includes(hint)) return true
  }
  // Generic exec-like names — exact match to avoid false positives
  // (e.g. a tool literally named 'runtime' should not match).
  if (/^(exec|run|run_command|runcommand|run_code|runcode)$/.test(lower)) return true
  return false
}

/**
 * Pull the command-like string out of a tool's argument bag. Tries the
 * field aliases that RuleMatcher.getFieldValue also tries, so policy
 * matching and post-hoc parsing agree on which field carries the command.
 */
export function extractCommandString(args: Record<string, unknown> | undefined): string | undefined {
  if (!args) return undefined
  const candidates = ['command', 'cmd', 'shell', 'script', 'exec', 'code', 'body', 'content', 'text', 'data']
  for (const key of candidates) {
    const v = args[key]
    if (typeof v === 'string' && v.trim().length > 0) return v
  }
  return undefined
}