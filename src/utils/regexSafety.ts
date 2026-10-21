/**
 * Compile-time ReDoS
 * guard for SPL policy regexes.
 *
 * SPL `paramsRegex` / `bodyRegex` patterns are compiled with
 * `new RegExp(pattern, 'i')` and evaluated synchronously on the tool-call
 * hot path. `decisionTimeoutMs` bounds the rule SCAN, but a synchronous
 * catastrophic-backtracking regex cannot be interrupted by a timer — one
 * pathological pattern freezes the whole harness process for seconds to
 * minutes per matching attempt.
 *
 * The marketplace contract forbids a regex engine with linear-time
 * guarantees (`dependencies: {}` — no RE2 / node-re2), so this module
 * implements a conservative STATIC analyzer instead. It parses the
 * pattern and rejects the two classic exponential-backtracking shapes:
 *
 *   1. Ambiguous repetition boundary — a group under a repeat quantifier
 *      whose iterations can END with characters the next iteration can
 *      START with, e.g. `(a+)+`, `(a\w*)+`, `([\w.]+)+`, `(.*)*`. The
 *      split between iterations is ambiguous, so backtracking explores
 *      exponentially many partitions of the same string.
 *   2. Overlapping or empty alternation under a repeat quantifier, e.g.
 *      `(a|aa)*`, `(a|)*` — the same character can enter the group via
 *      either branch, recreating shape 1 inside the group.
 *
 * Deliberately NOT flagged (the direction that keeps the shipped policy
 * loadable): unambiguous nested quantifiers such as
 * `(?:-[a-zA-Z]+\s+)*` — every iteration starts with `-`, which no
 * iteration can end with, so split points are deterministic.
 * `tests/policyLoaderDefenses.test.ts` pins that the bundled
 * `policies/default-policy.spl.yaml` produces ZERO warnings through this
 * analyzer.
 *
 * This is a lint guard, not a proof: accepted patterns may still be
 * super-linear, and bounded polynomial blowups (e.g. `(a{1,3}){1,3}`)
 * are not flagged. Rejected patterns are skipped at load time with a
 * `warnings[]` entry (fail-loud); every other rule in the policy still
 * compiles and enforces.
 */

/** Character-set approximation used by the overlap checks. */
interface CharSet {
  /** `.` / negated class / backreference — overlaps everything. */
  universal: boolean
  literals: Set<string>
  /** Inclusive single-char code-point ranges. */
  ranges: Array<[string, string]>
  /** `\w` / `\d` / `\s` membership flags. */
  word: boolean
  digit: boolean
  space: boolean
}

interface Quantifier {
  min: number
  /** null = unbounded (`*`, `+`, `{n,}`). */
  max: number | null
}

type Atom =
  | { kind: 'anchor' }
  | { kind: 'char'; ch: string; quant?: Quantifier }
  | { kind: 'class'; set: CharSet; quant?: Quantifier }
  | { kind: 'group'; alternatives: Atom[][]; quant?: Quantifier }

function emptySet(): CharSet {
  return { universal: false, literals: new Set(), ranges: [], word: false, digit: false, space: false }
}

function universalSet(): CharSet {
  return { universal: true, literals: new Set(), ranges: [], word: false, digit: false, space: false }
}

function charSet(ch: string): CharSet {
  const set = emptySet()
  set.literals.add(ch)
  return set
}

function escapeClassSet(escape: string): CharSet {
  // \W / \D / \S are complements — approximate conservatively as universal.
  if (escape === 'W' || escape === 'D' || escape === 'S') return universalSet()
  const set = emptySet()
  if (escape === 'w') set.word = true
  else if (escape === 'd') set.digit = true
  else set.space = true
  return set
}

function unionSets(a: CharSet, b: CharSet): CharSet {
  return {
    universal: a.universal || b.universal,
    literals: new Set([...a.literals, ...b.literals]),
    ranges: [...a.ranges, ...b.ranges],
    word: a.word || b.word,
    digit: a.digit || b.digit,
    space: a.space || b.space,
  }
}

const WORD_CHAR = /[0-9A-Za-z_]/
const DIGIT_CHAR = /[0-9]/
const SPACE_CHAR = /[ \t\n\r\f\v\u00a0]/

function foldCase(ch: string): string {
  const lo = ch.toLowerCase()
  return lo === ch ? ch.toUpperCase() : lo
}

/**
 * Does `ch` (ASCII-case-insensitively, mirroring the engine's `'i'`
 * compile flag) appear in `set`?
 */
function literalInSet(ch: string, set: CharSet): boolean {
  if (set.literals.has(ch) || set.literals.has(foldCase(ch))) return true
  const folded = foldCase(ch)
  for (const [lo, hi] of set.ranges) {
    // Conservative: test the char and its case fold against every range.
    if ((ch >= lo && ch <= hi) || (folded >= lo && folded <= hi)) return true
  }
  if (set.word && WORD_CHAR.test(ch)) return true
  if (set.digit && DIGIT_CHAR.test(ch)) return true
  if (set.space && SPACE_CHAR.test(ch)) return true
  return false
}

/** The concrete code-point ranges behind the `\w` / `\d` / `\s` flags. */
function flagClassRanges(set: CharSet): Array<[string, string]> {
  const out: Array<[string, string]> = []
  if (set.word) out.push(['0', '9'], ['A', 'Z'], ['a', 'z'], ['_', '_'])
  if (set.digit) out.push(['0', '9'])
  // \t \n \v \f \r are contiguous code points 9-13.
  if (set.space) out.push(['\t', '\r'], [' ', ' '], [String.fromCharCode(0xa0), String.fromCharCode(0xa0)])
  return out
}

/**
 * Do two approximate character sets intersect?
 */
function intersects(a: CharSet, b: CharSet): boolean {
  if (a.universal || b.universal) return true
  for (const ch of a.literals) if (literalInSet(ch, b)) return true
  for (const ch of b.literals) if (literalInSet(ch, a)) return true
  for (const [alo, ahi] of a.ranges) {
    for (const [blo, bhi] of b.ranges) {
      if (alo <= bhi && blo <= ahi) return true
    }
  }
  if (a.word && (b.word || b.digit)) return true
  if (b.word && (a.word || a.digit)) return true
  if (a.digit && b.digit) return true
  if (a.space && b.space) return true
  const flagHitsRanges = (flags: CharSet, concrete: CharSet): boolean => {
    if (concrete.ranges.length === 0) return false
    for (const [flo, fhi] of flagClassRanges(flags)) {
      for (const [lo, hi] of concrete.ranges) {
        if (flo <= hi && lo <= fhi) return true
      }
    }
    return false
  }
  return flagHitsRanges(a, b) || flagHitsRanges(b, a)
}

function isVariableQuantifier(q: Quantifier | undefined): boolean {
  if (!q) return false
  return q.max === null || q.max > q.min
}

/** Can this atom consume a variable number of characters? */
function atomIsVariable(atom: Atom): boolean {
  if (atom.kind === 'anchor') return false
  if (isVariableQuantifier(atom.quant)) return true
  if (atom.kind === 'group') {
    return atom.alternatives.some((branch) => branch.some(atomIsVariable))
  }
  return false
}

/** Zero-width anchors aside, could this atom match the empty string? */
function atomCanBeEmpty(atom: Atom): boolean {
  if (atom.kind === 'anchor') return true
  if (atom.quant && atom.quant.min === 0) return true
  if (atom.kind === 'group') {
    return atom.alternatives.some((branch) => branch.every(atomCanBeEmpty))
  }
  return false
}

function groupCanBeEmpty(atom: Atom): boolean {
  return atom.kind === 'group' && atomCanBeEmpty(atom)
}

/** First characters a consuming match of `branch` can start with. */
function firstSetOfBranch(branch: Atom[]): CharSet {
  let acc = emptySet()
  for (const atom of branch) {
    if (atom.kind === 'anchor') continue
    acc = unionSets(acc, firstSetOfAtom(atom))
    if (!(atom.quant && atom.quant.min === 0) && !groupCanBeEmpty(atom)) break
  }
  return acc
}

/** Characters an iteration of `branch` can end with (tail-propagating). */
function endSetOfBranch(branch: Atom[]): CharSet {
  let acc = emptySet()
  for (let i = branch.length - 1; i >= 0; i--) {
    const atom = branch[i]
    if (atom.kind === 'anchor') continue
    if (atom.kind === 'char') acc = unionSets(acc, charSet(atom.ch))
    else acc = unionSets(acc, firstSetOfAtom(atom))
    if (!(atom.quant && atom.quant.min === 0) && !groupCanBeEmpty(atom)) break
  }
  return acc
}

function firstSetOfAtom(atom: Atom): CharSet {
  if (atom.kind === 'char') return charSet(atom.ch)
  if (atom.kind === 'class') return atom.set
  if (atom.kind === 'anchor') return emptySet()
  let acc = emptySet()
  for (const branch of atom.alternatives) {
    acc = unionSets(acc, firstSetOfBranch(branch))
  }
  return acc
}

const QUANTIFIER_RE = /^\{(\d+)(?:,(\d*)?)?\}/

function readQuantifier(src: string, pos: number): { q: Quantifier; len: number } | null {
  const c = src[pos]
  if (c === '*') return { q: { min: 0, max: null }, len: 1 }
  if (c === '+') return { q: { min: 1, max: null }, len: 1 }
  if (c === '?') return { q: { min: 0, max: 1 }, len: 1 }
  if (c !== '{') return null
  const m = QUANTIFIER_RE.exec(src.slice(pos, pos + 32))
  if (!m) return null
  const min = Number.parseInt(m[1], 10)
  const max = m[2] === undefined ? min : m[3] === '' || m[3] === undefined ? null : Number.parseInt(m[3], 10)
  return { q: { min, max }, len: m[0].length }
}

/**
 * Lenient regex-pattern parser. Returns the top-level alternation, or
 * `null` when the pattern is malformed (the caller lets `new RegExp`
 * produce the authoritative compile error in that case). Never throws.
 */
class PatternParser {
  private pos = 0

  constructor(private readonly src: string) {}

  parse(): Atom[][] | null {
    const alts = this.parseAlternation(0)
    if (alts === null || this.pos < this.src.length) return null
    return alts
  }

  private parseAlternation(depth: number): Atom[][] | null {
    const alts: Atom[][] = [[]]
    while (this.pos < this.src.length) {
      const c = this.src[this.pos]
      if (c === ')') {
        if (depth === 0) return null // unbalanced — malformed
        break
      }
      if (c === '|') {
        this.pos++
        alts.push([])
        continue
      }
      const atom = this.parseAtom(depth)
      if (atom === null) return null
      alts[alts.length - 1].push(atom)
    }
    return alts
  }

  private parseAtom(depth: number): Atom | null {
    const c = this.src[this.pos]
    if (c === '\\') {
      this.pos++
      const e = this.src[this.pos]
      if (e === undefined) return null
      this.pos++
      if (e === 'w' || e === 'W' || e === 'd' || e === 'D' || e === 's' || e === 'S') {
        const atom: Atom = { kind: 'class', set: escapeClassSet(e) }
        this.attachQuantifier(atom)
        return atom
      }
      if (e === 'b' || e === 'B' || e === 'A' || e === 'z' || e === 'Z') {
        return { kind: 'anchor' }
      }
      if (e === 'k') {
        // Backreference — conservatively a consuming atom over all chars.
        if (this.src[this.pos] === '<') {
          while (this.pos < this.src.length && this.src[this.pos] !== '>') this.pos++
          if (this.pos >= this.src.length) return null
          this.pos++
        }
        const atom: Atom = { kind: 'class', set: universalSet() }
        this.attachQuantifier(atom)
        return atom
      }
      const atom: Atom = { kind: 'char', ch: e }
      this.attachQuantifier(atom)
      return atom
    }
    if (c === '[') {
      const set = this.parseClass()
      if (set === null) return null
      const atom: Atom = { kind: 'class', set }
      this.attachQuantifier(atom)
      return atom
    }
    if (c === '.') {
      this.pos++
      const atom: Atom = { kind: 'class', set: universalSet() }
      this.attachQuantifier(atom)
      return atom
    }
    if (c === '^' || c === '$') {
      this.pos++
      return { kind: 'anchor' }
    }
    if (c === '(') {
      this.pos++
      if (this.src[this.pos] === '?') {
        const n = this.src[this.pos + 1]
        if (n === '=' || n === '!' || (n === '<' && (this.src[this.pos + 2] === '=' || this.src[this.pos + 2] === '!'))) {
          // Lookahead / lookbehind — zero-width; contents cannot be
          // backtracked across the boundary this analyzer models.
          this.skipGroupBody()
          return { kind: 'anchor' }
        }
        if (n === ':') {
          this.pos += 2
        } else if (n === '<') {
          // Named group `(?<name>...)` — consume the name.
          this.pos += 2
          while (this.pos < this.src.length && this.src[this.pos] !== '>') this.pos++
          if (this.pos >= this.src.length) return null
          this.pos++
        } else {
          return null // unknown group prefix — malformed, let RegExp report
        }
      }
      const alts = this.parseAlternation(depth + 1)
      if (alts === null || this.src[this.pos] !== ')') return null
      this.pos++
      const atom: Atom = { kind: 'group', alternatives: alts }
      this.attachQuantifier(atom)
      return atom
    }
    if (c === undefined) return null
    // Ordinary character. A stray quantifier at atom-start position is a
    // regex error in JS ("Nothing to repeat") — surface it as a char here
    // and let `new RegExp` produce the compile warning.
    this.pos++
    const atom: Atom = { kind: 'char', ch: c }
    this.attachQuantifier(atom)
    return atom
  }

  private attachQuantifier(atom: Atom & { quant?: Quantifier }): void {
    const read = readQuantifier(this.src, this.pos)
    if (!read) return
    atom.quant = read.q
    this.pos += read.len
    // Lazy marker (`*?`, `+?`, `{n,m}?`) — semantics only, ignore.
    if (this.src[this.pos] === '?') this.pos++
  }

  private parseClass(): CharSet | null {
    // this.pos sits on '['.
    this.pos++
    let negated = false
    if (this.src[this.pos] === '^') {
      negated = true
      this.pos++
    }
    const set = emptySet()
    let pending: string | null = null
    const flush = (): void => {
      if (pending !== null) {
        set.literals.add(pending)
        pending = null
      }
    }
    let first = true
    while (this.pos < this.src.length) {
      let ch = this.src[this.pos]
      if (ch === ']' && !first) {
        this.pos++
        flush()
        return negated ? universalSet() : set
      }
      first = false
      if (ch === '\\') {
        this.pos++
        const e = this.src[this.pos]
        if (e === undefined) return null
        this.pos++
        if (e === 'w' || e === 'W' || e === 'd' || e === 'D' || e === 's' || e === 'S') {
          flush()
          const inner = escapeClassSet(e)
          set.literals = new Set([...set.literals, ...inner.literals])
          set.ranges = [...set.ranges, ...inner.ranges]
          set.word = set.word || inner.word
          set.digit = set.digit || inner.digit
          set.space = set.space || inner.space
          set.universal = set.universal || inner.universal
          continue
        }
        ch = e
      }
      // Range: `pending` is the range start, current char is '-', and a
      // real char follows (not the closing bracket).
      if (ch === '-' && pending !== null) {
        let next = this.src[this.pos + 1]
        if (next === undefined) return null
        let endChar = next
        if (next === '\\') {
          endChar = this.src[this.pos + 2] ?? ''
          if (endChar === '') return null
          this.pos += 2
        } else {
          this.pos += 1
        }
        if (endChar !== ']') {
          set.ranges.push([pending, endChar])
          pending = null
          this.pos++
          continue
        }
        // `-` before `]` is a literal dash.
      }
      flush()
      pending = ch
      this.pos++
    }
    return null // unterminated class
  }

  private skipGroupBody(): void {
    // Consume until the matching ')', respecting nesting, classes and
    // escapes. this.pos sits just after the group prefix.
    let depth = 1
    let inClass = false
    while (this.pos < this.src.length) {
      const ch = this.src[this.pos]
      if (ch === '\\') {
        this.pos += 2
        continue
      }
      if (inClass) {
        if (ch === ']') inClass = false
        this.pos++
        continue
      }
      if (ch === '[') {
        inClass = true
        this.pos++
        continue
      }
      if (ch === '(') depth++
      else if (ch === ')') {
        depth--
        if (depth === 0) {
          this.pos++
          return
        }
      }
      this.pos++
    }
  }
}

/** A repeat quantifier that can revisit the group body enough times to blow up. */
function hasDangerousRepeatQuantifier(atom: Atom & { quant?: Quantifier }): boolean {
  const q = atom.quant
  if (!q) return false
  if (q.max === null) return true // * + {n,}
  return q.max > q.min && q.max > 1 // {n,m} with m>n≥…, plus {0,2}+
}

function analyzeAlternation(alts: Atom[][], report: (reason: string) => void): void {
  for (const branch of alts) {
    for (const atom of branch) {
      if (atom.kind !== 'group') continue
      // Recurse first: nested groups are checked standalone as well.
      analyzeAlternation(atom.alternatives, report)
      checkRepeatedGroup(atom, report)
    }
  }
}

function checkRepeatedGroup(atom: Atom & { kind: 'group' }, report: (reason: string) => void): void {
  if (!hasDangerousRepeatQuantifier(atom)) return
  const alts = atom.alternatives

  // Shape 2: overlapping / empty alternation under a repeat quantifier.
  const firsts = alts.map(firstSetOfBranch)
  for (let i = 0; i < alts.length; i++) {
    if (alts[i].every(atomCanBeEmpty)) {
      report('an alternative matches the empty string under a repeat quantifier')
      return
    }
    for (let j = i + 1; j < alts.length; j++) {
      if (intersects(firsts[i], firsts[j])) {
        report('alternation branches can start with the same characters under a repeat quantifier')
        return
      }
    }
  }

  // Shape 1: ambiguous repetition boundary. Only variable-length
  // iterations can split a string at more than one position; fixed-length
  // iterations (even of single chars, e.g. `(x|y)*`) are unambiguous.
  let start = emptySet()
  for (const first of firsts) start = unionSets(start, first)
  for (const branch of alts) {
    if (!branch.some(atomIsVariable)) continue
    const end = endSetOfBranch(branch)
    if (intersects(end, start)) {
      report(
        'an iteration can end with characters the next iteration can start with ' +
          '(ambiguous repetition boundary) — catastrophic backtracking risk',
      )
      return
    }
  }
}

/**
 * Statically detect regex patterns with catastrophic-backtracking risk.
 * Returns a human-readable reason string when the pattern is rejected,
 * or `null` when it is accepted. Never throws — malformed patterns
 * return `null` so the real `new RegExp` compile error can surface.
 */
export function detectUnsafeRegexPattern(pattern: string): string | null {
  if (typeof pattern !== 'string' || pattern.length === 0) return null
  let alts: Atom[][] | null = null
  try {
    alts = new PatternParser(pattern).parse()
  } catch {
    return null // analyzer bug guard — fail open here; the compile step still validates
  }
  if (alts === null) return null
  let finding: string | null = null
  analyzeAlternation(alts, (reason) => {
    if (finding === null) finding = reason
  })
  return finding
}
