/**
 * Sensitive-path deny-list + plugin-owned `fs.watch` (Stage 3 §6.2).
 *
 * Hardcoded, non-overridable safety net: agents / sub-shells cannot read or
 * write a list of well-known credential / secret / system files regardless of
 * what the SPL policy file says. Mirrors the InlineSelfProtection pattern
 * (3 hardcoded rules at L1) — adding a sensitive-path rule here costs nothing
 * at runtime but ensures the rail cannot be silently disabled by tampering
 * with `policies/default-policy.spl.yaml`.
 *
 * Two surfaces:
 *
 *  - **Deny-list (`evaluateSensitivePathGuard`)** — invoked synchronously
 *    from `ApplicationCollector.evaluateTool` and `RuntimeHook.runEval`,
 *    BEFORE the inline self-protection check, BEFORE SPL. Matches any
 *    path-shaped field in `params` (path aliases) and any path-looking
 *    token inside command / body strings. Returns a `block` SecurityDecision
 *    on first hit; the caller short-circuits the SPL pipeline.
 *
 *  - **Watcher (`SensitivePathWatcher`)** — plugin-owned `fs.watch` on the
 *    directories backing the deny-list. Captures external mutations that
 *    bypass the harness's `fs/observed` event (third-party tool effects,
 *    direct `cat` / shell redirection, kernel-mediated reads). Emits a
 *    `security_audit` event per change for observability; it does NOT
 *    block — the wire-level action on `security_audit` is `allow` (audit-only).
 *
 * Path normalisation helpers (`expandHome`, `stripTrailingSlash`,
 * `resolveSymlink`) and the small glob subset (`*` = single segment) are
 * kept in this file because both surfaces consume them.
 */

import { existsSync, realpathSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import type { InterventionContext, SecurityDecision } from '../types/index.js'
import { expandHome } from '../utils/expandHome.js'
import { homeDir } from '../utils/expandHome.js'
import { escapeRegex } from '../utils/escapeRegex.js'
import { buildInlineGuardDecision } from '../utils/inlineGuardDecision.js'
import { normalizeForScan } from './InlinePromptInjection.js'

/**
 * Hardcoded deny-list — non-overridable. Includes SSH private/public keys,
 * AWS / GPG / Docker credential files, well-known system files (`/etc/shadow`,
 * `/etc/sudoers*`), cloud-metadata service, package-manager state, and
 * per-process environ.
 *
 * Patterns accepted:
 *   - Literal path:  `/etc/shadow`, `~/.aws/credentials`
 *   - Directory:     `~/.ssh/`, `~/.aws/` (matches any file under the dir)
 *   - Single-segment glob: `/proc/PID/environ`, `/var/lib/dpkg/info/NAME`
 *     (the single-segment wildcard is replaced with `[^/]+` at compile time)
 *
 * Rationale per family:
 *   - `~/.ssh/...`      : private keys, authorized_keys, known_hosts, config
 *   - `~/.aws/...`      : long-lived IAM credentials, config, SSO cache
 *   - `~/.gnupg/`       : GPG private keyring
 *   - `~/.docker/config.json` : registry credentials
 *   - `~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`
 *                         : VCS / package manager credential caches
 *   - `/etc/shadow`, `/etc/sudoers*`, `/etc/gshadow`
 *                         : system credential / authorization databases
 *   - `/proc/PID/environ` : another process's environment (may contain secrets
 *                           injected via --setenv or runtime vars)
 *   - `/var/lib/dpkg/info/...` : package install scripts (executed as root
 *                         via dpkg postinst hooks; a known lateral movement
 *                         vector when the agent has write access)
 *   - `169.254.169.254/...` : cloud-instance metadata service (AWS / GCP /
 *                         Azure — credential / instance-role exposure)
 */
export const DEFAULT_SENSITIVE_PATHS: readonly string[] = [
  // SSH
  '~/.ssh/',
  '~/.ssh/id_rsa',
  '~/.ssh/id_ed25519',
  '~/.ssh/id_ecdsa',
  '~/.ssh/id_dsa',
  '~/.ssh/authorized_keys',
  '~/.ssh/known_hosts',
  '~/.ssh/config',
  // Cloud / dev credentials
  '~/.aws/',
  '~/.aws/credentials',
  '~/.aws/config',
  '~/.gnupg/',
  '~/.docker/config.json',
  // C : Kubernetes / GCP / Azure dev credentials
  // (these were the highest-ROI gaps that an operator
  // discovering the deny-list would immediately expect to find. ~/.kube
  // holds the service-account bearer token used for cluster admin;
  // ~/.gcloud/* holds application_default_credentials.json + legacy
  // gcloud legacy-credentials; ~/.azure holds az login tokens.)
  '~/.kube/',
  '~/.kube/config',
  '~/.gcloud/',
  '~/.gcloud/application_default_credentials.json',
  '~/.gcloud/legacy_credentials/',
  '~/.gcloud/properties',
  '~/.azure/',
  '~/.azure/accessTokens.json',
  '~/.azure/azureProfile.json',
  // VCS / package manager credential caches
  '~/.git-credentials',
  '~/.netrc',
  '~/.npmrc',
  '~/.pypirc',
  // System credential databases
  '/etc/shadow',
  '/etc/sudoers',
  '/etc/sudoers.d/',
  '/etc/gshadow',
  // Process environment + package manager state
  '/proc/*/environ',
  '/var/lib/dpkg/info/*',
  // Cloud metadata service (IPv4 link-local)
  '169.254.169.254/',
  '169.254.169.254/latest/meta-data/',
]

/** Block code for the inline sensitive-path guard. Distinct from the
 *  SPL `SELF_PROTECTION_*` codes and the existing inline
 *  `INLINE_SELF_PROTECTION_001/014/015` codes so audit consumers can
 *  filter on the deny reason without colliding with sibling rules. */
export const INLINE_SENSITIVE_PATH_CODE = 'INLINE_SENSITIVE_PATH_001' as const

/**
 * Path aliases for the `params` lookup — mirrors `RuleMatcher.FIELD_ALIASES`
 * (`path | file_path | file | src | source | target | destination | dest | destination_path`).
 * Body aliases (`content | text | data`) and command aliases
 * (`command | cmd | shell | script | exec`) are handled separately because
 * they receive a substring scan rather than a literal-path equality check.
 */
const PATH_FIELD_ALIASES = [
  'path',
  'file_path',
  'file',
  'src',
  'source',
  'target',
  'destination',
  'dest',
  'destination_path',
] as const

const COMMAND_FIELD_ALIASES = ['command', 'cmd', 'shell', 'script', 'exec'] as const
const BODY_FIELD_ALIASES = ['content', 'text', 'data'] as const

export interface SensitivePathGuardConfig {
  /** Master switch — defaults to true. The marketplace rejects
   *  `enabled: false` in `normalizeConfig` (mirrors inlineGuards). */
  enabled: boolean
  /** Operator-added patterns. Empty array → fallback to
   *  `DEFAULT_SENSITIVE_PATHS` (the safety net cannot be downgraded
   *  to an empty list — the same pattern as `inlineGuards.engineLaunchers`). */
  paths: string[]
  /** Master switch for the fs.watch watcher (observability only). */
  watchEnabled: boolean
  /** Per-directory debounce window for change events. Default 500 ms. */
  watchDebounceMs: number
}

// ---------------------------------------------------------------------------
// Path normalisation
// ---------------------------------------------------------------------------

/** Strip a single trailing `/` (but not `//` or root `/`). */
export function stripTrailingSlash(p: string): string {
  if (p.length > 1 && p.endsWith('/')) return p.slice(0, -1)
  return p
}

/**
 * `fs.realpathSync` wrapped in try/catch. ENOENT / EACCES / ENOTDIR all
 * surface as the input path — the caller treats a non-existent path as
 * "no match possible" downstream, which is the right behaviour for an
 * attacker probing non-existent paths.
 */
export function resolveSymlink(p: string): string {
  try {
    return realpathSync(p)
  } catch {
    return p
  }
}

// ---------------------------------------------------------------------------
// Glob compilation (small subset: literal segments + `*` single-segment wildcard)
// ---------------------------------------------------------------------------

interface CompiledPathPattern {
  /** Original source pattern. */
  readonly source: string
  /** Whether this is a directory-prefix match (no trailing filename). */
  readonly directoryPrefix: boolean
  /**
   * Pattern kind for audit-side observability:
   *   - `'literal'`: no wildcard segments (default deny-list majority)
   *   - `'single_glob'`: contains a `*` single-segment wildcard
   *   - `'multi_glob'`: contains a `**` multi-segment wildcard — broader
   *     reach than literal, so audit consumers may want to flag it
   *     distinctly in the security_audit trail
   */
  readonly kind: 'literal' | 'single_glob' | 'multi_glob'
  /** Pre-compiled matcher function. Returns true if `target` matches the pattern. */
  readonly matches: (target: string) => boolean
}

/** Both the compiled regexes and the match
 *  target are separator-normalized to '/' before comparison. On
 *  Windows, `expandHome`/`realpathSync` produce backslash paths while
 *  the shipped deny-list uses '/', so a Windows path such as
 *  `E:/Users/alice/.ssh/id_rsa` never matched the `~/.ssh/id_rsa`
 *  pattern (the guard silently passed symlink-aliased credential
 *  reads). Identity on POSIX so Linux/mac matching is byte-unchanged
 *  (a backslash is a legal filename character there and must keep
 *  matching literally). */
const toMatchPath = (p: string): string =>
  process.platform === 'win32' ? p.split('\\').join('/') : p

function compilePattern(raw: string): CompiledPathPattern | null {
  const expanded = expandHome(raw)
  // (multi-user): `~/...` deny-list patterns should
  // match any user's home directory, not just the current user. We
  // compile a primary regex against `$HOME` plus secondary regexes
  // for `/root/` (Linux canonical) and `/home/<user>/` (any-user
  // placeholder). The matcher's `matches()` tests the candidate
  // against ALL compiled regexes for the same source — OR-semantics.
  const homeVariants = homeVariantsFor(raw, expanded)
  if (homeVariants.length === 0) return null
  const primary = toMatchPath(homeVariants[0]!)
  const directoryPrefix = primary.endsWith('/')
  // Determine glob kind from the primary variant. Each variant must
  // share the same segment shape (only the leading home-root differs).
  const stripped = stripTrailingSlash(primary)
  if (!stripped) return null
  const segments = stripped.split('/')
  if (segments[0] === '') {
    segments.shift()
  }
  let hasMulti = false
  let hasSingle = false
  for (const seg of segments) {
    if (seg === '') return null
    if (seg === '**') hasMulti = true
    else if (seg === '*') hasSingle = true
  }
  const kind: CompiledPathPattern['kind'] = hasMulti
    ? 'multi_glob'
    : hasSingle
      ? 'single_glob'
      : 'literal'
  const regexes = homeVariants.map((variant) => {
    const variantSegments = stripTrailingSlash(toMatchPath(variant)).split('/')
    let variantPrefix = ''
    if (variantSegments[0] === '') {
      variantSegments.shift()
      variantPrefix = '/'
    }
    return new RegExp(
      '^' +
        variantPrefix +
        variantSegments
          .map((seg) => {
            if (seg === '**') return '.+'
            if (seg === '*') return '[^/]+'
            return escapeRegex(seg)
          })
          .join('/') +
        (directoryPrefix ? '(?:/.*)?' : '') +
        '$',
    )
  })
  return {
    source: raw,
    directoryPrefix,
    kind,
    matches: (target: string): boolean => {
      const t = toMatchPath(stripTrailingSlash(expandHome(target)))
      return regexes.some((re) => re.test(t))
    },
  }
}

/**
 * (multi-user): generate the canonical home-root
 * prefixes that a `~/...` deny-list pattern should match against. The
 * primary entry uses `$HOME` (current user); secondary entries cover
 * the conventions for other-user homes on the platform:
 *   - Linux: `/root/<rest>` (root canonical) and `/home/<user>/<rest>`
 *   - macOS: `/Users/<user>/<rest>`
 * For absolute / cloud-metadata paths (no leading `~`), a single-entry
 * list with the expanded form is returned.
 *
 * The `<user>` literal on both sides of the match line up: the
 * compiled regex contains the literal token `<user>`, and the candidate
 * expansion (`expandUserHome`) emits the same literal token. This lets
 * a `~/.ssh/` pattern match `${HOME}/.ssh/...`, `/root/.ssh/...`, and
 * `/home/<user>/.ssh/...` candidates with a single source entry.
 */
/**
 * `$HOME`-rooted prefixes for `<rest>`, in both the verbatim and realpath'd
 * form.
 *
 * Candidate paths are realpath'd before matching, but `$HOME` was used
 * verbatim. On macOS the default HOME sits under `/var` → `/private/var`, so
 * the deny-list side kept `/var/...` while the candidate side had already
 * become `/private/var/...` — the two never lined up, and a symlink pointing
 * at `~/.ssh/id_rsa` passed the guard untouched. Emitting both forms closes
 * that gap.
 *
 * Additive on purpose: for a deny-list an extra variant can only block more,
 * never fewer. Since `resolveSymlink(home)` is the same directory reached by
 * a longer route, every path it adds was already logically under `$HOME`.
 */
function homeRestVariants(rest: string): string[] {
  const home = homeDir()
  const out = [`${home}/${rest}`]
  const real = resolveSymlink(home)
  if (real !== home) out.push(`${real}/${rest}`)
  return out
}

function homeVariantsFor(raw: string, expanded: string): string[] {
  if (!raw.startsWith('~')) return [expanded]
  // Bare `~` or `~/...` (current user): primary + secondary variants
  // for `/root/` and `/home/<user>/` / `/Users/<user>/`.
  if (raw === '~' || raw.startsWith('~/') || raw.startsWith('~\\')) {
    const slash = raw.indexOf('/')
    const rest = raw.slice(slash + 1) // strip leading `/`; '' for bare `~`
    if (!rest) return [expanded]
    const variants: string[] = homeRestVariants(rest)
    if (process.platform === 'darwin') {
      variants.push(`/Users/<user>/${rest}`)
    } else {
      variants.push(`/home/<user>/${rest}`)
      variants.push(`/root/${rest}`)
    }
    return variants
  }
  // `~user/...`: primary is `${HOME}/...` (current user), secondary
  // variants add the per-user + canonical-root shapes.
  const slash = raw.indexOf('/')
  const user = raw.slice(1, slash)
  const rest = raw.slice(slash + 1)
  if (!user || user === '~') return [expanded]
  const variants: string[] = homeRestVariants(rest)
  if (process.platform === 'darwin') {
    variants.push(`/Users/<user>/${rest}`)
  } else {
    variants.push(`/home/<user>/${rest}`)
    if (user === 'root') variants.push(`/root/${rest}`)
  }
  return variants
}

// ---------------------------------------------------------------------------
// Candidate extraction
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Candidate extraction
// ---------------------------------------------------------------------------

interface PathCandidate {
  /** Origin: which field the candidate was lifted from. */
  readonly field: string
  /** Resolved path string. Empty when the candidate is a bare command
   *  line (no path-shaped token could be lifted). */
  readonly value: string
}

function collectCandidates(ctx: InterventionContext): PathCandidate[] {
  const out: PathCandidate[] = []
  const params = (ctx.params && typeof ctx.params === 'object') ? ctx.params as Record<string, unknown> : {}
  for (const key of PATH_FIELD_ALIASES) {
    const v = params[key]
    if (typeof v === 'string' && v.length > 0) {
      out.push({ field: key, value: v })
    }
  }
  // Command / body / content substrings: pull every token that looks like
  // an absolute path or starts with `~`. We don't try to parse shell —
  // a literal-path substring is enough to catch `cat ~/.ssh/id_rsa`,
  // `python -c "open('/etc/shadow')"`, and write bodies that embed paths.
  for (const key of COMMAND_FIELD_ALIASES) {
    const v = params[key]
    if (typeof v === 'string' && v.length > 0) {
      collectPathTokens(v, `params.${key}`, out)
    }
  }
  if (typeof ctx.body === 'string' && ctx.body.length > 0) {
    collectPathTokens(ctx.body, 'body', out)
  }
  for (const key of BODY_FIELD_ALIASES) {
    const v = params[key]
    if (typeof v === 'string' && v.length > 0) {
      collectPathTokens(v, `params.${key}`, out)
    }
  }
  // argv-based extraction (RuntimeHook path): each argv entry may itself
  // be a path. The argv is most relevant when it's a `bash -c "cmd"` pair,
  // in which case the command body is already covered above via the
  // body / command alias; we still scan argv for direct paths like
  // `/etc/shadow` passed as a literal argument to a binary.
  if (Array.isArray(ctx.params?.['argv'])) {
    const argv = ctx.params['argv'] as unknown[]
    for (const entry of argv) {
      if (typeof entry === 'string' && entry.length > 0) {
        collectPathTokens(entry, 'argv', out)
      }
    }
  }
  return out
}

// Path-shaped tokens — matches:
// `~/foo/bar` (current-user home: also `~user/foo/bar` —
//     `~alice/.ssh/id_rsa` is the multi-user-system bypass; the deny-list
//     under `~` should not be bypassable just by switching to a different
//     username)
//   - `/etc/shadow` (absolute)
//   - `169.254.169.254/...` (IPv4 link-local cloud metadata)
// the previous `~/` regex did not match `~user/`
// forms, so `cat ~root/.ssh/id_rsa` / `cat ~alice/.aws/credentials`
// bypassed the deny-list on multi-user hosts. The `expandHome` helper
// leaves `~user/` as-is on purpose (it only knows about `$HOME`); the
// candidate collection now also accepts `~user/...` and `findHit`
// resolves it via `expandUserHome` to a per-user absolute path before
// testing against the compiled deny-list (which has been re-expanded
// for the same user).
const PATH_TOKEN_RE = /(~[A-Za-z0-9._\-+]*\/[A-Za-z0-9._\-+/]+|\/[A-Za-z0-9._\-+/]+|(?:\d{1,3}\.){3}\d{1,3}\/[A-Za-z0-9._\-+/]*)/g

/**
 * resolve `~user/path` to a canonical absolute path on the host.
 * On Linux the convention is `/home/<user>`; macOS uses `/Users/<user>`;
 * `~root` is conventionally `/root`, but is also a common alias for the
 * current user's HOME on systems where `HOME=/root` (CI containers,
 * bare-metal root, marketplace sandbox).
 *
 * Returns a list of expanded candidates — callers test each one against
 * the deny-list. The list includes:
 *   - the platform-canonical form (Linux: `/home/<user>/`, macOS:
 *     `/Users/<user>/`, root: `/root/`)
 *   - the `${HOME}/<rest>` form (covers systems where the current user
 *     IS the named user, e.g. `~root/...` on a CI container with
 *     `HOME=/root`)
 *   - a `<user>`-placeholder form (lines up with the corresponding
 *     deny-list pattern variant — the compiled regex carries the
 *     literal `<user>` token, so the candidate expansion must too)
 *
 * The function is best-effort and never throws; a malformed input
 * returns the original string as a single-element list.
 */
function expandUserHome(p: string): string[] {
  const out: string[] = []
  if (!p || typeof p !== 'string' || !p.startsWith('~')) return [p]
  const slash = p.indexOf('/')
  // Bare `~` or `~/...` → use the platform HOME (delegates to `expandHome`).
  if (slash === 1) {
    out.push(expandHome(p))
    return out
  }
  if (slash < 0) return [p] // bare `~` or `~user` without trailing path
  const user = p.slice(1, slash)
  if (!user || user === '~') {
    out.push(expandHome(p))
    return out
  }
  // Convention map; /etc/passwd lookup is intentionally avoided to keep
  // the guard free of side effects (it must remain safe to call in
  // tests + contexts where /etc/passwd may not exist).
  //
  // Order matters for `findHit` / `block_reason` :
  // put `${HOME}` expansion FIRST so the audit `resolved` field records
  // the canonical, operator-readable form (`/home/operator/.ssh/...`)
  // rather than the `<user>` placeholder. The `<user>` placeholder is
  // still kept later in the list — the deny-list pattern compilation
  // uses the same placeholder, so we need the candidate side to carry
  // a matching form for cross-user deny-list matching to fire.
  const rest = p.slice(slash)
  // `${HOME}/<rest>` — covers `~root/...` on systems where the
  // current user IS root (HOME=/root) AND on every system where
  // `~<self>/...` should resolve to the user's own home. Listed
  // first so `findHit` prefers the canonical HOME expansion for
  // the audit trail.
  out.push(`${homeDir()}${rest}`)
  if (process.platform === 'darwin') {
    out.push(`/Users/${user}${rest}`)
    out.push(`/Users/<user>${rest}`)
  } else {
    out.push(`/home/${user}${rest}`)
    out.push(`/home/<user>${rest}`)
    if (user === 'root') out.push(`/root${rest}`)
  }
  return out
}

function collectPathTokens(text: string, field: string, out: PathCandidate[]): void {
  const re = new RegExp(PATH_TOKEN_RE.source, 'g')
  let match: RegExpExecArray | null
  while ((match = re.exec(text)) !== null) {
    out.push({ field, value: match[1] })
  }
}

/**
 * (rev): wraps the InlinePromptInjection
 * `normalizeForScan` (NFKC + zero-width/RTL strip) with an additional
 * pass that collapses runs of `/` to a single `/`. The NFKC pass turns
 * a full-width slash `／` (U+FF0F) into `/`, so an attacker payload of
 * `~/／.ssh/id_rsa` arrives at this guard as `~//.ssh/id_rsa`. Without
 * collapse, the compiled `~/.ssh/` regex (anchored on `${HOME}/.ssh/`)
 * would not match the doubled `/`. Collapsing `//+` → `/` lets the
 * canonical path reach the deny-list.
 *
 * The function never throws (the underlying `normalizeForScan` has a
 * try/catch fallback); a non-string input returns the empty string.
 */
function normalizePathForScan(text: string): string {
  const base = normalizeForScan(text)
  // Collapse `//+` → `/`. Leading `//` (UNC-style paths on Windows) is
  // not relevant here — this guard is path-shaped against POSIX trees.
  return base.replace(/\/{2,}/g, '/')
}

// ---------------------------------------------------------------------------
// Match entry point
// ---------------------------------------------------------------------------

interface MatchHit {
  readonly pattern: string
  readonly candidate: PathCandidate
  readonly resolved: string
  /**
   * Pattern kind propagated from `CompiledPathPattern` so the audit
   * trail can distinguish literal matches (the deny-list majority)
   * from single-glob and multi-glob matches. :
   * a `**`-glob match fires with `pattern_kind: 'multi_glob'` on the
   * resulting `audit_details` so audit consumers can grep for broader
   * reach even when the matched path itself is innocuous.
   */
  readonly patternKind: 'literal' | 'single_glob' | 'multi_glob'
}

/**
 * Walk the candidates and return the first match against the compiled
 * patterns, OR null if no pattern matches. Symlink resolution is applied
 * to the candidate value before testing so an attacker who links
 * `/tmp/innocent -> ~/.ssh/id_rsa` cannot bypass the deny-list.
 *
 * `~user/...` candidates (e.g. `~alice/.ssh/id_rsa`)
 * are now expanded via `expandUserHome` to `/home/alice/.ssh/id_rsa`
 * before the deny-list comparison — previously `~user/` was treated as
 * a literal string and slipped past `~/.ssh/`.
 *
 * NFKC-normalisation + zero-width/RTL strip is
 * applied to the candidate value before matching, so an attacker can't
 * bypass the path regex with full-width slashes (`／`), zero-width
 * characters (`U+200B`), or RTL overrides. Mirrors the
 * `normalizeForScan` helper used by InlinePromptInjection.
 */
function findHit(candidates: PathCandidate[], patterns: CompiledPathPattern[]): MatchHit | null {
  for (const cand of candidates) {
    // NFKC + strip + collapse double-slashes first. The
    // `normalizePathForScan` helper never throws (unpaired-surrogate
    // fallback to raw text). Empty input is returned as '' by the
    // helper, which `expandHome` / `expandUserHome` pass through
    // untouched — no false-positive on empty candidates.
    const normalized = normalizePathForScan(cand.value)
    const expandedHome = expandHome(normalized)
    const userHomeVariants = expandUserHome(normalized)
    // (multi-user): `expandUserHome` may yield multiple candidates
    // (e.g. `~root/...` → both `$HOME/...` and `/root/...`); test each
    // one against the deny-list so a `~/.ssh/` pattern compiled against
    // the current HOME matches regardless of which user-home it maps to.
    // Prefer canonical absolute variants for the audit `resolved` field
    // (operator-readable + stable for post-hoc correlation) — the
    // original `~`-bearing form stays on `candidate.value`.
    const allVariants: string[] = [expandedHome, ...userHomeVariants]
    // (symlink bypass): append the resolved (realpath)
    // variants AFTER the literal variants so symlink-aliasing bypasses
    // are caught — e.g. an attacker linking `/tmp/innocent ->
    // ~/.ssh/id_rsa` previously slipped through because the literal
    // candidate name did not match the deny-list. `resolveSymlink` is
    // a no-op on ENOENT/EACCES/ENOTDIR, so non-symlinked paths are
    // unchanged. Literal variants stay FIRST so the existing
    // audit-`resolved` semantics for the "sensitive path IS a symlink
    // to innocuous target" case remain stable (the literal match
    // fires, `resolved` carries the input rather than the realpath).
    const seen = new Set<string>(allVariants)
    for (const v of allVariants) {
      if (!v) continue
      const r = resolveSymlink(v)
      if (r && r !== v && !seen.has(r)) {
        seen.add(r)
        allVariants.push(r)
      }
    }
    for (const pat of patterns) {
      // Pick the first matching variant. Prefer absolute-path variants
      // over the bare `~`-bearing form so the audit trail records a
      // canonical path (operators read `/home/alice/.ssh/id_rsa`, not
      // `~alice/.ssh/id_rsa`).
      for (const v of allVariants) {
        if (!v.startsWith('~') && pat.matches(v)) {
          return {
            pattern: pat.source,
            candidate: cand,
            resolved: v,
            patternKind: pat.kind,
          }
        }
      }
      // Fallback: if only the bare `~`-form matched (e.g. an exact
      // `~/...` candidate against a `~/...` pattern with no other
      // expansion), record the canonical `${HOME}` form on `resolved`
      // for readability. The bare form is preserved on `candidate.value`.
      if (expandedHome !== normalized && pat.matches(expandedHome)) {
        const resolved = resolveSymlink(expandedHome) || expandedHome
        return {
          pattern: pat.source,
          candidate: cand,
          resolved,
          patternKind: pat.kind,
        }
      }
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// Block decision factory
// ---------------------------------------------------------------------------

function buildSensitivePathBlock(matchedPattern: string, hit: MatchHit): SecurityDecision {
  const reason =
    '访问敏感路径 `' + hit.resolved + '`（命中规则 `' + matchedPattern + '`，来源字段 `' +
    hit.candidate.field + '`）已被内嵌敏感路径守卫阻断（不可被策略文件改写关闭）'
  // delegate to the shared
  // `buildInlineGuardDecision` so all four inline guards produce the
  // same decision shape.
  //
  // extend the runtime extension fields with
  // audit metadata so the security_audit trail records WHICH deny-list
  // pattern fired AND its reach class. Literal hits carry the matched
  // path verbatim; glob hits (single-segment `*` / multi-segment `**`)
  // carry `pattern_kind` so audit consumers can flag broader-reach
  // matches distinctly. The trailing `risk_flags` lets the consumer
  // correlate with `LoopedToolDetector` / `TokenUsageDetector` style
  // semantics.
  const base = buildInlineGuardDecision(
    {
      policyId: 'inline-sensitive-path-guard',
      policyName: 'Inline Sensitive-Path Guard (hardcoded, non-overridable)',
      blockCode: INLINE_SENSITIVE_PATH_CODE,
    },
    reason,
  )
  const extended = base as unknown as SecurityDecision & {
    audit_details?: Record<string, unknown>
    risk_flags?: string[]
  }
  // sample_excerpt: 240 chars of the candidate value (capped). This
  // matches the InlinePromptInjection convention so audit consumers
  // can present a uniform excerpt regardless of which inline guard
  // fired.
  const sampleExcerpt =
    hit.candidate.value.length > 240
      ? hit.candidate.value.slice(0, 240) + '...'
      : hit.candidate.value
  extended.audit_details = {
    matched_pattern: matchedPattern,
    fingerprint_kind: `path:${hit.patternKind}`,
    sample_excerpt: sampleExcerpt,
    field_source: hit.candidate.field,
    pattern_description:
      `inline sensitive-path guard matched \`${matchedPattern}\` (pattern_kind=\`${hit.patternKind}\`) ` +
      `on field \`${hit.candidate.field}\` → resolved \`${hit.resolved}\``,
    // runtime extras (not part of the strict Intervention.audit_details
    // schema; preserved on the top-level SecurityDecision via the
    // `as unknown as` cast above so audit consumers can grep for
    // broader-reach matches).
    resolved_path: hit.resolved,
    pattern_kind: hit.patternKind,
    raw_value: hit.candidate.value,
  }
  extended.risk_flags = ['sensitive_path_access']
  return extended
}

// ---------------------------------------------------------------------------
// Public entry point — mirrors `evaluateInlineSelfProtection` signature
// ---------------------------------------------------------------------------

/**
 * Evaluate the inline sensitive-path guard against the supplied context.
 * Returns a `block` SecurityDecision on first match, or `null` when no
 * deny-list pattern matched (the caller falls through to the inline
 * self-protection / SPL pipeline).
 *
 * The function is synchronous and never throws — a malformed context
 * (params not an object, body not a string, etc.) is treated as "no match".
 */
export function evaluateSensitivePathGuard(
  ctx: InterventionContext,
  cfg: SensitivePathGuardConfig,
): SecurityDecision | null {
  if (!cfg.enabled) return null
  try {
    const patterns: CompiledPathPattern[] = []
    for (const p of cfg.paths) {
      const compiled = compilePattern(p)
      if (compiled) patterns.push(compiled)
    }
    if (patterns.length === 0) return null
    const candidates = collectCandidates(ctx)
    if (candidates.length === 0) return null
    const hit = findHit(candidates, patterns)
    if (!hit) return null
    return buildSensitivePathBlock(hit.pattern, hit)
  } catch {
    // Defensive — inline module failure must never block all tool calls.
    return null
  }
}

// ---------------------------------------------------------------------------
// Watcher directory helpers — exported so SensitivePathWatcher can reuse
// the same expand-home / strip-trailing-slash logic without duplicating.
// ---------------------------------------------------------------------------

/**
 * Return the unique set of directories backing `paths`. Each pattern is
 * mapped to the deepest existing ancestor so `fs.watch` always has a
 * real directory to attach to (we cannot watch `/proc/<pid>/environ`
 * itself because pid changes constantly; instead we watch `/proc` and
 * note that the event came from that glob family).
 *
 * Patterns that do not match any existing directory (e.g. `~/.aws/` on
 * a fresh host) are returned with `exists: false` so the caller can log
 * a `sensitive_path_watcher_skip` and continue.
 */
export interface WatchedDirectory {
  /** The original deny-list pattern that produced this directory. */
  readonly pattern: string
  /** The directory path to pass to `fs.watch`. */
  readonly directory: string
  /** Whether the directory currently exists on the filesystem. */
  readonly exists: boolean
}

export function listWatchedDirectories(paths: readonly string[]): WatchedDirectory[] {
  const seen = new Set<string>()
  const out: WatchedDirectory[] = []
  for (const raw of paths) {
    const expanded = expandHome(raw)
    const stripped = stripTrailingSlash(expanded)
    if (!stripped || !isAbsolute(stripped)) continue
    // For globbed patterns (containing `*`) we walk up to the deepest
    // ancestor that is itself a literal absolute path; that's what
    // `fs.watch` attaches to.
    const dir = stripped.includes('*') ? parentOfFirstGlob(stripped) : stripped
    if (seen.has(dir)) continue
    seen.add(dir)
    out.push({ pattern: raw, directory: dir, exists: existsSync(dir) })
  }
  return out
}

function parentOfFirstGlob(p: string): string {
  const parts = p.split('/')
  for (let i = parts.length - 1; i >= 0; i--) {
    if (parts[i]!.includes('*')) {
      // Walk up one segment beyond the glob-bearing component.
      const head = parts.slice(0, i).join('/')
      return head || '/'
    }
  }
  return p
}

/** Join two path segments without producing a doubled separator. */
export function safeJoin(parent: string, child: string): string {
  if (child.startsWith('/')) return child
  return join(parent, child)
}
