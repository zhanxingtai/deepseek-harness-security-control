/**
 * argvDerive — extract the command string the existing SPL rules can match
 * against, from a SubprocessSpawnSpec.
 *
 * Background: the SPL rule matcher ([src/intervention/RuleMatcher.ts](../intervention/RuleMatcher.ts))
 * was written for `tools/pre-execute`, where the model supplies a `command`
 * string (the JSON `arguments.command` for bash). At the subprocess seam we
 * only have `argv` and `executable`. The existing 014/015/016/017/018 rules
 * still fire IF we hand them the right string:
 *
 *   bash: argv[0] in {bash, sh} + argv[1] == '-c' → command is argv[2]
 *   pwsh: argv[0] ends with 'pwsh' + argv contains '-Command' → the value
 *         after -Command is the command (the actual flag value depends on
 *         the harness's ENCODING_PREAMBLE prefix; we strip it)
 *   subagent / LSP / others: no known body shape, fall back to argv.join(' ')
 *
 * This helper is pure and dependency-free. Tests live in
 * tests/argvDerive.test.ts.
 */
import { basename } from 'node:path'

const BASH_BASENAMES = new Set(['bash', 'sh', 'dash', 'ksh', 'zsh', 'busybox'])
const PWSH_BASENAMES = new Set(['pwsh', 'powershell', 'powershell.exe', 'pwsh.exe'])

/** Strip a single trailing NUL/space from a string — defensive against
 *  broken argv layouts on Linux where `ps` reports trailing empties. */
function trimTail(s: string): string {
  let end = s.length
  while (end > 0 && (s[end - 1] === '\0' || s[end - 1] === ' ')) end--
  return s.slice(0, end)
}

/**
 * Derive a single command string from the spec's argv. The returned string
 * is what gets passed to `body` and `params.command` in the
 * InterventionContext — feeding it through the existing `canonicalizeCommand`
 * folder yields the same string the tool layer would see, so SPL rules
 * written against `paramsRegex.command` or `bodyRegex[]` match identically.
 */
export function deriveBodyFromArgv(argv: readonly string[]): string {
  if (!Array.isArray(argv) || argv.length === 0) return ''
  const exe = basename(argv[0] ?? '').toLowerCase()
  // bash / sh: argv[1] must be the literal flag '-c'.
  if (BASH_BASENAMES.has(exe)) {
    for (let i = 1; i < argv.length; i++) {
      if (argv[i] === '-c' || argv[i] === '--command') {
        // -c must have a value. Defensive: a `-c` at the tail (no value)
        // is treated as "no command" — fall through to argv.join so the
        // SPL rules still see the `-c` token as data.
        const value = argv[i + 1]
        if (typeof value === 'string' && value.length > 0) {
          return trimTail(value)
        }
      }
      // `-i` (interactive) followed by `-c cmd` — keep scanning.
    }
    // No `-c` — interactive shell with positional script path; the script
    // path is the most useful "body" we have.
    if (argv.length >= 2 && argv[1] && !argv[1].startsWith('-')) {
      return trimTail(argv[1])
    }
    return argv.join(' ')
  }
  // pwsh: locate '-Command' or '-c' (the short form is ambiguous on pwsh —
  // -c on pwsh means "Command"; bash uses -c as well).
  if (PWSH_BASENAMES.has(exe)) {
    for (let i = 1; i < argv.length; i++) {
      const tok = argv[i]
      if (tok === '-Command' || tok === '-c') {
        // The harness prepends ENCODING_PREAMBLE; we don't know it here,
        // so return the raw value and let canonicalizeCommand handle the
        // tail. Tests cover this.
        return trimTail(argv[i + 1] ?? '')
      }
      if (tok === '-EncodedCommand' || tok === '-e' || tok === '-EC') {
        // Base64 — we don't decode (caller layer doesn't have a policy hook
        // for it), but return a sentinel so dashboards can see the choice.
        return `<encoded:${(argv[i + 1] ?? '').slice(0, 80)}>`
      }
    }
    return argv.join(' ')
  }
  // Unknown executable — join with a single space; preserves token boundaries
  // for paramsRegex.token matching.
  return argv.join(' ')
}

/**
 * Engine-launcher detection — the launcher gate. Returns true
 * when the basename of the executable or argv[0] is one of the known engine
 * launchers. Used by RuntimeHook to flag `risk_flags: ['unpatched_engine']`
 * when argv lacks the `--patch …security-monitor` flag shape.
 */
const ENGINE_LAUNCHER_BASENAMES = new Set([
  'node',
  'nodejs',
  'pnpm',
  'npm',
  'npx',
  'dsh',
  'tsx',
  'ts-node',
])

export function isEngineLauncher(command: string | undefined, argv: readonly string[]): boolean {
  const candidates: string[] = []
  if (typeof command === 'string' && command.length > 0) candidates.push(command)
  if (Array.isArray(argv) && argv.length > 0 && typeof argv[0] === 'string') {
    candidates.push(argv[0])
  }
  for (const c of candidates) {
    const base = basename(c).toLowerCase()
    if (ENGINE_LAUNCHER_BASENAMES.has(base)) return true
  }
  return false
}

/**
 * Look for the patch-flag shape on an argv vector. Used together with
 * `isEngineLauncher`: a launcher with `security-monitor` in argv is a
 * legitimate restart; without it, it's the 015-class attack.
 *
 * Returns true if argv contains `--patch <arg>` where `<arg>` references
 * the security-monitor patch file. Conservative — does NOT match the
 * bare word `security-monitor` anywhere; the file reference must appear
 * on the same argv slot or the next slot.
 */
export function argvMentionsSecurityMonitorPatch(argv: readonly string[]): boolean {
  if (!Array.isArray(argv)) return false
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]
    if (typeof tok !== 'string') continue
    if (/security-monitor\.patch\.ya?ml/i.test(tok)) return true
    if (tok === '--patch' || tok.startsWith('--patch=')) {
      const next = argv[i + 1] ?? ''
      if (typeof next === 'string' && /security-monitor/i.test(next)) return true
    }
  }
  return false
}