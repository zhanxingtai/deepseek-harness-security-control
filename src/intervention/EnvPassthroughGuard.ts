/**
 * Inline Env-Passthrough Guard.
 *
 * Hardcoded, non-overridable safety net: blocks tool calls and forks that
 * attempt to propagate a known-dangerous environment variable into a child
 * process via `params.env` / `spec.env`. Coverage:
 *
 *   - `LD_PRELOAD`        — `glibc` `dlopen()` hook: attacker loads a `.so`
 *                           into every spawned process; bypass of every
 *                           userland-side defense. Mitigation: the only safe
 *                           value is empty / unset. A non-empty value is
 *                           treated as a hijack.
 *   - `LD_LIBRARY_PATH`   — search-path override for `dlopen()`. Combined
 *                           with `LD_PRELOAD`, can shadow system libraries.
 *   - `NODE_OPTIONS`      — `node` CLI flag passthrough, including
 *                           `--require <script>` (process-startup code
 *                           injection) and `--inspect` (debugger attach).
 *   - `PYTHONPATH`        — `python`/`python3` module search-path override;
 *                           same effect as `NODE_OPTIONS` for Python-hosted
 *                           tooling.
 *   - `PYTHONSTARTUP`     — `python` startup file (executed on every REPL
 *                           start); smaller surface than `PYTHONPATH` but
 *                           same root cause (code injection via env).
 *   - `NODE_PATH`         — `node` module resolution override; analogous
 *                           to `PYTHONPATH` for the Node ecosystem.
 *   - `BASH_ENV`          — `bash` startup file (sourced on every non-
 *                           interactive `bash` invocation when set);
 *                           shell-startup code injection.
 *   - `ENV`               — POSIX `sh` / `ksh` startup file (sourced on
 *                           interactive shell start); same root cause as
 *                           `BASH_ENV` for the sh family.
 *   - `BASH_FUNC_*`       — bash exported-function channel
 *                           (`BASH_FUNC_cmd%%='() { evil; }'` is honoured
 *                           by every descendant bash and silently overrides
 *                           the command lookup); covered as a PREFIX match
 *                           because the suffix is the function name.
 *   - `SSH_AUTH_SOCK`     — SSH agent forwarding socket; a fork that
 *                           inherits `SSH_AUTH_SOCK` can drive the
 *                           operator's ssh-agent and use stored identities.
 *   - `PROMPT_COMMAND`    — bash pre-prompt hook (executed before every
 *                           interactive prompt); code-injection vector for
 *                           any subsequent interactive shell.
 *
 * Mirrors the InlineSelfProtection / SensitivePathGuard / InlinePromptInjection
 * pattern: deny-list is hardcoded and non-overridable — `keys: []` in
 * `normalizeConfig` is silently re-asserted to the marketplace fallback list.
 * `evaluateEnvPassthroughGuard()` is invoked synchronously from
 * `ApplicationCollector.evaluateTool` and `RuntimeHook.runEval`, BEFORE the
 * inline self-protection check, BEFORE SPL. Returns a `block` SecurityDecision
 * on first hit; the caller short-circuits the SPL pipeline.
 *
 * Field scope:
 *   - `params.env` (Record<string, unknown>) — the structured env payload
 *     that RuntimeHook lifts from `SubprocessSpawnSpec.env` and that any
 *     model-facing tool layer surfaces via `exec.arguments.env`.
 *   - Case-insensitive key match (Linux env-var convention is UPPER_CASE
 *     but the kernel is case-sensitive; we follow sibling inline guards'
 *     case-insensitive stance so a `ld_preload` lowercase spelling still
 *     trips the rail).
 *
 * What this guard deliberately does NOT do:
 *   - Body-text scan for `LD_PRELOAD=evil.so cmd` shell assignments. The
 *     existing SELF_PROTECTION_* rules + SPL body regex already cover that
 *     surface; layering another substring scan here would duplicate work
 *     and inflate false-positive risk.
 *   - Value-content inspection. A non-empty `LD_PRELOAD=/usr/lib64/libgomp.so`
 *     is just as much of a hijack as `LD_PRELOAD=/tmp/evil.so`; we treat
 *     any non-empty value as a block, on the principle that the legitimate
 *     state is empty/unset.
 */

import type { InterventionContext, SecurityDecision } from '../types/index.js'
import { buildInlineGuardDecision } from '../utils/inlineGuardDecision.js'

/**
 * Hardcoded deny-list — non-overridable. The keys are matched
 * case-insensitively against `params.env`.
 *
 * Order is preserved for the audit `matched_key` field — the wire
 * payload reports the FIRST key that hits, in catalogue order.
 */
export const DEFAULT_DANGEROUS_ENV_KEYS: readonly string[] = [
  // --- dlopen / module-resolution hijack ---
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'NODE_OPTIONS',
  'PYTHONPATH',
  'PYTHONSTARTUP',
  'NODE_PATH',
  // --- shell startup-file / function hijack ---
  'BASH_ENV',
  'ENV',
  'PROMPT_COMMAND',
  'SSH_AUTH_SOCK',
]

/**
 * Prefix-matched entries. Kept separate from the exact-match catalogue
 * because the suffix is attacker-chosen (e.g. `BASH_FUNC_cmd%%`); the
 * comparator treats these as `envKey.toUpperCase().startsWith(prefix)`
 * after the exact-match scan fails. Adding a new prefix here does NOT
 * shift the audit order of the exact-match keys.
 *
 * `BASH_FUNC_` is the bash exported-function channel; bash exports a
 * function `cmd` as `BASH_FUNC_cmd%%` and descendants auto-import it,
 * silently overriding command resolution. There is no legitimate use
 * of this variable in tool/fork env payloads.
 */
export const DEFAULT_DANGEROUS_ENV_PREFIXES: readonly string[] = [
  'BASH_FUNC_',
]

/** Block code for the inline env-passthrough guard. Distinct from the
 *  SPL `SELF_PROTECTION_*` codes and the existing inline
 *  `INLINE_SELF_PROTECTION_*` / `INLINE_SENSITIVE_PATH_001` /
 *  `INLINE_PROMPT_INJECTION_001` codes so audit consumers can filter
 *  on the deny reason without colliding with sibling rules. */
export const INLINE_ENV_PASSTHROUGH_CODE = 'INLINE_ENV_PASSTHROUGH_001' as const

export interface EnvPassthroughGuardConfig {
  /** Master switch — defaults to true. The marketplace rejects
   *  `enabled: false` in `normalizeConfig` (mirrors sibling guards). */
  enabled: boolean
  /** Operator-added env-var keys. Empty array → fallback to
   *  `DEFAULT_DANGEROUS_ENV_KEYS` (the safety net cannot be downgraded
   *  to an empty list — same pattern as
   *  `SensitivePathGuardConfig.paths` and
   *  `InlinePromptInjectionConfig.patterns`). */
  keys: string[]
}

interface EnvHit {
  /** The exact env-var key as it appeared in the carrier (preserves case
   *  for the audit trail). */
  readonly key: string
  /** The associated value. Truncated in the audit message but kept full
   *  in the decision `audit_details` field. */
  readonly value: string
  /** Provenance: which params field the env came from. Always
   *  `'params.env'` in the current integration — the field is lifted
   *  from `SubprocessSpawnSpec.env` by `RuntimeHook.buildContext` and
   *  arrives at the tool layer via `exec.arguments.env`. */
  readonly field: string
}

/**
 * Case-insensitive lookup: normalise both the env key and the catalogue
 * pattern to UPPER, then exact-match against `patterns` and prefix-match
 * against `prefixes`. Exact matches take precedence over prefix matches
 * — `BASH_ENV` (exact) wins over a hypothetical `BASH_*` prefix. The
 * original `key` is preserved on the returned hit so the audit event
 * reports what the attacker actually typed.
 */
function findEnvHit(
  env: Record<string, unknown>,
  patterns: readonly string[],
  prefixes: readonly string[],
  field: string,
): EnvHit | null {
  const patternUpper = new Set<string>()
  for (const p of patterns) patternUpper.add(p.toUpperCase())
  const prefixUpper: string[] = prefixes.map((p) => p.toUpperCase())
  for (const [k, v] of Object.entries(env)) {
    const kUpper = k.toUpperCase()
    if (patternUpper.has(kUpper)) {
      return {
        key: k,
        value: typeof v === 'string' ? v : v == null ? '' : String(v),
        field,
      }
    }
    for (const prefix of prefixUpper) {
      if (kUpper.startsWith(prefix)) {
        return {
          key: k,
          value: typeof v === 'string' ? v : v == null ? '' : String(v),
          field,
        }
      }
    }
  }
  return null
}

function truncateValue(v: string, max = 80): string {
  if (v.length <= max) return v
  return v.slice(0, max) + '…'
}

function buildEnvPassthroughBlock(hit: EnvHit): SecurityDecision {
  const reason =
    '高危环境变量透传命中：键 `' + hit.key + '` 的值 `' + truncateValue(hit.value) +
    '` 试图通过 `' + hit.field + '` 注入子进程。该键属于内嵌环境变量黑名单（不可被策略文件改写关闭）'
  // delegate to the shared
  // `buildInlineGuardDecision` so all four inline guards produce the
  // same decision shape. The local helper preserves the
  // `buildEnvPassthroughBlock(hit)` call signature.
  return buildInlineGuardDecision(
    {
      policyId: 'inline-env-passthrough-guard',
      policyName: 'Inline Env-Passthrough Guard (hardcoded, non-overridable)',
      blockCode: INLINE_ENV_PASSTHROUGH_CODE,
    },
    reason,
  )
}

/**
 * Evaluate the inline env-passthrough guard against the supplied context.
 * Returns a `block` SecurityDecision on first match, or `null` when no
 * deny-list pattern matched (the caller falls through to the inline
 * self-protection / SPL pipeline).
 *
 * The function is synchronous and never throws — a malformed context
 * (params not an object, env not an object, etc.) is treated as "no match".
 */
export function evaluateEnvPassthroughGuard(
  ctx: InterventionContext,
  cfg: EnvPassthroughGuardConfig,
): SecurityDecision | null {
  if (!cfg.enabled) return null
  try {
    const patterns = cfg.keys.length > 0 ? cfg.keys : DEFAULT_DANGEROUS_ENV_KEYS
    if (patterns.length === 0) return null

    // params.env — the only field the current integration surfaces. The
    // RuntimeHook path lifts `SubprocessSpawnSpec.env` into `params.env`
    // via `buildContext`; the tool layer mirrors the same shape so a
    // single comparator covers both surfaces.
    const params = (ctx.params && typeof ctx.params === 'object')
      ? ctx.params as Record<string, unknown>
      : undefined
    if (!params) return null
    const env = params.env
    if (!env || typeof env !== 'object' || Array.isArray(env)) return null

    const hit = findEnvHit(
      env as Record<string, unknown>,
      patterns,
      DEFAULT_DANGEROUS_ENV_PREFIXES,
      'params.env',
    )
    if (!hit) return null
    return buildEnvPassthroughBlock(hit)
  } catch {
    // Defensive — inline module failure must never block all tool calls.
    return null
  }
}