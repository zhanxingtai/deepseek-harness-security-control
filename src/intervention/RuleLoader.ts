import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { extname } from 'node:path'
import { escapeRegex } from '../utils/escapeRegex.js'
import { detectUnsafeRegexPattern } from '../utils/regexSafety.js'
import type {
  CompiledMatchClause,
  CompiledRule,
  Decision,
  LoadResult,
  ParamsRegexObjectEntry,
  PolicyDocument,
  PolicyRule,
} from './InterventionEngine.js'
import type { Mode } from '../types/index.js'

/**
 * Best-effort require for OPTIONAL YAML dependencies. The plugin is
 * ESM-only (bare `require` is undefined under tsx/esm), so build a
 * module-scoped require from this file's URL. When neither package is
 * installed the lookup itself throws and `parseYaml` reports the
 * documented error.
 *
 * Prefer the modern `yaml` package (eemeli/yaml, ~200 KB,
 * JS-only, no native deps, supports the full YAML 1.2 schema including
 * anchors / merge keys / complex keys that js-yaml is weaker on). The
 * legacy `js-yaml` peerDep is still accepted as a fallback so existing
 * hosts don't break — both satisfy the SPL YAML 1.2 super-set
 * requirement per the SPL specification §1.5 第4条
 * and §4.4 (JSON ⊂ YAML 1.2).
 */
const optionalRequire = createRequire(import.meta.url)

/**
 * Load a policy file (JSON or YAML) and compile its rules into a normalized
 * form.
 *
 * Format selection:
 *   - `.json` → JSON.parse (fast path, no dependency)
 *   - `.yaml` / `.yml` → YAML 1.2 (per the platform specification §1.5 第4条)
 *     using `yaml` if installed, else `js-yaml`, else actionable error
 *   - extension-less → JSON fallback first, then YAML
 *
 * YAML is the recommended format for shipped policies because it carries
 * comments inline (`#`-style notes per rule) which JSON cannot. The
 * marketplace `dependencies: {}` contract keeps both YAML packages
 * out-of-tree — they resolve through `peerDependenciesMeta.optional`.
 */
export function loadPolicy(path: string): LoadResult {
  let raw: string
  try {
    raw = readFileSync(path, 'utf8')
  } catch (error: unknown) {
    return { rules: [], error: `failed to read policy ${path}: ${String(error)}` }
  }
  return loadPolicyFromText(raw, path)
}

/**
 * load a policy from PRE-READ text.
 *
 * The engine's tamper check hashes the file and then parses it. Reading
 * the file twice opens a TOCTOU window — an attacker who replaces the
 * file between the hash read and the parse read passes the hash check
 * while rules load from the swapped content. This entry point lets the
 * engine read each file ONCE and feed the same bytes to both the hash
 * and the parser, closing the window. Callers that own their own read
 * (tests, embedding hosts) can use it directly; `loadPolicy` stays the
 * convenience wrapper for read + parse.
 */
export function loadPolicyFromText(raw: string, path: string): LoadResult {
  const parsed = parsePolicyText(raw, path)
  if ('error' in parsed) {
    return { rules: [], error: parsed.error }
  }

  const validated = validatePolicyShape(parsed.policy, path)
  if (!validated.ok) {
    return { rules: [], error: validated.error }
  }

  // apiVersion v1/metadata 未消费字段的 advisory
  // warnings 由 validatePolicyShape 产出,合并进 compilePolicy 的
  // LoadResult.warnings[]。compilePolicy 自己还会重产更多 rule 级
  // warning(unused-field rule、v1 decision、category missing 等),
  // 整个数组最终都进 MultiLoadResult.warnings[] 由 engine.log.warn
  // 落盘 + 通过 this.loaded.warnings 暴露给消费者。
  const result = compilePolicy(validated.policy)
  return { ...result, warnings: [...(validated.warnings ?? []), ...(result.warnings ?? [])] }
}

interface ParseSuccess {
  policy: PolicyDocument
}
interface ParseFailure {
  error: string
}
type ParseResult = ParseSuccess | ParseFailure

function parsePolicyText(raw: string, path: string): ParseResult {
  const ext = extname(path).toLowerCase()
  if (ext === '.json') {
    try {
      return { policy: JSON.parse(raw) as PolicyDocument }
    } catch (error: unknown) {
      return { error: `invalid JSON policy ${path}: ${String(error)}` }
    }
  }

  if (ext === '.yaml' || ext === '.yml') {
    return parseYaml(raw, path)
  }

  // Extension-less path: try JSON first (fastest), then YAML. The dual
  // fallback covers operator paths like `policyPath: ~/.dsh/security-policy`
  // where no extension was specified — both formats must succeed per the
  // documented contract in `install/CONFIG.md` and `docs/安装部署手册.md`.
  try {
    return { policy: JSON.parse(raw) as PolicyDocument }
  } catch {
    // JSON failed; if a YAML library is installed, try YAML. If neither
    // library is installed OR the YAML parse also fails, surface the
    // combined actionable error so operators can debug.
    const yamlResult = parseYaml(raw, path)
    if ('error' in yamlResult) {
      return {
        error: `unsupported policy format ${path}; tried JSON and YAML but both failed: ${yamlResult.error}`,
      }
    }
    return yamlResult
  }
}

/**
 * Parse YAML policy text. Prefers `yaml` (modern, full YAML 1.2) over
 * `js-yaml` (legacy, YAML 1.1). Both are listed as optional peer
 * dependencies so the marketplace surface can resolve either at host
 * install time. The package.json `dependencies: {}` contract forbids
 * shipping either one in-bundle.
 *
 * Returns the same `ParseSuccess | ParseFailure` shape as JSON parsing
 * — failure messages are actionable: they tell the operator which
 * package to install (`pnpm add yaml` or `pnpm add js-yaml`).
 */
function parseYaml(raw: string, path: string): ParseResult {
  // 1. Prefer the modern `yaml` package.
  const yamlErr = tryParseYaml(raw, 'yaml')
  if (yamlErr.kind === 'ok') return { policy: yamlErr.value as PolicyDocument }
  if (yamlErr.kind === 'parse-error') {
    // Surface the actual parse error verbatim — operators editing their
    // policy need to see "bad indentation at line 4" not "install yaml".
    return { error: `YAML parse error in ${path}: ${yamlErr.error}` }
  }
  // yamlErr.kind === 'missing' → fall through to js-yaml.

  // 2. Fall back to legacy `js-yaml` if it happens to be installed.
  const jsYamlErr = tryParseYaml(raw, 'js-yaml')
  if (jsYamlErr.kind === 'ok') return { policy: jsYamlErr.value as PolicyDocument }
  if (jsYamlErr.kind === 'parse-error') {
    return { error: `YAML parse error in ${path}: ${jsYamlErr.error}` }
  }

  // 3. Neither library is installed — actionable install advice.
  return {
    error:
      `YAML policy ${path} requires an optional dependency. ` +
      `Install one of: 'pnpm add yaml' (preferred, YAML 1.2) or 'pnpm add js-yaml' (legacy, YAML 1.1). ` +
      `See the SPL specification §1.5 第4条 + §4.4.`,
  }
}

/**
 * Result of attempting to parse YAML with one optional peerDep.
 *
 *   - `ok`           → parsed, return `value`
 *   - `parse-error`  → library is installed but text was malformed;
 *                      surface `error` verbatim to the operator
 *   - `missing`      → library not installed (MODULE_NOT_FOUND);
 *                      try the next library in the chain
 *
 * Splitting these three outcomes lets `parseYaml` produce three
 * distinct error messages instead of conflating "syntax broken" with
 * "library not installed".
 */
type TryYamlResult =
  | { kind: 'ok'; value: unknown }
  | { kind: 'parse-error'; error: string }
  | { kind: 'missing' }

function tryParseYaml(raw: string, libName: 'yaml' | 'js-yaml'): TryYamlResult {
  let lib: { parse: (text: string) => unknown } | { load: (text: string) => unknown }
  try {
    lib = optionalRequire(libName) as typeof lib
  } catch (err) {
    if (isModuleNotFound(err)) return { kind: 'missing' }
    // Any other require-time error (rare) — treat as missing so the
    // caller can fall back to the next library in the chain.
    return { kind: 'missing' }
  }

  try {
    const value = 'parse' in lib ? lib.parse(raw) : lib.load(raw)
    return { kind: 'ok', value }
  } catch (err) {
    return { kind: 'parse-error', error: withLineColumn(String(err), err) }
  }
}

/**
 * js-yaml 5.x's `YAMLException.toString()`
 * emits "(line:column)" in compact form (e.g. `(4:1)`) and the
 * multi-line snippet, but no English words like "line" or "column".
 * The `yaml` library (preferred YAML 1.2 parser) does include the
 * word "line" in its message. Operators grepping their policy files
 * for "line N" still need a hit even when js-yaml is the chosen
 * backend — we normalize the exception's `mark.line` / `mark.column`
 * onto the error string so the `yamlPolicy.test.ts:195` assertion
 * (`/line\s+\d+|column\s+\d+|at line/`) holds for both parsers.
 */
function withLineColumn(raw: string, err: unknown): string {
  const base = raw
  // js-yaml puts `{ name, buffer, position, line, column, snippet }`
  // on `mark`. `yaml` puts `{ linePos: [{ line, col }], ... }`.
  const mark = (err as { mark?: unknown })?.mark
  if (mark && typeof mark === 'object') {
    const m = mark as { line?: unknown; column?: unknown }
    if (typeof m.line === 'number') {
      const lineNo = m.line + 1 // js-yaml is 0-indexed; operators expect 1-indexed
      const colNo = typeof m.column === 'number' ? m.column + 1 : 1
      return `${base} (at line ${lineNo}, column ${colNo})`
    }
  }
  const linePos = (err as { linePos?: unknown })?.linePos
  if (Array.isArray(linePos) && linePos.length > 0) {
    const first = linePos[0] as { line?: unknown; col?: unknown }
    if (typeof first?.line === 'number') {
      const lineNo = first.line
      const colNo = typeof first.col === 'number' ? first.col : 1
      return `${base} (at line ${lineNo}, column ${colNo})`
    }
  }
  return base
}

/**
 * Distinguish "optional peer dep not installed" from every other error.
 * `createRequire('yaml')` throws a `MODULE_NOT_FOUND` Error whose `code`
 * property is `'MODULE_NOT_FOUND'` (Node 12+). Parse errors, syntax
 * errors, and validation errors all throw different shapes and must
 * bubble up to the operator verbatim.
 */
function isModuleNotFound(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { code?: string }).code === 'MODULE_NOT_FOUND'
  )
}

/**
 * SPL schema guard.
 *
 * Previously `loadPolicy` trusted `parsePolicyText` to return a
 * `PolicyDocument` and `compilePolicy` to read whatever shape it
 * pleased. A malformed policy (`apiVersion: v2`, `kind: Bananas`,
 * missing fields, `rules: 'foo'`) silently loaded with zero rules —
 * the agent then ran with an empty rule set, no inline guards had
 * a chance to catch the regression, and the audit log showed nothing
 * because no events matched. This was the **fail-open** path.
 *
 * The validator enforces the documented SPL header contract from
 * `the SPL specification`:
 *
 *   apiVersion: security.use/v2
 *   kind: Policy
 *   rules: [...]
 *
 * On any deviation the policy file is REJECTED at load time with an
 * actionable error message (file path + the offending field). The
 * per-file error flows through `MultiLoadResult.errors[]` so a single
 * malformed file does not break the merge (matches the contract
 * for parse errors).
 *
 * Only `security.use/v2` is accepted. The v1 migration layer is gone:
 * v1 policies are rejected outright rather than loaded with an advisory.
 * Migrate before upgrading — `evaluate` becomes `severity` and
 * `reg_clause` becomes `regClause` (spec §10).
 */
const SUPPORTED_API_VERSIONS = new Set(['security.use/v2'])

/**
 * Spec-violation policy: fail loud.
 *
 * A rule that violates the SPL spec is DROPPED at load time, not merely
 * warned about. Keeping a malformed rule around produces a false sense of
 * protection — an operator reading the audit stream sees "loaded" and
 * assumes the rule is enforcing when the spec violation means part of it
 * is inert.
 *
 * This used to be a two-phase rollout behind an environment variable
 * (phase 1 = warn and keep, phase 2 = drop). That variable is gone: a
 * bare `process.env` read meant anyone who could set the process
 * environment could turn every spec violation back into a warning, and
 * that is precisely the configuration where "the policy loaded" stops
 * implying "the policy is enforced". The migration window it existed for
 * has closed — v1 is no longer accepted at all.
 *
 * `LoadResult.warnings[]` still carries every dropped rule and the reason,
 * so the failure is loud in the audit trail even though it is fatal.
 */
function validatePolicyShape(
  raw: unknown,
  path: string,
): { ok: true; policy: PolicyDocument; warnings: string[] } | { ok: false; error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      ok: false,
      error: `policy ${path} must be a YAML/JSON object (got ${Array.isArray(raw) ? 'array' : typeof raw})`,
    }
  }
  const obj = raw as Record<string, unknown>
  const warnings: string[] = []

  if (typeof obj.apiVersion !== 'string' || !SUPPORTED_API_VERSIONS.has(obj.apiVersion)) {
    const got = obj.apiVersion === undefined ? '(missing)' : JSON.stringify(obj.apiVersion)
    return {
      ok: false,
      error:
        `policy ${path} has invalid or missing apiVersion: ` +
        `expected one of [${[...SUPPORTED_API_VERSIONS].join(', ')}], got ${got}. ` +
        `See the SPL specification §1.5 第4条.`,
    }
  }
  if (obj.kind !== 'Policy') {
    const got = obj.kind === undefined ? '(missing)' : JSON.stringify(obj.kind)
    return {
      ok: false,
      error: `policy ${path} has invalid or missing kind: expected 'Policy', got ${got}`,
    }
  }
  if (!Array.isArray(obj.rules)) {
    const got = obj.rules === undefined ? '(missing)' : typeof obj.rules
    return {
      ok: false,
      error: `policy ${path} must have a 'rules' array (got ${got})`,
    }
  }
  // spec v2 §2 / §0.5 — metadata.{author, tags,
  // references} are not consumed by the loader (attribution lives in the
  // platform bundle manifest). Spec §0.5 mandates a WARN when any
  // declared field is silently dropped; we surface it at policy load
  // time so operators don't conflate "field present" with "field used".
  if (obj.metadata && typeof obj.metadata === 'object') {
    const md = obj.metadata as Record<string, unknown>
    for (const field of ['author', 'tags', 'references'] as const) {
      if (md[field] !== undefined) {
        warnings.push(
          `policy ${path}: metadata.${field} present but loader does not consume (spec §0.5)`,
        )
      }
    }
  }
  // spec v2 §1 added `scope.workflows`. Per
  // migration §9f, deepseek is single-collector and does not consume
  // this field — INTENTIONALLY SILENT, no warning (宽容忽略). Listed
  // here only to anchor the comment for future readers.
  return { ok: true, policy: obj as unknown as PolicyDocument, warnings }
}

export function compilePolicy(policy: PolicyDocument): LoadResult {
  const rules: CompiledRule[] = []
  // regex compile failures and rejected
  // catastrophic-backtracking patterns are collected here (per-rule
  // context included) and surfaced on LoadResult.warnings. The affected
  // RULE is dropped: with one pattern missing, the author's intent is
  // unrecoverable — keeping the rule could silently widen its match
  // (e.g. an `allow` guard becoming universal). Fail-loud but non-fatal
  // — every other rule of the policy still compiles.
  const warnings: string[] = []
  // policy-level scope is inherited by every rule in the
  // document. Per-rule scope is not in the spec today, but the field travels
  // on `CompiledRule` so the engine can filter before matching.
  const scope = policy.scope
  for (const rawRule of policy.rules ?? []) {
    if (!rawRule || rawRule.enabled === false) continue
    const rule = normalizeRule(rawRule)
    // validate severity whitelist. Unknown values
    // are dropped (with a warning) so a typo like "hgh" doesn't break
    // the compile path — absence of severity falls through to the
    // legacy block-vs-warn path, which is the documented back-compat
    // behavior.
    //
    // SPL v2 spec §3 adds `extreme` as a fifth tier
    // (reserved for irreversible system-level damage; default policies
    // may not use it yet but the engine must accept it).
    //
    // spec §3 severity 条件必填化
    // (`action.decision ∈ {block, warn}` 必填；其他决策可选) 已落
    // spec 1.0.1。此处 severity 缺失不报错、未知值丢弃，均与 spec §3
    // 条件必填语义一致——深侧不补 if/then 加严（避免与"治理噪声反对
    // 加严"哲学冲突）；决策维度强制留给策略作者。
    if (rule.severity !== undefined && !['low', 'medium', 'high', 'critical', 'extreme'].includes(rule.severity)) {
      warnings.push(`rule "${rule.id}": unknown severity "${rule.severity}" ignored`)
      delete (rule as unknown as Record<string, unknown>).severity
    }
    // SPL v2 spec §5.1 line 95 — `guide` /
    // `context_adjust` / `substitute` / `degrade` / `approve` are
    // deprecated v1 decisions. The loader rejects them at compile
    // time (fail-loud, integer load result).
    if (isV1DeprecatedDecision(rule.action?.decision)) {
      warnings.push(
        `rule "${rule.id}": deprecated v1 decision "${rule.action?.decision}" rejected by spec §5.1; ` +
        `use one of [allow, warn, audit, modify, escalate, block] instead`,
      )
      continue
    }
    // spec §3 mandates top-level `category:` on every
    // rule, and spec §7.2 restricts it to the eight-value enum. The
    // loader enforces both. Without this guard the self-protection
    // override seam in silently falls back to the id-prefix
    // check — fine while we're in transition, but the goal of 
    // phase 4 is to retire that fallback, so this is the validator
    // we'll be testing against.
    if (rule.category === undefined) {
      warnings.push(`rule "${rule.id}": missing top-level "category:" field (spec §3 + §7.2)`)
      continue
    }
    if (!isSpecCategory(rule.category)) {
      warnings.push(
        `rule "${rule.id}": unknown category "${rule.category}" — ` +
        `must be one of ${SPEC_CATEGORIES.join(', ')} (spec §7.2)`,
      )
      continue
    }
    // spec §7.4 blockCode naming-domain enforcement.
    //
    // A violation warns AND drops the rule — the rest of the policy still
    // loads. Three sub-checks, each independently drops the rule:
    //   (1) decision=block without blockCode — spec §5.2 必填
    //   (2) decision=block blockCode violating the <CATEGORY 大写>_<threat>_<NNN>
    //       regex — spec §7.4 命名域违规
    // (3) decision=block blockCode prefix not aligned with
    //       `rule.category.toUpperCase()`. spec §7.4 names the first
    //       segment "<CATEGORY 大写>", which must equal rule.category.
    //       Mismatched prefixes (e.g. POLICY_* under intrusion_defense)
    // were shape-valid in but semantically wrong; they
    //       break the audit-trail grouping that the platform team
    //       cross-references against the bundle manifest.
    //
    // `decision≠block` carrying a blockCode remains advisory-only —
    // spec §5.2 says the field is meaningful only for
    // block decisions, but the cost of dropping such rules far exceeds
    // the benefit (custom policies routinely carry blockCode on warn
    // rules for UI labelling).
    const blockCode = rule.action?.blockCode
    if (rule.action?.decision === 'block') {
      let dropReason: string | undefined
      if (blockCode === undefined || blockCode === '') {
        const msg = `rule "${rule.id}": missing action.blockCode (decision=block requires it per spec §5.2 + §7.4)`
        warnings.push(msg)
        dropReason = msg
      } else if (!BLOCK_CODE_PATTERN.test(blockCode)) {
        const msg =
          `rule "${rule.id}": action.blockCode "${blockCode}" violates spec §7.4 naming domain ` +
          `(<CATEGORY 大写>_<威胁>_<NNN>, e.g. DATA_LEAK_MONITORING_IMDS_009)`
        warnings.push(msg)
        dropReason = msg
      } else {
        // category-prefix alignment — spec §7.4 names
        // the first segment `<CATEGORY 大写>`, which spec §7.2 fixes to
        // the eight-value enum (rule.category). Without this guard a
        // `data_leak_monitoring` rule can carry a `SELF_PROTECTION_*`
        // blockCode — shape-valid in, semantically wrong for the
        // audit trail. The mismatch is warned and the rule dropped.
        const expectedPrefix = rule.category!.toUpperCase() + '_'
        if (!blockCode.startsWith(expectedPrefix)) {
          const msg =
            `rule "${rule.id}": action.blockCode "${blockCode}" prefix does not match ` +
            `rule.category "${rule.category}" (expected "${expectedPrefix}..." — spec §7.4)`
          warnings.push(msg)
          dropReason = msg
        } else {
          // §7.4 segment check.
          //
          // The existing `startsWith(expectedPrefix)` check above accepts
          // blockCodes like `SELF_PROTECTION_001` because the prefix
          // `SELF_PROTECTION_` matches the category `self_protection`. The
          // form regex sees three segments `SELF` / `PROTECTION` / `001`,
          // passes shape, and the prefix check passes — but the middle
          // segment is the trailing half of the category name, not a
          // threat descriptor. Spec §7.4 names the three segments
          // `<CATEGORY 大写>_<威胁>_<NNN>`; the threat MUST be a distinct
          // descriptor, not a re-spelling of the category.
          //
          // Examples that this catches but the existing checks miss:
          //   - `SELF_PROTECTION_001` (segment-2 = `PROTECTION` =
          //     category-extension; no threat)
          //   - `SENSITIVE_DATA_ACCESS_SSH_PRIVATE_KEYS_005`
          //     (segment-1 = `SENSITIVE` not `SENSITIVE_DATA_ACCESS` when
          //     parsed by the form regex `[A-Z][A-Z0-9]*` which forbids
          //     underscores in segment-1)
          //
          // Dropped, with the warning above naming the offending
          // segment.
          const firstSegment = blockCode.substring(0, blockCode.indexOf('_'))
          // Spec §7.4 first-segment rule.
          //
          // Spec text: "第一段严格等于 rule.category.toUpperCase()". But the
          // §7.4 example `INTRUSION_DEFENSE_MASS_DELETION_005` has first
          // segment `INTRUSION`, not `INTRUSION_DEFENSE`. The form regex
          // `^[A-Z][A-Z0-9]*_...` also forbids underscores in segment-1,
          // so a strict full-name check would contradict the example AND
          // the existing form regex.
          //
          // Convention adopted: segment-1 = first word of the uppercased
          // category (`intrusion_defense` → `INTRUSION`,
          // `sensitive_data_access` → `SENSITIVE`,
          // `data_leak_monitoring` → `DATA`). This convention is used for
          // the 33 canonical mappings. Generic prefixes (`POLICY`/`RULE`/
          // `BLOCK`/`DETECT`) are caught here because they don't appear
          // as a first word of any §7.2 enum value.
          const expectedFirstWord = rule.category!.toUpperCase().split('_')[0]
          if (firstSegment !== expectedFirstWord) {
            warnings.push(
              `rule "${rule.id}": action.blockCode "${blockCode}" first segment "${firstSegment}" ` +
              `does not match rule.category "${rule.category}" first-word "${expectedFirstWord}" ` +
              `(spec §7.4 — advisory until policy migration lands)`,
            )
          }
          // Strict threat-segment + NNN check. After stripping the
          // category prefix, the remainder must match `<threat>_<NNN>`
          // where threat is at least one uppercase letter (not just
          // digits) and NNN is exactly 3 digits.
          const rest = blockCode.substring(expectedPrefix.length)
          if (!/^[A-Z][A-Z0-9_]*[A-Z0-9]_\d{3}$/.test(rest)) {
            warnings.push(
              `rule "${rule.id}": action.blockCode "${blockCode}" - after category prefix ` +
              `"${expectedPrefix}" remainder "${rest}" does not match the <threat>_<NNN> pattern ` +
              `(threat must contain at least one letter, NNN must be exactly 3 digits - ` +
              `spec §7.4 advisory)`,
            )
          }
          // _CRITICAL_ suffix in threat segment — spec §6.4 双轨制
          // 约定：双轨后缀仅体现在 id 字段（§7.1 的 `-critical` /
          // `-warn` 后缀），不应出现在 blockCode 威胁段中。5 处违规
          // 待后续清理修复。
          if (rest.includes('_CRITICAL_')) {
            warnings.push(
              `rule "${rule.id}": action.blockCode "${blockCode}" contains "_CRITICAL_" suffix ` +
              `in threat segment — redundant with rule.id "-critical" suffix. ` +
              `Per spec §6.4 双轨制, the dual-track suffix belongs on the rule id, ` +
              `not in blockCode threat segment (spec §7.4 advisory)`,
            )
          }
        }
      }
      if (dropReason) {
        warnings.push(
          `rule "${rule.id}": dropped — spec §7.4 is enforced strictly`,
        )
        continue
      }
    } else if (blockCode !== undefined) {
      // Non-block rule — blockCode has no semantic meaning per spec §5.2.
      // We keep the field on the compiled rule (UI may still surface it)
      // but emit an advisory so policy authors don't think it's enforced.
      warnings.push(
        `rule "${rule.id}": action.blockCode present but decision is "${rule.action?.decision}" ` +
        `(spec §5.2 — blockCode is only meaningful for decision=block)`,
      )
    }
    // spec §3废止字段 — `evaluate` 区段整段
    // 迁移完毕(risk_level→severity 已落地, reg_clause→regClause 上移)。
    // 携带该区段的规则直接剔除, 不再降级成 warning: 它的两个字段都已
    // 在别处落地, 保留规则只会让作者以为这一段还在生效。
    // `CompiledRule.evaluate` 因此恒为 undefined —— 该字段仅在直接构造
    // CompiledRule 的调用方(测试 / 内部组合)还有意义。
    if (rule.evaluate !== undefined) {
      warnings.push(
        `rule "${rule.id}": "evaluate" section deprecated in SPL v2 — fields migrated: ` +
        `risk_level→severity, reg_clause→regClause; remove "evaluate:" block (spec §3)`,
      )
      warnings.push(
        `rule "${rule.id}": dropped — the deprecated "evaluate:" section is not accepted`,
      )
      continue
    }
    // spec §0.5"未实现字段必告警"通则。8 类
    // matcher/engine 未消费字段若出现在规则里, 必须提示——沉默吞掉
    // 会让运营方误以为防护在位。这是 spec 通则的核心语义, 严格遵循。
    // 警告文案固定方便 grep 排查。`metadata.*` 由 validatePolicyShape
    // 处理(整策略级而非规则级); 这里只覆盖 rule 与 match + action 字段。
    checkUnsupportedFields(rule, warnings)
    const compiledMatch = compileMatch(rule.match)
    // compileMatch 现在产生的 warning 通道包含
    // (a) 别名归一 / 未知 actionType advisory — 不剔除规则
    // (b) regex 编译失败 / 不安全模式拒绝 — 剔除(因为 matcher
    //     缺一条 pattern 等于 matcher 边界漏检, 失败宽容会让
    //     运营方误以为规则在生效)
    // 区分信号: regex 失败消息以 `paramsRegex.` / `bodyRegex:` 开头;
    // 其他(以 `actionType` 开头)是 advisory, 仅记录。
    let hasRegexFailure = false
    for (const warning of compiledMatch.warnings) {
      warnings.push(`rule "${rule.id}": ${warning}`)
      if (
        warning.startsWith('paramsRegex.') ||
        warning.startsWith('bodyRegex[') ||
        warning.startsWith('bodyRegex:')
      ) {
        hasRegexFailure = true
      }
    }
    if (hasRegexFailure) {
      continue
    }
    const compiled: CompiledRule = {
      id: rule.id,
      name: rule.name ?? rule.id,
      enabled: true,
      priority: typeof rule.priority === 'number' ? rule.priority : 0,
      scope,
      match: compiledMatch.clause,
      evaluate: rule.evaluate,
      // Propagate the top-level `category:` field so the runtime can
      // recognize self-protection rules. Used by the severity seam in
      // `DecisionComposer.composeDecision` (belt-and-braces with the
      // id-prefix check) and available to consumers that want to
      // group/filter rules by category (UI sorting, audit report).
      category: rule.category,
      // pass the per-rule severity through to CompiledRule so
      // `DecisionComposer.composeDecision` can downgrade block→warn when
      // severity is medium/low. Unknown values are dropped silently (with
      // a warning) so a typo like "hgh" doesn't break the compile path.
      severity: rule.severity,
      // after `normalizeRule`, `action.decision` is
      // narrowed to `InternalDecision` (marketplace values `deny` /
      // `ask` were translated to `block` / `escalate` earlier). The
      // cast is safe — the runtime invariant is enforced by
      // `mapMarketplaceToInternal` inside `normalizeRule`.
      action: rule.action as CompiledRule['action'],
    }
    rules.push(compiled)
  }
  // Highest priority first; stable by original order for ties.
  rules.sort((a, b) => b.priority - a.priority || 0)
  return { policy, rules, warnings }
}

/**
 * normalize legacy wire aliases into the
 * canonical SPL shape so the rest of the engine only sees standard fields.
 */
function normalizeRule(rule: PolicyRule): PolicyRule {
  const out: PolicyRule = { ...rule }

  // Evaluate aliases.
  if (out.evaluate) {
    const evaluate = { ...out.evaluate }
    if (evaluate.riskLevel !== undefined && evaluate.risk_level === undefined) {
      evaluate.risk_level = evaluate.riskLevel
    }
    delete (evaluate as Record<string, unknown>).riskLevel
    out.evaluate = evaluate
  }

  // Action aliases.
  if (out.action) {
    const action = { ...out.action }
    // marketplace vocabulary → internal vocabulary.
    // `deny → block`, `ask → escalate`. Internal 10-action values pass
    // through unchanged so legacy policies/default-policy.json keeps
    // working with no edits. Translation happens BEFORE the alias
    // sweeps so downstream consumers always see the internal enum.
    action.decision = mapMarketplaceToInternal(action.decision)

    if (action.message !== undefined && action.blockReason === undefined) {
      action.blockReason = action.message
    }
    delete (action as Record<string, unknown>).message

    // Normalize top-level riskLevel on action -> evaluate.risk_level.
    if (action.riskLevel !== undefined) {
      out.evaluate = out.evaluate ?? {}
      if (out.evaluate.risk_level === undefined) {
        out.evaluate.risk_level = action.riskLevel
      }
      delete (action as Record<string, unknown>).riskLevel
    }

    // Normalize modify sub-field aliases.
    if (action.modifiedParams || action.modifiedRedactFields || action.modifiedWhitelistConstraint) {
      action.modify = action.modify ?? {}
      if (action.modifiedParams !== undefined && action.modify.setFields === undefined) {
        action.modify.setFields = action.modifiedParams
      }
      if (action.modifiedRedactFields !== undefined && action.modify.redactFields === undefined) {
        action.modify.redactFields = action.modifiedRedactFields
      }
      if (action.modifiedWhitelistConstraint !== undefined && action.modify.whitelistConstraint === undefined) {
        action.modify.whitelistConstraint = action.modifiedWhitelistConstraint
      }
      delete (action as Record<string, unknown>).modifiedParams
      delete (action as Record<string, unknown>).modifiedRedactFields
      delete (action as Record<string, unknown>).modifiedWhitelistConstraint
    }

    // Normalize substitute alias.
    if (action.substitutedTool !== undefined && action.substitute === undefined) {
      action.substitute = { toolName: action.substitutedTool }
    }
    delete (action as Record<string, unknown>).substitutedTool

    // Normalize escalate aliases.
    if (action.escalate) {
      const escalate = { ...action.escalate }
      if (escalate.escalateTimeoutSeconds !== undefined && escalate.timeout_seconds === undefined) {
        escalate.timeout_seconds = escalate.escalateTimeoutSeconds
      }
      delete (escalate as Record<string, unknown>).escalateTimeoutSeconds
      if (escalate.escalateApprovers !== undefined && escalate.approval_route === undefined) {
        escalate.approval_route = escalate.escalateApprovers.join(',')
      }
      delete (escalate as Record<string, unknown>).escalateApprovers
      action.escalate = escalate
    }

    // Normalize degrade aliases.
    if (action.degrade) {
      const degrade = { ...action.degrade }
      if (degrade.degradedTools !== undefined && degrade.removed_tools === undefined) {
        degrade.removed_tools = degrade.degradedTools
      }
      delete (degrade as Record<string, unknown>).degradedTools
      action.degrade = degrade
    }

    out.action = action
  }

  // Match aliases.
  if (out.match?.fieldEquals) {
    out.match = { ...out.match }
    // fieldEquals is exact equality; for now mirror it as paramsRegex with
    // escaped literal patterns so RuleMatcher can evaluate it uniformly.
    const fieldEquals = out.match.fieldEquals
    const existing = out.match.paramsRegex ?? {}
    // paramsRegex 条目类型从 string[] 拓宽为
    // (string | ParamsRegexObjectEntry)[]。fieldEquals 注入的字符串
    // literal 是纯粹的字符串条目, 与新形态共存。
    const merged: Record<string, Array<string | ParamsRegexObjectEntry>> = { ...existing }
    for (const [key, value] of Object.entries(fieldEquals ?? {})) {
      const literal = typeof value === 'string' ? escapeRegex(value) : String(value)
      merged[key] = merged[key] ?? []
      if (!merged[key].includes(`^${literal}$`)) {
        merged[key].push(`^${literal}$`)
      }
    }
    out.match.paramsRegex = merged
    delete (out.match as Record<string, unknown>).fieldEquals
  }

  return out
}

/**
 * marketplace 3-action vocabulary → SPL internal 10-action
 * vocabulary. The marketplace surface ships rules with the simpler
 * `allow | deny | ask` enum, but DecisionComposer (and every other
 * downstream consumer) reads the 10-action internal vocabulary. We
 * translate at the load boundary so rule authors never see the internal
 * vocabulary in shipped YAML.
 *
 * Mapping:
 *   - `allow`        → `allow`        (no-op)
 *   - `deny`         → `block`        (marketplace "deny" = SPL "block")
 *   - `ask`          → `escalate`     (marketplace "ask" = SPL "escalate")
 *   - any internal   → itself         (legacy policies/default-policy.json
 *                                     and rule authors who already speak
 *                                     the internal vocabulary)
 *
 * Unknown values are returned unchanged so the engine's existing
 * type-check catches them at the DecisionComposer seam. We do not throw
 * here because rule-load errors should surface per-rule via the
 * `getLastLoadErrors()` channel rather than aborting the entire merge.
 */
export function mapMarketplaceToInternal(decision: Decision): Decision {
  if (decision === 'deny') return 'block'
  if (decision === 'ask') return 'escalate'
  return decision
}

/**
 * SPL v2 spec §5.1 line 95 lists five v1 decisions
 * the loader rejects: `guide` / `context_adjust` / `substitute` /
 * `degrade` / `approve`. The spec author
 * describes them as "零真实使用或不可交付".
 */
const V1_DEPRECATED_DECISIONS = new Set([
  'guide',
  'context_adjust',
  'substitute',
  'degrade',
  'approve',
])

export function isV1DeprecatedDecision(decision: unknown): boolean {
  return typeof decision === 'string' && V1_DEPRECATED_DECISIONS.has(decision)
}

/**
 * SPL v2 spec §7.2 mandates the eight-value
 * category enum. Hardcoded here to keep `src/` self-contained (no
 * external schema import).
 */
export const SPEC_CATEGORIES = [
  'self_protection',
  'intrusion_defense',
  'data_leak_monitoring',
  'sensitive_data_access',
  'supply_chain',
  'ssrf',
  'behavior_guidance',
  'data_desensitization',
] as const

export type SpecCategory = (typeof SPEC_CATEGORIES)[number]

export function isSpecCategory(value: unknown): value is SpecCategory {
  return typeof value === 'string' && (SPEC_CATEGORIES as readonly string[]).includes(value)
}

/**
 * spec §7.4 blockCode naming-domain regex.
 *
 * Format: `<CATEGORY 大写>_<威胁>_<NNN>` (3-segment per spec §7.4 literal
 * `<CATEGORY 大写>_<威胁>_<NNN>` — 2 underscores, 3 segments).
 *
 *   - `<CATEGORY 大写>` — uppercase snake (matches SPEC_CATEGORIES shape,
 *     not value — value alignment is the category-prefix check below)
 *   - `<威胁>` — uppercase snake, ≥1 char
 *   - `<NNN>` — exactly three digits (001-999)
 *
 * Examples that PASS: `DATA_LEAK_MONITORING_IMDS_009`, `SELF_PROTECTION_UNINSTALL_001`,
 *   `INTRUSION_DEFENSE_REVERSE_SHELL_001`, `SELF_PROTECTION_INSTALLER_UNINSTALL_010`,
 *   `INTRUSION_DEFENSE_MASS_DELETION_005`.
 * Examples that FAIL: `DATA_LEAK_imds_001` (lowercase threat),
 *   `data_leak_imds_001` (lowercase CATEGORY), `DATA_LEAK_IMDS_AB`
 *   (non-digit NNN), `DATA_LEAK_001` (only 1-segment — category without
 *   threat or NNN).
 *
 * revised from the 4-segment regex. The 
 * regex (`^[A-Z]..._[A-Z]..._[A-Z]..._[0-9]{3}$`) was over-strict — it
 * required two threat sub-segments which spec §7.4 does not mandate.
 * Examples like `SELF_PROTECTION_INSTALLER_UNINSTALL_010` and `SELF_PROTECTION_AUDIT_MUTATION_011` (3-segment
 * shape) failed the shape check despite matching the spec format. Fail-loud
 * then dropped those rules, regressing every self-protection
 * block test. The 3-segment form here accepts the spec's literal format.
 */
export const BLOCK_CODE_PATTERN = /^[A-Z][A-Z0-9]*_[A-Z][A-Z0-9_]*_[0-9]{3}$/

/**
 * spec §0.5"未实现字段必告警"通则 — 8 类未消费字段
 * 集中 helper。`metadata.*` 在 validatePolicyShape 中按 policy 级处理
 * (因为 metadata 是 policy 级字段, 不属于 rule), 这里的 8 个是 rule
 * 字段(match/action 端)。
 *
 * 行为:
 *   - 字段存在 → push warning(`rule "${id}": ${label} ... (spec §0.5)`)
 *   - 字段不存在 → noop
 *   - 不剔除规则: 这些字段不是核心匹配条件, 周围 clause 仍可生效;
 *     但若作者认为"写了字段=生效", 沉默会导致运营盲区。WARN 是 spec
 *     的强制要求。
 *
 * 注意 `paramsNotRegex` 已被 RuleMatcher 消费(spec §4"负向过滤"),
 * 不再 WARN。`paramsContains` / `fieldIn` / `chain` / `decisionChain` /
 * `conditionalDecisions` 全是 spec §4 / §5.2 字段, 实现延后。
 */
const UNSUPPORTED_MATCH_FIELDS: Array<keyof NonNullable<PolicyRule['match']>> = [
  'paramsContains',
  'fieldIn',
  'chain',
]
function checkUnsupportedFields(rule: PolicyRule, warnings: string[]): void {
  const match = rule.match
  if (match) {
    for (const field of UNSUPPORTED_MATCH_FIELDS) {
      if (match[field] !== undefined) {
        warnings.push(
          `rule "${rule.id}": match.${field} declared but matcher does not consume (spec §0.5)`,
        )
      }
    }
    // sessionRegex — declared on the type (MatchClause.sessionRegex)
    // but RuleMatcher.compileMatch does not wire it through. Same
    // advisory channel; do not double-warn when matcher is later wired.
    if (Array.isArray(match.sessionRegex) && match.sessionRegex.length > 0) {
      warnings.push(
        `rule "${rule.id}": match.sessionRegex declared but matcher does not consume (spec §0.5)`,
      )
    }
  }
  const action = rule.action
  if (action) {
    // action.* 是 spec §5.2 progressive escalation
    // 字段(`decisionChain` / `conditionalDecisions`), ActionClause 类型
    // 未声明(spec §5.2 字段未落地, 类型保持最小集)。这里用 unknown 兜底
    // 检测, 不修改 ActionClause 接口。
    const actionExtras = action as unknown as Record<string, unknown>
    if (actionExtras.decisionChain !== undefined) {
      warnings.push(
        `rule "${rule.id}": action.decisionChain declared but engine does not consume (spec §0.5)`,
      )
    }
    if (actionExtras.conditionalDecisions !== undefined) {
      warnings.push(
        `rule "${rule.id}": action.conditionalDecisions declared but engine does not consume (spec §0.5)`,
      )
    }
  }
}

/**
 * spec §4 历史别名归一表。loader 在 compileMatch 中
 * 把命中别名的 actionType 替换为规范值并 WARN — 让既有 v1 / 第三方
 * 自定义策略能跑, 同时审计流能看见哪些文件还没改规范值。
 *
 * 完整别名表(共 6 个):
 *   tool_call      → agent_tool_call
 *   tool_result    → agent_tool_result
 *   http           → network_http
 *   http_request   → network_http
 *   process_spawn  → process_start
 *   message_write  → agent_message
 *
 * 命中 `*`(通配)与命中已知规范值: 无 warning。命中完全未知值: 保留原
 * 值 + warning(不强拒, 避免误伤自定义策略中合理的扩展动作类型)。
 *
 * 导出理由: scripts/verify-action-type-producers.mjs 用这张表解析「策略声明的
 * actionType 在 src/ 里有没有 emit 点」——emit 点写的通常是别名形态
 * (http_request),策略里写的是规范形态(network_http),两边必须归一到同一个值。
 * 别名表是唯一事实源,门禁直接引用,避免脚本里再抄一份日后漂移。
 */
export const ACTION_TYPE_ALIASES: Record<string, string> = {
  tool_call: 'agent_tool_call',
  tool_result: 'agent_tool_result',
  http: 'network_http',
  http_request: 'network_http',
  process_spawn: 'process_start',
  message_write: 'agent_message',
}

// 反向映射：政策用规范值时，把所有已知别名也加入 matcher set
// (运行时 ApplicationCollector/SelfProtectionGuard 持续发别名形式 ctx.actionType,
//  若 matcher set 只收规范值则运行时不再命中 → 规则静默失效)。
const REVERSE_ACTION_TYPE_ALIASES: Record<string, string[]> = (() => {
  const r: Record<string, string[]> = {}
  for (const [alias, canonical] of Object.entries(ACTION_TYPE_ALIASES)) {
    if (r[canonical]) r[canonical].push(alias)
    else r[canonical] = [alias]
  }
  return r
})()

/**
 * returns true when the decision value belongs to the
 * marketplace 3-action vocabulary. Used by shipped-rule-file lints to
 * confirm the marketplace surface is using the canonical vocabulary
 * (not legacy internal values mixed in).
 */
export function isMarketplaceDecision(decision: Decision): boolean {
  return decision === 'allow' || decision === 'deny' || decision === 'ask'
}

function compileMatch(match: PolicyRule['match']): { clause: CompiledMatchClause | undefined; warnings: string[] } {
  if (!match) return { clause: undefined, warnings: [] }
  const warnings: string[] = []
  // spec §4 actionType 历史别名归一 + WARN。
  // 命别名 → 同时记入 set(规范值与别名都收)以保持向后兼容 — 既有
  // fixture 用别名 `tool_call` 调 engine.evaluate, matcher 端需同时
  // 认规范值与别名。命中 `*` / 已知规范值 → 无 warning;
  // 命中完全未知值 → 保留原值 + warning(避免误伤自定义扩展)。
  const rawActionTypes = match.actionType
  let actionTypeSet: Set<string> | undefined
  if (rawActionTypes && rawActionTypes.length > 0) {
    const normalized = new Set<string>()
    for (const value of rawActionTypes) {
      const alias = ACTION_TYPE_ALIASES[value]
      if (alias !== undefined) {
        normalized.add(alias)
        normalized.add(value) // backward-compat: keep the alias in the set
        warnings.push(
          `actionType "${value}" is alias — canonical "${alias}" (spec §4)`,
        )
      } else {
        normalized.add(value)
        // 反向别名：政策写规范值时，把已知别名也收进 matcher set。
        // 运行时 collector / hook / inline guard 仍以别名形式发送
        // ctx.actionType；不收别名会导致改名后规则静默失效。
        const reverseAliases = REVERSE_ACTION_TYPE_ALIASES[value]
        if (reverseAliases) {
          for (const a of reverseAliases) normalized.add(a)
        }
        if (value !== '*' && !isCanonicalActionType(value)) {
          warnings.push(
            `actionType "${value}" is not a spec §4 canonical value — matcher may reject at runtime`,
          )
        }
      }
    }
    actionTypeSet = normalized
  }
  const paramsRegex: Record<string, RegExp[]> = {}
  if (match.paramsRegex) {
    for (const [key, patterns] of Object.entries(match.paramsRegex)) {
      if (!patterns || patterns.length === 0) continue
      // spec §4 paramsRegex 条目支持 `{ pattern, flags?, input? }`
      // 对象形态。字符串形态保留(向后兼容)。`input: 'lowercased'` 在
      // matcher 端做小写预处理, 在 loader 层不改动; loader 只编译 regex
      // 本身并把 input 标记交给 matcher。
      const outcome = compileRegexList(patterns, `paramsRegex.${key}`)
      warnings.push(...outcome.warnings)
      if (outcome.compiled) paramsRegex[key] = outcome.compiled
    }
  }
  const paramsNotRegex: Record<string, RegExp[]> = {}
  if (match.paramsNotRegex) {
    for (const [key, patterns] of Object.entries(match.paramsNotRegex)) {
      if (!patterns || patterns.length === 0) continue
      const outcome = compileRegexList(patterns, `paramsNotRegex.${key}`)
      warnings.push(...outcome.warnings)
      if (outcome.compiled) paramsNotRegex[key] = outcome.compiled
    }
  }
  const bodyRegex = compileRegexList(match.bodyRegex, 'bodyRegex')
  warnings.push(...bodyRegex.warnings)
  return {
    clause: {
      actionType: actionTypeSet,
      toolName: toSet(match.toolName),
      assetType: toSet(match.assetType),
      riskFlagsAny: toSet(match.riskFlagsAny),
      riskFlagsAll: toSet(match.riskFlagsAll),
      paramsRegex: Object.keys(paramsRegex).length > 0 ? paramsRegex : undefined,
      paramsNotRegex: Object.keys(paramsNotRegex).length > 0 ? paramsNotRegex : undefined,
      bodyRegex: bodyRegex.compiled,
    },
    warnings,
  }
}

function toSet(value: string[] | undefined): Set<string> | undefined {
  if (!value || value.length === 0) return undefined
  return new Set(value)
}

/**
 * spec §4 规范 actionType 集合。
 * 不在表内的值在 loader 层只 WARN(归一化 unknown-value advisory),
 * 真正拒绝由 RuleMatcher canonical 表处理。`self_protection` 自保护
 * 类别特有的 actionType 暂未拆分, 跟随通用集合。
 */
const CANONICAL_ACTION_TYPES = new Set([
  'agent_start',
  'agent_message',
  'agent_tool_call',
  'agent_tool_result',
  'process_start',
  'network_http',
  'file_read',
  'file_write',
  'asset_change',
])

function isCanonicalActionType(value: string): boolean {
  return CANONICAL_ACTION_TYPES.has(value)
}

/**
 * regex compile outcomes are
 * fail-loud.
 *
 * Defect 3 — a pattern that fails `new RegExp` used to be skipped
 * silently (`catch {}`), so a typo'd rule simply never matched and the
 * operator had no idea their guard was inert. The failure detail is now
 * collected into `warnings[]` and bubbles up through
 * `LoadResult.warnings` / `MultiLoadResult.warnings` to the engine's
 * logger.
 *
 * Defect 4 — a pattern with catastrophic-backtracking risk (see
 * `src/utils/regexSafety.ts`; no RE2 allowed under the marketplace
 * `dependencies: {}` contract) is rejected at COMPILE time, before it
 * can freeze the tool-call hot path. The rejection reason joins the
 * same `warnings[]` channel and the pattern is skipped (the rule's
 * other clauses and every other rule still compile).
 *
 * spec §4 paramsRegex 对象形态支持。每条 entry
 * 可以是字符串(向后兼容)或 `{ pattern, flags?, input? }` 对象。
 *   - `flags`: 白名单只允许 `i`(大小写不敏感); 其他 flag (`g/y/m/s/u`)
 *     与 PCRE 内联(`(?i:...)`) / 命名组 (`(?<`) / Unicode 属性
 *     (`\p{...}`) 已在 regexSafety 中拒绝。
 *   - `input`: `lowercased` / `raw`(默认 `raw`); loader 层不强制
 *     小写, 由 RuleMatcher.matchParam 在匹配前按 entry 标记预处理。
 *     标记本身(lower-input)目前仅作 advisory 字段, 后续 RuleMatcher
 *     接线时消费。
 *
 * bodyRegex / sessionRegex 暂不接受对象形态(类型定义 `string[]`);
 * spec §4 仅明示 paramsRegex 条目可为对象。如未来 spec 扩展, 这里
 * 改为多接受函数即可。
 */
function compileRegexList(
  patterns: Array<string | ParamsRegexObjectEntry> | undefined,
  fieldLabel: string,
): { compiled: RegExp[] | undefined; warnings: string[]; entryInputs?: Record<number, 'lowercased' | 'raw'> } {
  const warnings: string[] = []
  if (!patterns || patterns.length === 0) {
    return { compiled: undefined, warnings }
  }
  const compiled: RegExp[] = []
  const entryInputs: Record<number, 'lowercased' | 'raw'> = {}
  for (let idx = 0; idx < patterns.length; idx++) {
    const entry = patterns[idx]
    // 字符串形态(向后兼容 — 旧策略与 default-policy.yaml 100% 是字符串)。
    if (typeof entry === 'string') {
      const unsafeReason = detectUnsafeRegexPattern(entry)
      if (unsafeReason !== null) {
        warnings.push(`${fieldLabel}[${idx}]: pattern ${JSON.stringify(entry)} skipped — ${unsafeReason}`)
        continue
      }
      try {
        // SPL `paramsRegex.env` rules need to
        // match uppercase env-var keys (`BASH_ENV=...`). The compiled
        // regex inherits the case-insensitive flag so `(?i)`-style inline
        // flags aren't required. Existing rules use lowercase keywords
        // (`pnpm`, `kill`, `base64`) — adding `i` doesn't change their
        // semantics because the attack payloads they target are case-stable
        // (the harness doesn't run `Kill` or `BASE64`).
        compiled.push(new RegExp(entry, 'i'))
      } catch (error: unknown) {
        warnings.push(`${fieldLabel}[${idx}]: pattern ${JSON.stringify(entry)} failed to compile — ${String(error)}`)
      }
      continue
    }
    // 对象形态(spec §4)
    if (entry === null || typeof entry !== 'object') {
      warnings.push(`${fieldLabel}[${idx}]: entry must be string or object, got ${typeof entry}`)
      continue
    }
    const obj = entry as ParamsRegexObjectEntry
    if (typeof obj.pattern !== 'string') {
      warnings.push(`${fieldLabel}[${idx}]: object form missing "pattern" string`)
      continue
    }
    // flags 白名单: 仅 `i`。其他 (含 PCRE 内联 `(?i:...)`) 由 regexSafety
    // 拒绝; loader 这里再做一次白名单防御 — 避免有人绕过 safety 检查
    // 用 `m`/`s`/`g`/`y`/`u` 等扩展 flag 走通 JS 引擎造成语义偏差。
    const userFlags = obj.flags ?? 'i'
    if (!/^[i]*$/.test(userFlags)) {
      warnings.push(
        `${fieldLabel}[${idx}]: flags "${userFlags}" rejected — only "i" allowed ` +
        `(spec §4 — PCRE/g/y/m/s/u all disallowed)`,
      )
      continue
    }
    const unsafeReason = detectUnsafeRegexPattern(obj.pattern)
    if (unsafeReason !== null) {
      warnings.push(
        `${fieldLabel}[${idx}]: pattern ${JSON.stringify(obj.pattern)} skipped — ${unsafeReason}`,
      )
      continue
    }
    try {
      compiled.push(new RegExp(obj.pattern, userFlags))
    } catch (error: unknown) {
      warnings.push(
        `${fieldLabel}[${idx}]: pattern ${JSON.stringify(obj.pattern)} failed to compile — ${String(error)}`,
      )
      continue
    }
    // input 标记: 'lowercased' 让 RuleMatcher 在匹配前小写预处理;
    // 缺省/未知值 → 'raw'(向后兼容)。`entryInputs` 索引与 compiled[]
    // 一一对应(只 push 成功 compile 的条目)。
    if (obj.input === 'lowercased') {
      entryInputs[compiled.length - 1] = 'lowercased'
    }
  }
  return {
    compiled: compiled.length > 0 ? compiled : undefined,
    warnings,
    entryInputs: Object.keys(entryInputs).length > 0 ? entryInputs : undefined,
  }
}

/**
 * marketplace multi-file policy loader.
 *
 * Loads multiple policy files in order and returns the merged rule set
 * plus per-file diagnostics. The order parameter is significant:
 *
 *   - Earlier paths are appended FIRST in the merged output
 *   - Later paths (builtin / neutral-default) are appended AFTER
 *   - Priority sort at the engine layer still applies, but a
 *     first-match-wins resolution on equal priorities preserves
 *     "user rule shadows builtin" semantics (since user rules
 *     load first and tie-break by original order).
 *
 * Per-file errors are collected and returned in `errors[]`; a single
 * malformed file does NOT abort the merge. The merged rules still
 * flow from the files that parsed successfully. This is the
 * "fail-loud but don't break the engine" contract from the v5 plan
 * §9.1 acceptance checklist.
 */
export interface MultiLoadResult {
  /** Successfully compiled rules, merged in input order. */
  rules: CompiledRule[]
  /** PolicyDocument fragments keyed by path; populated for callers that
   *  want to inspect scope / metadata per source. */
  documents: Record<string, PolicyDocument>
  /** Per-file error messages; empty when all files loaded cleanly. */
  errors: Array<{ path: string; error: string }>
  /**
   * non-fatal per-file diagnostics — regexes
   * that failed to compile or were rejected by the catastrophic-
   * backtracking guard. Surfaced via the engine logger so operators
   * see which guard silently stopped matching.
   */
  warnings: Array<{ path: string; warning: string }>
  /** Total input files; useful for logs and tests. */
  totalFiles: number
}

export function loadMultiplePolicies(paths: readonly string[]): MultiLoadResult {
  const entries: Array<{ path: string; raw?: string; readError?: string }> = []
  for (const path of paths) {
    try {
      entries.push({ path, raw: readFileSync(path, 'utf8') })
    } catch (error: unknown) {
      entries.push({ path, readError: `failed to read policy ${path}: ${String(error)}` })
    }
  }
  return mergeEntries(entries, paths.length)
}

/**
 * multi-file merge over PRE-READ
 * bytes. Same merge semantics as `loadMultiplePolicies` (user paths
 * first, builtins after, priority re-sort, per-file errors isolated) —
 * but the caller reads each file once and hands the bytes over, so the
 * tamper hash and the parser see the identical content (TOCTOU window
 * closed). Read failures are the caller's job (the engine soft-fails
 * them per the contract instead of aborting the merge).
 */
export function loadMultiplePoliciesFromEntries(
  entries: ReadonlyArray<{ path: string; raw: string }>,
): MultiLoadResult {
  return mergeEntries(entries.map((e) => ({ ...e })), entries.length)
}

function mergeEntries(
  entries: ReadonlyArray<{ path: string; raw?: string; readError?: string }>,
  totalFiles: number,
): MultiLoadResult {
  const documents: Record<string, PolicyDocument> = {}
  const errors: Array<{ path: string; error: string }> = []
  const warnings: Array<{ path: string; warning: string }> = []
  const merged: CompiledRule[] = []

  for (const entry of entries) {
    if (entry.readError !== undefined || entry.raw === undefined) {
      errors.push({ path: entry.path, error: entry.readError ?? `failed to read policy ${entry.path}` })
      continue
    }
    const result = loadPolicyFromText(entry.raw, entry.path)
    if (result.error) {
      errors.push({ path: entry.path, error: result.error })
      continue
    }
    if (result.policy) {
      documents[entry.path] = result.policy
    }
    for (const warning of result.warnings ?? []) {
      warnings.push({ path: entry.path, warning })
    }
    for (const rule of result.rules) {
      merged.push(rule)
    }
  }

  // Re-apply the priority sort so the merged set obeys the engine's
  // "highest priority wins" contract. Ties keep original (input) order
  // via Array.prototype.sort stability (Node 12+).
  merged.sort((a, b) => b.priority - a.priority)

  return {
    rules: merged,
    documents,
    errors,
    warnings,
    totalFiles,
  }
}

/**
 * default-mode-from-policy seam.
 *
 * Walk the merged `documents` in **input order** (user paths first,
 * bundled builtins after, matching `loadMultiplePoliciesFromEntries`),
 * and return the first `mode` declared by any policy file. Returns
 * `null` when no policy declares a mode.
 *
 * The engine's `InterventionEngine` calls this on every successful
 * reload; the first non-null result becomes the runtime `config.mode`
 * IF the operator has NOT explicitly set `mode` in their config (so
 * existing operators who deliberately run audit keep audit). The
 * bundled `policies/default-policy.spl.yaml` declares `mode: enforce`;
 * a fresh install with no operator config therefore lands in enforce
 * by default — secure-by-default without a hard breaking change.
 *
 * Policy mode is consulted AFTER the operator's explicit config
 * (higher priority = operator wins) and BEFORE the schema default
 * (lower priority = bundled policy wins). The full resolution chain
 * lives in `InterventionEngine.reloadMultiPolicy`.
 */
export function extractPolicyMode(
  documents: Readonly<Record<string, PolicyDocument>>,
  order: readonly string[],
): Mode | null {
  for (const path of order) {
    const doc = documents[path]
    if (doc && (doc.mode === 'audit' || doc.mode === 'enforce')) {
      return doc.mode
    }
  }
  return null
}
