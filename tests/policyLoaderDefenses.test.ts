/**
 * 2026-09-29, pre-open-source review) — policy loader
 * defenses. Locks the four merged fixes:
 *
 *   Defect 1 — TOCTOU: the engine hashed each policy file
 *   (`_hashFile`) and then RE-READ it inside `loadMultiplePolicies`, so
 *   swapping the file between the two reads passed the hash check while
 *   rules loaded from the swapped content. The engine now reads each
 *   file exactly once per reload and feeds the same bytes to both the
 *   hash and the parser (`loadPolicyFromText` /
 *   `loadMultiplePoliciesFromEntries`). The fs-mock below flips file
 *   content between consecutive reads to prove only one read happens.
 *
 *   Defect 2 — silent degradation: the loud POLICY-RELOAD-FAILED
 *   warning was gated behind DSH_DEBUG === '1', so production hosts had
 *   no observable signal when a reload committed with errors. Now the
 *   engine always warns through the injected logger and fires
 *   `onReloadError`, which bootstrap wires to a
 *   `security_audit/policy_reload_error` audit row (NDJSON assertion at
 *   the bottom of this file, through the real `apply()` bootstrap).
 *
 *   Defect 3 — fail-open regex compile: invalid patterns used to be
 *   skipped via `catch {}`. Compile failures now surface as
 *   `LoadResult.warnings` / `MultiLoadResult.warnings` and are logged
 *   by the engine; other rules still compile.
 *
 *   Defect 4 — ReDoS: patterns with catastrophic-backtracking risk are
 *   rejected at compile time by the static analyzer in
 *   `src/utils/regexSafety.ts` (no RE2 allowed under the marketplace
 *   `dependencies: {}` contract), with the rejection reason joining the
 *   same warnings channel. A pin asserts the shipped
 *   `policies/default-policy.spl.yaml` produces ZERO warnings (no false
 * positives on the shipped baseline). :
 *   `policies/legacy.yaml` removed.
 */

import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

import { normalizeConfig, type Config } from '../src/config.js'
import {
  InterventionEngine,
  type PolicyReloadErrorInfo,
} from '../src/intervention/InterventionEngine.js'
import {
  loadPolicy,
  loadPolicyFromText,
  loadMultiplePoliciesFromEntries,
} from '../src/intervention/RuleLoader.js'
import { detectUnsafeRegexPattern } from '../src/utils/regexSafety.js'
import { apply } from '../src/index.js'
import type { Context } from '../src/types/external.js'

/**
 * fs harness for. Wraps ONLY `readFileSync`: every read of a
 * watched path is counted, and once a path has been read `afterReads`
 * times, subsequent reads return attacker-controlled content instead of
 * the real bytes — simulating a file swap between the hash read and the
 * parse read. All other fs functions pass through untouched.
 */
const fsState = vi.hoisted(() => ({
  readCounts: new Map<string, number>(),
  swaps: new Map<string, { afterReads: number; evilText: string }>(),
}))

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  const realRead = actual.readFileSync
  return {
    ...actual,
    readFileSync: ((path: unknown, options?: unknown) => {
      const p = String(path)
      const swap = fsState.swaps.get(p)
      const count = (fsState.readCounts.get(p) ?? 0) + 1
      fsState.readCounts.set(p, count)
      if (swap && count > swap.afterReads) {
        return options === undefined ? Buffer.from(swap.evilText) : swap.evilText
      }
      return (realRead as (...args: unknown[]) => unknown)(path, options)
    }) as typeof actual.readFileSync,
  }
})

const DEFAULT_POLICY_PATH = fileURLToPath(
  new URL('../policies/default-policy.spl.yaml', import.meta.url),
)

let tmpDir: string
const engines: InterventionEngine[] = []

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'dsh-issue164-'))
  fsState.readCounts.clear()
  fsState.swaps.clear()
  delete process.env.DSH_DEBUG
})

afterEach(() => {
  for (const engine of engines.splice(0)) {
    try {
      engine.shutdown()
    } catch {
      /* best-effort teardown */
    }
  }
  rmSync(tmpDir, { recursive: true, force: true })
})

function track(engine: InterventionEngine): InterventionEngine {
  engines.push(engine)
  return engine
}

function makeLogger() {
  const warns: string[] = []
  const errors: string[] = []
  const infos: string[] = []
  const logger = {
    warn: (m: string) => warns.push(m),
    error: (m: string) => errors.push(m),
    info: (m: string) => infos.push(m),
  }
  return { logger, warns, errors, infos }
}

function writePolicy(fileName: string, rules: unknown[], extra: Record<string, unknown> = {}): string {
  const path = join(tmpDir, fileName)
  writeFileSync(
    path,
    JSON.stringify({ apiVersion: 'security.use/v2', kind: 'Policy', metadata: { id: fileName }, rules, ...extra }),
  )
  return path
}

function makeConfig(intervention: Record<string, unknown>): Config {
  return normalizeConfig({
    mode: 'audit',
    collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
    intervention,
  })
}

/** Safe rule used by the defect-1 scenarios. */
const SAFE_RULE = {
  id: 'safe',
  category: 'intrusion_defense',
  priority: 100,
  match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['^echo safe$'] } },
  action: { decision: 'block', blockReason: 'safe', blockCode: 'INTRUSION_DEFENSE_SAFE_001' },
}

/** Attacker rule: swaps the guard to a permissive decision. */
const EVIL_RULE = {
  id: 'evil',
  category: 'intrusion_defense',
  priority: 200,
  match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['^echo safe$'] } },
  action: { decision: 'allow' },
}

describe('hash and parse share one read (TOCTOU)', () => {
  it('reads each policy file exactly once per reload; a mid-reload swap cannot split hash from parse', () => {
    const policyPath = writePolicy('toctou.json', [SAFE_RULE])
    const tamperEvents: unknown[] = []
    const engine = track(
      new InterventionEngine(makeConfig({ policyPath, reloadIntervalMs: 0 }), {
        builtinRulePaths: [],
        onTamper: (info) => tamperEvents.push(info),
      }),
    )

    // Arm the attacker BEFORE the first load: from the SECOND read of
    // this file onward the bytes on "disk" are the swapped policy. Pre-fix
    // code read the file TWICE on the first load (hash, then parse), so
    // the swap landed inside the window: hash(good) passed while the evil
    // rules loaded, with no tamper. Fixed code reads once per reload —
    // the first load sees only the good bytes.
    fsState.swaps.set(policyPath, {
      afterReads: 1,
      evilText: JSON.stringify({ apiVersion: 'security.use/v2', kind: 'Policy', metadata: { id: 'evil' }, rules: [EVIL_RULE] }),
    })
    engine.initialize()

    // The decisive pin: the EVIL rule did NOT load and no tamper fired —
    // the hashed bytes and the parsed bytes are the same bytes.
    expect(fsState.readCounts.get(policyPath)).toBe(1)
    expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['safe'])
    expect(tamperEvents).toHaveLength(0)

    // Next reload: the single read now returns the swapped bytes, so the
    // hash check sees the change and rejects it as tamper (rules stay
    // safe). Exactly one read happened during this reload.
    const readsBefore = fsState.readCounts.get(policyPath) ?? 0
    engine.triggerReload()
    const readsDuringReload = (fsState.readCounts.get(policyPath) ?? 0) - readsBefore

    expect(readsDuringReload).toBe(1)
    expect(engine.getPolicyTamperState().tamperCount).toBe(1)
    expect(tamperEvents).toHaveLength(1)
    expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['safe'])
  })

  it('still detects a genuine swap between two reloads (tamper path intact)', () => {
    const policyPath = writePolicy('between-reloads.json', [SAFE_RULE])
    const tamperEvents: unknown[] = []
    const engine = track(
      new InterventionEngine(makeConfig({ policyPath, reloadIntervalMs: 0 }), {
        builtinRulePaths: [],
        onTamper: (info) => tamperEvents.push(info),
      }),
    )
    engine.initialize()
    expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['safe'])

    // Disk content genuinely changes before the next reload — the very
    // next read returns the swapped bytes, the hash diverges, tamper.
    fsState.swaps.set(policyPath, {
      afterReads: 1,
      evilText: JSON.stringify({ apiVersion: 'security.use/v2', kind: 'Policy', metadata: { id: 'evil' }, rules: [EVIL_RULE] }),
    })
    engine.triggerReload()

    expect(engine.getPolicyTamperState().tamperCount).toBe(1)
    expect(tamperEvents).toHaveLength(1)
    expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['safe'])
  })

  it('loadPolicyFromText parses pre-read bytes; loadMultiplePoliciesFromEntries merges in input order', () => {
    // apiVersion v2 + agent_tool_call规范值 + 空
    // match.actionType → 0 warning。否则旧 fixture(apiVersion v1 +
    // 别名)会触发 advisory 警告。
    const userRaw = JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'u' },
      rules: [{ id: 'user', category: 'behavior_guidance', priority: 50, match: {}, action: { decision: 'allow' } }],
    })
    const builtinRaw = JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'b' },
      rules: [{ id: 'builtin', category: 'behavior_guidance', priority: 50, match: {}, action: { decision: 'allow' } }],
    })
    const single = loadPolicyFromText(userRaw, join(tmpDir, 'virtual-u.json'))
    expect(single.error).toBeUndefined()
    expect(single.rules.map((r) => r.id)).toEqual(['user'])

    const merged = loadMultiplePoliciesFromEntries([
      { path: join(tmpDir, 'u.json'), raw: userRaw },
      { path: join(tmpDir, 'b.json'), raw: builtinRaw },
    ])
    // Equal priority → input order preserved (user shadows builtin).
    expect(merged.rules.map((r) => r.id)).toEqual(['user', 'builtin'])
    expect(merged.errors).toEqual([])
    expect(merged.warnings).toEqual([])
  })
})

describe('broken policy reload is observable', () => {
  /**
   * Engine in bundled-baseline tamper mode: edits to the USER file pass
   * tamper (only the bundled file is hash-pinned), so a broken user file
   * reaches the parse-error path instead of tripping `policy_tamper` —
   * the production scenario this defect is about.
   */
  function bootBundledBaseline(opts: {
    userRules: unknown[]
    logger?: ReturnType<typeof makeLogger>['logger']
    onReloadError?: (info: PolicyReloadErrorInfo) => void
  }): { engine: InterventionEngine; userPath: string; bundledPath: string } {
    const bundledContent = JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'bundled' },
      rules: [
        {
          id: 'bundled-guard',
          category: 'intrusion_defense',
          priority: 10,
          match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['^ls aux$'] } },
          action: { decision: 'block', blockReason: 'bundled', blockCode: 'INTRUSION_DEFENSE_BUNDLED_GUARD_001' },
        },
      ],
    })
    const bundledPath = join(tmpDir, 'bundled-baseline.json')
    writeFileSync(bundledPath, bundledContent, 'utf8')
    const bundledContentHash = createHash('sha256').update(bundledContent).digest('hex')
    const bundledHash = createHash('sha256').update(`${bundledPath}:${bundledContentHash}`).digest('hex')

    const userPath = writePolicy('user-policy.json', opts.userRules)
    const engine = track(
      new InterventionEngine(makeConfig({ policyPaths: [userPath], reloadIntervalMs: 0 }), {
        builtinRulePaths: [bundledPath],
        trustedBaselineHash: bundledHash,
        ...(opts.logger ? { logger: opts.logger } : {}),
        ...(opts.onReloadError ? { onReloadError: opts.onReloadError } : {}),
      }),
    )
    engine.initialize()
    return { engine, userPath, bundledPath }
  }

  const USER_RULE = {
    id: 'user-rule',
    category: 'intrusion_defense',
    priority: 100,
    match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['^echo user$'] } },
    action: { decision: 'block', blockReason: 'user', blockCode: 'INTRUSION_DEFENSE_USER_RULE_001' },
  }

  it('warns loudly + fires onReloadError when the operator policy breaks (no DSH_DEBUG needed)', () => {
    const { logger, warns } = makeLogger()
    const reloadErrors: PolicyReloadErrorInfo[] = []
    const { engine, userPath } = bootBundledBaseline({
      userRules: [USER_RULE],
      logger,
      onReloadError: (info) => reloadErrors.push(info),
    })
    expect(reloadErrors).toHaveLength(0)
    expect(engine.getLoadedPolicy().rules.map((r) => r.id).sort()).toEqual(['bundled-guard', 'user-rule'])

    // Operator saves a broken policy (schema-invalid kind).
    writeFileSync(
      userPath,
      JSON.stringify({ apiVersion: 'security.use/v2', kind: 'Bananas', metadata: { id: 'user-policy.json' }, rules: [USER_RULE] }),
    )
    engine.triggerReload()

    expect(warns.some((m) => m.includes('POLICY RELOAD FAILED'))).toBe(true)
    expect(reloadErrors).toHaveLength(1)
    expect(reloadErrors[0].firstFailure).toBe(true)
    expect(reloadErrors[0].policyPath).toContain(userPath)
    expect(reloadErrors[0].error).toMatch(/kind/)
    // Bundled file still parses → rule set reduced, not zeroed.
    expect(reloadErrors[0].ruleCount).toBe(1)
    expect(engine.getLoadedPolicy().error).toBeTruthy()
    expect(engine.getLastLoadErrors().some((e) => e.path === userPath)).toBe(true)
  })

  it('fails loud at STARTUP when the policy is already broken (previously silent)', () => {
    const { logger, warns } = makeLogger()
    const reloadErrors: PolicyReloadErrorInfo[] = []
    const bundledContent = JSON.stringify({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'bundled' },
      rules: [],
    })
    const bundledPath = join(tmpDir, 'bundled-startup.json')
    writeFileSync(bundledPath, bundledContent, 'utf8')
    const bundledHash = createHash('sha256')
      .update(`${bundledPath}:${createHash('sha256').update(bundledContent).digest('hex')}`)
      .digest('hex')

    const userPath = join(tmpDir, 'broken-at-startup.json')
    writeFileSync(userPath, '{ this is not valid JSON', 'utf8')

    const engine = track(
      new InterventionEngine(makeConfig({ policyPaths: [userPath], reloadIntervalMs: 0 }), {
        builtinRulePaths: [bundledPath],
        trustedBaselineHash: bundledHash,
        logger,
        onReloadError: (info) => reloadErrors.push(info),
      }),
    )
    engine.initialize()

    expect(warns.some((m) => m.includes('POLICY RELOAD FAILED'))).toBe(true)
    expect(reloadErrors).toHaveLength(1)
    expect(reloadErrors[0].firstFailure).toBe(true)
    expect(reloadErrors[0].ruleCount).toBe(0)
    expect(engine.getLoadedPolicy().rules).toHaveLength(0)
  })

  it('does not re-emit while the same error persists; re-emits when the error changes; stops after recovery', () => {
    const { logger } = makeLogger()
    const reloadErrors: PolicyReloadErrorInfo[] = []
    const { engine, userPath } = bootBundledBaseline({
      userRules: [USER_RULE],
      logger,
      onReloadError: (info) => reloadErrors.push(info),
    })

    const brokenKind = JSON.stringify({ apiVersion: 'security.use/v2', kind: 'Bananas', metadata: { id: 'user-policy.json' }, rules: [USER_RULE] })
    const brokenJson = '{ nope'

    writeFileSync(userPath, brokenKind)
    engine.triggerReload()
    expect(reloadErrors).toHaveLength(1)
    expect(reloadErrors[0].firstFailure).toBe(true)

    // Same broken file, watcher fires again → same error text → no spam.
    engine.triggerReload()
    expect(reloadErrors).toHaveLength(1)

    // Different breakage → new error text → one more event.
    writeFileSync(userPath, brokenJson)
    engine.triggerReload()
    expect(reloadErrors).toHaveLength(2)
    expect(reloadErrors[1].firstFailure).toBe(false)

    // Recovery → no further events, error cleared.
    writeFileSync(userPath, JSON.stringify({ apiVersion: 'security.use/v2', kind: 'Policy', metadata: { id: 'user-policy.json' }, rules: [USER_RULE] }))
    engine.triggerReload()
    expect(reloadErrors).toHaveLength(2)
    expect(engine.getLoadedPolicy().error).toBeUndefined()
    expect(engine.getLoadedPolicy().rules.map((r) => r.id).sort()).toEqual(['bundled-guard', 'user-rule'])
  })

  it('keeps the surviving rules effective after a reload failure', async () => {
    const { logger } = makeLogger()
    const reloadErrors: PolicyReloadErrorInfo[] = []
    const { engine, userPath } = bootBundledBaseline({
      userRules: [USER_RULE],
      logger,
      onReloadError: (info) => reloadErrors.push(info),
    })
    writeFileSync(userPath, '{ broken')
    engine.triggerReload()
    expect(reloadErrors).toHaveLength(1)

    // Bundled guard still blocks its command…
    const blocked = await engine.evaluate({ actionType: 'tool_call', toolName: 'bash', params: { command: 'ls aux' } })
    expect(blocked.decision).toBe('block')
    expect(blocked.block_code).toBe('INTRUSION_DEFENSE_BUNDLED_GUARD_001')
    // …and the broken file's rule no longer exists (no stale guarding).
    const allowed = await engine.evaluate({ actionType: 'tool_call', toolName: 'bash', params: { command: 'echo user' } })
    expect(allowed.decision).toBe('allow')
  })

  it('a throwing onReloadError callback does not break the engine (invariant #3)', () => {
    const { logger } = makeLogger()
    const userPath = writePolicy('throwing-cb.json', [USER_RULE])
    const engine = track(
      new InterventionEngine(makeConfig({ policyPath: userPath, reloadIntervalMs: 0 }), {
        builtinRulePaths: [],
        logger,
        onReloadError: () => {
          throw new Error('callback boom')
        },
      }),
    )
    expect(() => engine.initialize()).not.toThrow()
    writeFileSync(userPath, '{ broken')
    expect(() => engine.triggerReload()).not.toThrow()
  })

  it('emits a security_audit/policy_reload_error row through the real apply() bootstrap', async () => {
    const eventsPath = join(tmpDir, 'bootstrap-events.jsonl')
    const debugLogPath = join(tmpDir, 'bootstrap-debug.log')
    const brokenPath = join(tmpDir, 'bootstrap-broken.json')
    writeFileSync(brokenPath, '{ not valid json', 'utf8')

    const errorLines: string[] = []
    const ctx = {
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: (m: string) => errorLines.push(m),
      },
      on: () => {},
      effect: () => {},
      inject: () => {},
      reflect: { get: () => undefined, _getImpl: () => undefined, store: {}, props: {} },
    } as unknown as Context

    apply(ctx, {
      enabled: true,
      mode: 'audit',
      collector: { localOutputPath: eventsPath, flushIntervalMs: 10, debugLogPath },
      application: { enabled: true },
      intervention: { mode: 'audit', policyPath: brokenPath },
    })
    await new Promise((resolve) => setTimeout(resolve, 200))

    const rows = readFileSync(eventsPath, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as Record<string, any>)
    const row = rows.find(
      (r) => r.event_type === 'security_audit' && r.audit_details?.event_type_alias === 'policy_reload_error',
    )
    expect(row).toBeDefined()
    expect(row.audit_category).toBe('policy')
    expect(row.audit_action).toBe('warn')
    // Bundled default policy still parses → rules in effect → 'medium'.
    expect(row.severity).toBe('medium')
    expect(row.outcome).toBe('failure')
    expect(String(row.target)).toContain(brokenPath)
    expect(String(row.audit_details.error)).toMatch(/JSON/i)
    expect(row.audit_details.first_failure).toBe(true)
    // The loud warning also reaches the host logger (not console).
    expect(errorLines.some((m) => m.includes('policy_reload_error'))).toBe(true)
  })
})

describe('invalid regexes are fail-loud', () => {
  const POLICY_WITH_BAD_REGEX = JSON.stringify({
    // v2 + 故意保留 `tool_call` 别名 — 这条测试是
    // 单元验证 loader 行为, 不是测别名归一。alias 归一产生 1 条
    // advisory warning, 加上 r-bad 的 regex 失败 = 2 条 warning;
    // 后面断言改为 "≥2" 兼容。
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'p' },
    rules: [
      {
        id: 'r-bad',
        category: 'intrusion_defense',
        priority: 100,
        match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['[unclosed'] } },
        action: { decision: 'block', blockReason: 'bad', blockCode: 'INTRUSION_DEFENSE_BAD_REGEX_001' },
      },
      {
        id: 'r-good',
        category: 'intrusion_defense',
        priority: 90,
        match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['^echo good$'] } },
        action: { decision: 'block', blockReason: 'good', blockCode: 'INTRUSION_DEFENSE_GOOD_REGEX_001' },
      },
    ],
  })

  it('collects the compile failure into LoadResult.warnings and keeps the valid rules', () => {
    const result = loadPolicyFromText(POLICY_WITH_BAD_REGEX, join(tmpDir, 'bad-regex.json'))
    expect(result.error).toBeUndefined()
    expect(result.rules.map((r) => r.id)).toEqual(['r-good'])
    // 2 条 warning(r-bad regex 失败 + tool_call alias)
    const regexWarnings = (result.warnings ?? []).filter((m) =>
      m.includes('[unclosed'),
    )
    expect(regexWarnings).toHaveLength(1)
    expect(result.warnings?.some((m) => m.includes('r-bad') && m.includes('[unclosed'))).toBe(true)
  })

  it('engine logs the warning on reload and the surviving rule still enforces', async () => {
    const { logger, warns } = makeLogger()
    const policyPath = join(tmpDir, 'engine-bad-regex.json')
    writeFileSync(policyPath, POLICY_WITH_BAD_REGEX, 'utf8')
    const engine = track(
      new InterventionEngine(makeConfig({ policyPath, reloadIntervalMs: 0 }), {
        builtinRulePaths: [],
        logger,
      }),
    )
    engine.initialize()

    expect(warns.some((m) => m.includes('policy warning') && m.includes('failed to compile'))).toBe(true)
    expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['r-good'])

    const d = await engine.evaluate({ actionType: 'tool_call', toolName: 'bash', params: { command: 'echo good' } })
    expect(d.decision).toBe('block')
    expect(d.block_code).toBe('INTRUSION_DEFENSE_GOOD_REGEX_001')
  })
})

describe('catastrophic-backtracking guard', () => {
  it('detectUnsafeRegexPattern rejects classic exponential patterns', () => {
    expect(detectUnsafeRegexPattern('(a+)+$')).toBeTruthy()
    expect(detectUnsafeRegexPattern('(a*)*')).toBeTruthy()
    expect(detectUnsafeRegexPattern('(x|xy)*z')).toBeTruthy()
    expect(detectUnsafeRegexPattern('(a|aa)+')).toBeTruthy()
    expect(detectUnsafeRegexPattern('([\\w.]+)+$')).toBeTruthy()
    expect(detectUnsafeRegexPattern('(a|)*b')).toBeTruthy()
  })

  it('detectUnsafeRegexPattern accepts unambiguous nested quantifiers (shipped-policy shape)', () => {
    // The `-e ...` reverse-shell family in the bundled policy: every
    // iteration starts with `-`, which no iteration can end with.
    expect(detectUnsafeRegexPattern('(?:-[a-zA-Z]+\\s+)*-e')).toBeNull()
    expect(detectUnsafeRegexPattern('(x|y)*')).toBeNull()
    expect(detectUnsafeRegexPattern('(ab)+')).toBeNull()
    expect(detectUnsafeRegexPattern('(a|bc)+')).toBeNull()
    expect(detectUnsafeRegexPattern('[\\s\\S]{0,400}?')).toBeNull()
    expect(detectUnsafeRegexPattern('(-[a-zA-Z]*\\s+)?\\S*x')).toBeNull()
  })

  it('the shipped default policy loads with zero regex-safety warnings', () => {
    // `policies/legacy.yaml` removed. The remaining
    // shipped file MUST still load with zero warnings through the regex
    // safety analyzer.
    //
    // spec §0.5 advisory warnings (apiVersion v1
    // actionType alias, evaluate deprecated, ...) are EXPECTED on the
    // shipped file (commit B migrates them out). The "zero warnings"
    // invariant now means "no regex safety rejection" — the catastrophic
    // backtracking detector must NEVER flag the shipped rules. All other
    // warnings are advisory.
    const shipped = loadPolicy(DEFAULT_POLICY_PATH)
    expect(shipped.error).toBeUndefined()
    expect(shipped.rules.length).toBeGreaterThan(0)
    const regexWarnings = (shipped.warnings ?? []).filter((m) =>
      m.includes('catastrophic backtracking') || m.includes('failed to compile'),
    )
    expect(regexWarnings).toEqual([])
  })

  it('rejects a dangerous pattern with a warning while the other rules keep enforcing', async () => {
    const { logger, warns } = makeLogger()
    const policyPath = join(tmpDir, 'redos-policy.json')
    writeFileSync(
      policyPath,
      JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'p' },
        rules: [
          {
            id: 'r-redos',
            category: 'intrusion_defense',
            priority: 100,
            match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['(a+)+$'] } },
            action: { decision: 'block', blockReason: 'redos', blockCode: 'INTRUSION_DEFENSE_REDOS_001' },
          },
          {
            id: 'r-good',
            category: 'intrusion_defense',
            priority: 90,
            match: { actionType: ['tool_call'], toolName: ['bash'], paramsRegex: { command: ['^echo good$'] } },
            action: { decision: 'block', blockReason: 'good', blockCode: 'INTRUSION_DEFENSE_GOOD_REGEX_002' },
          },
        ],
      }),
      'utf8',
    )
    const engine = track(
      new InterventionEngine(makeConfig({ policyPath, reloadIntervalMs: 0 }), {
        builtinRulePaths: [],
        logger,
      }),
    )
    engine.initialize()

    expect(warns.some((m) => m.includes('policy warning') && m.includes('catastrophic backtracking'))).toBe(true)
    // Dangerous pattern skipped, everything else intact.
    expect(engine.getLoadedPolicy().rules.map((r) => r.id)).toEqual(['r-good'])

    // A payload crafted to explode `(a+)+$` evaluates instantly because
    // the pattern never made it into the compiled rule set.
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: `${'a'.repeat(32)}!` },
    })
    expect(d.decision).toBe('allow')

    const blocked = await engine.evaluate({ actionType: 'tool_call', toolName: 'bash', params: { command: 'echo good' } })
    expect(blocked.decision).toBe('block')
    expect(blocked.block_code).toBe('INTRUSION_DEFENSE_GOOD_REGEX_002')
  })
})
