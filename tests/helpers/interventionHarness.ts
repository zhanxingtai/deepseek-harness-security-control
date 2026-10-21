/**
 * Shared test harness for tests/intervention.test.ts.
 *
 * Setup helpers that used to be duplicated at the top of the test file
 * (makeAgent / makeConfig / writePolicy / withDefaultPolicy) plus the
 * pipeline boot helper used by the table-driven default-policy cases.
 */
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../../src/config.js'
import { LocalNdjsonSink } from '../../src/collectors/LocalNdjsonSink.js'
import { ApplicationCollector } from '../../src/collectors/ApplicationCollector.js'
import { InterventionEngine } from '../../src/intervention/InterventionEngine.js'
import type { Agent, ToolExecution } from '../../src/types/external.js'

/** Absolute path of the shipped default SPL policy. */
export const DEFAULT_POLICY_PATH = fileURLToPath(
  new URL('../../policies/default-policy.spl.yaml', import.meta.url),
)

export function makeAgent(overrides?: Partial<Agent>): Agent {
  return {
    id: 'agent-1',
    session: {
      header: { id: 'session-1', createdAt: Date.now() },
      events: [],
    },
    options: { provider: 'test', model: 'test-model' },
    ...overrides,
  } as Agent
}

export function makeConfig(
  tmpDir: string,
  mode: 'audit' | 'enforce' = 'audit',
  policyPath: string = join(tmpDir, 'policy.json'),
): Config {
  return normalizeConfig({
    mode,
    collector: {
      localOutputPath: join(tmpDir, 'security-events.jsonl'),
      flushIntervalMs: 10,
    },
    intervention: {
      policyPath,
      reloadIntervalMs: 0,
      // fix: vitest's per-module instance cost
      // the unicode / fragment-fold pipeline push the default
      // 50ms cooperative deadline past the budget on a slow host. Tests
      // raise to 5s so the rule set exercises fully without fail-open
      // masking the result. Production callers keep the 50ms cap.
      decisionTimeoutMs: 5_000,
    },
  })
}

export function writePolicy(tmpDir: string, rules: unknown[]): void {
  const policy = {
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'test-policy' },
    rules,
  }
  writeFileSync(join(tmpDir, 'policy.json'), JSON.stringify(policy, null, 2))
}

/** helper: build an InterventionEngine bound to the shipped default policy.
 *  Replaces 3 identical local copies that lived inside describe blocks
 *  `default policy: uninstall-attack hardening`, `SELF_PROTECTION_PATH_GUARD_033`,
 *  and `Field-level softening detection`. The `tmpDir` is the per-test scratch
 *  directory created by the describe's beforeEach — the caller still owns its
 *  lifecycle (rmSync in afterEach). */
export function withDefaultPolicy(
  tmpDir: string,
  decisionTimeoutMs?: number,
): InterventionEngine {
  const cfg = makeConfig(tmpDir, 'enforce', DEFAULT_POLICY_PATH)
  if (decisionTimeoutMs !== undefined) {
    cfg.intervention.decisionTimeoutMs = decisionTimeoutMs
  }
  const engine = new InterventionEngine(cfg)
  engine.initialize()
  return engine
}

/** Boot an enforce-mode engine against a JSON policy written to `policy.json`
 *  in `tmpDir`. Used by the nested escalate/degrade decision tests. */
export function engineWithRules(tmpDir: string, rules: unknown[]): InterventionEngine {
  writePolicy(tmpDir, rules)
  const engine = new InterventionEngine(makeConfig(tmpDir, 'enforce'))
  engine.initialize()
  return engine
}

export interface Pipeline {
  config: Config
  eventCollector: LocalNdjsonSink
  interventionEngine: InterventionEngine
  collector: ApplicationCollector
}

/** Boot the full sink + engine + collector pipeline against `policyPath`.
 *  The caller owns shutdown of every returned component. */
export function startPipeline(tmpDir: string, policyPath: string, mode: 'audit' | 'enforce' = 'audit'): Pipeline {
  const config = makeConfig(tmpDir, mode, policyPath)
  const eventCollector = new LocalNdjsonSink(config)
  const interventionEngine = new InterventionEngine(config)
  const collector = new ApplicationCollector(config, eventCollector, interventionEngine)
  eventCollector.initialize()
  collector.initialize()
  interventionEngine.initialize()
  return { config, eventCollector, interventionEngine, collector }
}

export function makeToolExec(name: string, arguments_: Record<string, unknown>): ToolExecution {
  return {
    callId: 'call-1',
    rootCallId: 'call-1',
    name,
    arguments: arguments_,
    agent: makeAgent(),
    signal: new AbortController().signal,
  }
}
