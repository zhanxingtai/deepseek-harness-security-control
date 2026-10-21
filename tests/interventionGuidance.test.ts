/**
 * 2026-08-28) wiring test — InterventionEngine ↔ GuidanceStateMachine.
 *
 * SPL v2 spec §5.1 line 95 rejects `guide` /
 * `context_adjust` / `substitute` / `degrade` / `approve` at load time.
 * The GuidanceStateMachine contract (`context_adjust` decision with
 * `guidance: { template_id, max_attempts, … }`) depends on the v1
 * decision vocabulary that v2 retires. The tests below now pin the
 * NEW contract — rules carrying a v1 deprecated decision are
 * dropped at compile time with a warning that names the deprecated
 * value, and the engine evaluates to the default `allow` because no
 * rule ever fires.
 *
 * Coverage:
 *   1. context_adjust rule is dropped + warning mentions "context_adjust".
 *   2. guide / substitute / degrade / approve are all rejected.
 *   3. Other v2 decisions in the same file are kept (only the v1 row drops).
 *   4. evaluate() returns the default allow when only v1 rules are loaded.
 *   5. non-context_adjust (v2) decisions keep the engine's normal verdict.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'
import type { InterventionContext } from '../src/types/index.js'

function makeConfig(tmpDir: string): Config {
  return normalizeConfig({
    mode: 'audit',
    collector: {
      localOutputPath: join(tmpDir, 'security-events.jsonl'),
      flushIntervalMs: 10,
    },
    intervention: {
      policyPath: join(tmpDir, 'policy.json'),
      reloadIntervalMs: 0,
    },
  })
}

function writeGuidancePolicy(
  tmpDir: string,
  rule: Record<string, unknown>,
): void {
  const policy = {
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata: { id: 'guidance-test' },
    rules: [rule],
  }
  writeFileSync(join(tmpDir, 'policy.json'), JSON.stringify(policy, null, 2))
}

const baseCtx = (sessionId: string): InterventionContext => ({
  actionType: 'tool_call',
  toolName: 'bash',
  params: { command: 'echo hi' },
  sessionId,
  runId: 'run-1',
})

// every v1 deprecated decision the spec retires.
const V1_DECISIONS = ['guide', 'context_adjust', 'substitute', 'degrade', 'approve'] as const

describe('InterventionEngine — GuidanceStateMachine promotion (deprecated)', () => {
  let tmpDir: string
  let engine: InterventionEngine

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'sst-security-control-dsh-guidance-'))
  })

  afterEach(() => {
    engine?.shutdown()
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('rejects a context_adjust rule with a warning and drops it from the loaded rule set', () => {
    const config = makeConfig(tmpDir)
    writeGuidancePolicy(tmpDir, {
      id: 'guidance-echo',
      name: 'echo-guidance',
      enabled: true,
      priority: 1000,
      category: 'behavior_guidance',
      match: { actionType: ['tool_call'], toolName: ['bash'] },
      action: {
        decision: 'context_adjust',
        guidance: {
          template_id: 'tpl-1',
          template_version: 1,
          rendered: 'Try a different phrasing next time.',
          allowed_scope: 'in_session',
          escalate_threshold: 2,
          max_attempts: 3,
        },
      },
    })
    engine = new InterventionEngine(config)
    engine.initialize()

    const loaded = engine.getLoadedPolicy()
    expect(loaded.rules.map((r) => r.id)).not.toContain('guidance-echo')
    expect(loaded.warnings ?? []).toEqual(
      expect.arrayContaining([
        expect.stringContaining('context_adjust'),
        expect.stringContaining('deprecated v1 decision'),
        expect.stringContaining('guidance-echo'),
      ]),
    )
  })

  it('rejects every v1 deprecated decision (guide / context_adjust / substitute / degrade / approve)', () => {
    for (const decision of V1_DECISIONS) {
      const localTmpDir = mkdtempSync(join(tmpdir(), 'sst-security-control-dsh-guidance-'))
      try {
        const config = makeConfig(localTmpDir)
        writeFileSync(
          join(localTmpDir, 'policy.json'),
          JSON.stringify({
            apiVersion: 'security.use/v2',
            kind: 'Policy',
            metadata: { id: 'guidance-test' },
            rules: [
              {
                id: `v1-${decision}`,
                enabled: true,
                priority: 1000,
                category: 'behavior_guidance',
                match: { actionType: ['tool_call'], toolName: ['bash'] },
                action: { decision, guidance: { template_id: 'tpl' } },
              },
            ],
          }),
        )
        const localEngine = new InterventionEngine(config)
        localEngine.initialize()
        const loaded = localEngine.getLoadedPolicy()
        expect(loaded.rules.map((r) => r.id)).not.toContain(`v1-${decision}`)
        expect(loaded.warnings ?? []).toEqual(
          expect.arrayContaining([
            expect.stringContaining(decision),
            expect.stringContaining('deprecated v1 decision'),
          ]),
        )
        localEngine.shutdown()
      } finally {
        rmSync(localTmpDir, { recursive: true, force: true })
      }
    }
  })

  it('keeps v2 rules in the same file; only the v1 row is dropped', () => {
    const config = makeConfig(tmpDir)
    writeFileSync(
      join(tmpDir, 'policy.json'),
      JSON.stringify({
        apiVersion: 'security.use/v2',
        kind: 'Policy',
        metadata: { id: 'guidance-test' },
        rules: [
          {
            id: 'kept-block',
            enabled: true,
            priority: 1000,
            category: 'intrusion_defense',
            match: { actionType: ['tool_call'], toolName: ['bash'] },
            action: { decision: 'block', blockReason: 'kept', blockCode: 'INTRUSION_DEFENSE_TEST_KEPT_BLOCK_001' },
          },
          {
            id: 'dropped-context-adjust',
            enabled: true,
            priority: 1000,
            category: 'behavior_guidance',
            match: { actionType: ['tool_call'], toolName: ['bash'] },
            action: { decision: 'context_adjust', guidance: { template_id: 'tpl' } },
          },
        ],
      }),
    )
    engine = new InterventionEngine(config)
    engine.initialize()

    const loaded = engine.getLoadedPolicy()
    expect(loaded.rules.map((r) => r.id)).toContain('kept-block')
    expect(loaded.rules.map((r) => r.id)).not.toContain('dropped-context-adjust')
    expect(loaded.warnings ?? []).toEqual(
      expect.arrayContaining([expect.stringContaining('context_adjust')]),
    )
  })

  it('evaluate() returns default allow when only v1 deprecated rules are loaded', async () => {
    const config = makeConfig(tmpDir)
    writeGuidancePolicy(tmpDir, {
      id: 'guidance-echo',
      enabled: true,
      priority: 1000,
      category: 'behavior_guidance',
      match: { actionType: ['tool_call'], toolName: ['bash'] },
      action: {
        decision: 'context_adjust',
        guidance: { template_id: 'tpl-1', max_attempts: 3, rendered: 'hi' },
      },
    })
    engine = new InterventionEngine(config)
    engine.initialize()

    const decision = await engine.evaluate(baseCtx('s1'))
    expect(decision.decision).toBe('allow')
    // The guidance seam never engaged — no guidance_count, no escalate.
    expect(decision.guidance_count).toBeUndefined()
    expect(decision.escalate_promoted).toBeUndefined()
    expect(decision.escalate).toBeUndefined()
  })

  it('v2 block rules are unaffected by v1 rejection and fire normally', async () => {
    const config = makeConfig(tmpDir)
    writeGuidancePolicy(tmpDir, {
      id: 'always-block',
      name: 'always-block',
      enabled: true,
      priority: 1000,
      category: 'intrusion_defense',
      match: { actionType: ['tool_call'], toolName: ['bash'] },
      action: { decision: 'block', blockReason: 'test', blockCode: 'INTRUSION_DEFENSE_TEST_ALWAYS_BLOCK_001' },
    })
    engine = new InterventionEngine(config)
    engine.initialize()

    for (let i = 0; i < 5; i++) {
      const d = await engine.evaluate(baseCtx('sblock'))
      expect(d.decision).toBe('block')
      expect(d.guidance_count).toBeUndefined()
      expect(d.escalate_promoted).toBeUndefined()
    }
  })
})
