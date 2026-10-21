import { describe, expect, it, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

function makeConfig(tmpDir: string, interventionOverrides?: Record<string, unknown>): Config {
  return normalizeConfig({
    mode: 'enforce',
    intervention: {
      policyPath: join(tmpDir, 'policy.json'),
      reloadIntervalMs: 0,
      ...interventionOverrides,
    },
  })
}

/** Policy with `count` rules that all match a tool_call on toolName 'Bash'. */
function writePolicy(tmpDir: string, count: number): void {
  const rules = Array.from({ length: count }, (_, i) => ({
    id: `rule-${i}`,
    enabled: true,
    priority: 100 - i,
    category: 'intrusion_defense' as const,
    match: { actionType: ['tool_call'], toolName: ['Bash'] },
    action: { decision: 'block', blockCode: `INTRUSION_DEFENSE_TEST_${String(i).padStart(3, '0')}` },
  }))
  writeFileSync(
    join(tmpDir, 'policy.json'),
    JSON.stringify({ apiVersion: 'security.use/v2', kind: 'Policy', metadata: { id: 'test' }, rules }, null, 2),
  )
}

const bashCtx = { actionType: 'tool_call', toolName: 'Bash', params: { command: 'ls' } }

/**
 * The cooperative deadline check inside matchRules runs at rule index 32, 64,
 * ... and compares Date.now() against start + decisionTimeoutMs. Mocking
 * Date.now to jump forward on the second call makes the deadline deterministic
 * without any real waiting.
 */
function mockClockToForceDeadline(): void {
  const realNow = Date.now.bind(Date)
  let calls = 0
  vi.spyOn(Date, 'now').mockImplementation(() => {
    calls += 1
    return calls < 2 ? realNow() : realNow() + 60_000
  })
}

describe('InterventionEngine evaluation deadline (decisionTimeoutMs)', () => {
  const tmpDirs: string[] = []

  afterEach(() => {
    vi.restoreAllMocks()
    for (const d of tmpDirs.splice(0)) {
      if (existsSync(d)) rmSync(d, { recursive: true, force: true })
    }
  })

  function setup(rules: number, interventionOverrides?: Record<string, unknown>): {
    engine: InterventionEngine
    tmpDir: string
  } {
    const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-timeout-'))
    tmpDirs.push(tmpDir)
    writePolicy(tmpDir, rules)
    const engine = new InterventionEngine(makeConfig(tmpDir, interventionOverrides))
    engine.initialize()
    return { engine, tmpDir }
  }

  it('fails open by default when the evaluation deadline is exceeded', async () => {
    const { engine } = setup(40)
    mockClockToForceDeadline()

    const decision = await engine.evaluate(bashCtx)

    expect(decision.decision).toBe('allow')
    expect(decision.fail_strategy).toBe('fail_open')
    expect(decision.reason).toContain('fail-open')
    expect(engine.getEvaluationTimeoutState().timeoutCount).toBe(1)
    expect(engine.getEvaluationTimeoutState().lastTimeoutAt).not.toBeNull()
    engine.shutdown()
  })

  it('fails closed when failStrategy is fail_closed', async () => {
    const { engine } = setup(40, { failStrategy: 'fail_closed' })
    mockClockToForceDeadline()

    const decision = await engine.evaluate(bashCtx)

    expect(decision.decision).toBe('block')
    expect(decision.fail_strategy).toBe('fail_closed')
    engine.shutdown()
  })

  it('fail_open_high_risk_only blocks high-risk contexts on timeout, allows otherwise', async () => {
    const { engine } = setup(40, { failStrategy: 'fail_open_high_risk_only' })
    mockClockToForceDeadline()

    const blocked = await engine.evaluate({ ...bashCtx, riskFlags: ['reverse_shell'] })
    expect(blocked.decision).toBe('block')

    mockClockToForceDeadline()
    const allowed = await engine.evaluate(bashCtx)
    expect(allowed.decision).toBe('allow')
    engine.shutdown()
  })

  it('does not trigger when the evaluation finishes within the deadline', async () => {
    const { engine } = setup(40)
    // No clock mock: 40 cheap rules finish in microseconds.

    const decision = await engine.evaluate(bashCtx)

    expect(decision.decision).toBe('block')
    expect(engine.getEvaluationTimeoutState().timeoutCount).toBe(0)
    engine.shutdown()
  })

  it('decisionTimeoutMs <= 0 disables the deadline', async () => {
    const { engine } = setup(40, { decisionTimeoutMs: 0 })
    mockClockToForceDeadline()

    const decision = await engine.evaluate(bashCtx)

    expect(decision.decision).toBe('block')
    expect(engine.getEvaluationTimeoutState().timeoutCount).toBe(0)
    engine.shutdown()
  })
})
