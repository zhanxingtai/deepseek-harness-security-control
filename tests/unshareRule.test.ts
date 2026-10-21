/**
 * Unshare detection tests.
 */
import { describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeConfig, type Config } from '../src/config.js'
import { InterventionEngine } from '../src/intervention/InterventionEngine.js'

describe('SELF_PROTECTION_UNSHARE_034', () => {
  let config: Config
  let interventionEngine: InterventionEngine
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'dsh-unshare-'))
  })

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true })
  })

  function withDefaultPolicy(): InterventionEngine {
    const defaultPolicyPath = fileURLToPath(new URL('../policies/default-policy.spl.yaml', import.meta.url))
    config = normalizeConfig({
      mode: 'enforce',
      collector: { localOutputPath: join(tmpDir, 'security-events.jsonl'), flushIntervalMs: 10 },
      // fix: vitest's per-module instance cost
      // the unicode / fragment-fold pipeline push the default
      // 50ms cooperative deadline past the budget when this file runs
      // alongside the full suite. Tests raise to 5s so the rule set
      // exercises fully without fail-open masking the result.
      // Production callers keep the 50ms cap.
      intervention: { policyPath: defaultPolicyPath, reloadIntervalMs: 0, decisionTimeoutMs: 5_000 },
    })
    interventionEngine = new InterventionEngine(config)
    interventionEngine.initialize()
    return interventionEngine
  }

  it('blocks unshare -p (PID namespace)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'unshare -p bash -c "echo pwned"' },
    })
    expect(d.decision).toBe('block')
    expect(d.block_code).toBe('SELF_PROTECTION_UNSHARE_034')
  })

  it('blocks unshare --pid (long form)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'unshare --pid /bin/bash' },
    })
    expect(d.block_code).toBe('SELF_PROTECTION_UNSHARE_034')
  })

  it('blocks unshare -m -p (mount + PID together)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'unshare -m -p --fork bash' },
    })
    expect(d.block_code).toBe('SELF_PROTECTION_UNSHARE_034')
  })

  it('blocks unshare -fp (fork + PID)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'unshare -fp sh' },
    })
    expect(d.block_code).toBe('SELF_PROTECTION_UNSHARE_034')
  })

  it('ALLOWS unshare without -p / --pid (no PID namespace)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'unshare -m bash' },
    })
    expect(d.decision).toBe('allow')
  })

  it('ALLOWS a benign tool call (no unshare)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'bash',
      params: { command: 'ls -la /tmp' },
    })
    expect(d.decision).toBe('allow')
  })

  it('works for python tool (not just bash)', async () => {
    const engine = withDefaultPolicy()
    const d = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'python',
      params: { command: 'subprocess.run(["unshare", "-p", "/bin/sh"])' },
    })
    expect(d.block_code).toBe('SELF_PROTECTION_UNSHARE_034')
  })
})
