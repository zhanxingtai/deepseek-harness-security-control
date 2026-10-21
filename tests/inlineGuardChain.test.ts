/**
 * Unit tests for `runInlineGuardChain`.
 *
 * The helper is the shared iteration / short-circuit driver used by
 * both `ApplicationCollector.evaluateTool` (tool layer) and
 * `RuntimeHook.runInlineGuards` (pre-spawn seam). These tests cover:
 *   - first non-null decision wins (short-circuit)
 *   - enabled()=false skips a step silently
 *   - enabled()=true runs the step
 *   - an empty chain returns undefined (caller falls through to SPL)
 *   - a step whose evaluate() throws is swallowed (invariant #3)
 *   - declaration order is preserved
 *
 * The Integration contract is verified separately by the per-guard
 * suites (sensitivePathGuard / envPassthroughGuard / inlinePromptInjection)
 * + ApplicationCollector / runtimeHook — those tests assert the chain
 * wires through to the real evaluators.
 */

import { describe, expect, it, vi } from 'vitest'
import { runInlineGuardChain } from '../src/intervention/inlineGuardChain.js'
import type { InterventionContext, SecurityDecision } from '../src/types/index.js'

const CTX: InterventionContext = {
  actionType: 'tool_call',
  toolName: 'bash',
  params: {},
}

function block(policyId: string): SecurityDecision {
  return {
    decision: 'block',
    mode: 'enforce',
    block_reason: `forced ${policyId}`,
    block_code: `${policyId}_001`,
    appealable: false,
    fail_strategy: 'inline_self_protection',
    latency_ms: 0,
    policy_id: policyId,
  }
}

describe('runInlineGuardChain', () => {
  it('returns undefined on an empty chain', () => {
    expect(runInlineGuardChain(CTX, [])).toBeUndefined()
  })

  it('returns undefined when every step declines (returns null)', () => {
    expect(
      runInlineGuardChain(CTX, [
        { label: 'a', evaluate: () => null },
        { label: 'b', evaluate: () => null },
      ]),
    ).toBeUndefined()
  })

  it('returns the first non-null decision and skips subsequent steps', () => {
    const second = vi.fn(() => null)
    const decision = runInlineGuardChain(CTX, [
      { label: 'first', evaluate: () => block('first') },
      { label: 'second', evaluate: second },
      { label: 'third', evaluate: () => block('third') },
    ])
    expect(decision?.policy_id).toBe('first')
    expect(second).not.toHaveBeenCalled()
  })

  it('skips a step whose enabled() returns false', () => {
    const enabled = vi.fn(() => true)
    const enabledFalse = vi.fn(() => false)
    const decision = runInlineGuardChain(CTX, [
      { enabled: enabledFalse, label: 'off', evaluate: () => block('off') },
      { enabled, label: 'on', evaluate: () => block('on') },
    ])
    expect(decision?.policy_id).toBe('on')
    expect(enabledFalse).toHaveBeenCalledTimes(1)
    expect(enabled).toHaveBeenCalledTimes(1)
  })

  it('omitting the enabled() predicate always runs the step', () => {
    const evaluate = vi.fn(() => block('always'))
    const decision = runInlineGuardChain(CTX, [
      { label: 'always', evaluate },
    ])
    expect(decision?.policy_id).toBe('always')
    expect(evaluate).toHaveBeenCalledTimes(1)
  })

  it('swallows evaluate() throws and continues to the next step (invariant #3)', () => {
    const warn = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    try {
      const decision = runInlineGuardChain(CTX, [
        {
          label: 'crash',
          evaluate: () => {
            throw new Error('guard exploded')
          },
        },
        { label: 'recover', evaluate: () => block('recover') },
      ])
      expect(decision?.policy_id).toBe('recover')
    } finally {
      warn.mockRestore()
    }
  })

  it('forwards step errors to onError sink when supplied', () => {
    const onError = vi.fn()
    const decision = runInlineGuardChain(
      CTX,
      [
        {
          label: 'crash',
          evaluate: () => {
            throw new Error('guard exploded')
          },
        },
        { label: 'recover', evaluate: () => block('recover') },
      ],
      onError,
    )
    expect(decision?.policy_id).toBe('recover')
    expect(onError).toHaveBeenCalledTimes(1)
    expect(onError.mock.calls[0][0]).toBe('crash')
    expect(onError.mock.calls[0][1]).toBeInstanceOf(Error)
    expect((onError.mock.calls[0][1] as Error).message).toBe('guard exploded')
  })

  it('does not throw when onError itself throws (sink faults are silent)', () => {
    expect(() =>
      runInlineGuardChain(
        CTX,
        [
          {
            label: 'crash',
            evaluate: () => {
              throw new Error('guard exploded')
            },
          },
          { label: 'recover', evaluate: () => block('recover') },
        ],
        () => {
          throw new Error('sink exploded')
        },
      ),
    ).not.toThrow()
  })

  it('preserves declaration order across many steps', () => {
    const order: string[] = []
    const decision = runInlineGuardChain(CTX, [
      {
        label: 'a',
        evaluate: () => {
          order.push('a')
          return null
        },
      },
      {
        label: 'b',
        evaluate: () => {
          order.push('b')
          return null
        },
      },
      {
        label: 'c',
        evaluate: () => {
          order.push('c')
          return block('c')
        },
      },
      {
        label: 'd',
        evaluate: () => {
          order.push('d')
          return null
        },
      },
    ])
    expect(decision?.policy_id).toBe('c')
    expect(order).toEqual(['a', 'b', 'c'])
  })

  it('forwards the same context to every step', () => {
    const seen: InterventionContext[] = []
    runInlineGuardChain(CTX, [
      {
        label: 'a',
        evaluate: (c) => {
          seen.push(c)
          return null
        },
      },
      {
        label: 'b',
        evaluate: (c) => {
          seen.push(c)
          return null
        },
      },
    ])
    expect(seen).toHaveLength(2)
    expect(seen[0]).toBe(CTX)
    expect(seen[1]).toBe(CTX)
  })
})
