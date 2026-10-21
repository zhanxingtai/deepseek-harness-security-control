/**
 * Self-Protection Tool Guard — `ctx.tools.guard` seam ( §6.2).
 *
 * The 3 hardcoded inline self-protection rules (uninstall / kill / restart-
 * without-patch, see `InlineSelfProtection.ts`) are the non-overridable
 * safety net. Historically they were evaluated inside the
 * `tools/pre-execute` waterfall via `ApplicationCollector.evaluateTool` —
 * an ASYNC path that carries SPL folding + decision-timeout latency and,
 * worse, only denies when `config.mode === 'enforce'` (in `audit` mode the
 * attack was audited-but-allowed).
 *
 * This module moves the tool-layer enforcement to the harness
 * `ctx.tools.guard()` seam, where Cordis evaluates guards SYNCHRONOUSLY
 * after every pre-execute listener and before the tool body. Returning a
 * string is a monotonic denial — independent of `config.mode`, no timeout,
 * no async waterfall. The guard callback is a pure synchronous deny-list
 * match (compiled regex bundle cached at module scope in
 * `InlineSelfProtection`), so 9 stays well under 5 ms.
 *
 * Double-audit prevention: the pre-execute waterfall NO LONGER evaluates
 * inline self-protection (removed from `evaluateTool`; the sensitive-path /
 * prompt-injection / env-passthrough guards stay there unchanged). When the
 * guard denies, exactly ONE audit event is emitted here —
 * `security_audit` with `audit_details.policy_id: 'inline-self-protection'`.
 * The pre-execute `agent_tool_call` event for the same call still exists
 * (it fired before the guard, as an allow-shaped audit record), but the
 * block decision itself is recorded exactly once, on this seam.
 *
 * Fail-closed rationale: any unexpected exception inside the guard callback
 * returns a generic denial string instead of rethrowing. Invariant
 * forbids throwing to the host, and for the self-protection surface a
 * silently-disabled safety net is the worst failure mode — denying the
 * call is always recoverable (the model can retry with a different tool),
 * while allowing an uninstall / kill because the guard crashed is not.
 * (`evaluateInlineSelfProtection` itself already swallows matcher errors
 * and returns null; the outer catch here is defense-in-depth for wrapper /
 * event-construction bugs.)
 *
 * The RuntimeHook (subprocess spawn) seam keeps its own inline evaluation —
 * spawn has no guard concept.
 */

import type { Context, ToolExecution, ToolGuard, ToolsRuntimeLike } from '../types/external.js'
import type { SecurityDecision, SecurityEvent } from '../types/index.js'
import { DEFAULT_PLATFORM_ID } from '../types/index.js'
import { buildHostMeta } from '../collectors/LocalNdjsonSink.js'
import { generateEventId } from '../utils/eventId.js'
import { nowMs } from '../utils/time.js'
import {
  evaluateInlineSelfProtection,
  type InlineGuardsConfig,
} from './InlineSelfProtection.js'
import type { RuntimeHookSessionContext } from './InterventionEngine.js'

/** Injectable dependencies for the self-protection guard. */
export interface SelfProtectionGuardDeps {
  /** Launcher / package-name deny-list configuration (`config.inlineGuards`). */
  guards: InlineGuardsConfig
  /** Local NDJSON sink — the guard denial audit event is queued here. */
  eventCollector: { report(event: SecurityEvent): void }
  /** Best-effort session identity for the audit event. */
  sessionResolve: () => RuntimeHookSessionContext | undefined
  /** Warn sink for guard-internal failures (invariant #3: log, never throw). */
  logger: { warn: (message: string, ...args: unknown[]) => void }
  /** Clock override for tests. Defaults to `nowMs()`. */
  now?: () => number
}

/**
 * Generic denial reason used when the guard wrapper itself fails
 * (fail-closed path). Deliberately vague — it should only ever surface
 * when the guard module is broken, and the audit event carries the
 * diagnostic detail.
 */
const FAIL_CLOSED_REASON =
  '工具调用被 self-protection 守卫保守拒绝（守卫内部异常，fail-closed）'

/**
 * Build the `ctx.tools.guard` callback for the 3 inline self-protection
 * rules. The returned function is synchronous, never throws, and does not
 * mutate the (readonly) execution payload — it only reads `name` /
 * `arguments` and copies the params record reference.
 */
export function createSelfProtectionGuard(deps: SelfProtectionGuardDeps): ToolGuard {
  return (execution: Readonly<ToolExecution>): string | undefined => {
    try {
      const params = extractParams(execution.arguments)
      const decision = evaluateInlineSelfProtection(
        {
          actionType: 'tool_call',
          toolName: execution.name,
          params,
          body: typeof params['body'] === 'string' ? params['body'] : undefined,
        },
        deps.guards,
      )
      if (!decision) return undefined
      emitGuardDenial(deps, execution, decision)
      return decision.block_reason ?? FAIL_CLOSED_REASON
    } catch (error: unknown) {
      // Fail-closed (see module header): the guard crashed — deny the call
      // rather than silently dropping the safety net. Never rethrow
      // (invariant #3).
      try {
        deps.logger.warn(
          `[SecurityMonitor] self-protection guard failed; fail-closed denial: ${String(error)}`,
        )
      } catch {
        // logger itself must not break the guard
      }
      return FAIL_CLOSED_REASON
    }
  }
}

/**
 * Register the guard on the live `ctx.tools` service. Follows the
 * RuntimeHook convention: the harness `external.ts` stub does not declare
 * the service, so we reach through a typed cast. Returns false (without
 * throwing) when the service is unavailable or `guard()` rejects.
 */
export function installSelfProtectionGuard(ctx: Context, guard: ToolGuard): boolean {
  const tools = (ctx as unknown as { tools?: ToolsRuntimeLike }).tools
  if (!tools || typeof tools.guard !== 'function') return false
  const dispose = tools.guard(guard)
  ctx.effect(() => dispose, 'security-monitor: self-protection guard disposer')
  return true
}

// --- internal helpers ---------------------------------------------------------

function extractParams(arguments_: unknown): Record<string, unknown> {
  if (typeof arguments_ === 'object' && arguments_ !== null && !Array.isArray(arguments_)) {
    return arguments_ as Record<string, unknown>
  }
  return {}
}

/**
 * Emit the single audit record for a guard denial. Failures are swallowed
 * (warn-only): the denial decision must stand even when the audit sink is
 * unavailable — a missing audit trail is an operator problem, not a reason
 * to let an uninstall / kill through.
 */
function emitGuardDenial(
  deps: SelfProtectionGuardDeps,
  execution: Readonly<ToolExecution>,
  decision: SecurityDecision,
): void {
  try {
    const session = deps.sessionResolve()
    const ts = deps.now?.() ?? nowMs()
    const event: SecurityEvent = {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: 'security_audit',
      layer: 'application',
      source_layer: 'application',
      ts,
      timestamp: ts,
      pid: process.pid,
      collection_method: 'agent_api',
      session_id: session?.sessionId,
      run_id: session?.runId,
      agent_id: session?.agentId,
      tool_name: execution.name,
      audit_category: 'policy',
      audit_action: 'block',
      severity: 'high',
      summary: `self-protection guard denied tool '${execution.name}' (${decision.block_code ?? 'unknown'})`,
      target: execution.name,
      outcome: 'blocked',
      reason: 'block',
      blocked: true,
      audit_details: {
        event_type_alias: 'self_protection_guard_denied',
        policy_id: 'inline-self-protection',
        policy_name: decision.policy_name,
        block_code: decision.block_code,
        block_reason: decision.block_reason,
        tool_name: execution.name,
        guard_seam: 'ctx.tools.guard',
      },
      ...buildHostMeta(),
    }
    deps.eventCollector.report(event)
  } catch (error: unknown) {
    try {
      deps.logger.warn(
        `[SecurityMonitor] self-protection guard denial audit emit failed: ${String(error)}`,
      )
    } catch {
      // best-effort
    }
  }
}
