/**
 * EventEmitter — event-infrastructure for `ApplicationCollector`.
 *
 * Owns the canonical base-event shape, the `source` / `collector` stamping,
 * the SPL-decision → event-payload application, and the event-report wiring
 * to `LocalNdjsonSink`. Pure aside from the shared stats counter that
 * `ApplicationCollector` also reads via `getStats()`.
 *
 * Public API surface (consumed by ApplicationCollector):
 *   - `makeBaseEvent(eventType, sessionContext)` — build the platform-
 *     standard event shell (comm / event_id / event_type / layer /
 *     source_layer / ts / pid / session_id / run_id / agent_id /
 *     buildHostMeta() / blocked:false).
 *   - `stampSource(event, collector)` — stamp `source` + structured
 *     `collector` metadata per the platform spec (`source` is a string,
 *     hook/middleware/collector details live on `collector`).
 *   - `applyDecisionToEvent(event, decision?)` — hoist the SPL decision
 *     onto the emitted event (`blocked`, top-level `block_reason`,
 *     `intervention` with marketplace 3-action vocabulary, optional
 *     `risk_assessment`).
 *   - `emit(event)` — call `LocalNdjsonSink.report()` and bump the
 *     shared `eventsEmitted` counter.
 *
 * The class is intentionally framework-light: no Cordis, no fs I/O,
 * no session lookups. All it owns is the (LocalNdjsonSink, stats,
 * logger) triple + the four methods above.
 */
import type { LocalNdjsonSink } from './LocalNdjsonSink.js'
import { buildHostMeta } from './LocalNdjsonSink.js'
import { DEFAULT_PLATFORM_ID, type SecurityDecision, type SecurityEvent, type SessionContext, type SourceMeta } from '../types/index.js'
import { generateEventId } from '../utils/eventId.js'
import { nowMs } from '../utils/time.js'
import { toMarketplaceDecision } from '../utils/decisionVocabulary.js'

/** Stats counter shared with the host `ApplicationCollector` so `getStats()`
 *  keeps reading one shape. The host owns the lifetime; we only mutate
 *  `eventsEmitted`. */
export interface EventEmitterStats {
  eventsEmitted: number
}

export class EventEmitter {
  private readonly eventCollector: LocalNdjsonSink
  private readonly stats: EventEmitterStats

  constructor(eventCollector: LocalNdjsonSink, stats: EventEmitterStats) {
    this.eventCollector = eventCollector
    this.stats = stats
  }

  /**
   * Build the platform-standard base event shell. Every emitted event
   * starts from this shape; per-`event_type` fields are stamped onto the
   * returned object by the caller (or by `applyDecisionToEvent` /
   * `stampSource`).
   *
   * `blocked: false` is the default; SPL blocks hoist it to `true` via
   * `applyDecisionToEvent`. The shape is identical to the pre-extraction
   * private helper at `ApplicationCollector.ts:1434-1452`.
   */
  makeBaseEvent(eventType: string, sessionContext: SessionContext): SecurityEvent {
    const ts = nowMs()
    return {
      comm: DEFAULT_PLATFORM_ID,
      event_id: generateEventId(),
      event_type: eventType,
      layer: 'application',
      source_layer: 'application',
      ts,
      timestamp: ts,
      pid: process.pid,
      collection_method: 'agent_api',
      session_id: sessionContext.sessionId,
      run_id: sessionContext.runId,
      agent_id: sessionContext.agentId,
      ...buildHostMeta(),
      blocked: false,
    }
  }

  /**
   * Stamp the platform-standard `source` string and structured `collector`
   * metadata onto an application-layer event. Per the platform spec,
   * `source` must be a string, not an object; hook/middleware/collector
   * details live on `collector`.
   *
   * Source string is the marketplace form's stable identifier — the
   * 0.4.0 segment is the bundled-plugin release that introduced the
   * class, not a runtime version. Audit consumers rely on the literal.
   */
  stampSource(event: SecurityEvent, collector: SourceMeta): void {
    event.source = 'sst-security-control-dsh.application-collector.0.4.0'
    event.collector = collector
  }

  /**
   * Hoist a SPL `SecurityDecision` onto the emitted event. Three pieces
   * of the decision land on the event:
   *   1. `blocked: boolean` — convenience filter for dashboards
   *   2. top-level `block_reason` (only on `decision === 'block'`) — single
   *      field for the SPL engine / inline self-protection layers
   *   3. `intervention` — the marketplace wire vocabulary:
   *        - `decision` is the 3-action projection
   *          (`allow | deny | ask`)
   *        - `decision_internal` preserves the SPL 10-action vocabulary
   *          (`block`, `modify`, `substitute`, …) for audit consumers
   *        - `fail_strategy` is stripped (preserved on the internal
   *          SecurityDecision for telemetry but not part of the platform
   *          `intervention` field table)
   *
   * No-op when `decision` is undefined (the audit-mode default — the
   * call still succeeds without the intervention shape on the event).
   */
  applyDecisionToEvent(event: SecurityEvent, decision?: SecurityDecision): void {
    if (!decision) return
    event.blocked = decision.decision === 'block'
    // Top-level block_reason : the tool-layer decision
    // already carries its own block_reason via the SPL engine / inline
    // self-protection. Hoist it to the event's top-level so audit
    // dashboards have a single field to filter on across both layers.
    if (decision.decision === 'block' && decision.block_reason) {
      event.block_reason = decision.block_reason
    }
    // fail_strategy is preserved on the internal SecurityDecision for
    // telemetry, but the platform `intervention` field table does not list it,
    // so it is not propagated to the emitted event payload.
    // marketplace wire vocabulary — the wire-level
    // `decision` is the 3-action projection (`allow | deny | ask`), and
    // the SPL internal 10-action decision is preserved on
    // `decision_internal` for audit consumers.
    event.intervention = decision.intervention
      ? {
          ...withoutFailStrategy(decision.intervention),
          decision: toMarketplaceDecision(decision.decision),
          decision_internal: decision.decision,
        }
      : {
          decision: toMarketplaceDecision(decision.decision),
          decision_internal: decision.decision,
          mode: decision.mode,
          block_reason: decision.block_reason,
          block_code: decision.block_code,
          appealable: decision.appealable,
          // severity trace copied onto the fallback event so
          // the wire-side BlockRow can read it whether the upstream
          // produced a full Intervention object or not.
          severity: decision.severity,
          severity_downgraded: decision.severity_downgraded,
          severity_rule_id: decision.severity_rule_id,
        }
    if (decision.risk_signal) {
      event.risk_assessment = decision.risk_signal
    }
  }

  /**
   * Hand the event to `LocalNdjsonSink` and bump the shared counter.
   *
   * host_id / container_id are stamped by LocalNdjsonSink via
   * buildHostMeta() inside its report() path (top-level Config.hostId /
   * Config.containerId feed buildHostMeta). ApplicationCollector no
   * longer threads the environment slice — see plan step 4.
   */
  emit(event: SecurityEvent): void {
    this.eventCollector.report(event)
    this.stats.eventsEmitted++
  }
}

/**
 * Return a copy of an `Intervention` with `fail_strategy` removed. The field is
 * retained on the internal `SecurityDecision` (see DecisionComposer) but the
 * platform event schema's `intervention` field table does not list it.
 */
function withoutFailStrategy(
  intervention: NonNullable<SecurityDecision['intervention']>,
): NonNullable<SecurityDecision['intervention']> {
  const { fail_strategy: _failStrategy, ...rest } = intervention
  void _failStrategy
  return rest
}