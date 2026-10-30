/**
 * LocalNdjsonSink — local-only audit sink.
 *
 * Synchronously writes every reported SecurityEvent to the local NDJSON file
 * (one JSON object per line, capped at `config.collector.maxFileBytes`),
 * with an anti-tamper integrity baseline, a disk-low degraded mode, and an
 * ENOSPC escape channel (a full disk must not be able to both silence
 * the sink and erase the enforcement record — the local file is the source
 * of truth for the audit trail).
 *
 * Debug-log phases: `initialize`, `flush_empty`, `local_direct`,
 * `local_batch`, `integrity`, `integrity_gap`, `truncate`, `sink_disk_low`,
 * `sink_disk_recovered`, `shutdown` (plus `local_direct_escape` /
 * `local_batch_escape` for the ENOSPC escape channel).
 */
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, statSync, unlinkSync } from 'node:fs'
import fs from 'node:fs'
import { basename as pathBasename, dirname, join as joinPath } from 'node:path'
import { hostname, userInfo } from 'node:os'
import type { Config } from '../config.js'
import type { Mode, SecurityEvent, PolicyEvaluationMatch } from '../types/index.js'
import { inferRiskLevel, DEFAULT_PLATFORM_ID } from '../types/index.js'
import { validateEvent, type ValidationIssue } from '../utils/schema.js'
import { expandHome } from '../utils/expandHome.js'
import { generateEventId } from '../utils/eventId.js'
import { appendToCappedNdjson } from '../utils/cappedNdjson.js'
import { DebugLog, createDebugLogFromConfig } from '../utils/debugLog.js'

const PARENT_POLICY_ID = DEFAULT_PLATFORM_ID
const PARENT_POLICY_VERSION = 1

/**
 * How long the sink waits before the SECOND stat that confirms a
 * missing audit log. The window has to cover a rotator's
 * rename→create gap (milliseconds) without stalling the write path
 * for long: the delay is only paid on the rare "file is gone" branch.
 */
const INTEGRITY_CONFIRM_DELAY_MS = 50

/**
 * Park the current thread for `ms` milliseconds without spinning the
 * event loop. `Atomics.wait` on a SharedArrayBuffer is the only
 * synchronous sleep available in Node — the sink's write path is
 * synchronous (`lstatSync` / `appendFileSync`), so an async pause
 * would have to race the next write.
 */
function sleepSyncMs(ms: number): void {
  if (!Number.isFinite(ms) || ms <= 0) return
  const shared = new Int32Array(new SharedArrayBuffer(4))
  Atomics.wait(shared, 0, 0, ms)
}

/**
 * Human-readable stat kind for the integrity-alert channel. `unknown`
 * when the stat is missing (the path vanished again) or when the kind
 * is not one of the special file types.
 */
function describeStatKind(stat: import('node:fs').Stats | undefined): string {
  if (!stat) return 'unknown'
  if (stat.isCharacterDevice()) return 'character_device'
  if (stat.isBlockDevice()) return 'block_device'
  if (stat.isSymbolicLink()) return 'symlink'
  if (stat.isFIFO()) return 'fifo'
  if (stat.isSocket()) return 'socket'
  if (stat.isDirectory()) return 'directory'
  return 'unknown'
}

/**
 * Event types for which a policy_evaluation.status of `no_match` makes sense
 * (the event type participates in SPL evaluation). All other types without an
 * intervention are `not_applicable`.
 *
 * Not referenced by the local persistence path (the compressed empty-hit
 * form omits `status`); exported for the future upload-time expansion,
 * which must re-derive `status` from this set before batch upload.
 */
export const POLICY_APPLICABLE_EVENT_TYPES = new Set([
  'agent_start',
  'agent_stop',
  'agent_session_start',
  'agent_tool_call',
  'agent_tool_result',
  'agent_message',
  'network_http',
  'process_start',
  'process_change',
  'process_exit',
  'process_snapshot',
  'file_read',
  'file_write',
  'file_delete',
  'file_privilege',
  'code_mode_exec',
  'runtime_spawn_intent',
  'runtime_spawn_denied',
  'runtime_terminal_intent',
  'asset_add',
  'asset_change',
  'asset_remove',
  'asset_snapshot',
  'security_audit',
])

/** Local-only stats surface. */
export interface LocalNdjsonSinkStats {
  queued: number
  flushed: number
  dropped: number
  errors: number
  /** Events dropped because the batch queue overflowed. */
  queueQueueCount?: number
  /** NDJSON rotations performed since startup. */
  rotatedCount?: number
  /** Timestamp (ms since epoch) of the last rotation. */
  lastRotationAt?: number | null
  /** Non-enforcement-critical events dropped while
   *  the disk-low degraded mode was active (running counter, reset on
   *  recovery). */
  droppedDiskLow?: number
  /** Events that landed in the ENOSPC escape
   *  channel (`<localPath>.critical.jsonl`) because the primary sink
   *  threw ENOSPC. Operators reading the NDJSON for forensic replay
   *  should also grep the critical file when this counter is > 0. */
  criticalWritten: number
}

/** Optional seam knobs (logger, session resolver). */
export interface LocalNdjsonSinkOptions {
  logger?: Pick<Console, 'log' | 'warn' | 'error'>
  /**
   * Shared diagnostic log. When omitted
   * `initialize()` derives one from `config.collector.debugLogPath`
   * via `createDebugLogFromConfig` so legacy callers stay
   * byte-identical. Operators who want one DebugLog to serve both
   * the sink's phase lines AND the `apply()` error sites should pass
   * the same instance to both `LocalNdjsonSink` and `apply()`'s
   * error hooks.
   */
  debugLog?: DebugLog
  /**
   * session context resolver for events that are not
   * produced by a collector with direct session access (e.g. the
   * collector_integrity / security_audit events emitted by
   * `reportIntegrityGap`). When injected, the resolver maps the
   * plugin's own `process.pid` to the currently active session. If no
   * session is active, the identity fields are written null per the
   * platform identity rule.
   */
  resolveSessionByPid?: (pid: number) => { sessionId: string; runId: string; agentId?: string } | undefined
  /**
   * Test-only seam for the free-disk query. When
   * omitted, the sink uses the real `fs.statfsSync` (`_freeDiskBytes`).
   * Tests inject a fake statfs so the disk-low / recovery state machine is
   * driven deterministically; the implementation itself never changes
   * behaviour based on this knob.
   */
  freeDiskBytes?: (dirPath: string) => number | null
  /**
   * Test-only seam for the SECOND-STRIKE confirmation window: how long
   * the sink waits before re-statting an audit log it just found
   * missing. Defaults to 50 ms (enough to cover a rotator's
   * rename→create gap). The implementation never changes behaviour based
   * on this knob beyond the wait itself.
   */
  integrityConfirmDelayMs?: number
  /**
   * observer fired whenever the local NDJSON
   * is rotated or truncated by the sink itself (`size cap`,
   * `low disk`, the rare `_doTruncate` from operator action). Used
   * by `OverviewCache` to invalidate its cached block counts so a
   * size-cap rotation does not surface stale aggregates for up to
   * TTL_MS.
   *
   * The callback runs AFTER the file is deleted and the baseline
   * is reset, so any cache that reads `getStats()` after the
   * callback sees the post-rotation state (`flushed` unchanged,
   * `lastRotationAt` updated). Errors thrown by the callback are
   * caught and warned — the sink's contract is "never throw to
   * the host" (invariant #3), and the rotation is already done.
   */
  onRotate?: (info: { reason: string; rotatedCount: number; lastRotationAt: number }) => void
}

/**
 * Predicate for the disk-low degraded mode
 * ("enforce-only persistence"). An event is enforcement-critical when it
 * records an actual enforcement / tamper outcome:
 *   - any event carrying `blocked: true` (SPL / inline blocks),
 *   - `runtime_spawn_denied` (spawn-seam denials),
 *   - security_audit with action block / deny / tamper / escalate, or with
 *     a failure outcome (integrity gaps, disk-low itself while active).
 * Pure + exported so both sink paths and the tests share one definition.
 */
export function isEnforcementCriticalEvent(event: SecurityEvent): boolean {
  if (event.blocked === true) return true
  if (event.event_type === 'runtime_spawn_denied') return true
  if (event.event_type === 'security_audit') {
    const action = event.audit_action
    if (action === 'block' || action === 'deny' || action === 'tamper' || action === 'escalate') {
      return true
    }
    if (event.outcome === 'failure') return true
  }
  return false
}

/**
 * LocalNdjsonSink — local-only audit sink.
 *
 * Synchronously writes every reported SecurityEvent to `config.collector.localOutputPath`
 * (NDJSON, one JSON object per line, capped at `MAX_FILE_BYTES`). Optional
 * debug log at `config.collector.debugLogPath` records lifecycle and per-event
 * phases for operator forensics. The class is the source of truth for the
 * audit trail in audit and enforce modes.
 */
export class LocalNdjsonSink {
  // The file-size cap and disk watermarks are read from
  // `this.config.{maxFileBytes,diskWarnWatermarkBytes,
  // diskLowWatermarkBytes}` so the operator-facing config is the single
  // source of truth.

  private config: Config['collector']
  private flushTimer?: ReturnType<typeof setInterval>
  private localPath?: string
  /**
   * Shared diagnostic log. Injected by
   * `apply()` (constructed from `collector.debugLogPath`); if no
   * injection happens, `initialize()` derives one from the same
   * config key. See `src/utils/debugLog.ts` for the full contract.
   */
  private debugLog?: DebugLog
  /**
   * Throttle the `flush_empty` debug line to once every
   * 30 seconds so a long idle period doesn't spam the debug log.
   */
  private lastFlushEmptyLogAt = 0
  private stats: LocalNdjsonSinkStats = {
    queued: 0,
    flushed: 0,
    dropped: 0,
    errors: 0,
    criticalWritten: 0,
  }
  private logger: Pick<Console, 'log' | 'warn' | 'error'>
  /**
   * queue overflow counter. The buffered batch
   * queue (kept for the flushTimer path) is bounded so a bursty
   * upstream cannot exhaust memory. Events beyond the cap are
   * dropped and counted here so the platform can alert on
   * sustained backpressure.
   */
  private droppedFromQueueOverflow = 0
  /**
   * last rotation timestamp + count for stats.
   * `report()` writes through synchronously today, so the batch queue
   * is normally empty; the rotation counter tracks any
   * size-cap / low-disk deletion.
   */
  private rotatedCount = 0
  private lastRotationAt: number | null = null
  /**
   * Buffered batch queue. `report()` writes directly via
   * `writeLocalDirect`, so this queue is normally empty. The flushTimer
   * still fires `flush()` which drains whatever accumulated here (none, in
   * practice); tests that synthesize a non-empty batch can drive it.
   */
  private pendingBatch: SecurityEvent[] = []
  /**
   * Byte size of the local NDJSON after the last verified write, used to
   * detect audit-log tampering (deletion or truncation) between flushes.
   * `undefined` until the first write of this process.
   */
  private lastLocalBytes?: number
  /**
   * inode of the last verified write. Catches the
   * "mv file + create new file" tamper (size check is fooled because the
   * new file is empty / re-baselined) and the "rm + symlink /dev/null"
   * tamper (size check is fooled because writes still succeed and look
   * like normal appends).
   */
  private lastLocalInode?: number
  /**
   * session context resolver for events emitted outside a
   * collector with direct session access (e.g. collector_integrity
   * security_audit). Populated by `setResolveSessionByPid` after
   * ApplicationCollector is constructed because LocalNdjsonSink must
   * be created first.
   */
  private resolveSessionByPid?: (pid: number) => { sessionId: string; runId: string; agentId?: string } | undefined
  /**
   * Disk-low degradation state. `diskLowActive` is
   * the temporary enforce-only persistence mode (set when free disk crosses
   * `diskLowWatermarkBytes`, cleared with hysteresis after
   * `sinkDiskLow.recoverMarginBytes` of headroom is restored).
   * `droppedWhileDiskLow` counts the non-enforcement-critical events that
   * were dropped during the episode; it is surfaced in the recovery audit
   * event and reset when the episode ends.
   */
  private diskLowActive = false
  private droppedWhileDiskLow = 0
  private sinkDiskLow: Config['sinkDiskLow']
  /** Test-only statfs seam (see `LocalNdjsonSinkOptions.freeDiskBytes`). */
  private freeDiskBytesImpl?: (dirPath: string) => number | null
  /** Rotation observer — see `LocalNdjsonSinkOptions.onRotate`. */
  private onRotateCallback?: (info: { reason: string; rotatedCount: number; lastRotationAt: number }) => void
  /** Normalized identity stamps used to backfill events whose
   *  producer omitted `host_id` / `container_id` (see `ensureSessionContext`). */
  private hostId: string
  private containerId: string
  /** Rate-limit state for the invalid-event drop warn — one
   *  misbehaving producer used to emit one warn PER dropped event. */
  private lastInvalidDropLogAt = 0
  private invalidDropsSuppressed = 0
  /** Runtime mode for `buildPolicyEvaluation`'s fallback — used for
   *  intervention-less events so the emitted row claims the mode the engine
   *  actually ran instead of a hardcoded default. */
  private mode: Mode
  /**
   * Operator declaration: the audit log file's lifecycle is owned by an
   * EXTERNAL tool (a log rotator, a shipper, a volume manager). When
   * true, a file-lifecycle anomaly (the log disappeared / shrank / was
   * swapped) is an expected lifecycle event: the sink re-baselines and
   * logs a WARN instead of raising an `integrity/detect` gap.
   *
   * Default false — the anomaly is reported. An operator turns this on
   * when the rotation strategy cannot be recognised by the archive-
   * sibling heuristic (e.g. `copytruncate`, or a rotator that moves the
   * file to another directory).
   */
  private externallyManagedLog: boolean
  /**
   * Delay before the second stat that confirms a missing audit log.
   * See `LocalNdjsonSinkOptions.integrityConfirmDelayMs`.
   */
  private integrityConfirmDelayMs: number

  constructor(config: Config, options: LocalNdjsonSinkOptions = {}) {
    this.config = config.collector
    this.sinkDiskLow = config.sinkDiskLow
    // The RUNTIME mode — the mode the engine actually ran under. Taken
    // from the authoritative `intervention.mode` (the Config UI edits
    // that key); `config.mode` is the legacy top-level alias and
    // `normalizeConfig` mirrors the effective value onto both, so the
    // two agree by construction. This snapshot backs the
    // `policy_evaluation.mode` field, which describes the posture the
    // evaluation ran under — NOT the posture of an individual
    // decision (a mode-independent safety-net denial carries
    // `intervention.mode: 'enforce'` inside an audit-mode runtime).
    this.mode = config.intervention?.mode ?? config.mode
    // The operator's declaration about the log file's lifecycle — see
    // the `externallyManagedLog` field comment.
    this.externallyManagedLog = config.collector.externallyManagedLog === true
    // The second-stat confirmation window. `INTEGRITY_CONFIRM_DELAY_MS`
    // unless the caller overrides it (test seam).
    this.integrityConfirmDelayMs =
      typeof options.integrityConfirmDelayMs === 'number'
        ? options.integrityConfirmDelayMs
        : INTEGRITY_CONFIRM_DELAY_MS
    // Normalized-config identity stamps. `normalizeConfig`
    // guarantees both are non-empty strings (hostId falls back to
    // `hostname()`, containerId to `'host'`), so the sink can backfill
    // events from producers that omit the platform-mandated wire fields
    // instead of dropping them (see `ensureSessionContext`). The `??`
    // fallbacks mirror that contract for the type system — the Config
    // interface marks both optional even though normalization fills them.
    this.hostId = config.hostId ?? hostname()
    this.containerId = config.containerId ?? 'host'
    this.logger = options.logger ?? console
    this.resolveSessionByPid = options.resolveSessionByPid
    this.debugLog = options.debugLog
    this.freeDiskBytesImpl = options.freeDiskBytes
    this.onRotateCallback = options.onRotate
  }

  /**
   * late-binding setter for the session resolver. The host
   * constructs LocalNdjsonSink before ApplicationCollector, so the
   * resolver cannot be supplied to the constructor; this setter is called
   * once ApplicationCollector is available.
   */
  setResolveSessionByPid(
    resolver: (pid: number) => { sessionId: string; runId: string; agentId?: string } | undefined,
  ): void {
    this.resolveSessionByPid = resolver
  }

  /**
   * guarantee that `agent_id` / `session_id` / `run_id`
   * are present on every event. Prefer the active PID->session cache; fall back
   * to explicit JSON null when no session is active — per the platform
   * identity rule (common.json) an undeterminable identity is written null,
   * never a fabricated sentinel, so SOC correlation does not link unrelated
   * events. Explicit values (including null) are preserved so callers that
   * intentionally stub a field (e.g. fs handlers with no active session)
   * are not overwritten.
   *
   * The same guarantee covers `host_id` / `container_id`:
   * several producers (RuntimeHook subprocess events, bootstrap startup
   * events, intervention paths) build events without these platform-mandated
   * wire fields; the sink backfills them from the normalized config instead
   * of dropping the event with a per-event warn.
   */
  private ensureSessionContext(event: SecurityEvent): void {
    if (event.host_id === undefined) event.host_id = this.hostId
    if (event.container_id === undefined) event.container_id = this.containerId
    if (event.agent_id === undefined && this.resolveSessionByPid) {
      const pid = typeof event.pid === 'number' ? event.pid : process.pid
      const session = this.resolveSessionByPid(pid)
      if (session?.agentId) {
        if (event.agent_id === undefined) event.agent_id = session.agentId
        if (event.session_id === undefined) event.session_id = session.sessionId
        if (event.run_id === undefined) event.run_id = session.runId
        return
      }
    }
    // Identity unknown — write JSON null per the platform rule. The
    // pre-null form used '__plugin__' / '__unattributed__' sentinels,
    // which SOC tooling could mistake for real correlation keys.
    if (event.agent_id === undefined) event.agent_id = null
    if (event.session_id === undefined) event.session_id = null
    if (event.run_id === undefined) event.run_id = null
  }

  initialize(): void {
    this.localPath = expandHome(this.config.localOutputPath)
    // DebugLog is the shared diagnostic log
    // for both LocalNdjsonSink phases and the apply() error sites.
    // If no DebugLog was injected, derive one from the same
    // config key so legacy behaviour is preserved. Empty string →
    // undefined → every debug emission short-circuits via DebugLog.write().
    if (!this.debugLog) {
      this.debugLog = createDebugLogFromConfig(this.config, this.logger)
    }
    // Owner-only perms (standard audit): the debug log may carry sensitive
    // context (stack traces, argv previews, env var names — opt-in by
    // the operator). The file MUST be owner-only readable.
    // DebugLog re-chmods internally on first write / creation /
    // rotation, so no pre-emptive chmod is needed
    // here. Windows has no chmod (NTFS ACL is the equivalent); the
    // underlying chmodSync throws EPERM and DebugLog swallows it.
    const dir = dirname(this.localPath)
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true })
    }
    // The sink file and the `.critical.jsonl`
    // escape channel must be owner-only (0o600); creation via
    // `appendToCappedNdjson` falls back to the process umask (typically
    // 0644 = group/world readable). Tighten any pre-existing file at
    // startup; every append / rotation re-asserts via `_chmodOwnerOnly`.
    if (existsSync(this.localPath)) this._chmodOwnerOnly(this.localPath)
    if (existsSync(this._criticalPath())) this._chmodOwnerOnly(this._criticalPath())
    // check disk space at startup. Below 10MB free
    // we still load (the audit log may be the only thing keeping the
    // host honest) but we log a hard warn so the operator can act.
    // The same probe drives the disk-low state machine —
    // starting below the low watermark enters the enforce-only degraded
    // mode and emits `security_audit/sink_disk_low`.
    const free = this._queryFreeDiskBytes(dir)
    if (free !== null) {
      this.updateDiskLowState(free, dir)
      if (free < this.config.diskLowWatermarkBytes) {
        this.logger.error(
          `[LocalNdjsonSink] low disk space at startup: ${free} bytes free at ${dir} (watermark ${this.config.diskLowWatermarkBytes})`,
        )
      } else if (free < this.config.diskWarnWatermarkBytes) {
        this.logger.warn(
          `[LocalNdjsonSink] disk space low: ${free} bytes free at ${dir} (warning watermark ${this.config.diskWarnWatermarkBytes})`,
        )
      }
    }
    this.flushTimer = setInterval(() => this.flush(), this.config.flushIntervalMs)

    // Emit the `initialize` debug line. Fire-and-forget —
    // the debug log is never on the critical path.
    this.debugLog?.write('initialize', {
      localOutputPath: this.localPath,
      debugLogPath: this.debugLog.getPath() ?? null,
      batchSize: this.config.batchSize,
    })
  }

  /**
   * Build the `policy_evaluation` block required by the collector-access-spec
   * v1 wire format. The block is derived from the event's own `intervention`
   * field; when no intervention is present the decision is `allow` and the
   * status reflects whether this event type is normally policy-evaluated.
   *
   * Non-`block` decisions (`modify`, `substitute`, `context_adjust`,
   * `escalate`, `degrade`) are mapped to `allow` at the policy_decision level
   * because the platform contract only records the final allow/block verdict
   * there; the full decision is still preserved in `intervention.decision`.
   *
   * The platform per-type validator requires every
   * `matches[]` element AND `final_match` to carry `priority`, `risk_level`,
   * `decision`, `policy_version` (string).
   *
   * Local-volume form: when nothing matched, the block compresses to the
   * minimal `{ schema_version, mode, policy_decision }` — `status` /
   * `matches` / `final_match` are omitted because they are derivable
   * (status from POLICY_APPLICABLE_EVENT_TYPES, matches/final_match are
   * constants for the empty case) and dominated the NDJSON byte budget
   * (~110 bytes × every event). An uploader must expand the minimal form
   * back to the full platform shape (status + `matches: []` +
   * `final_match: null`) before batch upload.
   */
  private buildPolicyEvaluation(event: SecurityEvent): NonNullable<SecurityEvent['policy_evaluation']> {
    // Fall back to the sink's RUNTIME mode, not a hardcoded
    // 'audit' — intervention-less events (network_http / agent_message /
    // agent_tool_result / fs rows) should claim the mode the engine
    // actually ran so operator triage sees the right mode.
    //
    // The runtime mode is used for EVERY event, including the ones
    // that carry an intervention: `policy_evaluation` describes the
    // posture the evaluation ran under, while the posture of an
    // individual verdict lives on `intervention.mode`. The two differ
    // exactly for the mode-independent safety nets (the hardcoded
    // self-protection guard denies regardless of the runtime mode and
    // stamps `intervention.mode: 'enforce'` +
    // `intervention.mode_independent: true`) — reading the
    // intervention's mode here would have reported the whole runtime
    // as 'enforce' because of one guard hit.
    const base = { schema_version: 1, mode: this.mode }
    const intervention = event.intervention
    if (intervention?.decision) {
      const ruleId = intervention.policy_id ?? intervention.policy_name ?? 'unknown-rule'
      const rawDecision = intervention.decision
      // `intervention.decision` is the marketplace 3-action
      // vocabulary (`allow | deny | ask`); the spec's `PolicyEvaluationMatch.decision`
      // still expects `allow | block`. Map `deny` → `block` and the rest to
      // `allow` so the per-match field conforms. The richer 10-action SPL
      // decision is preserved on `decision_internal` for audit consumers.
      const narrowedDecision: PolicyEvaluationMatch['decision'] =
        rawDecision === 'deny' ? 'block' : 'allow'
      const match: PolicyEvaluationMatch = {
        policy_id: PARENT_POLICY_ID,
        policy_version: String(PARENT_POLICY_VERSION),
        rule_id: ruleId,
        priority: this.extractMatchPriority(event),
        risk_level: this.extractMatchRiskLevel(event) ?? inferRiskLevel(rawDecision),
        decision: narrowedDecision,
      }
      return {
        ...base,
        status: 'matched',
        policy_decision: narrowedDecision,
        matches: [match],
        final_match: match,
      }
    }
    // Compressed empty-hit form — see the doc comment above.
    return {
      ...base,
      policy_decision: 'allow',
    }
  }

  /**
   * Pull the matched rule's priority off the event when present (the SPL eval
   * side carries it on `risk_signal.matched_policies[].priority`). Falls back
   * to `0` when no signal is reachable.
   */
  private extractMatchPriority(event: SecurityEvent): number {
    const fromIntervention = (event.intervention as Record<string, unknown> | undefined)?.priority
    if (typeof fromIntervention === 'number') return fromIntervention
    // risk_signal lives on intervention.risk_assessment (single-copy
    // invariant — the top-level event.risk_assessment duplicate was
    // removed in the 2026-10-27 dedup batch).
    const fromRisk = (event.intervention?.risk_assessment as Record<string, unknown> | undefined)?.max_priority
    if (typeof fromRisk === 'number') return fromRisk
    return 0
  }

  /**
   * Pull the matched rule's risk_level off the event when present (the SPL
   * eval side stencils it on `risk_signal.dimensions`). Falls back to `null`
   * so the caller can use `inferRiskLevel(decision)` as a deterministic
   * default per SPL §4.2.1.
   */
  private extractMatchRiskLevel(event: SecurityEvent): 'critical' | 'high' | 'medium' | 'low' | null {
    // Single copy on intervention.risk_assessment (see extractMatchPriority).
    const fromRisk = (event.intervention?.risk_assessment as Record<string, unknown> | undefined)?.risk_level
    if (fromRisk === 'critical' || fromRisk === 'high' || fromRisk === 'medium' || fromRisk === 'low') {
      return fromRisk
    }
    const dims = (event.intervention?.risk_assessment as Record<string, unknown> | undefined)?.dimensions as
      | Record<string, number>
      | undefined
    if (dims && Object.keys(dims).length > 0) {
      const max = Math.max(...Object.values(dims))
      if (max >= 100) return 'critical'
      if (max >= 75) return 'high'
      if (max >= 40) return 'medium'
      return 'low'
    }
    return null
  }

  /**
   * Transform an internal SecurityEvent into the wire-shape expected by the
   * platform: top-level `schema_version: 1`, a derived `policy_evaluation`
   * block, and `blocked: true` enforced when the policy evaluation says
   * enforce+block. The transformation is idempotent: calling it more than once
   * on the same object does not create duplicate blocks.
   */
  private buildTransportEvent(event: SecurityEvent): SecurityEvent {
    if (event.schema_version === 1 && event.policy_evaluation) {
      return event
    }
    const policyEvaluation = this.buildPolicyEvaluation(event)
    event.schema_version = 1
    event.policy_evaluation = policyEvaluation
    if (policyEvaluation.mode === 'enforce' && policyEvaluation.policy_decision === 'block' && event.blocked !== true) {
      event.blocked = true
    }
    return event
  }

  /**
   * Rate-limited variant of the invalid-event drop warn: the
   * first drop logs immediately and further drops within 30 s collapse into
   * a `(+N suppressed)` suffix on the next emitted line, so one misbehaving
   * producer cannot flood the log (one line per dropped event). `stats.dropped`
   * still counts every drop, so the loss remains visible via `/security status`.
   */
  private warnInvalidDrop(event: SecurityEvent, issues: ValidationIssue[]): void {
    const now = Date.now()
    this.invalidDropsSuppressed++
    if (this.lastInvalidDropLogAt !== 0 && now - this.lastInvalidDropLogAt < 30_000) return
    const suppressed = this.invalidDropsSuppressed - 1
    const suffix = suppressed > 0 ? ` (+${suppressed} earlier drops suppressed)` : ''
    this.lastInvalidDropLogAt = now
    this.invalidDropsSuppressed = 0
    this.logger.warn(
      `[LocalNdjsonSink] dropped invalid event ${String(event.event_id)}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}${suffix}`,
    )
  }

  /**
   * Write a single event to local NDJSON. Synchronous, validation-aware,
   * integrity-baseline-aware. The only path `report()` takes now.
   */
  private writeLocalDirect(event: SecurityEvent): void {
    if (!this.localPath) return
    // Disk-low degraded mode — only
    // enforcement-critical events land; everything else is counted and
    // dropped (the recovery event carries the summary).
    if (this.dropIfDegraded(event)) return
    if (this.config.validateEvents) {
      const issues = validateEvent(event)
      if (issues.length > 0) {
        this.stats.dropped++
        this.warnInvalidDrop(event, issues)
        return
      }
    }
    // The single-event write path funnels
    // through `enqueueOrPersist` — the shared core that both this path
    // and the legacy batch path use for the disk-write side (cap
    // append, ENOSPC escape, truncated baseline reset, stat refresh).
    // The per-event filter above stays here because the batch path
    // collects `accepted` / `lines` across many events, while this
    // path is exactly one event; the shared helper assumes the
    // caller has already done that filtering.
    this.enqueueOrPersist([event], [JSON.stringify(event) + '\n'], 'single')
  }

  /**
   * Report an event to the local sink. Always synchronous, always local-only.
   */
  report(event: SecurityEvent): void {
    // Every event must carry platform-mandated wire fields and session
    // context before any sink sees it. `buildTransportEvent` is idempotent
    // so callers that pre-built a transport shape are still safe.
    this.ensureSessionContext(event)
    this.buildTransportEvent(event)
    this.writeLocalDirect(event)
  }

  /**
   * Public flush. Drains the buffered batch queue (if anything accumulated)
   * via `writeLocal`. The flushTimer fires this on `flushIntervalMs`; with
   * the synchronous-per-event write path the queue is normally empty.
   */
  flush(): void {
    // The idle flush tick doubles as the disk
    // recovery probe — a quiet host (no events flowing) still notices the
    // disk recovered and exits the enforce-only degraded mode.
    // `updateDiskLowState` is edge-triggered, so calling it here is cheap.
    if (this.localPath) {
      const free = this._queryFreeDiskBytes(dirname(this.localPath))
      if (free !== null) this.updateDiskLowState(free, dirname(this.localPath))
    }
    if (this.pendingBatch.length === 0) {
      // Throttle the `flush_empty` debug line to once per 30 s so a long
      // idle period doesn't spam the debug log.
      const now = Date.now()
      if (this.debugLog?.isEnabled() && now - this.lastFlushEmptyLogAt > 30_000) {
        this.lastFlushEmptyLogAt = now
        this.debugLog.write('flush_empty')
      }
      return
    }
    const batch = this.pendingBatch
    this.pendingBatch = []
    try {
      const accepted = this.writeLocal(batch)
      this.stats.flushed += accepted.length
    } catch (error: unknown) {
      this.stats.errors++
      this.logger.error(
        `[LocalNdjsonSink] local NDJSON write failed during flush: ${
          error instanceof Error ? error.message : String(error)
        }`,
      )
    }
  }

  shutdown(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer)
      this.flushTimer = undefined
    }
    // Drain any final buffered batch so an in-progress flush isn't lost
    // when the process exits between flush ticks.
    this.flush()
    this.debugLog?.write('shutdown')
  }

  getStats(): LocalNdjsonSinkStats {
    return {
      ...this.stats,
      queueQueueCount: this.droppedFromQueueOverflow,
      rotatedCount: this.rotatedCount,
      lastRotationAt: this.lastRotationAt,
      droppedDiskLow: this.droppedWhileDiskLow,
    }
  }

  /**
   * Return the resolved local NDJSON path. The constructor accepts `~/`
   * expansion via the shared `expandHome` helper, so the value here is the
   * post-expansion absolute path
   * that `report()` writes to. Returns `undefined` before
   * `initialize()` runs (the path is not yet resolved). Used by
   * `/security status` and `ctx.remote.securityMonitor.overview`
   * so the operator / DSH Web UI can confirm where the audit
   * trail is landing without re-implementing the `~` expansion logic.
   */
  getLocalOutputPath(): string | undefined {
    return this.localPath
  }

  /**
   * Write a batch to the local NDJSON. Returns the list of accepted
   * events (after the validateEvents filter). Used by `flush()` and
   * by `writeLocalDirect` (one-line wrapper). Throws on a fatal disk
   * error so the caller can decide how to react.
   *
   * The disk-write side (cap append, ENOSPC
   * escape, truncated baseline reset, stat refresh, debug log) is
   * delegated to `enqueueOrPersist` — the single shared core that
   * `writeLocalDirect` also funnels through. The per-event filter
   * (degraded-mode drop + validateEvents) stays here because the batch
   * path collects `accepted` / `lines` across many events, while the
   * single-event path is exactly one event.
   */
  private writeLocal(batch: SecurityEvent[]): SecurityEvent[] {
    if (!this.localPath) return batch
    const accepted: SecurityEvent[] = []
    const lines: string[] = []
    for (const event of batch) {
      // Same degraded-mode filter as
      // `writeLocalDirect` (the batch path is only exercised by tests /
      // flush callers, but the filter must hold on both paths).
      if (this.dropIfDegraded(event)) continue
      if (this.config.validateEvents) {
        const issues = validateEvent(event)
        if (issues.length > 0) {
          this.stats.dropped++
          this.warnInvalidDrop(event, issues)
          continue
        }
      }
      const line = JSON.stringify(event) + '\n'
      lines.push(line)
      accepted.push(event)
    }
    this.enqueueOrPersist(accepted, lines, 'batch')
    return accepted
  }

  /**
   * Shared core for the two NDJSON write paths
   * (`writeLocalDirect` / `writeLocal`). Handles:
   *
   *  - `checkLocalIntegrity()` + `truncateIfLowDisk()` setup
   *  - `appendToCappedNdjson()` with the size cap
   *  - ENOSPC escape channel → `<localPath>.critical.jsonl` (invariant #7)
   *  - Truncated baseline reset + post-write stat refresh (bytes + inode)
   *  - Stats + debugLog writes (count, bytes, truncated flag)
   *
   * The caller is responsible for the per-event filter (degraded-mode
   * drop + validateEvents) because the single-event path is exactly one
   * event and the batch path accumulates `accepted` / `lines` across
   * many events. The shared helper assumes the inputs are already
   * validated and non-empty (`accepted.length === lines.length`).
   *
   * `context` switches the stats / debugLog shape:
   *   - `'single'` → `stats.flushed++` + `debugLog('local_direct', …)`
   *   - `'batch'`  → `debugLog('local_batch', …)` (no flushed++ — the
   *     batch is accounted via the per-event stat when events are
   *     enqueued; the test suite asserts `stats.flushed` per-event).
   *
   * Returns silently on success. On a fatal disk error (non-ENOSPC, or
   * ENOSPC with critical path also failing):
   *   - `'single'`: warn-log and return — the host pipeline continues
   *   - `'batch'`: rethrow so the flush() caller can record the loss
   *
   * Never throws on the integrity / disk-low side — those are handled
   * via the audit-event emit path internally. Invariant holds.
   */
  private enqueueOrPersist(
    events: readonly SecurityEvent[],
    lines: readonly string[],
    context: 'single' | 'batch',
  ): void {
    if (!this.localPath) return
    if (events.length === 0 || lines.length === 0) return
    // Anti-tamper: verify the audit log exists at (or grew from) the size
    // we last wrote. A missing or shorter file means someone deleted /
    // truncated the trail between our writes; record a synthetic
    // `collector_integrity` event instead of silently continuing. (After
    // a process restart `lastLocalBytes` is undefined and the next write
    // re-baselines, so an external `rm` that happened while we were down
    // is not double-reported.)
    this.checkLocalIntegrity()
    // If disk space has crossed the low watermark, delete the
    // active NDJSON before appending so we don't aggravate a full-disk
    // situation. The size-cap itself is handled by `appendToCappedNdjson`.
    this.truncateIfLowDisk()
    let result
    try {
      result = appendToCappedNdjson(this.localPath, [...lines], this.config.maxFileBytes, {
        logger: this.logger,
      })
      // Re-assert 0o600 — creation and the
      // rotation path (rename over the target) both fall back to the
      // umask, which is typically group/world readable.
      this._chmodOwnerOnly(this.localPath)
    } catch (error: unknown) {
      // ENOSPC escape channel: a full disk must not be able to both
      // silence the sink and erase the enforcement record. When the primary
      // sink throws
      // ENOSPC, attempt to write the lines to
      // `<localPath>.critical.jsonl` (independent file, no disk-low
      // gate, larger cap).
      if (this._isEnospc(error)) {
        if (this._tryWriteCritical([...lines])) {
          this.logger.error(
            `[LocalNdjsonSink] primary sink ENOSPC on ${context} of ${lines.length} line(s); ` +
              `written to ${this._criticalPath()} (escape channel)`,
          )
          this.stats.criticalWritten += lines.length
          this.debugLog?.write(
            context === 'single' ? 'local_direct_escape' : 'local_batch_escape',
            {
              count: lines.length,
              criticalPath: this._criticalPath(),
            },
          )
          return
        }
      }
      // Fatal disk error: single path warns + swallows, batch path
      // rethrows so the flush() caller can record the loss.
      if (context === 'single') {
        const first = events[0]
        this.logger.warn(
          `[LocalNdjsonSink] writeLocalDirect failed for ${String(first?.event_id)}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        )
        return
      }
      throw error
    }
    if (result.truncated) {
      // The utility deleted the file because it was over the cap. Reset
      // the integrity baseline so the next write starts clean.
      this._resetLocalBaseline('size cap')
    }
    try {
      const stat = statSync(this.localPath)
      this.lastLocalBytes = stat.size
      // also record the inode of the underlying file
      // so a subsequent mv + recreate (or a rm + symlink) is detectable.
      this.lastLocalInode = stat.ino
    } catch {
      /* file vanished mid-write; next flush will flag it */
    }
    if (context === 'single') {
      const first = events[0]
      this.stats.flushed++
      this.debugLog?.write('local_direct', {
        eventId: first?.event_id,
        eventType: first?.event_type,
      })
    } else {
      this.debugLog?.write('local_batch', {
        count: events.length,
        bytes: lines.reduce((acc, l) => acc + l.length, 0),
        truncated: result.truncated,
      })
    }
  }

  /**
   * If disk space has crossed the low watermark, delete the
   * active NDJSON so the next append starts fresh. This is a safety valve
   * independent of the 50 MiB size cap handled by `appendToCappedNdjson`.
   *
   * Also drives the disk-low degradation state machine
   * (`updateDiskLowState`). The truncate fires ONCE per
   * degraded episode (on entry), not on every write: deleting the file
   * before EVERY append while below the watermark would destroy the
   * enforcement-critical audit trail the degraded mode deliberately keeps.
   * The size cap still bounds the
   * file during the episode, and if the disk is truly full the append
   * itself fails (caught + warned) without unlinking the trail.
   *
   * Order matters: truncate BEFORE emitting the transition event —
   * `_doTruncate` unlinks the file, so emitting first would delete the
   * very record we just wrote.
   */
  private truncateIfLowDisk(): void {
    if (!this.localPath) return
    const dir = dirname(this.localPath)
    const free = this._queryFreeDiskBytes(dir)
    if (free === null) return
    const wasActive = this.diskLowActive
    if (free < this.config.diskLowWatermarkBytes && !wasActive) {
      this.logger.error(
        `[LocalNdjsonSink] low disk: ${free} bytes free at ${dir}; truncating local NDJSON`,
      )
      this._doTruncate('low disk')
    }
    this.updateDiskLowState(free, dir)
  }

  /**
   * Edge-triggered disk-low state machine.
   *
   *   enter : free < diskLowWatermarkBytes
   *   exit  : free >= diskLowWatermarkBytes + sinkDiskLow.recoverMarginBytes
   *
   * The hysteresis margin (default 50 MiB) keeps a disk hovering at the
   * watermark from flapping the degraded mode on every write. Both edges
   * emit a `security_audit` event via the direct-write bypass (see
   * `emitSinkDiskEvent`). Never throws.
   */
  private updateDiskLowState(free: number, dir: string): void {
    const low = this.config.diskLowWatermarkBytes
    if (!this.diskLowActive && free < low) {
      this.diskLowActive = true
      this.logger.error(
        `[LocalNdjsonSink] disk below low watermark: ${free} bytes free at ${dir} ` +
          `(watermark ${low}); entering enforce-only persistence ` +
          `(only blocked/denied/tamper-class events land until recovery)`,
      )
      this.emitSinkDiskEvent('sink_disk_low', free, dir)
      return
    }
    if (this.diskLowActive && free >= low + this.sinkDiskLow.recoverMarginBytes) {
      const dropped = this.droppedWhileDiskLow
      this.diskLowActive = false
      this.droppedWhileDiskLow = 0
      this.logger.warn(
        `[LocalNdjsonSink] disk recovered: ${free} bytes free at ${dir}; exiting enforce-only persistence ` +
          `(${dropped} non-critical event(s) dropped while degraded)`,
      )
      this.emitSinkDiskEvent('sink_disk_recovered', free, dir, dropped)
    }
  }

  /**
   * True when the event must keep landing even in
   * disk-low degraded mode — blocked tool calls, SPL denials, runtime-spawn
   * denials, tamper/escalation audits, and any audit with a failure outcome
   * (integrity gaps, etc.). Everything else is counted + dropped so a
   * full disk cannot both silence the sink AND erase the enforcement
   * record.
   */
  private dropIfDegraded(event: SecurityEvent): boolean {
    if (!this.diskLowActive) return false
    if (isEnforcementCriticalEvent(event)) return false
    this.droppedWhileDiskLow += 1
    this.stats.dropped += 1
    this.debugLog?.write('sink_disk_low_drop', {
      eventId: event.event_id,
      eventType: event.event_type,
      droppedWhileDiskLow: this.droppedWhileDiskLow,
    })
    return true
  }

  /**
   * Direct-write bypass for the disk-low transition
   * events. Modeled on `reportIntegrityGap`: the event is appended straight
   * to the NDJSON (with the transport wrapper) instead of going through
   * `report()` → `writeLocalDirect` — the normal path would re-enter the
   * degraded-mode filter / low-disk check and recurse (or drop the very
   * event announcing the transition). Failures are swallowed: a lost
   * degradation signal must never crash the sink (invariant #3).
   */
  private emitSinkDiskEvent(
    kind: 'sink_disk_low' | 'sink_disk_recovered',
    free: number,
    dir: string,
    droppedEvents = 0,
  ): void {
    try {
      const session = this.resolveSessionByPid?.(process.pid)
      const now = Date.now()
      const isLow = kind === 'sink_disk_low'
      const message = isLow
        ? `本地审计 sink 磁盘低于低水位（free=${free}B < watermark=${this.config.diskLowWatermarkBytes}B @ ${dir}）；` +
          '已进入临时 enforce-only 降级态，仅 enforcement-critical 事件继续落盘'
        : `本地审计 sink 磁盘已恢复（free=${free}B @ ${dir}）；退出 enforce-only 降级态，` +
          `降级期间共丢弃 ${droppedEvents} 条非关键事件`
      const event: SecurityEvent = {
        comm: DEFAULT_PLATFORM_ID,
        event_id: generateEventId(),
        event_type: 'security_audit',
        layer: 'application',
        source_layer: 'application',
        ts: now,
        pid: process.pid,
        collection_method: 'agent_api',
        host_id: hostname(),
        container_id: process.env.CONTAINER_ID || 'host',
        session_id: session?.sessionId ?? null,
        run_id: session?.runId ?? null,
        agent_id: session?.agentId ?? null,
        audit_category: 'sink',
        audit_action: isLow ? 'escalate' : 'warn',
        target: this.localPath!,
        outcome: isLow ? 'failure' : 'success',
        severity: isLow ? 'high' : 'medium',
        reason: message,
        audit_details: {
          event_type_alias: kind,
          free_bytes: free,
          watermark_bytes: this.config.diskLowWatermarkBytes,
          recover_margin_bytes: this.sinkDiskLow.recoverMarginBytes,
          dropped_events: droppedEvents,
          detail: message,
        },
      }
      this.buildTransportEvent(event)
      appendToCappedNdjson(this.localPath!, [JSON.stringify(event) + '\n'], this.config.maxFileBytes, {
        logger: this.logger,
      })
      // Owner-only perms (umask fallback otherwise).
      this._chmodOwnerOnly(this.localPath!)
      this.stats.flushed++
      this.debugLog?.write(kind, {
        freeBytes: free,
        watermarkBytes: this.config.diskLowWatermarkBytes,
        droppedEvents,
      })
    } catch {
      /* never throw to host — the next probe will retry recovery detection */
    }
  }

  /**
   * Test-only state snapshot (mirrors the
   * `SensitivePathWatcher.describe()` convention).
   */
  getDiskLowState(): { active: boolean; droppedWhileActive: number } {
    return {
      active: this.diskLowActive,
      droppedWhileActive: this.droppedWhileDiskLow,
    }
  }

  /**
   * Apply 🟢 collector/sinkDiskLow keys in place.
   * The sink holds `config.collector` / `config.sinkDiskLow` by reference
   * so scalar mutations are visible on the very next write; the only field
   * needing active work is `flushIntervalMs`, whose timer is rebuilt
   * (clearInterval + setInterval) so the new cadence takes effect without
   * losing the pending batch. 🟡 keys (localOutputPath/debugLogPath) are
   * returned as needsRestartKeys and never applied here.
   */
  livePatch(patch: Record<string, unknown>): {
    ok: boolean
    appliedKeys: string[]
    needsRestartKeys: string[]
    error?: string
  } {
    const appliedKeys: string[] = []
    const needsRestartKeys: string[] = []
    try {
      const collector = patch['collector']
      if (collector && typeof collector === 'object' && !Array.isArray(collector)) {
        const c = collector as Record<string, unknown>
        const assignNumber = (field: 'batchSize' | 'flushIntervalMs' | 'maxFileBytes' | 'diskWarnWatermarkBytes' | 'diskLowWatermarkBytes'): void => {
          const value = c[field]
          if (typeof value === 'number' && Number.isFinite(value)) {
            this.config[field] = value
            appliedKeys.push(`collector.${field}`)
          }
        }
        // `redactRawParams` is hardcoded to true in
        // marketplace form (Config type is `true`). livePatch silently
        // ignores any input here — see config.ts.
        const assignBool = (field: 'validateEvents'): void => {
          const value = c[field]
          if (typeof value === 'boolean') {
            this.config[field] = value
            appliedKeys.push(`collector.${field}`)
          }
        }
        assignNumber('batchSize')
        assignNumber('maxFileBytes')
        assignNumber('diskWarnWatermarkBytes')
        assignNumber('diskLowWatermarkBytes')
        assignBool('validateEvents')
        if (typeof c['flushIntervalMs'] === 'number' && Number.isFinite(c['flushIntervalMs']) && c['flushIntervalMs'] > 0) {
          this.config.flushIntervalMs = c['flushIntervalMs']
          appliedKeys.push('collector.flushIntervalMs')
          // Timer rebuild: only when a timer is live (post-initialize).
          // The pending batch is untouched across the swap.
          // Require `> 0` — Node's
          // setInterval clamps non-positive values to 1ms (CPU spin),
          // and a re-applied 0/negative would silently degrade to that
          // — operators expecting a slow cadence would see flush events
          // fire as fast as the event loop allows.
          if (this.flushTimer) {
            clearInterval(this.flushTimer)
            this.flushTimer = setInterval(() => this.flush(), this.config.flushIntervalMs)
          }
        }
        if ('localOutputPath' in c) needsRestartKeys.push('collector.localOutputPath')
        if ('debugLogPath' in c) needsRestartKeys.push('collector.debugLogPath')
      }
      const sinkDiskLow = patch['sinkDiskLow']
      if (sinkDiskLow && typeof sinkDiskLow === 'object' && !Array.isArray(sinkDiskLow)) {
        const value = (sinkDiskLow as Record<string, unknown>)['recoverMarginBytes']
        if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
          this.sinkDiskLow.recoverMarginBytes = value
          appliedKeys.push('sinkDiskLow.recoverMarginBytes')
        }
      }
      appliedKeys.sort()
      needsRestartKeys.sort()
      return { ok: true, appliedKeys, needsRestartKeys }
    } catch (error: unknown) {
      return {
        ok: false,
        appliedKeys,
        needsRestartKeys,
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }

  /**
   * Free-disk probe honoring the test seam.
   * Falls back to the real `fs.statfsSync` (`_freeDiskBytes`) when no
   * injection is present; a throwing / malformed injected probe degrades
   * to `null` (unknown → no state change), matching `_freeDiskBytes`.
   */
  private _queryFreeDiskBytes(dirPath: string): number | null {
    if (this.freeDiskBytesImpl) {
      try {
        return this.freeDiskBytesImpl(dirPath)
      } catch {
        return null
      }
    }
    return this._freeDiskBytes(dirPath)
  }

  /**
   * Delete the active NDJSON and reset all baselines that point to it.
   * Called when the file exceeds the size cap or disk is critically low.
   */
  private _doTruncate(reason: string): void {
    if (!this.localPath) return
    let currentSize = 0
    try {
      currentSize = statSync(this.localPath).size
      unlinkSync(this.localPath)
    } catch (err) {
      this.logger.error(
        `[LocalNdjsonSink] truncate failed: ${(err as Error).message} — continuing with current file`,
      )
      return
    }
    this._resetLocalBaseline(reason, currentSize)
  }

  /**
   * Reset integrity baseline after the local NDJSON was deleted and
   * recreated. This prevents the anti-tamper checks from flagging the
   * intentional truncation as an audit gap.
   */
  private _resetLocalBaseline(reason: string, deletedBytes?: number): void {
    this.rotatedCount += 1
    this.lastRotationAt = Date.now()
    this.lastLocalBytes = undefined
    this.lastLocalInode = undefined
    const sizePart = typeof deletedBytes === 'number' ? `, ${deletedBytes} bytes` : ''
    this.logger.warn(
      `[LocalNdjsonSink] truncated local NDJSON (${reason}${sizePart}) — file count=${this.rotatedCount}`,
    )
    this.debugLog?.write('truncate', {
      reason,
      deletedBytes: deletedBytes ?? null,
      rotatedCount: this.rotatedCount,
    })
    // Fire the rotation observer AFTER the baseline
    // reset so any cache reading `getStats()` next sees the new
    // counters. Errors are caught and warned (invariant #3).
    if (this.onRotateCallback) {
      try {
        this.onRotateCallback({
          reason,
          rotatedCount: this.rotatedCount,
          lastRotationAt: this.lastRotationAt,
        })
      } catch (err: unknown) {
        this.logger.warn(
          `[LocalNdjsonSink] onRotate callback failed: ${err instanceof Error ? err.message : String(err)}`,
        )
      }
    }
  }

  /**
   * Best-effort free disk space query. Returns
   * `null` if the platform doesn't support `statfs` (Windows) or the path
   * is unreachable. We use the synchronous `statfsSync` from `node:fs`
   * when available; on platforms without it we silently return null.
   *
   * Note: `statfsSync` returns `bfree` in blocks, not bytes —
   * multiply by `bsize` to get free bytes.
   */
  /**
   * ENOSPC escape channel (a full disk must not be able to both silence the
   * sink and erase the enforcement record). When the primary sink throws
   * ENOSPC, writeLocalDirect and writeLocal both try the critical
   * path `<localPath>.critical.jsonl` (independent file, no disk-low
   * gate, larger cap). If the critical path also fails, the existing
   * logger.warn / rethrow path records the loss.
   */
  private _criticalPath(): string {
    return this.localPath ? `${this.localPath}.critical.jsonl` : ''
  }

  private _isEnospc(error: unknown): boolean {
    if (!error || typeof error !== 'object') return false
    const code = (error as { code?: unknown }).code
    return code === 'ENOSPC'
  }

  private _tryWriteCritical(lines: string[]): boolean {
    const path = this._criticalPath()
    if (!path) return false
    try {
      // Larger cap (500 MiB) than the primary sink because the critical
      // path is the last-resort audit record — we'd rather keep more
      // than risk losing enforcement evidence. No integrity baseline
      // tracking (no lastLocalBytes / lastLocalInode for this file) —
      // the primary sink's integrity still gates the visible audit
      // trail; the critical file is forensic fallback only.
      appendToCappedNdjson(path, lines, 500 * 1024 * 1024, {
        logger: this.logger,
      })
      // The escape channel carries enforcement
      // evidence — same owner-only perm contract as the primary sink.
      this._chmodOwnerOnly(path)
      return true
    } catch {
      return false
    }
  }

  private _freeDiskBytes(dirPath: string): number | null {
    try {
      // statfsSync is Node 18.15+. `bfree` is free blocks; `bsize` is
      // the block size. Multiply to obtain free bytes. The typeof guard
      // covers hosts on Node < 18.15 where the export is undefined.
      // Accessed via the default import (not a named import) so older
      // runtimes don't fail at ESM link time.
      const stat = fs.statfsSync as unknown as undefined | ((p: string) => { bfree: number; bsize: number })
      if (typeof stat !== 'function') return null
      const info = stat(dirPath)
      if (typeof info.bfree !== 'number' || typeof info.bsize !== 'number') return null
      return info.bfree * info.bsize
    } catch {
      return null
    }
  }

  /**
   * Idempotent chmod 0o600 on a sink-owned file.
   * `appendToCappedNdjson` creates / recreates files with the process
   * umask (typically 0644 = group/world readable), so every write path
   * re-asserts owner-only perms after appending — including files
   * produced by rotation, the low-disk truncate, and the ENOSPC escape
   * channel. Never throws (EPERM on Windows; ENOENT mid-write race).
   */
  private _chmodOwnerOnly(path: string): void {
    try {
      chmodSync(path, 0o600)
    } catch {
      /* best effort — permissions are hygiene, not enforcement */
    }
  }

  private checkLocalIntegrity(): void {
    if (this.lastLocalBytes === undefined) return // first write of this process
    let stat: import('node:fs').Stats
    try {
      // `statSync` FOLLOWS symlinks — a
      // symlink swap resolves to the target's stat and could pass every check
      // (e.g. symlink → original hardlink keeps size + inode happy).
      // `lstatSync` stats the link itself: a symlink now fails
      // `isFile()` and is reported as `file_replaced` with
      // `stat_kind: 'symlink'` through the same integrity-alert channel.
      stat = lstatSync(this.localPath!)
    } catch {
      // File is gone entirely. Distinguish a compliant external rotation
      // (an operator / harness housekeeping job renamed the log to an
      // archive sibling — the real-data `file_deleted` alert was this
      // case, prev_bytes well under the size cap) from a hostile
      // deletion of the audit trail.
      if (this.isCompliantRotation()) {
        // Rotation: re-baseline silently. The next append recreates the
        // file and starts a fresh trail — no integrity alert.
        this.logger.warn(
          `[LocalNdjsonSink] audit log rotated externally (archive sibling present) — re-baselining without integrity alert (prev_bytes=${this.lastLocalBytes})`,
        )
        this.debugLog?.write('external_rotation', { prevBytes: this.lastLocalBytes ?? null })
        this.rotatedCount += 1
        this.lastRotationAt = Date.now()
        this.lastLocalBytes = undefined
        this.lastLocalInode = undefined
        return
      }
      // The operator declared the log's lifecycle as externally managed
      // (`collector.externallyManagedLog`) — the file's disappearance is
      // then an expected lifecycle event, not evidence of tampering.
      if (this.externallyManagedLog) {
        this.handleExternalLifecycle('deleted')
        return
      }
      // SECOND-STRIKE CONFIRMATION.
      //
      // A single failed stat cannot tell "the trail was deleted" from
      // "the trail is being rotated right now": an external rotator
      // that renames the log away and creates a fresh one leaves the
      // path missing for the few milliseconds between the two steps,
      // and a stat landing in that window reports a hostile deletion
      // that never happened. Re-stat once after a short delay; if the
      // path is back, the trail was rotated, not deleted.
      const confirmation = this.confirmPathReappeared()
      if (confirmation.reappeared) {
        if (confirmation.stat?.isFile()) {
          // Rotation window: the file is a regular file again. Re-baseline
          // silently — a trail that was renamed away and recreated is a
          // fresh trail, not a gap.
          this.logger.warn(
            `[LocalNdjsonSink] audit log path was momentarily absent (rotation window) — re-baselining without integrity alert (prev_bytes=${this.lastLocalBytes})`,
          )
          this.debugLog?.write('external_rotation', {
            prevBytes: this.lastLocalBytes ?? null,
            confirmed: true,
          })
          this.rotatedCount += 1
          this.lastRotationAt = Date.now()
          this.lastLocalBytes = undefined
          this.lastLocalInode = undefined
          return
        }
        // The path came back as something that is NOT a regular file
        // (symlink / device / FIFO) — that is the replacement attack,
        // not a rotation. Fall through to the replacement branch below.
        this.reportIntegrityGap('file_replaced', this.lastLocalBytes, {
          prev_inode: this.lastLocalInode,
          current_inode: confirmation.stat?.ino,
          stat_kind: describeStatKind(confirmation.stat),
        })
        return
      }
      // An attacker deleted the audit trail.
      this.reportIntegrityGap('file_deleted', this.lastLocalBytes)
      return
    }
    // defense against the in-place inode substitution where the sink path is
    // re-pointed at a character device after our last inode baseline.
    // The mv+recreate-style swap changes the inode (caught below).
    // A hardlink-to-/dev/null IN PLACE keeps the same inode — writes
    // silently go to /dev/null, the audit trail evaporates, and the
    // regular inode + size checks both pass. `stat.isFile()` rejects
    // anything that is not a regular file (character / block device,
    // FIFO, socket, symlink). Report as `file_replaced` (the most
    // specific existing event) and surface the stat kind for triage.
    if (!stat.isFile()) {
      if (this.externallyManagedLog) {
        this.handleExternalLifecycle('replaced')
        return
      }
      this.reportIntegrityGap('file_replaced', this.lastLocalBytes, {
        prev_inode: this.lastLocalInode,
        current_inode: stat.ino,
        stat_kind: describeStatKind(stat),
      })
      return
    }
    if (stat.size < this.lastLocalBytes) {
      // A shrinking file is the copytruncate shape (an external rotator
      // empties the file in place) as well as the hostile-truncation
      // shape. An operator who declared the log externally managed has
      // told us which one it is.
      if (this.externallyManagedLog) {
        this.handleExternalLifecycle('truncated')
        return
      }
      this.reportIntegrityGap('file_truncated', this.lastLocalBytes)
      return
    }
    // inode check catches the mv+recreate and the
    // symlink-to-/dev/null attacks. Both keep the size check happy but
    // change the underlying file. The size check above is also kept so
    // a truncation that also changes inode is still reported as truncated
    // (the more specific event).
    if (this.lastLocalInode !== undefined && stat.ino !== this.lastLocalInode) {
      if (this.externallyManagedLog) {
        this.handleExternalLifecycle('replaced')
        return
      }
      this.reportIntegrityGap('file_replaced', this.lastLocalBytes, {
        prev_inode: this.lastLocalInode,
        current_inode: stat.ino,
      })
    }
    // Greater-than is not a truncation; we only re-baseline after a clean
    // append (writeLocal) so an external append cannot silently shift us.
    this.debugLog?.write('integrity', {
      size: stat.size,
      inode: stat.ino,
    })
  }

  /**
   * SECOND-STRIKE confirmation for a missing audit log.
   *
   * Re-stats the path after a short synchronous delay. Returns
   * `{ reappeared: false }` when the path is still gone (a real
   * deletion), and `{ reappeared: true, stat }` when the path is back
   * (the rotator's rename→create window closed while we waited).
   *
   * WHY the delay is synchronous: the sink's write path is synchronous
   * (`lstatSync` / `appendFileSync`), so an async confirmation would
   * have to race the next write — and the whole point of the
   * confirmation is to decide BEFORE the next write whether the trail
   * is gone. `Atomics.wait` parks the thread without spinning the
   * event loop.
   *
   * Protected (not private) so the test suite can drive the branch
   * deterministically instead of racing a real filesystem race.
   */
  protected confirmPathReappeared(): { reappeared: boolean; stat?: import('node:fs').Stats } {
    sleepSyncMs(this.integrityConfirmDelayMs)
    try {
      const stat = lstatSync(this.localPath!)
      return { reappeared: true, stat }
    } catch {
      return { reappeared: false }
    }
  }

  /**
   * Operator-declared external lifecycle: the audit log's file
   * lifecycle (rotation / deletion / truncation) is owned by another
   * tool, so a lifecycle anomaly is an expected event, not evidence of
   * tampering. Re-baseline silently and keep the counters honest.
   *
   * This is the operator's explicit statement — the default posture
   * (this flag off) keeps reporting every anomaly as an integrity gap.
   */
  private handleExternalLifecycle(kind: 'deleted' | 'truncated' | 'replaced'): void {
    this.logger.warn(
      `[LocalNdjsonSink] audit log ${kind} — externally managed log declared (collector.externallyManagedLog=true); re-baselining without integrity alert (prev_bytes=${this.lastLocalBytes})`,
    )
    this.debugLog?.write('external_lifecycle', {
      kind,
      prevBytes: this.lastLocalBytes ?? null,
      prevInode: this.lastLocalInode ?? null,
    })
    this.rotatedCount += 1
    this.lastRotationAt = Date.now()
    this.lastLocalBytes = undefined
    this.lastLocalInode = undefined
  }

  /**
   * Detect a compliant EXTERNAL rotation: the active log path is gone,
   * but a sibling archive matching `<name>.<suffix>` / `<name>-<suffix>`
   * exists with a recent mtime (renamed within the last minute). The
   * sink's OWN rotations never reach this check — size-cap rotation is a
   * rename-over-target (the path never goes missing) and the disk-low
   * truncate resets the baseline first. This branch exists for operator
   * / harness housekeeping that renames the log away (the observed
   * real-data `file_deleted` alert, prev_bytes far under the cap).
   * Anything not matching the archive-sibling pattern is treated as a
   * hostile deletion.
   */
  private isCompliantRotation(): boolean {
    if (!this.localPath) return false
    const dir = dirname(this.localPath)
    const base = pathBasename(this.localPath)
    let siblings: string[]
    try {
      siblings = readdirSync(dir)
    } catch {
      return false
    }
    const cutoff = Date.now() - 60_000
    for (const name of siblings) {
      if (name === base) continue
      // `<base>.<something>` or `<base>-<something>` (e.g.
      // security-events.jsonl.1, security-events.jsonl.20261027.bak).
      if (!name.startsWith(`${base}.`) && !name.startsWith(`${base}-`)) continue
      try {
        const st = statSync(joinPath(dir, name))
        if (st.isFile() && st.mtimeMs >= cutoff) return true
      } catch {
        /* vanished mid-scan — not evidence */
      }
    }
    return false
  }

  private reportIntegrityGap(
    kind: 'file_deleted' | 'file_truncated' | 'file_replaced',
    prevBytes: number,
    extra?: { prev_inode?: number; current_inode?: number; stat_kind?: string },
  ): void {
    this.stats.errors++
    const message =
      kind === 'file_deleted'
        ? `审计日志被删除（prev_bytes=${prevBytes}）`
        : kind === 'file_truncated'
          ? `审计日志被截断（prev_bytes=${prevBytes}）`
          : `审计日志被替换（prev_bytes=${prevBytes}, prev_inode=${extra?.prev_inode}, current_inode=${extra?.current_inode}${extra?.stat_kind ? `, stat_kind=${extra.stat_kind}` : ''}）`
    this.logger.error(`[LocalNdjsonSink] ${message}，已写入 security_audit 事件`)
    try {
      // Write directly to local NDJSON: calling report(event) would cause
      // infinite recursion through writeLocalDirect → checkLocalIntegrity → reportIntegrityGap.
      // Keep session context via resolveSessionByPid so tests can verify attribution.
      const session = this.resolveSessionByPid?.(process.pid)
      const sessionId = session?.sessionId ?? null
      const runId = session?.runId ?? null
      const agentId = session?.agentId ?? null
      const event: SecurityEvent = {
        comm: DEFAULT_PLATFORM_ID,
        event_id: generateEventId(),
        event_type: 'security_audit',
        layer: 'application',
        source_layer: 'application',
        ts: Date.now(),
        pid: process.pid,
        collection_method: 'agent_api',
        host_id: hostname(),
        container_id: process.env.CONTAINER_ID || 'host',
        session_id: sessionId,
        run_id: runId,
        agent_id: agentId,
        audit_category: 'integrity',
        audit_action: 'detect',
        target: this.localPath!,
        outcome: 'failure',
        severity: 'high',
        reason: message,
        audit_details: {
          integrity: kind,
          prev_bytes: prevBytes,
          detail: message,
          ...(extra?.prev_inode !== undefined ? { prev_inode: extra.prev_inode } : {}),
          ...(extra?.current_inode !== undefined ? { current_inode: extra.current_inode } : {}),
          ...(extra?.stat_kind !== undefined ? { stat_kind: extra.stat_kind } : {}),
        },
      }
      this.buildTransportEvent(event)
      appendToCappedNdjson(this.localPath!, [JSON.stringify(event) + '\n'], this.config.maxFileBytes, {
        logger: this.logger,
      })
      // Owner-only perms (umask fallback otherwise).
      this._chmodOwnerOnly(this.localPath!)
      this.stats.flushed++
      this.debugLog?.write('integrity_gap', {
        kind,
        prevBytes,
        prevInode: extra?.prev_inode ?? null,
        currentInode: extra?.current_inode ?? null,
        statKind: extra?.stat_kind ?? null,
      })
    } catch {
      /* never throw to host — the next flush will retry detection */
    }
  }
}

let cachedOsUsername: string | undefined

/**
 * Resolve the OS login username of the user executing the event producer:
 * USER → USERNAME → os.userInfo().username. Resolved once per process —
 * the value cannot change for the plugin's lifetime. Any lookup failure
 * (e.g. username unresolvable) degrades to '' rather than throwing, so the
 * audit write path is never broken by identity resolution.
 */
function resolveOsUsername(): string {
  if (cachedOsUsername !== undefined) return cachedOsUsername
  let resolved = ''
  try {
    resolved = process.env.USER || process.env.USERNAME || userInfo().username || ''
  } catch {
    resolved = ''
  }
  cachedOsUsername = resolved
  return resolved
}

export function buildHostMeta(): Partial<SecurityEvent> {
  // Note: `pid` is intentionally NOT set here. Application-layer events set
  // it to `process.pid` (the plugin's own pid) for diagnostic correlation;
  // system-layer events set it to the monitored pid. Setting it in this helper
  // would clobber the caller-supplied value, so each event type is responsible
  // for its own `pid` semantics.
  return {
    host_id: hostname(),
    container_id: process.env.CONTAINER_ID || 'host',
    username: resolveOsUsername(),
  }
}
