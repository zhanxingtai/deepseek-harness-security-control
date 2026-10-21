import type {
  Agent,
  ContentBlock,
  FsObservation,
  FsTarget,
  FsWriteIntentPayload,
  GenerateOptions,
  PreStepPayload,
  AgentCreatedPayload,
  StreamChunk,
  ToolExecution,
  ToolExecutionResult,
  TurnStoppingPayload,
} from '../types/external.js'
import type { RuntimeHookSessionContext } from '../intervention/InterventionEngine.js'
import { httpRequestContext, type HttpRequestSessionContext } from '../utils/httpContext.js'
import type { Config } from '../config.js'
import type { InterventionContext, SecurityDecision, SecurityEvent, SessionContext, SourceMeta } from '../types/index.js'
import { DEFAULT_PLATFORM_ID } from '../types/index.js'
import { generateEventId } from '../utils/eventId.js'
import { deriveDataLeakFlags } from '../utils/dataLeakFlags.js'
import { nowMs } from '../utils/time.js'
import {
  redactAndCollectKeys,
  redactRawParams,
  truncateString,
  limitPayloadSize,
  DEFAULT_PAYLOAD_MAX_BYTES,
} from '../utils/redact.js'
import { redactStreamContent } from '../utils/contentRedactor.js'
import { safeExtractString, safeExtractRecord } from '../utils/safeExtract.js'
import { extractContentString, md5Hex } from '../utils/hash.js'
import {
  extractCommandString,
  isShellLikeTool,
  parseShellFileOps,
} from '../utils/shellFileOps.js'
import { buildHostMeta, LocalNdjsonSink } from './LocalNdjsonSink.js'
import type { InterventionEngine } from '../intervention/InterventionEngine.js'
import { evaluateSensitivePathGuard } from '../intervention/SensitivePathGuard.js'
import { evaluateInlinePromptInjection } from '../intervention/InlinePromptInjection.js'
import { evaluateEnvPassthroughGuard } from '../intervention/EnvPassthroughGuard.js'
import { runInlineGuardChain } from '../intervention/inlineGuardChain.js'
import { LoopedToolDetector, type LoopedToolHit } from '../intervention/LoopedToolDetector.js'
import {
  TokenUsageDetector,
  teeLlmStream,
  type TokenUsageHit,
} from '../utils/tokenUsage.js'
import { PidBindingStore } from './pidBindingStore.js'
import { EventEmitter } from './EventEmitter.js'
import { SessionStore } from './SessionStore.js'

export interface ApplicationCollectorStats {
  eventsEmitted: number
  sessionsTracked: number
}

/** Pending fs/write-intent decision awaiting absorption into the matching
 *  fs/observed for the same targetKey. */
interface PendingWriteIntent {
  kind: 'createIfAbsent' | 'replaceIfVersion'
  version?: string
  displayPath: string
  toolName?: string
  ts: number
}

export interface ApplicationCollectorOptions {
  /** Window (ms) for absorbing fs/write-intent into fs/observed. Default 2000. */
  fsIntentAbsorbMs?: number
  /** Inject the harness `ctx.logger` so warn/error lines surface in the
   *  operator's harness console. Default falls back to `console` for
   *  legacy callers (matches the `LocalNdjsonSink` seam). The shape is
   *  narrower than `LocalNdjsonSink`'s `Pick<Console, ...>` because the
   *  Cordis `Logger` interface only declares debug/info/warn/error. */
  logger?: {
    warn: (m: string, ...a: unknown[]) => void
    error: (m: string, ...a: unknown[]) => void
  }
}

/**
 * Collects application-layer events from Harness Cordis events and forwards
 * normalized SecurityEvents to the LocalNdjsonSink.  This class also maintains a
 * lightweight in-memory session cache so that later events can be correlated with
 * the original user prompt, system prompt, and previous actions.
 */
export class ApplicationCollector {
  private config: Config['application']
  // Shared reference to the collector config block — a hot-update of
  // `collector.redactRawParams` takes effect on the very next tool call.
  private collectorConfig: Config['collector']
  private interventionConfig: Config['intervention']
  // Inline sensitive-path deny-list. Safety-net semantics — the operator
  // cannot disable the deny-list (paths: [] is silently re-asserted to
  // the marketplace hardcoded list inside normalizeConfig).
  private sensitivePathGuard: Config['sensitivePathGuard']
  // Inline prompt-injection fingerprint matcher. Same safety-net semantics
  // as `sensitivePathGuard` — patterns: [] is silently re-asserted to the
  // marketplace 24-pattern catalogue inside normalizeConfig.
  private inlinePromptInjection: Config['inlinePromptInjection']
  // Inline env-passthrough guard. Same safety-net semantics —
  // keys: [] is silently re-asserted to the marketplace hardcoded 6-key
  // deny-list (LD_PRELOAD / LD_LIBRARY_PATH / NODE_OPTIONS / PYTHONPATH /
  // PYTHONSTARTUP / NODE_PATH) inside normalizeConfig.
  private envPassthroughGuard: Config['envPassthroughGuard']
  // Per-tool call-counter loop detector. Audit-only — fires
  // security_audit/looped_tool when a single (sessionId, toolName) pair
  // crosses the threshold within the sliding window. Does NOT participate
  // in the SPL pipeline. Owned here because it needs session-eviction hooks
  // wired alongside the existing sessions / recentUserMessages TTL cleanup.
  private loopedToolDetector: LoopedToolDetector
  // Per-session token-usage burst detector fed by the llm/stream tee.
  // Audit-only — fires security_audit/anomalous_token_usage when a call's
  // token total exceeds burstFactor × the in-window mean baseline. Does
  // NOT block or modify the LLM stream. Owned here for the same
  // session-eviction reason as `loopedToolDetector`.
  private tokenUsageDetector: TokenUsageDetector
  // LocalNdjsonSink stamps hostId/containerId via buildHostMeta() in its
  // report() path. Top-level Config carries the values; the previous
  // `environment` sub-object is gone.
  private eventCollector: LocalNdjsonSink
  private interventionEngine?: InterventionEngine
  /**
   * pid → session mapping lives in its own data class
   * (`./pidBindingStore.ts`). The harness process (and any tool
   * process it spawns) can be looked up by `pid` or `ppid` when an
   * emit path lacks session context but the pid is still attributable.
   *
   * `PidBindingStore` owns the cap (5 000) + LRU-by-`ts` eviction +
   * invalid-PID guard + cascade eviction on parent-session retirement.
   * The store is pure: no Cordis, no logger, no event emission.
   */
  private pidSessionMap = new PidBindingStore()
  /**
   * Session-state container (sessions Map +
   * recentUserMessages + mostRecentSession pointer + the TTL eviction
   * primitives). Owned by ApplicationCollector but the actual data lives
   * in `./SessionStore.ts`. The getter below (`get sessions()`) proxies
   * test reads — see `tests/ApplicationCollector.test.ts:826,855,1039`.
   */
  private sessionStore!: SessionStore
  /** keyed by targetKey; populated by fs/write-intent, consumed by fs/observed
   *  so one file mutation yields a single audit record (see onFsObserved). */
  private pendingIntents = new Map<string, PendingWriteIntent>()
  private readonly intentAbsorbMs: number
  private stats: ApplicationCollectorStats = { eventsEmitted: 0, sessionsTracked: 0 }
  /**
   * Event-infrastructure (base-event shape, source
   * stamping, decision application, sink-report wiring). Owns the
   * `eventsEmitted++` increment; the previous inline `emit` method on
   * this class forwarded here.
   */
  private eventEmitter!: EventEmitter
  private ttlTimer?: ReturnType<typeof setInterval>
  private logger: { warn: (m: string, ...a: unknown[]) => void; error: (m: string, ...a: unknown[]) => void }

  constructor(
    config: Config,
    eventCollector: LocalNdjsonSink,
    interventionEngine?: InterventionEngine,
    options: ApplicationCollectorOptions = {},
  ) {
    this.config = config.application
    this.collectorConfig = config.collector
    this.interventionConfig = config.intervention
    this.sensitivePathGuard = config.sensitivePathGuard
    this.inlinePromptInjection = config.inlinePromptInjection
    this.envPassthroughGuard = config.envPassthroughGuard
    // Construct the loop detector and wire the hit callback to emit a
    // security_audit/looped_tool event. The detector is pure (no I/O) —
    // the host owns the audit emission so the same eventCollector reporting
    // contract is reused.
    this.loopedToolDetector = new LoopedToolDetector(
      config.loopedToolDetector,
      (hit) => this.emitLoopedToolAudit(hit),
    )
    // Construct the token-usage burst detector and wire the hit callback
    // to emit a security_audit/anomalous_token_usage event. Same ownership
    // split as the loop detector — the detector is pure; the host owns
    // emission.
    this.tokenUsageDetector = new TokenUsageDetector(
      config.tokenUsageDetector,
      (hit) => this.emitAnomalousTokenUsageAudit(hit),
    )
    this.eventCollector = eventCollector
    this.interventionEngine = interventionEngine
    this.intentAbsorbMs = options.fsIntentAbsorbMs ?? 2000
    // Prefer the injected logger so the collector's warn/error lines reach
    // the operator's harness console. Default to `console` for tests and
    // legacy callers (matches the LocalNdjsonSink seam).
    this.logger = options.logger ?? console
    // Instantiate the event-infrastructure +
    // session-state modules. They share the `stats` reference so the host
    // `getStats()` keeps reading one shape (`{ eventsEmitted,
    // sessionsTracked }`); the loop + token-usage detectors are passed
    // to SessionStore so the TTL sweep can drop their per-session state.
    this.eventEmitter = new EventEmitter(eventCollector, this.stats)
    this.sessionStore = new SessionStore(this.stats, {
      applicationConfig: this.config,
      loopedToolDetector: this.loopedToolDetector,
      tokenUsageDetector: this.tokenUsageDetector,
      pidBindingStore: this.pidSessionMap,
    })
  }

  initialize(): void {
    this.ttlTimer = setInterval(() => this.evictStaleSessions(), Math.max(this.config.sessionTtlMs / 2, 1000))
  }

  shutdown(): void {
    if (this.ttlTimer) {
      clearInterval(this.ttlTimer)
      this.ttlTimer = undefined
    }
    // Session state lives in SessionStore — clear via that
    // module so the lifecycle stays in one place. The Map
    // references returned by `getSessions()` are the same Map instances
    // the store holds, so the wipe propagates to any test that held
    // a reference via `priv.sessions`.
    this.sessionStore.clearAll()
    // pidSessionMap holds per-pid entries for the
    // lifetime of the process unless explicitly cleared. Shutdown
    // already clears sessions + recentUserMessages (via SessionStore);
    // do the same here for consistency. The process exits shortly after
    // so this is mostly cosmetic, but it keeps the destroy/reload path
    // symmetric and prevents unit-test harnesses from leaking entries
    // across boots in the same process.
    this.pidSessionMap.clear()
  }

  /**
   * Apply application-layer keys in place. Every field here is a threshold
   * read off a shared config reference at use time — the capture booleans /
   * toolResultMaxChars on `config.application`, the looped-tool +
   * token-usage detector windows on their (shared) detector configs, and
   * the inline-guard paths / patterns / keys deny-list extensions on their
   * shared guard configs (the guards themselves are stateless matchers,
   * so the next evaluation picks the new lists up with no re-register).
   * `sessionTtlMs` additionally rebuilds the session-eviction timer so the
   * new cadence is genuinely in effect. All `enabled` switches in these
   * blocks are rejected at the classifier level and never reach this
   * method from LivePatchManager.
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
      const app = patch['application']
      if (app && typeof app === 'object' && !Array.isArray(app)) {
        const a = app as Record<string, unknown>
        const assignBool = (field: 'captureUserPrompt' | 'captureSystemPrompt' | 'captureAgentPlan' | 'captureReasoning'): void => {
          if (typeof a[field] === 'boolean') {
            this.config[field] = a[field]
            appliedKeys.push(`application.${field}`)
          }
        }
        assignBool('captureUserPrompt')
        assignBool('captureSystemPrompt')
        assignBool('captureAgentPlan')
        assignBool('captureReasoning')
        if (typeof a['toolResultMaxChars'] === 'number' && Number.isFinite(a['toolResultMaxChars'])) {
          this.config.toolResultMaxChars = a['toolResultMaxChars']
          appliedKeys.push('application.toolResultMaxChars')
        }
        if (typeof a['sessionTtlMs'] === 'number' && Number.isFinite(a['sessionTtlMs']) && a['sessionTtlMs'] > 0) {
          this.config.sessionTtlMs = a['sessionTtlMs']
          appliedKeys.push('application.sessionTtlMs')
          // Require `> 0` (the Math.max
          // floor below already protects the timer cadence, but a 0/
          // negative livePatch would silently saturate the eviction
          // timer at 1s — the rejection here keeps the operator-visible
          // behavior consistent with what the timer will actually do).
          if (this.ttlTimer) {
            clearInterval(this.ttlTimer)
            this.ttlTimer = setInterval(
              () => this.evictStaleSessions(),
              Math.max(this.config.sessionTtlMs / 2, 1000),
            )
          }
        }
      }
      // `redactRawParams` is hardcoded to true in
      // marketplace form (Config type is `true`, normalizeConfig overrides
      // any input). livePatch can no longer apply changes to it — silently
      // ignored here. The audit trail no longer tracks a non-applied key.
      const collectorPatch = patch['collector']
      if (collectorPatch && typeof collectorPatch === 'object' && !Array.isArray(collectorPatch)) {
        // redactRawParams intentionally not handled — see config.ts
        void collectorPatch
      }
      const looped = patch['loopedToolDetector']
      if (looped && typeof looped === 'object' && !Array.isArray(looped)) {
        const l = looped as Record<string, unknown>
        if (typeof l['windowMs'] === 'number' && Number.isFinite(l['windowMs'])) {
          this.loopedToolDetector.config.windowMs = l['windowMs']
          appliedKeys.push('loopedToolDetector.windowMs')
        }
        if (typeof l['thresholdPerWindow'] === 'number' && Number.isFinite(l['thresholdPerWindow'])) {
          this.loopedToolDetector.config.thresholdPerWindow = l['thresholdPerWindow']
          appliedKeys.push('loopedToolDetector.thresholdPerWindow')
        }
      }
      const token = patch['tokenUsageDetector']
      if (token && typeof token === 'object' && !Array.isArray(token)) {
        const t = token as Record<string, unknown>
        if (typeof t['windowMs'] === 'number' && Number.isFinite(t['windowMs'])) {
          this.tokenUsageDetector.config.windowMs = t['windowMs']
          appliedKeys.push('tokenUsageDetector.windowMs')
        }
        if (typeof t['burstFactor'] === 'number' && Number.isFinite(t['burstFactor'])) {
          this.tokenUsageDetector.config.burstFactor = t['burstFactor']
          appliedKeys.push('tokenUsageDetector.burstFactor')
        }
        if (typeof t['minBaselineSamples'] === 'number' && Number.isFinite(t['minBaselineSamples'])) {
          this.tokenUsageDetector.config.minBaselineSamples = t['minBaselineSamples']
          appliedKeys.push('tokenUsageDetector.minBaselineSamples')
        }
      }
      const spg = patch['sensitivePathGuard']
      if (spg && typeof spg === 'object' && !Array.isArray(spg)) {
        const s = spg as Record<string, unknown>
        if (Array.isArray(s['paths'])) {
          this.sensitivePathGuard.paths = [
            ...(s['paths'] as unknown[]).filter((x): x is string => typeof x === 'string'),
          ]
          appliedKeys.push('sensitivePathGuard.paths')
        }
      }
      const ipi = patch['inlinePromptInjection']
      if (ipi && typeof ipi === 'object' && !Array.isArray(ipi)) {
        const i = ipi as Record<string, unknown>
        if (Array.isArray(i['patterns'])) {
          this.inlinePromptInjection.patterns = [
            ...(i['patterns'] as unknown[]).filter((x): x is string => typeof x === 'string'),
          ]
          appliedKeys.push('inlinePromptInjection.patterns')
        }
        if (typeof i['excerptMaxChars'] === 'number' && Number.isFinite(i['excerptMaxChars'])) {
          this.inlinePromptInjection.excerptMaxChars = i['excerptMaxChars']
          appliedKeys.push('inlinePromptInjection.excerptMaxChars')
        }
      }
      const epg = patch['envPassthroughGuard']
      if (epg && typeof epg === 'object' && !Array.isArray(epg)) {
        const e = epg as Record<string, unknown>
        if (Array.isArray(e['keys'])) {
          this.envPassthroughGuard.keys = [
            ...(e['keys'] as unknown[]).filter((x): x is string => typeof x === 'string'),
          ]
          appliedKeys.push('envPassthroughGuard.keys')
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
   * Stamp the platform-standard `source` string and structured `collector`
   * metadata onto an application-layer event. Per the platform spec,
   * `source` must be a string, not an object; hook/middleware/collector
   * details live on `collector`.
   *
   * Implementation lives in `./EventEmitter.ts`. This
   * wrapper remains so the handler bodies can keep calling
   * `this.stampSource(...)` without rewrites.
   */
  private stampSource(event: SecurityEvent, collector: SourceMeta): void {
    this.eventEmitter.stampSource(event, collector)
  }

  /**
   * TTL sweep — delegates to SessionStore. The store
   * owns the loop / token-usage detector cascade + the pidBindingStore
   * cascade + the `recentUserMessages` wipe. Kept as a thin wrapper
   * so `tests/ApplicationCollector.test.ts:827,835,1043` can keep
   * driving it directly via `(collector as unknown as
   * { evictStaleSessions: () => void }).evictStaleSessions()`.
   */
  private evictStaleSessions(): void {
    this.sessionStore.evictStaleSessions()
  }

  // --- Cordis event handlers ------------------------------------------------

  onAgentSessionStart({ agent, source }: AgentCreatedPayload): void {
    const sessionId = agent.session.header.id
    const sessionContext = this.getOrCreateSession(sessionId, agent)
    // The harness process itself belongs to this session.
    this.bindPidToSession(process.pid, sessionContext)

    if (this.config.captureSystemPrompt && source) {
      sessionContext.systemPrompt = source
    }

    const event = this.makeBaseEvent('agent_session_start', sessionContext)
    event.agent_id = agent.id
    event.model_provider = agent.options?.provider
    event.model_name = agent.options?.model
    this.stampSource(event, { hook_name: 'agent_session_start', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })
    this.emit(event)

    // Also emit agent_start for compatibility with the platform ingest schema.
    // Emit `agents` as a single-element array per the spec
    // (§agent_start). The platform consumer shape is
    // `agents[*].{id, name, agentDir, config, skills, tools}`. The Cordis
    // `Agent` payload only carries `id` + `options.{provider,model}`
    // — no filesystem-shaped agentDir/config/skills/tools. ebpf collectors
    // fill these by reading /proc; the Cordis plugin can only resolve `id`
    // + `name` (we use `id` for both — the spec example also uses identical
    // values), and emits `null` for the unavailable fields so the schema
    // shape stays stable for downstream joiners. Loose `agent_id` /
    // `agent_config` / `model_*` keys are retained for backward compat with
    // existing consumers that haven't migrated to `agents[*]`.
    const startEvent = this.makeBaseEvent('agent_start', sessionContext)
    startEvent.agent_id = agent.id
    startEvent.agent_config = { provider: agent.options?.provider, model: agent.options?.model }
    startEvent.model_provider = agent.options?.provider
    startEvent.model_name = agent.options?.model
    // Surface skills/tools when Cordis exposes them. The stub carries them
    // as optional arrays; real harness payloads populate them so dashboards
    // can reason about the agent's capability surface.
    const skills = agent.options?.skills
    const tools = agent.options?.tools
    startEvent.skills = skills
    startEvent.tools = tools
    startEvent.agents = [{ id: agent.id, name: agent.id, agentDir: null, config: null, skills: skills ?? null, tools: tools ?? null }]
    this.stampSource(startEvent, { hook_name: 'agent_start', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })
    this.emit(startEvent)
  }

  async onAgentPreStep({ agent, messages, turn }: PreStepPayload): Promise<void> {
    const sessionContext = this.getOrCreateSession(agent.session.header.id, agent)
    sessionContext.runId = `${sessionContext.sessionId}-${turn}`

    const text = messages.flatMap((m) => m.content).map(blocksToText).join('')
    // Cordis re-fires `agent/pre-step` with an empty `messages` array right
    // after a blocked tool call (the harness loops back to retry). Skipping
    // these keeps the audit log focused on actual user/model turns.
    if (!text) return

    sessionContext.messageIndex++

    const ts = nowMs()
    this.sessionStore.getRecentUserMessages().set(sessionContext.sessionId, {
      prompt: text,
      timestamp: ts,
    })
    sessionContext.userPrompt = text
    // `lastUserMessageAt` is updated BEFORE the
    // prompt-injection block path returns so `evictStaleSessions` can age
    // out a long-running session even when every message is blocked by
    // the guard (a DoS loop of repeated blocked injections would otherwise
    // keep the session alive forever by continuously refreshing this
    // timestamp). `sessionStartTs` is intentionally NOT reset — it is
    // stamped once in `getOrCreateSession` and the audit metric
    // `agent_stop.duration` is computed against it as a whole-session
    // span. Resetting on block would silently inflate that metric
    // (audit consumers would lose the blocked-time share of the duration).
    sessionContext.lastUserMessageAt = ts

    const event = this.makeBaseEvent('agent_message', sessionContext)
    event.role = messages[0]?.role ?? 'user'
    // Cap user-controllable payload to avoid OOM. toolResultMaxChars (100k)
// and the payload cap (1 MiB) are the two size guards — tool result is
// audited in detail, message bodies are capped at 1 MiB to keep a single
// event bounded.
    const capped = limitPayloadSize(text, DEFAULT_PAYLOAD_MAX_BYTES)
    event.content = capped.value
    event.content_length = capped.value.length
    if (capped.truncated) {
      event.content_truncated = true
      event.content_original_length = capped.originalLength
    }
    event.message_index = sessionContext.messageIndex
    this.stampSource(event, { hook_name: 'agent_message', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })

    // Message-level intervention is opt-in. In audit mode we still record
    // anything that the engine decided, but trivial allow decisions are not
    // attached to the event payload (the platform `intervention` field table
    // does not list a `fail_strategy` sub-field and reference data shows that
    // non-evaluating allow events emit no intervention at all).
    if (this.interventionConfig.enabled && this.interventionEngine) {
      // Inline prompt-injection guard fires BEFORE evaluateMessage. The
      // 24-pattern catalogue is hardcoded and non-overridable —
      // no `INJECT_*` SPL rules exist in the
      // shipped policies, so this guard is the **only** prompt-injection
      // defence and a policy YAML edit cannot neutralise it. On hit the
      // audit event carries `block_code: 'INLINE_PROMPT_INJECTION_001'`
      // + redacted `sample_excerpt` for post-hoc review.
      const messageCtx = this.buildMessageInterventionContext(event)
      const injectionDecision = evaluateInlinePromptInjection(
        messageCtx,
        this.inlinePromptInjection,
      )
      if (injectionDecision) {
        this.applyDecisionToEvent(event, injectionDecision)
        this.emit(event)
        return
      }
      const decision = await this.evaluateMessage(event)
      if (decision && decision.decision !== 'allow') {
        this.applyDecisionToEvent(event, decision)
      }
    }

    this.emit(event)
  }

  onToolPreExecute(exec: ToolExecution, decision?: SecurityDecision): void {
    const sessionContext = this.resolveSessionContext(exec)
    if (!sessionContext) return

    // Stamp the most-recent session so RuntimeHook can correlate spawns
    // that lack the `exec` reference. Captured BEFORE stepIndex++ so the
    // first pre-execute in a session is recorded. Also stamp the explicit
    // task_id / turn_id aliases so the runtime_*_intent events carry them
    // without RuntimeHook having to re-derive them from session_id / run_id.
    this.sessionStore.setMostRecentSession({
      sessionId: sessionContext.sessionId,
      runId: sessionContext.runId,
      agentId: sessionContext.agentId,
      taskId: sessionContext.sessionId,
      turnId: sessionContext.runId,
    })
    // Record the harness process pid for this session so system-layer scans
    // can correlate spawned/descendant processes.
    this.bindPidToSession(process.pid, sessionContext)

    sessionContext.stepIndex++
    const toolCallId = this.buildToolCallId(sessionContext, exec)

    const event = this.makeBaseEvent(this.classifyToolEvent(exec.name), sessionContext)
    event.tool_call_id = toolCallId
    event.tool_name = exec.name
    event.tool_kind = 'native'
    // Use the key-tracking redaction so the event surfaces which keys were
    // masked. Same masking semantics as `redactSensitiveBody` (one-line
    // change, no behavior shift on the masked values themselves), but the
    // side-channel list feeds `event.redacted_keys` for the platform audit
    // contract.
    const { result: maskedParams, redactedKeys: paramsKeys } = redactAndCollectKeys(
      safeExtractRecord(exec.arguments),
    )
    event.params = maskedParams
    // `tool_params` is the platform audit contract carrier. Marketplace form
    // honours `collector.redactRawParams` (default true) so sensitive keys
    // are masked on persist. When `redactRawParams: false`, the verbatim
    // JSON lands on `tool_params` for forensic replay; the operator's
    // call is recorded on `redacted: false` in the `params_redaction`
    // side-channel.
    const rawParamsJson = JSON.stringify(exec.arguments ?? {})
    const redacted = redactRawParams(rawParamsJson, {
      enabled: this.collectorConfig.redactRawParams,
    })
    event.tool_params = redacted.value
    // `redacted_keys` is set after the user_prompt redaction below so the
    // union list includes both params-side and prompt-side hits.
    event.params_redaction = {
      enabled: this.collectorConfig.redactRawParams,
      redacted: redacted.redacted,
      raw_size_bytes: redacted.size,
      raw_hash_sha256: redacted.hash,
    }
    // Also cap the user_prompt surfaced on tool_call events (a single
    // multi-MB user prompt would otherwise ride on every tool event until
    // session expiry). Per invariant #6, redact
    // the user_prompt BEFORE the size cap so a Bearer token sitting at
    // byte 100 of a 2 MiB prompt is masked even when the tail would
    // otherwise survive the cap. KEY-based + value-pattern through
    // `redactStreamContent` — JSON-parse attempt first (covers prompts
    // shaped like `{ "Authorization": "Bearer xxx" }`), then the
    // documented credential-family patterns.
    const promptRedaction = redactStreamContent(sessionContext.userPrompt ?? '')
    const promptCapped = limitPayloadSize(promptRedaction.value, DEFAULT_PAYLOAD_MAX_BYTES)
    event.user_prompt = promptCapped.value
    if (promptCapped.truncated) {
      event.user_prompt_truncated = true
      event.user_prompt_original_length = promptCapped.originalLength
    }
    // Surface the user_prompt-side hits on a dedicated field so audit
    // consumers can tell which sub-emitter (params vs. prompt) fired
    // without diffing the union `redacted_keys` list.
    event.user_prompt_redacted_keys = promptRedaction.redactedKeys
    // Merge into the union `redacted_keys` so the existing consumer
    // contract (single flat array of all masked keys) still holds.
    event.redacted_keys = [
      ...paramsKeys,
      ...redacted.redactedKeys,
      ...promptRedaction.redactedKeys,
    ].sort()
    event.previous_actions = sessionContext.previousActions.slice(-50)
    event.step_index = sessionContext.stepIndex
    event.is_code_mode = this.isCodeMode(exec.name)
    // Surface a normalised `path` on every `agent_tool_call` whose tool name
    // carries a file-shaped intent. Previously this only ran when
    // classifyToolEvent promoted the event to file_*; now that promotion
    // no longer happens (fs/observed owns the file_* stream), we still
    // want SPL rules that match `path` to fire on the agent_tool_call
    // side. The path is best-effort — tools with no path-like arg simply
    // omit the field.
    const normalisedPath = this.normalizePath(safeExtractRecord(exec.arguments))
    if (normalisedPath !== undefined) {
      event.path = normalisedPath
    }
    this.stampSource(event, { hook_name: 'agent_tool_call', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })

    if (event.is_code_mode) {
      event.code_language = safeExtractString((exec.arguments as Record<string, unknown>)?.language)
      event.code_content = truncateString(safeExtractString((exec.arguments as Record<string, unknown>)?.code), 4000)
      event.code_content_length = event.code_content.length
      // Hash the actual code body so the platform can fingerprint what was
      // about to be executed (post-execute result hash covers the output).
      if (event.code_content) event.hash = md5Hex(event.code_content)
    }

    // Intent hash for write-class events: the platform can correlate
    // "agent tried to write content X to path Y" with future reads of Y
    // to detect tampering, even when the write itself was blocked.
    //
    // Trigger on the presence of a normalised path (which only
    // write/read/edit tool args carry) AND a non-empty content field.
    // Read-only file tools (Read with no `content` arg) produce no hash —
    // the read fingerprint is the post-execute `hash` on the
    // `agent_tool_result`, not the pre-execute intent hash.
    if (event.path !== undefined) {
      const content = extractContentString(exec.arguments as Record<string, unknown> | undefined)
      if (content !== undefined) event.hash = md5Hex(content)
    }

    // Post-hoc shell file-op parsing: for shell-like tools (bash, python -c,
    // node -e, ...), the command string may embed file operations that the
    // tool-name classifier cannot see. Derive them here and attach to the
    // same event so audit dashboards correlate shell-driven file activity
    // with native file_* events. Empty when nothing recognized.
    if (isShellLikeTool(exec.name)) {
      const cmd = extractCommandString(exec.arguments as Record<string, unknown> | undefined)
      if (cmd) {
        const derived = parseShellFileOps(cmd)
        if (derived.length > 0) {
          event.derived_file_ops = derived
        }
      }
    }

    this.applyDecisionToEvent(event, decision)
    if (decision?.decision === 'block') {
      // Count blocked tool_calls per session so agent_stop can emit
      // `intervention_blocked: boolean` without re-parsing previousActions
      // (which doesn't store the decision field).
      sessionContext.blockedToolCallCount =
        (sessionContext.blockedToolCallCount ?? 0) + 1
    }
    if (decision?.decision === 'block' && decision.block_reason) {
      // Record so onToolPostExecute can avoid duplicating block_reason into
      // error_message when Cordis still calls us back in audit mode. Keyed
      // by `exec.callId` (stable per Cordis invocation) so concurrent tool
      // calls do not collide on the synthetic tool_call_id (see
      // pendingToolStarts rationale and SessionContext doc).
      sessionContext.blockedCalls!.set(exec.callId, decision.block_reason)
    }
    // Cache start time + the synthetic tool_call_id so post-execute can
    // compute a real duration instead of falling back to 0. Keyed by
    // `exec.callId` (NOT the synthetic toolCallId) so concurrent tool
    // dispatches (read:9 / read:10 / read:11 fired in the same step batch)
    // each retrieve their own pre-execute, not the latest one's. The
    // synthetic toolCallId is stored inside the entry so the emitted
    // agent_tool_result event still carries the id pre-execute stamped —
    // existing audit consumers see no change.
    sessionContext.pendingToolStarts!.set(exec.callId, { toolCallId, startTime: nowMs() })
    // Record this `tools/pre-execute` call against the per-(session, tool)
    // sliding window. The detector returns the hit on the call that
    // crosses the threshold and stays silent on every other call (see
    // LoopedToolDetector for the re-arm policy). The `audit` emit happens
    // inside the hit callback that was wired in the constructor —
    // `record()` itself is non-blocking and never throws.
    this.loopedToolDetector.record(exec.name, sessionContext.sessionId, nowMs())
    this.emit(event)

    // when the matched rule(s)
    // fired on the canonical (folded / normalised / spaced) form of
    // the input rather than verbatim text, surface a paired
    // `security_audit/canonicalization_applied` row alongside the
    // `agent_tool_call` event. Tells operators the rail had to rewrite
    // obfuscated text before matching (volume metric = attack-volume
    // signal; per-event detail = what got rewritten). Only emits when
    // there IS a decision (audit-mode allow decisions also flow
    // through here); `decision.canonicalization_applied` is the
    // engine-set flag from `matchRules()`.
    if (decision?.canonicalization_applied) {
      this.emitCanonicalizationAudit(sessionContext, exec, toolCallId, decision)
    }

    // Emit a platform-standard `file_privilege` companion event for native
    // chmod/chown/setfacl tools and for shell-derived privilege ops
    // (e.g. `bash -c "chmod 777 /etc/shadow"`). The companion event carries
    // the same tool_call_id so it joins back to the invoking
    // agent_tool_call.
    this.emitFilePrivilegeEvents(sessionContext, exec, toolCallId, event, decision)
  }

  onToolPostExecute(exec: ToolExecution, result: ToolExecutionResult): void {
    const sessionContext = this.resolveSessionContext(exec)
    if (!sessionContext) return

    // Look up by `exec.callId` (the stable Cordis identifier for THIS
    // invocation), NOT by recomputing the synthetic tool_call_id from the
    // current stepIndex. Concurrent tool calls share stepIndex at
    // post-execute time, so a recomputed lookup collides on whatever
    // sibling fired last. The synthetic id we emit below comes from the
    // entry pre-execute stored, so audit consumers still see the matching
    // pre/post pair under one tool_call_id.
    const pendingEntry = sessionContext.pendingToolStarts!.get(exec.callId)
    const toolCallId = pendingEntry?.toolCallId ?? this.buildToolCallId(sessionContext, exec)
    const wasBlocked = sessionContext.blockedCalls!.has(exec.callId)
    if (wasBlocked) {
      // Blocked tool calls do not produce a separate agent_tool_result event:
      // the block is fully described by the agent_tool_call event's
      // intervention.block_reason. Reference data emits zero blocked
      // agent_tool_result events.
      sessionContext.blockedCalls!.delete(exec.callId)
      sessionContext.pendingToolStarts!.delete(exec.callId)
      void result
      return
    }

    const startTime = pendingEntry?.startTime ?? nowMs()
    sessionContext.pendingToolStarts!.delete(exec.callId)
    const duration = nowMs() - startTime

    const event = this.makeBaseEvent('agent_tool_result', sessionContext)
    event.tool_call_id = toolCallId
    event.tool_name = exec.name
    event.tool_kind = 'native'
    event.duration = duration
    event.execution_duration_ms = duration
    event.execution_status = result.isError ? 'failure' : 'success'
    event.status = result.isError ? 'failure' : 'success'

    if (result.isError) {
      event.error_message = result.error.message
      // Emit `result` as an empty string on the failure path. The platform
      // spec treats `result` as a required full-content carrier; empty
      // string keeps the field schema-stable while signalling "no content
      // available" (error_message carries the diagnostic).
      event.result = ''
    } else {
      const preview = result.content.map(blocksToText).join('')
      // `result` is the required full-content carrier on `agent_tool_result`.
// Emit it verbatim when it fits under the configurable
// `toolResultMaxChars` cap (default 100k); oversized results keep the 4k
// `result_preview` + full-length `hash`/`result_size` fingerprints so
// lossless correlation survives either way.
      if (preview.length <= this.config.toolResultMaxChars) {
        event.result = preview
      } else {
        event.result_truncated = true
      }
      event.result_preview = truncateString(preview, 4000)
      event.result_preview_length = event.result_preview.length
      event.result_size = preview.length
      // Hash the FULL result (not the truncated preview) so the fingerprint
      // survives lossless correlation. Empty results are skipped — hashing
      // "" produces a stable but uninformative digest.
      if (preview.length > 0) event.hash = md5Hex(preview)
    }

    this.stampSource(event, { hook_name: 'agent_tool_result', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })

    // Track in session context for chain matching.
    sessionContext.previousActions.push({
      tool: exec.name,
      params: event.params,
      result_status: event.status,
      timestamp: nowMs(),
    })
    // cap the in-memory array at the same window
    // the readers use (slice(-50)). Without this trim, the array grows
    // unbounded across the session lifetime — memory leak in long-running
    // sessions. The readers were already truncating on read, so this is
    // a storage-shape fix only; observable behaviour on emitted events
    // is unchanged.
    if (sessionContext.previousActions.length > MAX_PREVIOUS_ACTIONS) {
      sessionContext.previousActions.splice(
        0,
        sessionContext.previousActions.length - MAX_PREVIOUS_ACTIONS,
      )
    }

    this.emit(event)
  }

  onToolResult(exec: ToolExecution, result: ToolExecutionResult): void {
    // `tools/result` emits the frozen, lossless-JSON final outcome.
    // We currently rely on tools/post-execute for the primary tool-result event;
    // this handler can later enrich the audit trail with normalized results.
    void result
    void exec
  }

  onAgentTurnStopping({ agent, turn }: TurnStoppingPayload): void {
    const sessionContext = this.getOrCreateSession(agent.session.header.id, agent)
    sessionContext.runId = `${sessionContext.sessionId}-${turn}`
    const event = this.makeBaseEvent('agent_stop', sessionContext)
    // Emit `duration` (ms since first session start). The Cordis
// `agent/turn-stopping` payload does not carry a duration, but
// `SessionContext.sessionStartTs` is stamped on first creation in
// `getOrCreateSession`, so the elapsed time is recoverable.
    if (sessionContext.sessionStartTs !== undefined) {
      event.duration = nowMs() - sessionContext.sessionStartTs
    }
    // The platform per-type JSON Schema marks `exit_code` as **required** on
    // agent_stop (not merely integer-or-null). Cordis does not surface an
    // exit code on `agent/turn-stopping`, and `ActionRecord` does not
    // persist the SPL decision, so we derive one from `blockedToolCallCount`
    // (incremented in onToolPreExecute when the SPL decision is `block`):
    //   - any prior tool_call was blocked ⇒ 64 (POSIX EX_USAGE)
    //   - otherwise 0 (clean turn stop)
    // Empty / null both fail the platform's required check; an integer is
    // the only valid choice.
    const blockedCount = sessionContext.blockedToolCallCount ?? 0
    event.exit_code = blockedCount > 0 ? 64 : 0
    // `intervention_blocked: boolean` lets dashboard consumers correlate
    // turn-stop with policy enforcement without inspecting `exit_code` semantics.
    event.intervention_blocked = blockedCount > 0
    this.stampSource(event, { hook_name: 'agent_stop', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })
    this.emit(event)
  }

  /**
   * fs/observed audit handler. The harness emits this after every successful
   * fs read/write/edit, carrying an authoritative `FsObservation` (present with
   * version, or absent). We translate it into the PLATFORM-STANDARD file
   * classes so the registry only ever sees file_read / file_write:
   *
   *   - a matching pending write-intent was absorbed  → `file_write`
   *     (a normal tool write becomes ONE audit record, carrying the intent
   *     decision in `fs_write_intent`)
   *   - otherwise the tool read/eyed the path (or it is absent) → `file_read`
   *
   * The custom `file_observed` / `file_write_intent` types are no longer
   * emitted on this path, so no downstream registry work is needed.
   *
   * Best-effort session correlation: the harness does not currently surface a
   * session id on fs events, so we tag the event with the most-recent session
   * if there is exactly one active session. Multi-session ambiguity is left
   * empty — the audit log retains the target identity either way.
   */
  onFsObserved(target: FsTarget, observation: FsObservation, actor: object | undefined): void {
    const sessionContext = this.sessionStore.pickRecentSession(actor)
    const intent = this.pendingIntents.get(target.targetKey)
    if (intent) {
      this.pendingIntents.delete(target.targetKey)
    }
    const isWrite = intent !== undefined
    const event = this.makeBaseEvent(isWrite ? 'file_write' : 'file_read', sessionContext)
    event.path = target.displayPath
    event.target_key = target.targetKey
    event.target_path = target.displayPath
    event.observation_kind = observation.kind
    if (observation.kind === 'present') {
      event.file_version = observation.version
    }
    if (intent) {
      // Absorb the just-heard write-intent decision into this observed event
      // (see onFsWriteIntent) so a single file mutation yields one audit
      // record instead of file_write_intent + file_observed pairs.
      event.fs_write_intent =
        intent.kind === 'replaceIfVersion'
          ? { kind: intent.kind, version: intent.version }
          : { kind: intent.kind }
    }
    event.tool_name = actorToolName(actor)
    // Surface the originating ToolExecution.callId on the fs/observed record.
// Without this the fs-side `file_read`/`file_write` is unjoinable to the
// matching `agent_tool_call` / `agent_tool_result` pair, defeating the
// deduplication rationale (a single read should produce one record
// stream that auditors can correlate by tool_call_id). The harness passes
// the originating ToolExecution as `actor`; we extract `callId`
// defensively the same way `actorToolName` does.
    event.tool_call_id = actorToolCallId(actor)
    this.stampSource(event, { hook_name: 'fs_observed', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })
    this.emit(event)
    // Sweep orphans (intents older than intentAbsorbMs that observed nothing)
    // — an observed for THIS target can only absorb one; other orphans need
    // the sweep just the same as when a fresh write-intent arrives.
    this.flushExpiredIntents()
  }

  /** Flush write-intents older than intentAbsorbMs as standalone `file_write`
   *  events — the write failed or bypassed the fs/observed path, so no
   *  absorption partner will arrive. The `fs_write_intent` field + absent
   *  version/hash mark the record as an attempt that did not land. Called on
   *  every intent and observed so the map never grows unbounded. */
  private flushExpiredIntents(): void {
    const cutoff = nowMs() - this.intentAbsorbMs
    for (const [key, intent] of Array.from(this.pendingIntents)) {
      if (intent.ts >= cutoff) continue
      this.pendingIntents.delete(key)
      const sessionContext = this.sessionStore.pickRecentSession(undefined)
      const event = this.makeBaseEvent('file_write', sessionContext)
      event.path = intent.displayPath
      event.target_key = key
      event.target_path = intent.displayPath
      event.tool_name = intent.toolName
      event.fs_write_intent =
        intent.kind === 'replaceIfVersion'
          ? { kind: intent.kind, version: intent.version }
          : { kind: intent.kind }
      this.stampSource(event, { hook_name: 'fs_write_intent', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })
      this.emit(event)
    }
  }

  /**
   * fs/write-intent audit handler. This is a SINGLE-SLOT Cordis waterfall
   * in the harness, owned by `fs-observation-policy`. To avoid breaking
   * the version-guard decision — which can upgrade `createIfAbsent` to
   * `replaceIfVersion` to force a conflict — we do NOT compete for the
   * slot. We only AUDIT the upstream payload so that the intent shape is
   * visible in the audit trail.
   *
   * SPL write blocking continues to flow through `tools/pre-execute`,
   * which is a separate decision point and unaffected by this handler.
   */
  async onFsWriteIntent(
    target: FsTarget,
    actor: object | undefined,
    next: () => Promise<FsWriteIntentPayload | undefined> | FsWriteIntentPayload | undefined,
  ): Promise<FsWriteIntentPayload | undefined> {
    let result: FsWriteIntentPayload | undefined
    try {
      result = await next()
    } catch (err) {
      this.logger.warn('fs/write-intent: next() threw', err)
      throw err
    }

    // Record the decision instead of emitting anything now: a tool-driven
    // write fires write-intent mid-write and fs/observed right after. The
    // absorbed kind turns the matching observed into ONE file_write
    // (onFsObserved); only intents that never see an observed within
    // intentAbsorbMs (failed / non-fs writes) are flushed standalone as
    // file_write by flushExpiredIntents.
    const kind: 'createIfAbsent' | 'replaceIfVersion' = result?.kind ?? 'createIfAbsent'
    this.pendingIntents.set(target.targetKey, {
      kind,
      version: result?.kind === 'replaceIfVersion' ? result.version : undefined,
      displayPath: target.displayPath,
      toolName: actorToolName(actor),
      ts: nowMs(),
    })
    this.flushExpiredIntents()

    return result
  }

  /**
   * Tap the `llm/stream` waterfall. Wraps the downstream stream in a tee
   * (`src/utils/tokenUsage.ts`) that yields every chunk unchanged while
   * feeding usage chunks to the token-usage burst detector. Audit-only:
   * the stream is never paused, buffered, throttled, or dropped, and
   * per-chunk detector errors are swallowed inside the tee (invariant #3
   * — never throw to the host).
   *
   * Session attribution: `llm/stream` payload does not carry the Cordis
   * session, so the detector keys on the most recent tool-call session
   * (set in `onToolPreExecute`); when no tool frame is active (e.g. the
   * first LLM call of a turn) it falls back to the session with the
   * freshest user message, else `'__unknown__'`.
   *
   * `options` is accepted for signature fidelity with the harness
   * waterfall; the detector intentionally does not read prompt content.
   */
  onLlmStream(
    options: GenerateOptions,
    source: AsyncIterable<StreamChunk>,
  ): AsyncIterable<StreamChunk> {
    void options
    try {
      const sessionId = this.sessionStore.resolveActiveSessionId()
      return teeLlmStream(source, (usage) => {
        this.tokenUsageDetector.record(sessionId, usage, nowMs())
      })
    } catch (err) {
      // Fail-open: generation must never break because the tap failed.
      this.logger.warn('onLlmStream tee setup failed; returning unwrapped stream', err)
      return source
    }
  }

  // --- Intervention helpers ---------------------------------------------------

  buildInterventionContext(exec: ToolExecution): InterventionContext | undefined {
    const sessionContext = this.resolveSessionContext(exec)
    if (!sessionContext) return undefined
    const args = safeExtractRecord(exec.arguments)
    // Data-leak detection flags (standard §5.2) from the command line —
// merged with harness-provided risk_flags. Detection only: every rule
// consuming these tags is warn/advisory.
    const providedFlags = Array.isArray(args.risk_flags) ? (args.risk_flags as string[]) : undefined
    const command = typeof args.command === 'string' ? args.command : undefined
    const derivedFlags = command ? deriveDataLeakFlags(command) : []
    const mergedFlags = [...(providedFlags ?? [])]
    for (const flag of derivedFlags) {
      if (!mergedFlags.includes(flag)) mergedFlags.push(flag)
    }
    return {
      actionType: 'tool_call',
      toolName: exec.name,
      params: args,
      body: typeof args.body === 'string' ? args.body : undefined,
      riskFlags: mergedFlags.length > 0 ? mergedFlags : undefined,
      sessionId: sessionContext.sessionId,
      runId: sessionContext.runId,
      agentId: sessionContext.agentId,
      platformId: DEFAULT_PLATFORM_ID,
      userPrompt: sessionContext.userPrompt,
      agentPlan: sessionContext.agentPlan,
      previousActions: sessionContext.previousActions.slice(-50),
    }
  }

  buildMessageInterventionContext(event: SecurityEvent): InterventionContext {
    const session = this.sessionStore.getSession(event.session_id ?? '')
    return {
      actionType: 'message_write',
      body: event.content,
      sessionId: event.session_id,
      runId: event.run_id,
      agentId: session?.agentId,
      platformId: DEFAULT_PLATFORM_ID,
      userPrompt: session?.userPrompt,
      agentPlan: session?.agentPlan,
      previousActions: session?.previousActions.slice(-50),
    }
  }

  async evaluateTool(exec: ToolExecution): Promise<SecurityDecision | undefined> {
    const ctx = this.buildInterventionContext(exec)
    if (!ctx) return undefined
    // the inline-guard sequence (prompt-injection
    // → sensitive-path → env-passthrough) is now driven by the shared
    // `runInlineGuardChain` helper. Both this site (tool layer) and the
    // RuntimeHook pre-spawn seam use the same iteration / short-circuit
    // logic. Inline self-protection NO LONGER runs here — the 3
    // hardcoded rules (uninstall / kill / restart-no-patch) live in the
    // synchronous `ctx.tools.guard` seam (see `SelfProtectionGuard.ts`).
    //
    // Step errors are not swallowed silently:
    // `onError` threads each failure out as a warn +
    // `security_audit/inline_guard_error` audit, mirroring
    // the safeHandler fail_safe contract.
    const chainDecision = runInlineGuardChain(
      ctx,
      [
        {
          label: 'inline-prompt-injection',
          evaluate: (c) => evaluateInlinePromptInjection(c, this.inlinePromptInjection),
        },
        {
          label: 'inline-sensitive-path',
          evaluate: (c) => evaluateSensitivePathGuard(c, this.sensitivePathGuard),
        },
        {
          label: 'inline-env-passthrough',
          evaluate: (c) => evaluateEnvPassthroughGuard(c, this.envPassthroughGuard),
        },
      ],
      (label, error) => this.emitInlineGuardError(label, error, ctx),
    )
    if (chainDecision) return chainDecision
    if (!this.interventionEngine) return undefined
    return this.interventionEngine.evaluate(ctx)
  }

  private async evaluateMessage(event: SecurityEvent): Promise<SecurityDecision | undefined> {
    // Asymmetric with evaluateTool(): inline guards (prompt-injection /
    // sensitive-path / env-passthrough) are NOT re-run here. The
    // prompt-injection guard already fired at the onAgentPreStep call
    // site (returned early on hit), and message_write has no
    // toolName / params.cmd / params.env surface for the path /
    // env-passthrough guards to operate on (those guards are
    // tool-argv-shaped, not message-body-shaped). Only the SPL
    // engine runs against the message body — keeping the asymmetry
    // intentional rather than letting a future cleanup "tidy" it by
    // moving the inline guards here too.
    const ctx = this.buildMessageInterventionContext(event)
    if (!this.interventionEngine) return undefined
    return this.interventionEngine.evaluate(ctx)
  }

  private applyDecisionToEvent(event: SecurityEvent, decision?: SecurityDecision): void {
    this.eventEmitter.applyDecisionToEvent(event, decision)
  }

  // --- helpers ----------------------------------------------------------------

  /**
   * §6.2 : emit a `security_audit/looped_tool` event
   * when the per-(session, tool) sliding window crosses the configured
   * threshold. The detector's hit payload carries everything the audit
   * event needs (toolName / sessionId / count / windowStart / windowEnd
   * / threshold / windowMs) — no synchronous lookups against the
   * session cache required.
   *
   * Audit shape mirrors the inline safety-net guards
   * (`security_audit/inline_prompt_injection_detect` etc.):
   *   - `audit_category: 'behavior'` — looping is a behavioural signal,
   *     not a policy / integrity / access event
   *   - `audit_action: 'detect'` — operator-facing vocabulary
   *     (`detect` ≠ `block`: the detector does not block)
   *   - `severity: 'medium'` — ticket spec
   *   - `outcome: 'success'` — the tool call itself completed; the
   *     audit records the observation
   *   - `audit_details` carries the structured hit payload for
   *     post-hoc dashboards
   *
   * The audit event shares the session identity of the calling tool
   * (best-effort — falls back to `'__plugin__'` when the session was
   * already evicted between record + emit). Best-effort is sufficient
   * because the detector is observability-only and never blocks.
   */
  private emitLoopedToolAudit(hit: LoopedToolHit): void {
    try {
      const sessionContext = this.sessionStore.getSession(hit.sessionId)
      const event: SecurityEvent = {
        comm: 'sst-security-control-dsh',
        event_id: generateEventId(),
        event_type: 'security_audit',
        layer: 'application',
        source_layer: 'application',
        ts: hit.windowEnd,
        timestamp: hit.windowEnd,
        pid: process.pid,
        collection_method: 'agent_api',
        session_id: sessionContext?.sessionId ?? hit.sessionId,
        run_id: sessionContext?.runId ?? hit.sessionId,
        agent_id: sessionContext?.agentId ?? '__plugin__',
        tool_name: hit.toolName,
        audit_category: 'behavior',
        audit_action: 'detect',
        severity: 'medium',
        summary: `per-tool loop detected: ${hit.toolName} ${hit.count}/${hit.threshold} in ${Math.round(hit.windowMs / 1000)}s window`,
        outcome: 'success',
        reason: 'detect',
        audit_details: {
          event_type_alias: 'looped_tool',
          tool_name: hit.toolName,
          session_id: hit.sessionId,
          call_count: hit.count,
          threshold: hit.threshold,
          window_start_ms: hit.windowStart,
          window_end_ms: hit.windowEnd,
          window_ms: hit.windowMs,
          detail: `inline_looped_tool guard fired: ${hit.toolName} called ${hit.count} times within ${hit.windowMs}ms (threshold=${hit.threshold})`,
        },
        ...buildHostMeta(),
      }
      this.eventCollector.report(event)
    } catch (err) {
      // Best-effort: an audit emit failure must never break the
      // detector loop. The detector already swallows callback throws.
      this.logger.warn('emitLoopedToolAudit failed', err)
    }
  }

  /**
   * §6.2 : emit a
   * `security_audit/anomalous_token_usage` event when the per-session
   * token-usage sliding window crosses the configured burst factor. Audit
   * shape mirrors `emitLoopedToolAudit`:
   *   - `audit_category: 'behavior'` — a token burst is a behavioural
   *     signal (runaway context / prompt-stuffing), not a policy decision
   *   - `audit_action: 'detect'` — the detector does not block generation
   *   - `severity: 'medium'` — mirrors the loop detector; a ≥3× burst is
   *     suspicious but routinely benign (one large file read inflates the
   *     next call's prompt), so operators triage from the audit signal
   *   - `token_usage_prompt` / `token_usage_completion` / `token_usage_total`
   *     carry the bursting call's normalized usage at the top level so
   *     token dashboards can consume them without cracking `audit_details`
   *
   * Session identity is best-effort (falls back to the detector key and
   * `'__plugin__'`) — the detector is observability-only and never blocks.
   */
  private emitAnomalousTokenUsageAudit(hit: TokenUsageHit): void {
    try {
      const sessionContext = this.sessionStore.getSession(hit.sessionId)
      const event: SecurityEvent = {
        comm: DEFAULT_PLATFORM_ID,
        event_id: generateEventId(),
        event_type: 'security_audit',
        layer: 'application',
        source_layer: 'application',
        ts: hit.ts,
        timestamp: hit.ts,
        pid: process.pid,
        collection_method: 'agent_api',
        session_id: sessionContext?.sessionId ?? hit.sessionId,
        run_id: sessionContext?.runId ?? hit.sessionId,
        agent_id: sessionContext?.agentId ?? '__plugin__',
        audit_category: 'behavior',
        audit_action: 'detect',
        severity: 'medium',
        summary:
          `anomalous token usage: ${hit.usage.totalTokens} tokens is ` +
          `${hit.ratio.toFixed(2)}x the ${Math.round(hit.baseline)}-token baseline ` +
          `(${hit.sampleCount} samples in ${Math.round(hit.windowMs / 1000)}s window)`,
        outcome: 'success',
        reason: 'detect',
        token_usage_prompt: hit.usage.inputTokens,
        token_usage_completion: hit.usage.outputTokens,
        token_usage_total: hit.usage.totalTokens,
        audit_details: {
          event_type_alias: 'anomalous_token_usage',
          session_id: hit.sessionId,
          input_tokens: hit.usage.inputTokens,
          output_tokens: hit.usage.outputTokens,
          total_tokens: hit.usage.totalTokens,
          baseline_tokens: hit.baseline,
          ratio: hit.ratio,
          burst_factor: hit.burstFactor,
          sample_count: hit.sampleCount,
          window_ms: hit.windowMs,
          detail:
            `token_usage_detector fired: ${hit.usage.totalTokens} tokens is ` +
            `${hit.ratio.toFixed(2)}x the ${Math.round(hit.baseline)}-token in-window mean ` +
            `(burst_factor=${hit.burstFactor}, samples=${hit.sampleCount})`,
        },
        ...buildHostMeta(),
      }
      this.eventCollector.report(event)
    } catch (err) {
      // Best-effort: an audit emit failure must never break the
      // detector loop. The detector already swallows callback throws.
      this.logger.warn('emitAnomalousTokenUsageAudit failed', err)
    }
  }

  /**
   * Emit a `security_audit/fail_safe` event when a
   * wrapped Cordis listener (via `safeHandler`) throws. The handler
   * error is caught and degraded to `ctx.logger.warn` per invariant #3
   * (never throw to the host), but operators have no visibility into
   * how often the safety net fires — a sustained burst of failures
   * suggests a regression that needs triage.
   *
   * Audit shape mirrors `emitLoopedToolAudit` / `emitAnomalousTokenUsageAudit`:
   *   - `audit_category: 'runtime'` — a handler crash is a runtime /
   *     reliability signal, not a policy / integrity / behaviour /
   *     access event. Falls back from an earlier 'reliability' label
   *     when the SecurityEvent type's audit_category union only
   *     accepts the seven canonical buckets listed in the schema.
   *   - `audit_action: 'detect'` — the listener already swallowed the
   *     throw; `detect` documents the observation
   *   - `severity: 'medium'` — handler bugs are routine (sync throws
   *     during refactors are the common case) and the warn is already in
   *     the log; severity
   *     is medium so dashboards can aggregate but no oncall paging fires
   *   - `outcome: 'success'` — the host was not affected (invariant #3
   *     held); the audit records the safety-net catch
   *   - `audit_details` carries the structured payload
   *     (handler_name / error_class / error_message / stack_excerpt)
   *     for post-hoc triage — the full stack is NOT recorded to keep
   *     the NDJSON entry bounded and to avoid carrying file paths /
   *     variable values into a long-lived audit log
   *
   * Session identity is best-effort — handler errors often happen
   * before any session context exists, so we fall back to `'__plugin__'`
   * and the plugin-level agent_id. Best-effort is sufficient because
   * the audit is observability-only and never blocks.
   */
  emitFailSafeAudit(handlerName: string, error: unknown): void {
    try {
      const ts = nowMs()
      const message = error instanceof Error ? error.message : String(error)
      const className =
        error instanceof Error ? error.name || error.constructor.name || 'Error' : typeof error
      const stack =
        error instanceof Error && typeof error.stack === 'string' ? error.stack.split('\n').slice(0, 4).join(' | ') : ''
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
        session_id: '__plugin__',
        run_id: '__plugin__',
        agent_id: '__plugin__',
        audit_category: 'runtime',
        audit_action: 'detect',
        severity: 'medium',
        summary: `fail_safe: ${handlerName} handler threw ${className} — caught by safeHandler`,
        outcome: 'success',
        reason: 'handler_exception_caught',
        audit_details: {
          event_type_alias: 'fail_safe',
          handler_name: handlerName,
          error_class: className,
          error_message: truncateString(message, 240),
          ...(stack ? { stack_excerpt: truncateString(stack, 480) } : {}),
          detail:
            `safeHandler caught a ${className} from the ${handlerName} listener; ` +
            `host pipeline continued (invariant #3: never throw to the host).`,
        },
        ...buildHostMeta(),
      }
      this.eventCollector.report(event)
    } catch (err) {
      // The audit emit itself failed — never let the safety-net
      // observability break the handler fall-through path.
      this.logger.warn('emitFailSafeAudit failed', err)
    }
  }

  /**
   * emit `security_audit/inline_guard_error` when a
   * step inside `runInlineGuardChain` throws. Mirrors `emitFailSafeAudit`
   * (safeHandler fail-safe observability). A silently swallowed
   * error would hide guard regressions from audit
   * consumers, so a bug in any of the 4 inline guards (prompt-injection /
   * sensitive-path / env-passthrough / self-protection) is observable
   * as a single security_audit event with the step label and error
   * excerpt. The SPL fallback is still the catch-all — chain execution
   * continues with the next step, so the rail is not silently opened
   * by a misbehaving guard.
   *
   * Best-effort: if `eventCollector.report` throws, the warn log line
   * is the authoritative record.
   */
  emitInlineGuardError(
    label: string,
    error: unknown,
    ctx: InterventionContext,
  ): void {
    this.logger.warn(`[SecurityMonitor] inline guard ${label} threw: ${String(error)}`)
    try {
      const ts = nowMs()
      const message = error instanceof Error ? error.message : String(error)
      const className =
        error instanceof Error
          ? error.name || error.constructor.name || 'Error'
          : typeof error
      const stack =
        error instanceof Error && typeof error.stack === 'string'
          ? error.stack.split('\n').slice(0, 4).join(' | ')
          : ''
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
        session_id: ctx.sessionId,
        run_id: ctx.runId,
        agent_id: ctx.agentId ?? '__plugin__',
        audit_category: 'runtime',
        audit_action: 'detect',
        severity: 'medium',
        summary: `inline_guard_error: ${label} threw ${className} — chain continued`,
        outcome: 'success',
        reason: 'inline_guard_exception_caught',
        audit_details: {
          event_type_alias: 'inline_guard_error',
          guard_label: label,
          action_type: ctx.actionType,
          tool_name: ctx.toolName,
          error_class: className,
          error_message: truncateString(message, 240),
          ...(stack ? { stack_excerpt: truncateString(stack, 480) } : {}),
          detail:
            `runInlineGuardChain caught a ${className} from the ${label} step; ` +
            `chain execution continued with the next guard (invariant #3: never throw to the host).`,
        },
        ...buildHostMeta(),
      }
      this.eventCollector.report(event)
    } catch (err) {
      this.logger.warn('emitInlineGuardError failed', err)
    }
  }

  private makeBaseEvent(eventType: string, sessionContext: SessionContext): SecurityEvent {
    return this.eventEmitter.makeBaseEvent(eventType, sessionContext)
  }

  private getOrCreateSession(sessionId: string, agent?: Agent): SessionContext {
    return this.sessionStore.getOrCreateSession(sessionId, agent)
  }

  /** Resolve the per-session state for a given tool execution. Public so
   * handlers.ts can clean up deny-path map entries
   *  when `tools/post-execute` is skipped by the harness after a deny
   *  return. The function is a pure read accessor — no mutation — so
   *  exposing it does not widen the public surface meaningfully.
   *
   * Implementation lives in `./SessionStore.ts`. Kept
   *  as a thin wrapper so callers stay unchanged. */
  resolveSessionContext(exec: ToolExecution): SessionContext | undefined {
    const sessionId = exec.agent?.session.header.id
    if (!sessionId) return undefined
    return this.getOrCreateSession(sessionId, exec.agent)
  }

  /**
   * look up a session by the observed PID. Used by the
   * system layer to enrich `process_*` events that were not stamped by the
   * active Python binding. Returns `undefined` when the PID is not known
   * to belong to any active agent session.
   *
   * Implementation lives in `./SessionStore.ts`. Kept
   * as a thin wrapper so callers stay unchanged.
   */
  resolveSessionByPid(pid: number): { sessionId: string; runId: string; agentId?: string } | undefined {
    return this.sessionStore.resolveSessionByPid(pid)
  }

  /**
   * typed convenience for NetworkHttpCollector. Falls back
   * to `resolveSessionByPid(process.pid)` when an outbound HTTP request is
   * not running inside an AsyncLocalStorage context.
   *
   * Implementation lives in `./SessionStore.ts`. Kept
   * as a thin wrapper so callers stay unchanged.
   */
  resolveHttpSessionByPid(pid: number): { sessionId: string; runId: string; agentId?: string } | undefined {
    return this.sessionStore.resolveHttpSessionByPid(pid)
  }

  /**
   * record that `pid` belongs to `session`. Called at
   * session start and at every tool pre-execute so that later system-layer
   * process scans can correlate descendants by `pid`/`ppid`.
   *
   * Three defensive guards are layered onto the bind:
   *   1. Reject obviously-invalid PIDs (NaN, ≤1). PIDs 0/1 are
   *      kernel/init sentinels on POSIX; cross-platform pid_t can be
   *      0/-1 on Windows spawn failures. Binding those would pollute
   *      the resolver with cache hits that always return an unrelated
   *      session — a session-correlation false-positive class that's
   *      hard to debug post-hoc.
   *   2. Force-evict the oldest-by-`ts` entries when the map crosses
   *      `PID_SESSION_MAP_MAX_SIZE`. The TTL sweep is the primary
   *      prune path; this cap is the safety net for bursts that
   *      outpace the sweep cadence.
   *   3. The `set` write below is unconditional — a fresh binding
   *      always wins, since the most-recent assignment is the
   *      authoritative cross-correlation (process forked at ts=T
   *      cannot have moved session between then and the resolve).
   *
   * Implementation lives in `./SessionStore.ts` →
   * `PidBindingStore.set`. Kept as a thin wrapper so callers stay
   * unchanged.
   */
  bindPidToSession(pid: number, session: SessionContext): void {
    this.sessionStore.bindPidToSession(pid, session)
  }

  /**
   * public binding entry used by RuntimeHook after it has
   * observed the real child PID returned by `ctx.subprocess.spawn`. The
   * session context is looked up from the in-memory session cache so the
   * system-layer `process_*` events can correlate by `pid`/`ppid`.
   *
   * Implementation lives in `./SessionStore.ts`. Kept
   * as a thin wrapper so callers stay unchanged.
   */
  bindChildPidToSession(pid: number, sessionId: string): void {
    this.sessionStore.bindChildPidToSession(pid, sessionId)
  }

  /**
   * most-recent-session lookup for RuntimeHook. The spawn
   * seam doesn't carry the `exec` object, so the wrapper uses "the last
   * pre-execute that fired" as the implicit correlation. The harness's
   * tool dispatch is single-threaded within an agent turn, so this is
   * safe — the spawn always follows its own pre-execute without another
   * tool's pre-execute interleaving.
   *
   * Returns `undefined` outside any active agent frame (e.g. harness
   * bootstrap helpers). The wrapper treats `undefined` as "untracked
   * spawn" and still emits the audit event without session metadata.
   *
   * Implementation lives in `./SessionStore.ts`. Kept
   * as a thin wrapper so callers stay unchanged.
   */
  resolveMostRecentSessionForRuntime(): RuntimeHookSessionContext | undefined {
    return this.sessionStore.resolveMostRecentSessionForRuntime()
  }

  /**
   * run `fn` inside an AsyncLocalStorage context that carries
   * the current agent session / tool-call identity. NetworkHttpCollector reads
   * this store to correlate outbound HTTP requests with the Cordis handler that
   * triggered them. If the payload carries no resolvable session, `fn` runs
   * without a store (the collector will fall back to most-recent session).
   */
  runWithHttpContext<T>(payload: unknown, fn: () => T): T {
    const ctx = this.resolveHttpContext(payload)
    if (!ctx) return fn()
    return httpRequestContext.run(ctx, fn)
  }

  private resolveHttpContext(payload: unknown): HttpRequestSessionContext | undefined {
    const exec = payload as { agent?: Agent; callId?: string } | undefined
    if (!exec?.agent?.session?.header?.id) return undefined
    const session = this.getOrCreateSession(exec.agent.session.header.id, exec.agent)
    return {
      sessionId: session.sessionId,
      runId: session.runId,
      agentId: session.agentId,
      toolCallId: exec.callId,
    }
  }

  private buildToolCallId(ctx: SessionContext, exec: ToolExecution): string {
    return `${ctx.sessionId}:${ctx.runId}:${exec.name}:${ctx.stepIndex}`
  }

  private classifyToolEvent(name: string): string {
    // Classify file-shaped tools
    // (read / write / edit / delete / chmod / …) as `agent_tool_call` here.
    // The platform-standard `file_read` / `file_write` event types are
    // produced by `onFsObserved` from the harness's authoritative observation
    // (it carries `file_version` / `kind`). Emitting `file_*` here would
    // double-fire one read/write as both `agent_tool_call` (with the
    // tool_call_id) AND `file_read` (with the file_version). SPL rules that
    // match `file_*` tool names still hit because we keep `tool_name` on the
    // emitted event (see onToolPreExecute line 207). The previous
    // substring-to-file_* mapping is retained as a comment for traceability
    // and as a fallback signpost: if `fs/observed` is ever unwired for a new
    // tool flow, the symptom (no file_* audit) is recoverable by simply
    // re-introducing the mapping here — the prior `file_*` labels are:
    //
    //   read/view         → file_read
    //   write/create/     → file_write
    //   edit/modify/patch
    //   delete/remove     → file_delete
    //   chmod/chown/      → file_privilege
    //   privilege
    //
    // `code_mode_exec` is NOT a file_* classification — it is the harness's
    // own code-mode-execution marker (DSH_TOOLS_MODE=code or the literal
    // `run_code` interpreter). Folding it into `agent_tool_call` would lose
    // the explicit code-execution audit signal, so the branch is preserved.
    if (name === RUN_CODE_NAME) return 'code_mode_exec'
    return 'agent_tool_call'
  }

  private isCodeMode(name: string): boolean {
    // Code mode is on when either:
    //  1. The harness has set DSH_TOOLS_MODE=code (the whole agent operates in
    //     code mode, even when individual tools are not the run_code
    //     interpreter — e.g. `bash` invocations are code-mode actions).
    //  2. The tool name is the literal `run_code` interpreter.
    // Both signals are surfaced on the event via `is_code_mode` so audit
    // dashboards can distinguish "executed arbitrary code" from "called a
    // pre-built tool".
    if (process.env.DSH_TOOLS_MODE === 'code') return true
    return name.toLowerCase() === RUN_CODE_NAME
  }

  /**
   * true when the tool name itself signals a file-privilege
   * change (chmod/chown/setfacl/chgrp/chattr). These tools emit a companion
   * `file_privilege` event in addition to the primary `agent_tool_call`.
   */
  private isPrivilegeTool(name: string): boolean {
    const lower = name.toLowerCase()
    return ['chmod', 'chown', 'chgrp', 'setfacl', 'chattr'].some((hint) => lower.includes(hint))
  }

  /**
   * emit `file_privilege` events for privilege-changing
   * tools and for shell-derived privilege ops. Each distinct path gets its
   * own event; the platform file.json schema requires `session_id` and `path`.
   */
  private emitFilePrivilegeEvents(
    sessionContext: SessionContext,
    exec: ToolExecution,
    toolCallId: string,
    sourceEvent: SecurityEvent,
    decision?: SecurityDecision,
  ): void {
    const paths = new Set<string>()
    if (this.isPrivilegeTool(exec.name)) {
      const path = this.normalizePath(safeExtractRecord(exec.arguments))
      if (path) paths.add(path)
    }
    if (sourceEvent.derived_file_ops) {
      for (const op of sourceEvent.derived_file_ops) {
        if (op.op === 'privilege' && typeof op.path === 'string') {
          paths.add(op.path)
        }
      }
    }
    if (paths.size === 0) return
    for (const path of paths) {
      const fp = this.makeBaseEvent('file_privilege', sessionContext)
      fp.tool_call_id = toolCallId
      fp.tool_name = exec.name
      fp.path = path
      fp.operation = exec.name
      if (decision) this.applyDecisionToEvent(fp, decision)
      this.stampSource(fp, { hook_name: 'agent_tool_call', middleware_name: DEFAULT_PLATFORM_ID, collector_name: 'application-collector' })
      this.emit(fp)
    }
  }

  /**
   * paired
   * `security_audit/canonicalization_applied` event emitted alongside
   * the `agent_tool_call` when at least one matched rule fired on the
   * CANONICAL (folded / normalised / spaced) form of the input rather
   * than verbatim text.
   *
   * Audit shape mirrors `emitLoopedToolAudit` /
   * `emitAnomalousTokenUsageAudit`:
   *   - `audit_category: 'behavior'` — input obfuscation is a
   *     behavioural signal (the agent is hiding intent), not a policy
   *     decision per se; SPL already decided block/modify in the
   *     paired `agent_tool_call`
   *   - `audit_action: 'detect'` — the detector (RuleMatcher traceSink)
   *     does not block; the matching SPL rule does, downstream
   *   - `severity: 'low'` — every canonicalization-applied audit is
   *     low-severity observability (the platform severity enum has no
   *     'info'; the info-level intent is expressed by this audit existing
   *     at all). A "block" via verbatim text is
   *     routine (most legitimate attacks spell the banned word);
   *     only the rare canonicalization-applied case is worth
   *     surfacing so operators can SEE the obfuscation arms-race
   *   - `outcome: 'success'` / `reason: 'detect'` — the detector ran
   *     cleanly; the SPL rule's block decision is on the paired event
   *   - `tool_call_id` joins the audit back to the originating
   *     `agent_tool_call` record
   *   - `audit_details.event_type_alias: 'canonicalization_applied'`
   *     distinguishes the row from sibling detectors in NDJSON
   *     consumer filters (looped_tool / anomalous_token_usage /
   *     inline_prompt_injection_detect / etc.)
   *   - `audit_details.rule_id` / `block_code` / `policy_id` carry the
   *     winning SPL rule (highest priority match) so post-hoc triage
   *     can correlate the obfuscation with the rule that caught it
   *   - `audit_details.tool_arguments_excerpt` carries the first 256
   *     chars of the obfuscated `arguments` so operators can SEE the
   *     obfuscation without leaking the full argument blob to the
   *     audit log (which would defeat the redaction invariant for
   *     tokens / paths)
   *
   * Best-effort + swallowed: invariant #3 (never throw to host). The
   * paired `agent_tool_call` event already shipped; this is pure
   * observability and must not break the call.
   */
  private emitCanonicalizationAudit(
    sessionContext: SessionContext,
    exec: ToolExecution,
    toolCallId: string,
    decision: SecurityDecision,
  ): void {
    try {
      const intervention = decision.intervention
      const ruleId = intervention?.policy_name ?? decision.policy_name ?? '__engine__'
      const args = safeExtractRecord(exec.arguments)
      const argsStr = JSON.stringify(args) ?? '{}'
      const excerpt = argsStr.length > 256 ? `${argsStr.slice(0, 256)}…` : argsStr

      const event: SecurityEvent = {
        comm: 'sst-security-control-dsh',
        event_id: generateEventId(),
        event_type: 'security_audit',
        layer: 'application',
        source_layer: 'application',
        ts: Date.now(),
        timestamp: Date.now(),
        pid: process.pid,
        collection_method: 'agent_api',
        session_id: sessionContext?.sessionId ?? '__plugin__',
        run_id: sessionContext?.runId ?? '__plugin__',
        agent_id: sessionContext?.agentId ?? '__plugin__',
        tool_name: exec.name,
        tool_call_id: toolCallId,
        audit_category: 'behavior',
        audit_action: 'detect',
        severity: 'low',
        summary:
          `canonicalization applied: rule ${ruleId} matched on canonical form ` +
          `(tool=${exec.name}, decision=${decision.decision})`,
        outcome: 'success',
        reason: 'detect',
        audit_details: {
          event_type_alias: 'canonicalization_applied',
          rule_id: ruleId,
          block_code: decision.block_code ?? intervention?.block_code,
          policy_id: decision.policy_id ?? intervention?.policy_id,
          decision: decision.decision,
          tool_name: exec.name,
          tool_call_id: toolCallId,
          tool_arguments_excerpt: excerpt,
          detail:
            `inline rule matcher fired on canonical (folded / normalised / spaced) form ` +
            `rather than verbatim text — see paired agent_tool_call ${toolCallId} for the obfuscated arguments`,
        },
        ...buildHostMeta(),
      }
      this.eventCollector.report(event)
    } catch (err) {
      // Best-effort: an audit emit failure must never break the
      // matched rule's downstream block decision.
      this.logger.warn('emitCanonicalizationAudit failed', err)
    }
  }

  private normalizePath(args: Record<string, unknown>): string | undefined {
    // Keep this alias list in sync with RuleMatcher.getFieldValue's `path`
    // aliases so a write that survives classification carries the same path
    // the SPL rules would match on.
    const candidates = ['path', 'file_path', 'file', 'src', 'source', 'target', 'destination', 'dest', 'destination_path']
    for (const key of candidates) {
      if (typeof args[key] === 'string') return args[key] as string
    }
    return undefined
  }

  private emit(event: SecurityEvent): void {
    // Implementation lives in `./EventEmitter.ts`. The
    // wrapper stays so handler bodies can keep the `this.emit(...)`
    // call shape without rewrites.
    this.eventEmitter.emit(event)
  }

  getStats(): ApplicationCollectorStats {
    return { ...this.stats }
  }

  /**
   * Read accessor for the sessions Map. The Map lives in
   * `SessionStore` but tests pin to this symbol via
   * `(collector as unknown as { sessions: Map<string, …> }).sessions` —
   * see `tests/ApplicationCollector.test.ts:826,855,1039`. Returns the
   * store's Map by reference so test mutations propagate to the same
   * SessionContext instances the collector reads (notably
   * `lastUserMessageAt = Date.now()` used to age the session past TTL).
   */
  get sessions(): Map<string, SessionContext> {
    return this.sessionStore.getSessions()
  }
}

const RUN_CODE_NAME = 'run_code'

// ring-buffer cap on the in-memory `previousActions`
// array. Mirrors the reader-side slice(-50) window so the underlying
// storage stays bounded across long-running sessions.
// Constant exported so tests can pin the cap.
export const MAX_PREVIOUS_ACTIONS = 50

function blocksToText(block: ContentBlock): string {
  return block.type === 'text' && 'text' in block ? block.text : ''
}

/**
 * Extract a tool name hint from the `actor` parameter of fs/* events. The
 * harness passes the originating ToolExecution when the event is emitted
 * directly by tool-fs / tool-str-replace-editor. We extract defensively
 * without depending on the full ToolExecution shape.
 */
function actorToolName(actor: object | undefined): string | undefined {
  if (!actor) return undefined
  const name = (actor as { name?: unknown }).name
  return typeof name === 'string' ? name : undefined
}

/**
 * Extract the originating ToolExecution.callId from the `actor` parameter of
 * fs/* events. Mirrors `actorToolName` — the harness passes the originating
 * ToolExecution with `callId` populated (see external.ts:138-146
 * ToolExecution). Surfacing this on the fs/observed record lets the platform
 * join `file_read`/`file_write` (fs/observed) ↔ `agent_tool_call` /
 * `agent_tool_result` (Cordis tools/*) by `tool_call_id`, so the fs side
 * still owns the canonical file_* stream, but it is no longer context-less.
 */
function actorToolCallId(actor: object | undefined): string | undefined {
  if (!actor) return undefined
  const callId = (actor as { callId?: unknown }).callId
  return typeof callId === 'string' ? callId : undefined
}
