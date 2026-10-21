/**
 * Local type stubs for Harness / Cordis APIs.
 *
 * These are minimal stand-ins that let the plugin build and run unit tests
 * independently of the full host monorepo workspace.  When the plugin
 * is linked against a real Harness installation, the real package types are used
 * instead (via peerDependencies).  Keep these stubs aligned with the actual
 * Harness interfaces discovered from source inspection.
 *
 * Marketplace alignment: prefer real `@deepseek-ai/cordis`
 * types when the host profile resolves the peer dependency.  The shape below
 * mirrors the Cordis 4.x public surface (Context / Events / Logger / Effect
 * / Inject / Awaitable) so the stub is structurally compatible; a Cordis-
 * backed build can drop these stubs entirely and `import type { Context }
 * from '@deepseek-ai/cordis'` directly.  Until then, every public type here
 * is re-exported from this module — `src/index.ts` and downstream files
 * import from `./types/external.js`, never from `@deepseek-ai/cordis`.
 *
 * When upgrading to the real types, replace this header comment and rename
 * each interface to `export type { Context } from '@deepseek-ai/cordis'`;
 * the rest of the codebase does not need to change because consumers import
 * from `./types/external.js` only.
 *
 * --------------------------------------------------------------------------
 * Stub annotation + harness path-mapping table
 * --------------------------------------------------------------------------
 * Every stub below is annotated with `[harness: ...]` pointing at the real
 * source path in the host workspace (the canonical interface
 * the stub mirrors) and a status flag (`stub` / `partial` / `wired`).
 * Replacing these stubs with the real Harness types is blocked on the host
 * source not being mounted in this build environment; this annotation +
 * table is the audit-ready substitute.
 *
 * Migration cookbook (when the host source becomes available):
 *   1. `pnpm add -D @deepseek-ai/cordis@^4.0.2` + the harness sub-packages
 *      whose types we mirror (subprocess, llm, fs, tools, agent).
 *   2. Replace the stub declarations below with
 *      `export type { Context, Events, Logger, Effect } from '@deepseek-ai/cordis'`
 *      + the relevant harness sub-package types. Field names already
 *      match the real shapes (annotated per-stub), so consumer code in
 *      `src/` and `tests/` does NOT need to change.
 *   3. Delete this stub file (or shrink it to the few types the harness
 *      does not surface — `FsObservation` discriminator variants are
 *      plugin-internal even on a real build).
 *   4. Update the host contract map below with the migration
 *      commit SHA + date so future drift is auditable.
 *
 * Host contract map — one row per stubbed type. The `host surface` column
 * names the host subsystem the type comes from, not a file path:
 *
 *   stub                                    | host surface | status   | notes
 *   ----------------------------------------|--------------|----------|------------------------------------------
 *   ReflectService (line 62)                | cordis       | stub     | `mixin('reflect', ['get','set','provide','accessor','mixin'])`
 *   Context (line 83)                       | cordis       | stub     | cordis 4.x public surface; peerDep override once profile is mounted
 *   Logger (line 105)                       | cordis       | stub     | trivially complete (4 method surface)
 *   EventListener<K> (line 112)             | cordis       | stub     | overload union mirrors `EventListener` on the real side
 *   Events (line 157)                       | core+fs+llm  | partial  | agent/{created,disposed,session-start,request,request-error,error} are emitted but NOT subscribed (we audit, not govern agent lifecycle); only `pre-step` / `turn-stopping` / `tools/pre-execute` / `tools/post-execute` / `tools/result` / `fs/observed` / `fs/write-intent` / `llm/stream` are consumed
 *   SessionHeader / Session / Agent /       | core/agent   | stub     | discriminated union on `kind: 'main' | 'sub' | 'sdk'` not surfaced (we use `header.id` only)
 *   AgentOptions (lines 178-202)            |              |          |
 *   AgentCreatedPayload (line 204)          | core/agent   | partial  | we subscribe but ignore the `source: string` discriminator
 *   PreStepPayload (line 209)               | core/agent   | partial  | `PreStepPayload.assembly` / `PreStepPayload.metadata` missing (we don't pass them through)
 *   PreStepDecision (line 216)              | core/agent   | stub     | union has 3 variants on the real side (`reject` / `enter` / `transform`); we only return 2
 *   TurnStoppingPayload (line 220)          | core/agent   | stub     | minimal — real payload carries `metrics: AgentRunMetrics` we don't read
 *   ContentBlock / UserMessage (lines       | core/agent   | stub     | we don't reach into content; the `text`-only `ContentBlock` variant is sufficient for the audit surface
 *   226-232)                                |              |          |
 *   ToolExecution (line 234)                | core/tools   | stub     | real payload adds `argsSchema: ZodType` + `runtime: ToolRuntime` not consumed by guards
 *   ToolExecution{Success,Failure}          | core/tools   | stub     | `meta` / `additionalContexts` are read-only audit fields; not widened
 *   (lines 244-260)                         |              |          |
 *   PreToolDecision / PostToolDecision      | core/tools   | stub     | real decisions carry `kind: 'substitute'` / `'modify'` for the SPL `modify` action — we audit the substitute path but do not implement it
 *   (lines 262-269)                         |              |          |
 *   ToolResultPayload (line 271)            | core/tools   | stub     | post-result audit carrier; minimal
 *   ToolGuard (line 289)                    | core/tools   | wired    | mirror is byte-identical to the host `ToolGuard`; swap to real type once peerDep lands
 *   ToolsRuntimeLike (line 292)             | core/tools   | wired    | `ctx.tools.guard(guard)` is the live install path (src/intervention/SelfProtectionGuard.ts); swap when peerDep available
 *   FsVersion / FsTarget / FsObservation /  | fs           | stub     | real host uses a branded `FsVersion` (we use plain string); `kind: 'present' | 'absent' | 'stale'` carries a third variant we don't model (write-conflict staleness)
 *   FsWriteIntentPayload (lines 309-327)    |              |          |
 *   SubprocessSpawnSpec (line 354)          | subprocess   | wired    | mirror is byte-identical to the real spec (no `command` field; argv-driven)
 *   SubprocessSpawnResult (line 399)        | subprocess   | wired    | mirror captures the synchronous-return contract; stream ends typed `unknown` to avoid pulling Writable/Readable across the boundary
 *   SubprocessTerminalSpawnSpec (line 413)  | subprocess   | stub     | real spec also carries `dataEvent: 'close' | 'message'`; we don't tap the terminal stream (the PTY-gap tombstone in `src/intervention/RuntimeHook.ts` documents it)
 *   SubprocessRuntimeLike (line 421)        | subprocess   | wired    | `spawn` is the live install path (src/intervention/RuntimeHook.ts); `spawnTerminal` is a no-op stub (PTY gap — see the tombstone in RuntimeHook.ts)
 *   TokenUsage / StreamChunk (lines 450-463)| llm          | wired    | mirror is byte-identical; `type` is open-string to allow provider-specific variants (`tool_call` / `reasoning` etc.)
 *   GenerateOptions (line 468)              | llm          | stub     | we only consume `model` / `provider` for the burst-detector's session attribution; real shape is provider-options-passthrough
 *
 * Status legend:
 *   `stub`     — minimal local declaration; real type is structurally
 *                similar but we haven't migrated (peerDep absent). Drift
 *                risk: real type widens without us noticing.
 *   `partial`  — used by the plugin in production; some real fields
 *                intentionally omitted because the consumer does not read
 *                them. Documented per-row.
 *   `wired`    — mirror is the install seam or a post-fix contract; any
 *                drift would be caught by runtimeHook / selfProtection /
 *                tokenUsage tests at the seam boundary.
 *
 * Drift guard: `tests/externalContract.test.ts` (dead-type scan +
 * registered-events audit + payload field consistency + runtime
 * unknown-event warn) catches drift between THIS file
 * and the plugin's actual `ctx.on` registrations + listener arities. The
 * drift guard runs without the host source — it is the harness-agnostic
 * half (the harness-aware half needs the host source
 * mounted + the migration cookbook step 1–2 above).
 */

//
// When that day comes:
//   1. `pnpm add -D @deepseek-ai/cordis@^4.0.2` in the plugin workspace
//   2. replace the stub declarations below with `export type { Context,
//      Events, Logger } from '@deepseek-ai/cordis'`
//   3. delete the local interfaces + the `import type` block
//
// Until then this stub is the source of truth — see
// `tests/externalContract.test.ts` for the bidirectional drift guard.

/** Minimal Cordis ReflectService stub. The real shape lives at
 * `@deepseek-ai/cordis`'s `ReflectService` (cordis).
 *
 * `get(name, strict?)` is the safe accessor
 * for opt-in service probes ('remote' / 'commands' / 'subprocess' /
 * 'typert' / 'reflect').
 *
 * the host-side mount API migrated
 * from `ctx.remote.$mount(...)` (gateway-client only) to
 * `ctx.typert.register(contribution)` plus
 * `ctx.reflect.provide(name, value)` for the Cordis Service that owns
 * the dispatched methods. Both are first-class on the stub now.
 *
 * `store` and `props` are exposed because `cordis`'s
 * mixin('reflect', ['get', 'set', 'provide', 'accessor', 'mixin'])
 * (cordis) installs these on `ctx.reflect`.
 */
export interface ReflectService {
  /** Safe accessor — returns the service value, or `undefined` when
   *  not (yet) provided. Does not throw "cannot get property X without
   *  inject" the way `ctx.X` does. */
  get(name: string, strict?: boolean): unknown
  /** Internal impl lookup; not consumed by the plugin. */
  _getImpl(name: string, strict?: boolean): unknown
  /** Service implementations, keyed by isolation label. */
  store: Record<symbol, unknown>
  /** Declared context properties (services and accessors), by name. */
  props: Record<string, unknown>
  /** — provider-side registration. Mirror of
   *  (host source):provide(name, value, check?)`.
   *  Used by `src/typert/host.ts#registerSecurityMonitorRemote` to
   *  install the `securityMonitor` Cordis service (whose methods the
   *  harness's TypertGateway dispatches against). Returns a disposer
   *  that unregisters the service. */
  provide(name: string, value: unknown, check?: () => boolean): () => Promise<void>
}

/** Minimal Cordis Context. */
export interface Context {
  on<K extends keyof Events>(name: K, listener: EventListener<K>): void
  logger: Logger
  effect(dispose: () => (() => void) | void, id?: string): void
  /** : `ctx.inject(['subprocess']...)` is the Cordis service-
   *  injection seam. The harness's `SubprocessRuntime` lives on
   *  `ctx.subprocess`; we resolve it inside the callback and monkey-patch
   *  its methods in place (Cordis permits method reassignment on a
   *  service instance; service replacement throws). */
  inject<T>(
    deps: string | string[],
    callback: (ctx: Context) => T | Promise<T>,
  ): T | Promise<T>
  /** : `ctx.reflect.get(name)` is the safe
   *  accessor for opt-in probes on services that are NOT declared in the
   *  plugin's `inject` (e.g. `ctx.reflect.get('remote')` for the
   *  client-only `remote` namespace — adding it to `inject` would
   *  pin the fiber to PENDING). See `src/index.ts` for why 'remote'
   *  is intentionally absent. */
  reflect: ReflectService
}

export interface Logger {
  debug(message: string, ...args: unknown[]): void
  info(message: string, ...args: unknown[]): void
  warn(message: string, ...args: unknown[]): void
  error(message: string, ...args: unknown[]): void
}

export type EventListener<K extends keyof Events> =
  K extends 'agent/created'
    ? (payload: AgentCreatedPayload) => void
    : K extends 'agent/pre-step'
      ? (
          payload: PreStepPayload,
          next: () => Promise<PreStepDecision>,
        ) => Promise<PreStepDecision>
      : K extends 'agent/turn-stopping'
        ? (payload: TurnStoppingPayload) => Promise<void>
        : K extends 'tools/pre-execute'
          ? (
              exec: ToolExecution,
              next: () => Promise<PreToolDecision>,
            ) => Promise<PreToolDecision>
          : K extends 'tools/post-execute'
              ? (
                  exec: ToolExecution,
                  result: ToolExecutionResult,
                  next: () => Promise<PostToolDecision>,
                ) => Promise<PostToolDecision>
              : K extends 'tools/result'
                ? (exec: ToolExecution, result: ToolExecutionResult) => void
                : K extends 'fs/observed'
                  ? (
                      target: FsTarget,
                      observation: FsObservation,
                      actor: object | undefined,
                    ) => void
                  : K extends 'fs/write-intent'
                    ? (
                        target: FsTarget,
                        actor: object | undefined,
                        next: () =>
                          | FsWriteIntentPayload
                          | undefined
                          | Promise<FsWriteIntentPayload | undefined>,
                      ) => Promise<FsWriteIntentPayload | undefined>
                    : K extends 'llm/stream'
                      ? (
                          options: GenerateOptions,
                          next: () => AsyncIterable<StreamChunk>,
                        ) => AsyncIterable<StreamChunk>
                      : never

export interface Events {
  'agent/created': AgentCreatedPayload
  'agent/pre-step': PreStepPayload
  'agent/turn-stopping': TurnStoppingPayload
  'tools/pre-execute': ToolExecution
  'tools/post-execute': { exec: ToolExecution; result: ToolExecutionResult }
  'tools/result': ToolResultPayload
  'fs/observed': { target: FsTarget; observation: FsObservation; actor: object | undefined }
  'fs/write-intent': {
    target: FsTarget
    actor: object | undefined
    next: () => Promise<FsWriteIntentPayload | undefined> | FsWriteIntentPayload | undefined
  }
  // LLM generation waterfall. The harness llm package
  // (the host LLM adapter) exposes `llm/stream` as
  // `(options: GenerateOptions, next: () => AsyncIterable<StreamChunk>) =>
  // AsyncIterable<StreamChunk>`; listeners wrap the downstream stream (tee)
  // and return it. Usage chunks (`type: 'usage'`) carry `TokenUsage`.
  'llm/stream': { options: GenerateOptions; next: () => AsyncIterable<StreamChunk> }
}

export interface SessionHeader {
  id: string
  createdAt: number
  cwd?: string
}

export interface Session {
  header: SessionHeader
  events: unknown[]
}

export interface Agent {
  id: string
  session: Session
  options?: AgentOptions
}

export interface AgentOptions {
  provider?: string
  model?: string
  /** Available skills for this agent (Cordis shape — may be absent in stubs). */
  skills?: string[]
  /** Available tools for this agent (Cordis shape — may be absent in stubs). */
  tools?: string[]
}

export interface AgentCreatedPayload {
  agent: Agent
  source: string
}

export interface PreStepPayload {
  agent: Agent
  messages: UserMessage[]
  turn: number
  signal: AbortSignal
}

export type PreStepDecision =
  | { kind: 'reject' }
  | { kind: 'enter'; messages: UserMessage[]; assembly?: unknown }

export interface TurnStoppingPayload {
  agent: Agent
  turn: number
  signal: AbortSignal
}

export type ContentBlock = { type: 'text'; text: string } | { type: unknown }

export interface UserMessage {
  role?: 'user' | 'assistant' | 'system'
  content: ContentBlock[]
  source?: { kind: string; plugin?: string }
}

export interface ToolExecution {
  callId: string
  rootCallId: string
  name: string
  arguments: unknown
  agent?: Agent
  parent?: symbol
  signal: AbortSignal
}

export interface ToolExecutionSuccess {
  isError: false
  value: unknown
  content: ContentBlock[]
  meta?: unknown
  additionalContexts?: UserMessage[]
}

export interface ToolExecutionFailure {
  isError: true
  error: { message: string; info?: unknown }
  content: ContentBlock[]
  meta?: unknown
  additionalContexts?: UserMessage[]
}

export type ToolExecutionResult = ToolExecutionSuccess | ToolExecutionFailure

export type PreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'ask'; reason?: string }

export type PostToolDecision =
  | { kind: 'accept'; content?: ContentBlock[]; value?: unknown; additionalContexts?: UserMessage[] }
  | { kind: 'block'; feedback: ContentBlock[]; additionalContexts?: UserMessage[] }

export interface ToolResultPayload {
  exec: ToolExecution
  result: ToolExecutionResult
}

// Tool guard seam --------------------------------
//
// Local mirror of the harness `ctx.tools` guard API (the host's ToolGuard
// type and its `guard()` registration seam).
// A guard is evaluated SYNCHRONOUSLY after every `tools/pre-execute`
// listener and before the tool body; returning a string monotonically
// denies the call (the string is the rejection reason shown to the model),
// returning undefined allows it. `guard()` returns a disposer.
//
// The harness types the execution as `Readonly<ToolExecution>` — guards
// must not mutate the dispatch payload.

/** Mirror of harness `ToolGuard`. */
export type ToolGuard = (execution: Readonly<ToolExecution>) => string | undefined

/** Minimal shape of the harness `ctx.tools` runtime service. */
export interface ToolsRuntimeLike {
  /** Register a monotonic denial guard. Returns a disposer. */
  guard(guard: ToolGuard): () => void
}

// --- Filesystem observation events (fs/*) ---------------------------------
//
// Mirror of the host fs service and the host fs service
// in the host monorepo. These are public Cordis events declared on
// `ctx.fs` and emitted by `tool-fs` / `tool-str-replace-editor` after a
// successful read/write/edit, plus the `fs/write-intent` waterfall that fires
// before a write. See the gap analysis for why we audit but do not
// occupy the write-intent decision slot (fs-observation-policy already does).
//
// We keep the stubs dependency-free: FsVersion is a branded string in the real
// harness but we accept plain string here.

/** Opaque file-version token. Branded `string` in the harness; treated as `string` here. */
export type FsVersion = string

/** A path resolved by a backend into a stable identity. */
export interface FsTarget {
  /** Opaque key — consumers MUST NOT parse or assume it is a local path. */
  targetKey: string
  /** Human-readable path for UI/audit. May be absolute, workspace-relative, or URI. */
  displayPath: string
}

/** One authoritative observation of a target. */
export type FsObservation =
  | { readonly kind: 'present'; readonly version: FsVersion }
  | { readonly kind: 'absent' }

/** A guarded write intent shape that listeners may return to alter the write. */
export type FsWriteIntentPayload =
  | { kind: 'createIfAbsent' }
  | { kind: 'replaceIfVersion'; version: FsVersion }

// Subprocess seam ---------------------------------------
//
// Local mirror of the host subprocess service `SubprocessSpawnSpec`
// in the harness. The plugin never imports the real package (zero-intrusion
// invariant #1) so we declare the spec locally; the RuntimeHook then wraps the
// live `ctx.subprocess` instance via `ctx.inject(['subprocess'], ...)`.
//
// Field names mirror the harness shape byte-for-byte so a future migration to
// peerDependencies would not need to remap. Plugin-side correlation metadata
// (tool_call_id, agent_id, session_id) flows through a side-channel WeakMap
// populated by ApplicationCollector.onToolPreExecute — keeping the spec itself
// non-intrusive.

/**
 * Mirror of the host subprocess service
 * (`SubprocessSpawnSpec`) — the real harness does NOT have a `command`
 * field; the program is `argv[0]`. RuntimeHook inspects `argv[0]` for
 * the executable name and `argv` for bash/pwsh body extraction. Any
 * `command`-shaped references in older drafts were the bug that
 * `runtime_spawn_intent` events silently dropped — schema validation
 * requires `executable` to be a non-empty string, but `spec.command`
 * was `undefined`, so the event was rejected by EventCollector and never
 * landed in NDJSON.
 */
export interface SubprocessSpawnSpec {
  /** Argument vector. argv[0] is the program name (path or basename). */
  argv: readonly string[]
  /** Working directory; defaults to the harness's cwd. */
  cwd?: string
  /** Environment variables to merge on top of the harness's scrubbed env. */
  env?: Record<string, string>
  /**
   * Per-stream stdio dispositions. The real harness spec
   * types `stdio` as the always-present object `SubprocessStdio`
   * (the host subprocess service) — the string
   * forms below only exist in this stub (and unit tests); production spawns
   * always arrive with `{ stdin, stdout, stderr }`. Consumers must not
   * assume the string forms (e.g. `spec.stdio === 'ignore'`) are reachable.
   */
  stdio?:
    | 'inherit'
    | 'pipe'
    | 'ignore'
    | {
        stdin?: 'pipe' | 'inherit' | 'ignore'
        stdout?: 'pipe' | 'inherit' | { maxBytes?: number }
        stderr?: 'pipe' | 'inherit' | { maxBytes?: number }
      }
  graceMs?: number
  signal?: AbortSignal
}

/**
 * Mirror of the harness's `SubprocessHandle`
 * (the host subprocess service) — the SYNCHRONOUS
 * return value of `ctx.subprocess.spawn(spec)`
 * (the host local subprocess adapter).
 *
 * the previous `{ handle: unknown, pid: number }` shape was a stub
 * invention that does not exist on the real handle. The real handle carries
 * stream ends + `done` + the terminate/waitForExit verbs and deliberately
 * NO `pid` — the child pid never crosses this seam, so the RuntimeHook no
 * longer populates `child_pid` on spawn events (session_id / cmdline carry
 * the correlation instead).
 *
 * Stream ends are typed `unknown`: the plugin never reads them, and typing
 * them as the harness's node stream types would drag `Writable` / `Readable`
 * / `Duplex` across the Cordis boundary stub for zero consumers.
 */
export interface SubprocessSpawnResult {
  readonly stdin?: unknown
  readonly stdout?: unknown
  readonly stderr?: unknown
  readonly control?: unknown
  readonly collected?: unknown
  /** Resolves with spawned-command exit facts; rejects for spawn or provider failures. */
  readonly done: Promise<unknown>
  /** Begin the provider's termination procedure on the managed range. Idempotent, no-op once gone. */
  terminate(): void
  /** Wait until the managed process range is empty. */
  waitForExit(signal?: AbortSignal): Promise<boolean>
}

export interface SubprocessTerminalSpawnSpec {
  argv: readonly string[]
  cwd?: string
  env?: Record<string, string>
  rows?: number
  cols?: number
}

export interface SubprocessRuntimeLike {
  /**
   * the harness's `spawn` is SYNCHRONOUS — `LocalSubprocessRuntime.
   * spawn` returns a `SubprocessHandle` directly
   * (subprocess-local/src/index.ts:179), and callers consume it
   * synchronously (`bash-local/src/index.ts:252-253` does
   * `const handle = this.ctx.subprocess.spawn(...); await handle.done`).
   * The RuntimeHook wrapper must preserve that contract byte-for-byte on
   * the allow path: returning a Promise here breaks `handle.done` for
   * every shell tool call.
   */
  spawn(spec: SubprocessSpawnSpec): SubprocessSpawnResult
  spawnTerminal(
    spec: SubprocessTerminalSpawnSpec,
  ): Promise<unknown>
  resolveExecutable?(command: string, env?: Record<string, string>, signal?: AbortSignal): Promise<string>
}

// LLM stream seam ------------------------------
//
// Local mirror of the host LLM adapter (`TokenUsage` /
// `StreamChunk`) and the host LLM adapter (`llm/stream`
// waterfall payload) in the harness. The plugin taps usage chunks via a
// tee wrapper (`src/utils/tokenUsage.ts`) — it never modifies the stream
// and never blocks generation.

/** Mirror of harness `TokenUsage` (the host LLM adapter).
 *  `totalTokens` is optional — providers may only report the split counts,
 *  in which case the detector derives total = inputTokens + outputTokens. */
export interface TokenUsage {
  inputTokens: number
  outputTokens: number
  totalTokens?: number
}

/** Mirror of harness `StreamChunk`. `type` discriminates the chunk kind
 *  ('text' | 'usage' | provider-specific variants); `usage` is present
 *  exactly when `type === 'usage'`. */
export interface StreamChunk {
  readonly type: string
  readonly usage?: TokenUsage
  readonly [key: string]: unknown
}

/** Mirror of harness `GenerateOptions` — provider/model selection plus
 *  request-scoped options. The detector does not read the prompt content;
 *  it only needs the stream seam, so the stub stays coarse. */
export interface GenerateOptions {
  model?: string
  provider?: string
  readonly [key: string]: unknown
}
