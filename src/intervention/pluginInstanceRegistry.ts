/**
 * Process-level registry of security-monitor plugin instances.
 *
 * ## Why this exists
 *
 * The unload sentinel (§6.2) used to declare "the plugin was removed at
 * runtime" the instant its Cordis scope was disposed. Real-data capture
 * (2026-10-22 → 2026-10-27, `security-events.jsonl`, 959 events) showed
 * that verdict is wrong for the two dominant cases:
 *
 *   - **HMR reload** — the plugin-manager disposes the scope and
 *     re-instantiates the plugin in the SAME process. 15 of the 29
 *     tamper-class events were followed by a `plugin_startup` in the
 *     same pid 1.8–140 s later. The plugin was never removed.
 *   - **Process teardown** — the other 14 were the LAST event of their
 *     pid: the host was exiting. The event's own claim ("the host
 *     process kept running") was false.
 *
 * The sentinel cannot ask the host "am I still loaded?" — the plugin's
 * own scope is already gone by then, and the host contract exposed to
 * the plugin (`src/types/external.ts`) has no plugin-registry accessor.
 *
 * What it CAN do is ask "did a NEW instance of this plugin register
 * itself in this process after I was disposed?". That question is
 * answered by a monotonic per-plugin activation counter kept on
 * `globalThis`.
 *
 * ## Why `globalThis`
 *
 * The counter MUST survive the HMR module re-import. Two properties
 * make `globalThis` the right carrier:
 *
 *   1. It is process-scoped — a new process starts a fresh counter, so
 *      a plugin removed by an outright process restart is never
 *      mistaken for a reload.
 *   2. It survives module re-evaluation. The harness HMR path
 *      (`packages/boot/hmr`) re-imports the plugin bundle; whether the
 *      ESM module cache is invalidated or not, `globalThis` state is
 *      preserved either way. A module-level `let` would NOT be — the
 *      counter would reset to 1 and every reload would look like a
 *      first-ever activation.
 *
 * The registry key is a `Symbol.for()` symbol so two copies of this
 * module (e.g. an HMR-reimported bundle alongside the original) resolve
 * to the SAME registry object instead of each keeping its own counter.
 *
 * ## Thread / process model
 *
 * Node is single-threaded and the counter mutation is a plain
 * `Map.set` — no lock needed. The registry is process-local by
 * construction and is never persisted.
 */

/**
 * Global registry key. `Symbol.for` (not `Symbol`) so every copy of this
 * module in the realm resolves to the same key.
 */
const REGISTRY_KEY = Symbol.for('dsh.security-control.plugin-instance-registry')

/** Per-plugin activation bookkeeping held by the registry. */
export interface PluginInstanceRegistryState {
  /**
   * Monotonic activation counter per plugin name. Starts at 1 for the
   * first activation of a plugin in this process.
   */
  readonly generations: Map<string, number>
  /** Wall-clock ms of the latest activation, per plugin name. */
  readonly activatedAt: Map<string, number>
}

/** The result of registering a plugin instance. */
export interface PluginInstanceRegistration {
  /** The plugin's short name (e.g. `security-monitor`). */
  readonly pluginName: string
  /** The activation counter value assigned to this instance. */
  readonly generation: number
  /** Wall-clock ms at which this instance registered. */
  readonly activatedAt: number
}

/**
 * The global host object. Typed as a symbol-keyed record so the cast
 * stays local to this module.
 */
function globalHost(): Record<symbol, PluginInstanceRegistryState | undefined> {
  return globalThis as unknown as Record<symbol, PluginInstanceRegistryState | undefined>
}

/**
 * Return the process-wide registry, creating it on first use.
 *
 * The registry object is stored BY REFERENCE on `globalThis`, so a
 * module re-import finds the existing object (and its counters) rather
 * than starting over.
 */
function ensureRegistry(): PluginInstanceRegistryState {
  const host = globalHost()
  const existing = host[REGISTRY_KEY]
  if (existing) return existing
  const created: PluginInstanceRegistryState = {
    generations: new Map<string, number>(),
    activatedAt: new Map<string, number>(),
  }
  host[REGISTRY_KEY] = created
  return created
}

/**
 * Register a freshly-activated plugin instance and return its
 * generation.
 *
 * Called by the sentinel at install time. Every activation of the
 * plugin — first boot, HMR reload, host restart within the same
 * process — bumps the counter for that plugin name.
 */
export function registerPluginInstance(
  pluginName: string,
  activatedAt: number = Date.now(),
): PluginInstanceRegistration {
  const registry = ensureRegistry()
  const generation = (registry.generations.get(pluginName) ?? 0) + 1
  registry.generations.set(pluginName, generation)
  registry.activatedAt.set(pluginName, activatedAt)
  return { pluginName, generation, activatedAt }
}

/**
 * The current activation counter for a plugin name. `0` means the
 * plugin has never been activated in this process.
 */
export function currentGeneration(pluginName: string): number {
  return ensureRegistry().generations.get(pluginName) ?? 0
}

/**
 * True when a NEWER instance of `pluginName` registered itself after
 * the instance holding `generation` was installed.
 *
 * This is the reload detector: the HMR path disposes the old scope and
 * re-instantiates the plugin in the same process, so the new instance
 * bumps the counter and the disposed instance can tell that it was
 * RELOADED rather than REMOVED.
 */
export function isReloadDetected(pluginName: string, generation: number): boolean {
  return currentGeneration(pluginName) > generation
}

/**
 * Test-only: drop the process-wide registry so a test can start from a
 * clean generation counter.
 */
export function resetPluginInstanceRegistry(): void {
  delete globalHost()[REGISTRY_KEY]
}
