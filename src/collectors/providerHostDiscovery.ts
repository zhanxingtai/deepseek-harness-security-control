/**
 * LLM provider host auto-discovery for the inline sensitive-header guard.
 *
 * Background: the guard exempts out-of-frame requests to
 * `sensitiveHeaderGuard.harnessPlaneHosts` because the harness plane
 * (llm-pi-ai adapter provider calls, plugin telemetry) legitimately
 * carries `Authorization: Bearer <key>`. Maintaining that list by hand
 * is whack-a-mole — every customer model / enterprise gateway / self-hosted
 * vLLM re-triggers the high-severity audit-only false positive.
 *
 * The DSH host persists user-configured provider routes in its settings
 * document (`<harness home>/settings.yaml`, harness home = `$DSH_HOME` or
 * `~/.dsh` — same rule as the host's `resolveDshHome`,
 * the settings file reader). Each
 * `llm-pi-ai.providers.<route>.baseURL` is an operator-trusted endpoint
 * the harness itself sends the model key to, so discovering hostnames
 * from there and exempting them introduces no new trust assumption.
 *
 * Scope discipline:
 *   - reads ONLY `baseURL` hostnames; `apiKeyEnv`-referenced key material
 *     is never read, copied, or logged;
 *   - parse/IO failures degrade to "no hosts" (current behaviour —
 *     audit-only noise), they never throw into the collector;
 *   - YAML parsing reuses the optional-peerDep chain (`yaml` → `js-yaml`)
 *     exactly like `RuleLoader`, so the bundle contract (no YAML lib
 *     in-bundle) is preserved.
 */
import { existsSync, readFileSync, statSync, watch } from 'node:fs'
import { createRequire } from 'node:module'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** Harness home resolution, mirroring the host's `resolveDshHome`. */
export function resolveHarnessHome(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = env['DSH_HOME']
  if (typeof fromEnv === 'string' && fromEnv.trim().length > 0) return fromEnv
  return join(homedir(), '.dsh')
}

/** Default settings document path under the harness home. */
export function defaultSettingsPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(resolveHarnessHome(env), 'settings.yaml')
}

const optionalRequire = createRequire(import.meta.url)

type YamlOutcome =
  | { kind: 'ok'; value: unknown }
  | { kind: 'parse-error'; error: string }
  | { kind: 'missing' }

function tryYaml(raw: string, libName: 'yaml' | 'js-yaml'): YamlOutcome {
  let lib: { parse?: (text: string) => unknown; load?: (text: string) => unknown }
  try {
    lib = optionalRequire(libName) as typeof lib
  } catch {
    return { kind: 'missing' }
  }
  try {
    const fn = lib.parse ?? lib.load
    if (typeof fn !== 'function') return { kind: 'missing' }
    return { kind: 'ok', value: (fn as (text: string) => unknown).call(lib, raw) }
  } catch (error) {
    return { kind: 'parse-error', error: error instanceof Error ? error.message : String(error) }
  }
}

function parseSettingsYaml(raw: string): unknown | undefined {
  const modern = tryYaml(raw, 'yaml')
  if (modern.kind === 'ok') return modern.value
  const legacy = tryYaml(raw, 'js-yaml')
  if (legacy.kind === 'ok') return legacy.value
  return undefined
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Extract provider hostnames from a settings document's
 * `llm-pi-ai.providers` dict. Invalid entries (missing baseURL,
 * unparseable URL, non-object profile) are skipped — discovery is
 * best-effort by design.
 */
export function parseProviderHostsFromSettings(raw: string): string[] {
  const doc = parseSettingsYaml(raw)
  if (!isPlainObject(doc)) return []
  const llm = doc['llm-pi-ai']
  if (!isPlainObject(llm)) return []
  const providers = llm['providers']
  if (!isPlainObject(providers)) return []
  const hosts = new Set<string>()
  for (const profile of Object.values(providers)) {
    if (!isPlainObject(profile)) continue
    const baseURL = profile['baseURL']
    if (typeof baseURL !== 'string' || baseURL.trim().length === 0) continue
    try {
      hosts.add(new URL(baseURL).hostname.toLowerCase())
    } catch {
      // Unparsable baseURL — skip; the llm-pi-ai adapter will surface
      // its own diagnostic for the route, discovery stays silent.
    }
  }
  return [...hosts]
}

/**
 * Read provider hostnames from a settings document. Missing file or
 * unreadable/invalid content → `[]` (never throws).
 */
export function readProviderHosts(settingsPath: string): string[] {
  try {
    if (!existsSync(settingsPath)) return []
    return parseProviderHostsFromSettings(readFileSync(settingsPath, 'utf8'))
  } catch {
    return []
  }
}

function sortedKey(hosts: readonly string[]): string {
  return [...hosts].sort().join('\n')
}

/**
 * Watch a settings document and invoke `onChange` with the current
 * provider host list whenever the parsed hostname set actually changes
 * (edits that do not touch provider routes do not fire).
 *
 * Implementation: `fs.watch` (`persistent: false` — must not keep the
 * host process alive) with an mtime-poll fallback every `pollMs`, plus a
 * short debounce so a multi-write save fires one callback. The caller
 * performs the initial read; the watcher only reports changes.
 */
export function watchProviderHosts(
  settingsPath: string,
  onChange: (hosts: string[]) => void,
  options: { debounceMs?: number; pollMs?: number } = {},
): { stop: () => void } {
  const debounceMs = options.debounceMs ?? 500
  const pollMs = options.pollMs ?? 5000
  let last = ''
  let timer: ReturnType<typeof setTimeout> | undefined
  let stopped = false

  const emit = (): void => {
    const hosts = readProviderHosts(settingsPath)
    const key = sortedKey(hosts)
    if (key === last) return
    last = key
    try {
      onChange(hosts)
    } catch {
      // Discovery callback failures must never reach the collector.
    }
  }
  const schedule = (): void => {
    if (stopped) return
    if (timer !== undefined) clearTimeout(timer)
    timer = setTimeout(emit, debounceMs)
    timer.unref?.()
  }

  last = sortedKey(readProviderHosts(settingsPath))

  let watcher: ReturnType<typeof watch> | undefined
  try {
    watcher = watch(settingsPath, { persistent: false }, () => schedule())
  } catch {
    watcher = undefined
  }

  let lastMtime = 0
  try {
    lastMtime = statSync(settingsPath).mtimeMs
  } catch {
    lastMtime = 0
  }
  // Poll fallback covers watch-mode degradation (NFS, some Windows
  // editors' atomic-rename saves) — same rationale as PolicyWatcher.
  const poll = setInterval(() => {
    if (stopped) return
    try {
      const mtime = statSync(settingsPath).mtimeMs
      if (mtime !== lastMtime) {
        lastMtime = mtime
        schedule()
      }
    } catch {
      // File absent mid-save — next poll retries.
    }
  }, pollMs)
  poll.unref?.()

  return {
    stop: (): void => {
      stopped = true
      if (timer !== undefined) clearTimeout(timer)
      try {
        watcher?.close()
      } catch {
        // already closed
      }
      clearInterval(poll)
    },
  }
}

/**
 * Hostname match against an exemption entry. Exact match, or suffix
 * match for `*.` wildcard entries (`*.openai.azure.com` matches
 * `acme.openai.azure.com`). Host and pattern are expected lowercase.
 */
export function matchesHostPattern(host: string, pattern: string): boolean {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1)
    return host === suffix.slice(1) || host.endsWith(suffix)
  }
  return host === pattern
}

/** True when any exemption entry matches the host. */
export function matchesAnyHostPattern(host: string, patterns: ReadonlySet<string>): boolean {
  for (const pattern of patterns) {
    if (matchesHostPattern(host, pattern)) return true
  }
  return false
}
