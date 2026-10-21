/**
 * Tests for `src/collectors/providerHostDiscovery.ts` — the provider
 * host auto-discovery layer of the inline sensitive-header guard.
 *
 * Covers: harness-home resolution, settings document parsing (valid /
 * catalog-route / malformed entries), file read degradation, the
 * change watcher (initial state, debounced change notification, stop),
 * and the wildcard host matcher.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  defaultSettingsPath,
  matchesAnyHostPattern,
  matchesHostPattern,
  parseProviderHostsFromSettings,
  readProviderHosts,
  resolveHarnessHome,
  watchProviderHosts,
} from '../src/collectors/providerHostDiscovery.js'

describe('resolveHarnessHome', () => {
  it('prefers $DSH_HOME over the homedir fallback', () => {
    expect(resolveHarnessHome({ DSH_HOME: '/custom/dsh' } as NodeJS.ProcessEnv)).toBe('/custom/dsh')
  })
  it('falls back to ~/.dsh when $DSH_HOME is absent or blank', () => {
    const env = {} as NodeJS.ProcessEnv
    expect(resolveHarnessHome(env)).toMatch(/[\\/]\.dsh$/)
    expect(resolveHarnessHome({ DSH_HOME: '  ' } as NodeJS.ProcessEnv)).toMatch(/[\\/]\.dsh$/)
  })
  it('defaultSettingsPath joins settings.yaml under the harness home', () => {
    expect(defaultSettingsPath({ DSH_HOME: '/custom/dsh' } as NodeJS.ProcessEnv)).toBe(
      join('/custom/dsh', 'settings.yaml'),
    )
  })
})

describe('parseProviderHostsFromSettings', () => {
  it('extracts hostnames from every route baseURL', () => {
    const raw = [
      'llm-pi-ai:',
      '  providers:',
      '    minimax-cn:',
      '      baseURL: https://api.minimax.chat/v1',
      '    acme-gateway:',
      '      baseURL: https://gateway.acme.example:8443/v1',
    ].join('\n')
    expect(parseProviderHostsFromSettings(raw).sort()).toEqual(['api.minimax.chat', 'gateway.acme.example'])
  })

  it('drops the port and lowercases hostnames', () => {
    const raw = 'llm-pi-ai:\n  providers:\n    local:\n      baseURL: https://LLM.internal.example:8443/v1\n'
    expect(parseProviderHostsFromSettings(raw)).toEqual(['llm.internal.example'])
  })

  it('skips catalog routes without explicit baseURL', () => {
    const raw = [
      'llm-pi-ai:',
      '  providers:',
      '    openai:',
      '      apiKeyEnv: OPENAI_API_KEY',
      '    declared:',
      '      baseURL: https://gateway.acme.example/v1',
    ].join('\n')
    expect(parseProviderHostsFromSettings(raw)).toEqual(['gateway.acme.example'])
  })

  it('skips malformed entries without failing the whole parse', () => {
    const raw = [
      'llm-pi-ai:',
      '  providers:',
      '    not-an-object: true',
      '    bad-url:',
      '      baseURL: "::not a url"',
      '    empty:',
      '      baseURL: ""',
      '    good:',
      '      baseURL: https://api.good.example/v1',
    ].join('\n')
    expect(parseProviderHostsFromSettings(raw)).toEqual(['api.good.example'])
  })

  it('returns [] for documents without an llm-pi-ai providers dict', () => {
    expect(parseProviderHostsFromSettings('other:\n  x: 1\n')).toEqual([])
    expect(parseProviderHostsFromSettings('llm-pi-ai:\n  providers: []\n')).toEqual([])
    expect(parseProviderHostsFromSettings('not: [valid')).toEqual([])
  })
})

describe('readProviderHosts', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'dsh-discovery-'))
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('reads hosts from an existing document', () => {
    const p = join(dir, 'settings.yaml')
    writeFileSync(p, 'llm-pi-ai:\n  providers:\n    a:\n      baseURL: https://api.a.example/v1\n')
    expect(readProviderHosts(p)).toEqual(['api.a.example'])
  })

  it('degrades to [] on missing file / unreadable path', () => {
    expect(readProviderHosts(join(dir, 'absent.yaml'))).toEqual([])
    expect(readProviderHosts(dir)).toEqual([])
  })
})

describe('watchProviderHosts', () => {
  let dir: string
  let settingsPath: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'dsh-discovery-watch-'))
    settingsPath = join(dir, 'settings.yaml')
    writeFileSync(settingsPath, 'llm-pi-ai:\n  providers:\n    a:\n      baseURL: https://api.a.example/v1\n')
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('notifies with the new host set when the document changes', async () => {
    const seen: string[][] = []
    const handle = watchProviderHosts(settingsPath, (hosts) => seen.push(hosts), {
      debounceMs: 50,
      pollMs: 100,
    })
    try {
      writeFileSync(
        settingsPath,
        'llm-pi-ai:\n  providers:\n    a:\n      baseURL: https://api.a.example/v1\n    b:\n      baseURL: https://api.b.example/v1\n',
      )
      await waitFor(() => seen.length > 0, 3000)
      expect(seen[seen.length - 1].sort()).toEqual(['api.a.example', 'api.b.example'])
    } finally {
      handle.stop()
    }
  })

  it('does not fire for edits that leave the host set unchanged', async () => {
    const seen: string[][] = []
    const handle = watchProviderHosts(settingsPath, (hosts) => seen.push(hosts), {
      debounceMs: 50,
      pollMs: 100,
    })
    try {
      // Same hosts, different formatting / unrelated key.
      writeFileSync(
        settingsPath,
        'ui:\n  x: 1\nllm-pi-ai:\n  providers:\n    a:\n      displayName: A\n      baseURL: https://api.a.example/v1\n',
      )
      await new Promise((r) => setTimeout(r, 500))
      expect(seen).toHaveLength(0)
    } finally {
      handle.stop()
    }
  })

  it('stop() silences further notifications', async () => {
    const seen: string[][] = []
    const handle = watchProviderHosts(settingsPath, (hosts) => seen.push(hosts), {
      debounceMs: 50,
      pollMs: 100,
    })
    handle.stop()
    writeFileSync(
      settingsPath,
      'llm-pi-ai:\n  providers:\n    z:\n      baseURL: https://api.z.example/v1\n',
    )
    await new Promise((r) => setTimeout(r, 400))
    expect(seen).toHaveLength(0)
  })
})

describe('matchesHostPattern / matchesAnyHostPattern', () => {
  it('exact match (lowercase both sides)', () => {
    expect(matchesHostPattern('api.minimax.chat', 'api.minimax.chat')).toBe(true)
    expect(matchesHostPattern('api.minimax.chat', 'api.other.com')).toBe(false)
  })
  it('wildcard matches subdomains and the apex', () => {
    expect(matchesHostPattern('acme.openai.azure.com', '*.openai.azure.com')).toBe(true)
    expect(matchesHostPattern('openai.azure.com', '*.openai.azure.com')).toBe(true)
    expect(matchesHostPattern('evilopenai.azure.com', '*.openai.azure.com')).toBe(false)
    expect(matchesHostPattern('x.openai.azure.com.evil.com', '*.openai.azure.com')).toBe(false)
  })
  it('matchesAnyHostPattern scans the set', () => {
    const set = new Set(['api.deepseek.com', '*.openai.azure.com'])
    expect(matchesAnyHostPattern('api.deepseek.com', set)).toBe(true)
    expect(matchesAnyHostPattern('acme.openai.azure.com', set)).toBe(true)
    expect(matchesAnyHostPattern('api.minimax.chat', set)).toBe(false)
  })
})

async function waitFor(cond: () => boolean, timeoutMs: number): Promise<void> {
  const start = Date.now()
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor timed out')
    await new Promise((r) => setTimeout(r, 50))
  }
}
