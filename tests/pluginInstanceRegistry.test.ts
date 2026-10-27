/**
 * Tests for the process-level plugin instance registry.
 *
 * The registry is the mechanism that lets the unload sentinel tell an
 * HMR RELOAD (the plugin came back) from a real REMOVAL (the plugin is
 * gone and the host keeps running). Its one hard requirement is that
 * the activation counter survives a module re-import — that IS the
 * HMR path (`packages/boot/hmr` re-imports the plugin bundle).
 *
 * A module-level counter would reset on every reload, which would make
 * every reload look like a first-ever activation and defeat the whole
 * detection. `vi.resetModules()` + a fresh dynamic import reproduces
 * that re-import faithfully.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  currentGeneration,
  isReloadDetected,
  registerPluginInstance,
  resetPluginInstanceRegistry,
} from '../src/intervention/pluginInstanceRegistry.js'

describe('plugin instance registry', () => {
  beforeEach(() => {
    resetPluginInstanceRegistry()
  })

  it('assigns increasing generations per plugin', () => {
    const first = registerPluginInstance('security-monitor', 1_000)
    const second = registerPluginInstance('security-monitor', 2_000)
    expect(first.generation).toBe(1)
    expect(second.generation).toBe(2)
    expect(first.activatedAt).toBe(1_000)
    expect(second.activatedAt).toBe(2_000)
  })

  it('tracks plugins independently', () => {
    registerPluginInstance('security-monitor')
    const other = registerPluginInstance('other-plugin')
    expect(other.generation).toBe(1)
    expect(currentGeneration('security-monitor')).toBe(1)
    expect(currentGeneration('other-plugin')).toBe(1)
  })

  it('reports no reload for the instance that is currently live', () => {
    const registration = registerPluginInstance('security-monitor')
    expect(isReloadDetected('security-monitor', registration.generation)).toBe(false)
  })

  it('reports a reload once a newer instance registers', () => {
    const first = registerPluginInstance('security-monitor')
    expect(isReloadDetected('security-monitor', first.generation)).toBe(false)
    registerPluginInstance('security-monitor')
    expect(isReloadDetected('security-monitor', first.generation)).toBe(true)
  })

  it('never reports a reload for an unknown plugin', () => {
    expect(currentGeneration('never-seen')).toBe(0)
    expect(isReloadDetected('never-seen', 0)).toBe(false)
  })

  it('survives a module re-import (the HMR reload property)', async () => {
    const first = await import('../src/intervention/pluginInstanceRegistry.js')
    const r1 = first.registerPluginInstance('security-monitor')

    // This is what the harness HMR path does: the plugin bundle is
    // re-imported, so the module is evaluated again. A module-level
    // counter would restart at 1 here.
    vi.resetModules()
    const second = await import('../src/intervention/pluginInstanceRegistry.js')
    const r2 = second.registerPluginInstance('security-monitor')

    expect(r2.generation).toBe(r1.generation + 1)
    // The OLD instance can now tell it was reloaded, not removed.
    expect(second.isReloadDetected('security-monitor', r1.generation)).toBe(true)
    expect(second.isReloadDetected('security-monitor', r2.generation)).toBe(false)
  })

  it('reset drops the counter so a fresh process-equivalent state is observable', () => {
    registerPluginInstance('security-monitor')
    expect(currentGeneration('security-monitor')).toBe(1)
    resetPluginInstanceRegistry()
    expect(currentGeneration('security-monitor')).toBe(0)
    expect(registerPluginInstance('security-monitor').generation).toBe(1)
  })
})
