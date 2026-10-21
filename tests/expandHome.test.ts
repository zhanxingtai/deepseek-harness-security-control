import { describe, expect, it } from 'vitest'
import { expandHome, homeDir } from '../src/utils/expandHome.js'

describe('homeDir', () => {
  it('resolves to HOME when set', () => {
    expect(homeDir()).toBe(process.env.HOME || process.env.USERPROFILE || homeDir())
    expect(homeDir().length).toBeGreaterThan(0)
  })
})

describe('expandHome (shared implementation)', () => {
  const HOME = homeDir()

  it.each([
    { input: '~', expected: HOME },
    { input: '~/.dsh/security-events.jsonl', expected: `${HOME}/.dsh/security-events.jsonl` },
    { input: '~/foo/bar', expected: `${HOME}/foo/bar` },
    { input: '~\\windows\\style', expected: `${HOME}\\windows\\style` },
    { input: '/etc/shadow', expected: '/etc/shadow' },
    { input: 'relative/path', expected: 'relative/path' },
    { input: '~user/other', expected: '~user/other' },
  ])('expands $input', ({ input, expected }) => {
    expect(expandHome(input)).toBe(expected)
  })

  it('honours a runtime HOME override (same chain as the legacy copies)', () => {
    const original = process.env.HOME
    try {
      process.env.HOME = '/tmp/fake-home-73'
      expect(expandHome('~/x.log')).toBe('/tmp/fake-home-73/x.log')
    } finally {
      if (original === undefined) delete process.env.HOME
      else process.env.HOME = original
    }
  })
})
