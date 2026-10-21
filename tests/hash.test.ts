import { describe, expect, it } from 'vitest'
import { extractContentString, md5Hex } from '../src/utils/hash.js'

describe('md5Hex', () => {
  it('hashes a known string', () => {
    // Standard MD5 of "hello" — confirms the algorithm and encoding.
    expect(md5Hex('hello')).toBe('5d41402abc4b2a76b9719d911017c592')
  })

  it('hashes empty string to the canonical empty-input digest', () => {
    expect(md5Hex('')).toBe('d41d8cd98f00b204e9800998ecf8427e')
  })

  it('returns the same hash for the same input', () => {
    expect(md5Hex('content-X')).toBe(md5Hex('content-X'))
  })

  it('returns different hashes for different inputs', () => {
    expect(md5Hex('a')).not.toBe(md5Hex('b'))
  })
})

describe('extractContentString', () => {
  it('returns the content field when present', () => {
    expect(extractContentString({ content: 'hello' })).toBe('hello')
  })

  it('tries aliases in priority order', () => {
    expect(extractContentString({ data: 'd' })).toBe('d')
    expect(extractContentString({ body: 'b' })).toBe('b')
    expect(extractContentString({ text: 't' })).toBe('t')
    expect(extractContentString({ value: 'v' })).toBe('v')
    expect(extractContentString({ script: 's' })).toBe('s')
    expect(extractContentString({ code: 'c' })).toBe('c')
    expect(extractContentString({ source: 'sr' })).toBe('sr')
  })

  it('prefers content over later aliases', () => {
    expect(extractContentString({ content: 'first', data: 'second' })).toBe('first')
  })

  it('returns undefined when no string candidate is present', () => {
    expect(extractContentString({ path: '/tmp/x', mode: 'w' })).toBeUndefined()
    expect(extractContentString({})).toBeUndefined()
  })

  it('returns undefined for non-string candidates', () => {
    // Number / boolean / object should not be mistaken for content.
    expect(extractContentString({ content: 123 as unknown as string })).toBeUndefined()
    expect(extractContentString({ content: true as unknown as string })).toBeUndefined()
    expect(extractContentString({ content: { nested: 'x' } as unknown as string })).toBeUndefined()
  })

  it('returns undefined for missing args', () => {
    expect(extractContentString(undefined)).toBeUndefined()
  })
})