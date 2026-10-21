/**
 * Payload size limit tests.
 */
import { describe, expect, it } from 'vitest'
import { limitPayloadSize, DEFAULT_PAYLOAD_MAX_BYTES, truncateString } from '../src/utils/redact.js'

describe('limitPayloadSize', () => {
  it('passes through small strings unchanged', () => {
    const r = limitPayloadSize('hello', 1024)
    expect(r.value).toBe('hello')
    expect(r.truncated).toBe(false)
    expect(r.originalLength).toBe(5)
  })

  it('truncates strings that exceed the cap', () => {
    const big = 'x'.repeat(2048)
    const r = limitPayloadSize(big, 100)
    expect(r.truncated).toBe(true)
    expect(r.originalLength).toBe(2048)
    // Stored value is within the cap (with a small suffix).
    expect(Buffer.byteLength(r.value as string, 'utf8')).toBeLessThanOrEqual(100)
  })

  it('handles multi-byte UTF-8 characters at the boundary', () => {
    // Each emoji is 4 bytes; pack them so the cap falls in the middle.
    const emojis = '🚀'.repeat(200) // 800 bytes
    const r = limitPayloadSize(emojis, 100)
    expect(r.truncated).toBe(true)
    // Stored value is within the cap (no broken char at the cut).
    expect(Buffer.byteLength(r.value as string, 'utf8')).toBeLessThanOrEqual(100)
  })

  it('handles empty / undefined values', () => {
    expect(limitPayloadSize('', 100).truncated).toBe(false)
    expect(limitPayloadSize(undefined as any, 100).truncated).toBe(false)
    expect(limitPayloadSize(null as any, 100).truncated).toBe(false)
  })

  it('default cap is 1 MiB', () => {
    expect(DEFAULT_PAYLOAD_MAX_BYTES).toBe(1024 * 1024)
  })

  it('accepts a custom suffix', () => {
    const r = limitPayloadSize('x'.repeat(100), 20, { suffix: '…' })
    expect(r.value).toContain('…')
  })

  it('preserves the original byte length for audit', () => {
    const r = limitPayloadSize('a'.repeat(10000), 50)
    expect(r.originalLength).toBe(10000)
  })

  it('truncateString still works (no regression)', () => {
    expect(truncateString('hello world', 5)).toBe('hello...')
    expect(truncateString('hi', 5)).toBe('hi')
    expect(truncateString('', 5)).toBe('')
  })
})
