import { describe, expect, it } from 'vitest'
import {
  redactSensitiveBody,
  redactAndCollectKeys,
  redactRawParams,
  truncateString,
  summarizeMultipartBody,
} from '../src/utils/redact.js'
import { createHash } from 'node:crypto'

describe('redactSensitiveBody', () => {
  it('masks default sensitive keys', () => {
    const result = redactSensitiveBody({
      command: 'curl -H "Authorization: Bearer token"',
      api_key: 'super-secret',
      password: 'hunter2',
      nested: { secret: 'hidden' },
    })
    expect(result.api_key).toBe('***')
    expect(result.password).toBe('***')
    expect(result.nested).toEqual({ secret: '***' })
    expect(result.command).toContain('Authorization: Bearer token')
  })

  it('uses custom patterns', () => {
    const result = redactSensitiveBody({ customSecret: 'x', public: 'y' }, ['custom'])
    expect(result.customSecret).toBe('***')
    expect(result.public).toBe('y')
  })

  it('handles non-objects gracefully', () => {
    expect(redactSensitiveBody(null as any)).toBe(null)
    expect(redactSensitiveBody('string' as any)).toBe('string')
  })
})

describe('truncateString', () => {
  it('leaves short strings unchanged', () => {
    expect(truncateString('hello', 10)).toBe('hello')
  })

  it('truncates long strings', () => {
    expect(truncateString('hello world', 5)).toBe('hello...')
  })
})

describe('redactRawParams', () => {
  const sample = JSON.stringify({
    command: 'curl -H "Authorization: Bearer abc123" https://api.example.com',
    api_key: 'super-secret',
    nested: { password: 'hunter2', public: 'visible' },
  })
  const sampleHash = createHash('sha256').update(sample, 'utf8').digest('hex')
  const sampleSize = Buffer.byteLength(sample, 'utf8')

  it('masks default sensitive keys by default (enabled:true)', () => {
    const out = redactRawParams(sample)
    expect(out.redacted).toBe(true)
    // KEY-BASED redaction — values keyed by api_key / password / token /
    // authorization / etc. are masked. Values inside non-sensitive keys
    // (e.g. a `command` string with a Bearer token) are NOT scanned;
    // value-pattern scanning is a future extension.
    expect(out.value).not.toContain('super-secret')
    expect(out.value).not.toContain('hunter2')
    expect(out.value).toContain('"api_key":"***"')
    expect(out.value).toContain('"password":"***"')
    expect(out.value).toContain('"public":"visible"') // non-sensitive value preserved
  })

  it('hash + size survive redaction (for事后对账)', () => {
    const out = redactRawParams(sample)
    expect(out.hash).toBe(sampleHash)
    expect(out.size).toBe(sampleSize)
  })

  it('hash is stable across runs (sha256 hex, deterministic)', () => {
    const a = redactRawParams(sample)
    const b = redactRawParams(sample)
    expect(a.hash).toBe(b.hash)
    expect(a.hash).toMatch(/^[0-9a-f]{64}$/)
  })

  it('enabled:false preserves plaintext verbatim', () => {
    const out = redactRawParams(sample, { enabled: false })
    expect(out.redacted).toBe(false)
    expect(out.value).toBe(sample)
    expect(out.hash).toBe(sampleHash)
    expect(out.size).toBe(sampleSize)
  })

  it('JSON.parse failure returns empty value but keeps hash + size (no leak)', () => {
    const broken = '{"command":"curl", oops'
    const out = redactRawParams(broken)
    expect(out.redacted).toBe(true)
    expect(out.value).toBe('') // never echo back the broken plaintext
    expect(out.hash).toBe(createHash('sha256').update(broken, 'utf8').digest('hex'))
    expect(out.size).toBe(Buffer.byteLength(broken, 'utf8'))
  })

  it('non-object root (array / scalar / null) returns empty value, no leak', () => {
    const arr = '[1,2,3]'
    const out1 = redactRawParams(arr)
    expect(out1.redacted).toBe(true)
    expect(out1.value).toBe('')
    expect(out1.hash).toBe(createHash('sha256').update(arr, 'utf8').digest('hex'))

    const scalar = 'plain-string'
    const out2 = redactRawParams(scalar)
    expect(out2.redacted).toBe(true)
    expect(out2.value).toBe('')

    const nullStr = 'null'
    const out3 = redactRawParams(nullStr)
    expect(out3.redacted).toBe(true)
    expect(out3.value).toBe('')
  })

  it('empty / undefined / null input is safe (no crash, redacted:true)', () => {
    expect(redactRawParams('').redacted).toBe(true)
    expect(redactRawParams('').value).toBe('')
    expect(redactRawParams('').hash).toBe(
      createHash('sha256').update('', 'utf8').digest('hex'),
    )
    expect(redactRawParams(undefined).redacted).toBe(true)
    expect(redactRawParams(null).redacted).toBe(true)
    expect(redactRawParams(null).size).toBe(0)
  })

  it('custom patterns extend the default set', () => {
    const out = redactRawParams(
      JSON.stringify({ api_key: 'k', customSecret: 'x', public: 'p' }),
      { enabled: true, patterns: ['custom'] },
    )
    expect(out.value).toContain('"api_key":"***"') // default still fires
    expect(out.value).toContain('"customSecret":"***"') // custom too
    expect(out.value).toContain('"public":"p"')
  })

  it('JSON.stringify output round-trips through JSON.parse (redacted value is valid JSON)', () => {
    const out = redactRawParams(sample)
    expect(() => JSON.parse(out.value)).not.toThrow()
  })

  it('redactedKeys lists dotted-path keys that were masked', () => {
    const out = redactRawParams(
      JSON.stringify({
        command: 'curl',
        api_key: 'k',
        headers: { authorization: 'Bearer x', accept: 'json' },
        nested: { password: 'p', public: 'ok' },
      }),
    )
    expect(out.redacted).toBe(true)
    expect(out.redactedKeys).toEqual([
      'api_key',
      'headers.authorization',
      'nested.password',
    ])
    // Values still masked, even though we now also report the keys
    expect(out.value).not.toContain('super-secret')
    expect(out.value).not.toContain('Bearer x')
  })

  it('redactedKeys is empty when nothing matched', () => {
    const out = redactRawParams(JSON.stringify({ command: 'ls', public: 'ok' }))
    expect(out.redacted).toBe(true)
    expect(out.redactedKeys).toEqual([])
  })
})

describe('redactAndCollectKeys', () => {
  it('returns the same masked body as redactSensitiveBody', () => {
    const input = { api_key: 'k', public: 'p', nested: { token: 't' } }
    const baseline = redactSensitiveBody(input)
    const { result } = redactAndCollectKeys(input)
    expect(result).toEqual(baseline)
  })

  it('returns dotted-path keys, sorted + deduplicated', () => {
    const { redactedKeys } = redactAndCollectKeys({
      api_key: 'k1',
      zzz_password: 'k2',
      headers: { authorization: 'Bearer x', accept: 'json' },
      // same key hit twice in the tree — still one entry
      mirror: { api_key: 'k3' },
    })
    expect(redactedKeys).toEqual([
      'api_key', // dedup — also hit under `mirror`
      'headers.authorization',
      'mirror.api_key',
      'zzz_password',
    ])
  })

  it('returns empty array when no keys match', () => {
    const { redactedKeys } = redactAndCollectKeys({ command: 'ls', public: 'ok' })
    expect(redactedKeys).toEqual([])
  })

  it('handles non-object input gracefully', () => {
    const { result, redactedKeys } = redactAndCollectKeys(null as any)
    expect(result).toBe(null)
    expect(redactedKeys).toEqual([])
  })
})

// E2-7 : progressive multipart/form-data summary tests.
// The helper walks FormData.entries() with bounded Blob reads so a
// 50-MiB upload writes a small audit row, not 50 MiB to NDJSON.
describe('summarizeMultipartBody ( E2-7)', () => {
  it('summarises a text-only FormData', async () => {
    const fd = new FormData()
    fd.set('username', 'alice')
    fd.set('comment', 'hello world')
    const summary = await summarizeMultipartBody(fd)
    expect(summary.kind).toBe('multipart_summary')
    expect(summary.field_count).toBe(2)
    expect(summary.blob_count).toBe(0)
    expect(summary.blob_truncated_count).toBe(0)
    expect(summary.original_size).toBe(Buffer.byteLength('alice', 'utf8') + Buffer.byteLength('hello world', 'utf8'))
    expect(summary.fields).toEqual([
      { name: 'username', kind: 'text', value: 'alice', truncated: false, original_length: 5 },
      { name: 'comment', kind: 'text', value: 'hello world', truncated: false, original_length: 11 },
    ])
  })

  it('truncates a long text field with the preview budget', async () => {
    const fd = new FormData()
    const long = 'x'.repeat(8000)
    fd.set('payload', long)
    const summary = await summarizeMultipartBody(fd, { previewBytes: 1024 })
    expect(summary.field_count).toBe(1)
    const field = summary.fields[0]!
    expect(field.kind).toBe('text')
    expect(field.original_length).toBe(8000)
    expect(field.truncated).toBe(true)
    if (field.kind === 'text') {
      expect(field.value.length).toBeLessThan(8000)
      expect(field.value.endsWith('…[truncated]')).toBe(true)
    }
  })

  it('summarises a Blob field without reading full bytes', async () => {
    const fd = new FormData()
    const blob = new Blob(['hello'.repeat(20)], { type: 'text/plain' })
    fd.set('attachment', blob)
    const summary = await summarizeMultipartBody(fd)
    expect(summary.blob_count).toBe(1)
    expect(summary.original_size).toBe(100)
    const field = summary.fields[0]!
    expect(field.kind).toBe('blob')
    if (field.kind === 'blob') {
      expect(field.content_type).toBe('text/plain')
      // `size` is the captured (preview) size; `original_size` is the full
      // blob size. For a 100-byte blob under the 4 KiB default preview
      // budget, the field is not truncated and `original_size === size`.
      expect(field.original_size).toBe(100)
      expect(field.size).toBe(100)
      expect(field.truncated).toBe(false)
      expect(field.preview.length).toBeGreaterThan(0)
      expect(field.preview.startsWith('hellohello')).toBe(true)
    }
  })

  it('truncates an oversized Blob and records original_size + truncated flag', async () => {
    const fd = new FormData()
    const big = new Blob(['A'.repeat(8192)])
    fd.set('big', big)
    const summary = await summarizeMultipartBody(fd, { previewBytes: 256 })
    expect(summary.blob_count).toBe(1)
    expect(summary.blob_truncated_count).toBe(1)
    const field = summary.fields[0]!
    if (field.kind === 'blob') {
      expect(field.original_size).toBe(8192)
      expect(field.truncated).toBe(true)
      expect(field.preview.length).toBeLessThanOrEqual(256)
    }
  })

  it('captures File.filename when the Blob is a File', async () => {
    const fd = new FormData()
    const file = new File(['content'], 'report.pdf', { type: 'application/pdf' })
    fd.set('document', file)
    const summary = await summarizeMultipartBody(fd)
    const field = summary.fields[0]!
    if (field.kind === 'blob') {
      expect(field.filename).toBe('report.pdf')
      expect(field.content_type).toBe('application/pdf')
    }
  })

  it('falls back to application/octet-stream when content-type is missing', async () => {
    const fd = new FormData()
    const blob = new Blob(['x'])
    fd.set('data', blob)
    const summary = await summarizeMultipartBody(fd)
    const field = summary.fields[0]!
    if (field.kind === 'blob') {
      expect(field.content_type).toBe('application/octet-stream')
    }
  })

  it('handles an empty FormData', async () => {
    const fd = new FormData()
    const summary = await summarizeMultipartBody(fd)
    expect(summary.field_count).toBe(0)
    expect(summary.blob_count).toBe(0)
    expect(summary.original_size).toBe(0)
  })

  it('mixes text and blob fields correctly', async () => {
    const fd = new FormData()
    fd.set('name', 'bob')
    fd.set('avatar', new Blob(['img'], { type: 'image/png' }))
    fd.set('bio', 'short bio')
    const summary = await summarizeMultipartBody(fd)
    expect(summary.field_count).toBe(3)
    expect(summary.blob_count).toBe(1)
    expect(summary.fields.map((f) => f.name)).toEqual(['name', 'avatar', 'bio'])
    expect(summary.fields[0]!.kind).toBe('text')
    expect(summary.fields[1]!.kind).toBe('blob')
    expect(summary.fields[2]!.kind).toBe('text')
  })

  it('produces JSON-serialisable output', async () => {
    const fd = new FormData()
    fd.set('username', 'alice')
    fd.set('file', new File(['data'], 'x.bin'))
    const summary = await summarizeMultipartBody(fd)
    // Round-trip through JSON.stringify — no functions, no Symbols, no BigInts.
    const json = JSON.stringify(summary)
    const parsed = JSON.parse(json)
    expect(parsed.kind).toBe('multipart_summary')
    expect(parsed.field_count).toBe(2)
  })

  it('uses default previewBytes of 4 KiB when not specified', async () => {
    const fd = new FormData()
    // 6 KiB blob should be truncated by the default 4 KiB budget.
    const big = new Blob(['B'.repeat(6 * 1024)])
    fd.set('upload', big)
    const summary = await summarizeMultipartBody(fd)
    expect(summary.blob_truncated_count).toBe(1)
    const field = summary.fields[0]!
    if (field.kind === 'blob') {
      expect(field.original_size).toBe(6 * 1024)
      expect(field.size).toBe(4 * 1024)
    }
  })

  it('reports original_size as the sum of all fields', async () => {
    const fd = new FormData()
    fd.set('text', 'hello') // 5
    fd.set('blob', new Blob(['world'])) // 5
    fd.set('big', new Blob(['x'.repeat(100)])) // 100
    const summary = await summarizeMultipartBody(fd)
    expect(summary.original_size).toBe(5 + 5 + 100)
  })
})
