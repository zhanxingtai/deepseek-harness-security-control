/**
 * Tests for the stdio-mirror value-pattern + argv-entry redactors
 *Covers the documented credential families and
 * the JSON-parse / argv-shape branches.
 *
 * The tests assert both the redacted VALUE (string substitution lands
 * the credential-shaped substring in `***`) and the redactedKeys
 * side-channel (audit rows name the family without exposing the value).
 */
import { describe, expect, it } from 'vitest'
import {
  redactStreamContent,
  redactArgvEntries,
  redactUrlQueryString,
  redactHttpBody,
} from '../src/utils/contentRedactor.js'

describe('redactStreamContent — JSON parse + KEY-based', () => {
  it('redacts a top-level sensitive key in a JSON object', () => {
    const r = redactStreamContent(JSON.stringify({ user: 'alice', token: 'ghp_abc123456789012345678' }))
    expect(r.value).toContain('"user":"alice"')
    expect(r.value).toContain('"token":"***"')
    expect(r.value).not.toContain('ghp_abc123456789012345678')
    expect(r.redactedKeys).toContain('token')
  })

  it('walks nested keys with dot-path redactedKeys', () => {
    const r = redactStreamContent(
      JSON.stringify({ headers: { Authorization: 'Bearer eyJabc.xyz123456789' } }),
    )
    expect(r.value).toContain('"Authorization":"***"')
    expect(r.redactedKeys).toContain('headers.Authorization')
  })

  it('walks arrays of objects', () => {
    const r = redactStreamContent(
      JSON.stringify([
        { name: 'auth', value: 'AKIAABCDEFGHIJKLMNOP' },
        { name: 'data', value: 'plain' },
      ]),
    )
    expect(r.value).toContain('"name":"auth"')
    expect(r.value).toContain('"value":"***"')
    expect(r.value).toContain('"name":"data"')
    expect(r.value).toContain('"value":"plain"')
    expect(r.redactedKeys.some((k) => k.startsWith('0.value'))).toBe(true)
  })

  it('redacts camelCase / snake_case / kebab-case matches', () => {
    for (const k of ['apiKey', 'api_key', 'api-key', 'APIKEY', 'apikey']) {
      const r = redactStreamContent(JSON.stringify({ [k]: 'ghp_abc123456789012345678' }))
      expect(r.value).toContain('"***"')
      expect(r.value).not.toContain('ghp_abc123456789012345678')
    }
  })

  it('does not redact non-sensitive keys', () => {
    const r = redactStreamContent(JSON.stringify({ user: 'alice', action: 'login' }))
    expect(r.value).toBe('{"user":"alice","action":"login"}')
    expect(r.redactedKeys).toEqual([])
  })
})

describe('redactStreamContent — value-pattern', () => {
  it('redacts Bearer tokens', () => {
    const r = redactStreamContent('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc')
    expect(r.value).toContain('Bearer ***')
    expect(r.value).not.toContain('eyJhbGciOiJIUzI1NiJ9')
    expect(r.redactedKeys).toContain('bearer_token')
  })

  it('redacts Basic auth', () => {
    const r = redactStreamContent('WWW-Authenticate: Basic YWxhZGRpbjpvcGVuc2VzYW1l')
    expect(r.value).toContain('Basic ***')
    expect(r.redactedKeys).toContain('basic_auth')
  })

  it('redacts AWS access keys', () => {
    const r = redactStreamContent('aws_access_key_id=AKIAABCDEFGHIJKLMNOP')
    expect(r.value).toContain('***')
    expect(r.value).not.toContain('AKIAABCDEFGHIJKLMNOP')
    expect(r.redactedKeys).toContain('aws_access_key')
  })

  it('redacts AWS session keys (ASIA)', () => {
    const r = redactStreamContent('STS token: ASIAABCDEFGHIJKLMNOP')
    expect(r.value).not.toContain('ASIAABCDEFGHIJKLMNOP')
    expect(r.redactedKeys).toContain('aws_session_key')
  })

  it('redacts GitHub PAT (gh[pousr]_)', () => {
    for (const prefix of ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_']) {
      const r = redactStreamContent(`token=${prefix}${'a'.repeat(40)}`)
      expect(r.value).toContain('***')
      expect(r.value).not.toContain(`${prefix}${'a'.repeat(40)}`)
      expect(r.redactedKeys).toContain('github_pat')
    }
  })

  it('redacts Slack tokens', () => {
    const r = redactStreamContent('SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnop')
    expect(r.value).toContain('***')
    expect(r.value).not.toContain('xoxb-1234567890')
    expect(r.redactedKeys).toContain('slack_token')
  })

  it('redacts PEM private-key blocks (multi-line)', () => {
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEAxxxx',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n')
    const r = redactStreamContent(`key:\n${pem}\n# end`)
    expect(r.value).not.toContain('MIIEowIBAAKCAQEAxxxx')
    expect(r.value).toContain('***')
    expect(r.redactedKeys).toContain('pem_private_key')
  })

  it('redacts URL query-string secrets', () => {
    const r = redactStreamContent('GET https://api.example.com/v1/?token=secret123&user=alice')
    expect(r.value).toContain('token=***')
    expect(r.value).toContain('user=alice')
    expect(r.value).not.toContain('secret123')
    expect(r.redactedKeys).toContain('query.token')
  })

  it('redacts multiple URL query secrets at once', () => {
    const r = redactStreamContent(
      'https://api.example.com/?api_key=ak123&apikey=ak456&password=pw789',
    )
    expect(r.value).toContain('api_key=***')
    expect(r.value).toContain('apikey=***')
    expect(r.value).toContain('password=***')
    expect(r.value).not.toMatch(/ak123|ak456|pw789/)
    expect(r.redactedKeys).toEqual(
      expect.arrayContaining(['query.api_key', 'query.apikey', 'query.password']),
    )
  })

  it('returns sorted + deduplicated redactedKeys', () => {
    const r = redactStreamContent(
      'Bearer eyJabc.xyz123456789 Bearer eyJdef.uvw456789012',
    )
    expect(r.redactedKeys).toEqual(['bearer_token'])
  })

  it('returns empty redactedKeys for benign text', () => {
    const r = redactStreamContent('hello world\nthis is a normal log line\n')
    expect(r.value).toBe('hello world\nthis is a normal log line\n')
    expect(r.redactedKeys).toEqual([])
  })

  it('handles empty / non-string input safely', () => {
    expect(redactStreamContent('')).toEqual({ value: '', redactedKeys: [] })
  })
})

describe('redactStreamContent — JSON + value-pattern interplay', () => {
  it('redacts bearer token nested inside a JSON string value', () => {
    const r = redactStreamContent(
      JSON.stringify({ log: 'response had Bearer eyJabc.xyz123456789' }),
    )
    expect(r.value).not.toContain('eyJabc.xyz123456789')
    expect(r.redactedKeys.some((k) => k.includes('bearer_token'))).toBe(true)
  })
})

describe('redactArgvEntries', () => {
  it('redacts --key=value for sensitive keys', () => {
    const r = redactArgvEntries(['curl', '--token=ghp_abc123456789012345678', 'https://x'])
    expect(r.argv[0]).toBe('curl')
    expect(r.argv[1]).toBe('--token=***')
    expect(r.argv[2]).toBe('https://x')
    expect(r.redactedKeys).toContain('argv.token')
  })

  it('redacts KEY=value (env-var form, ALL_CAPS key)', () => {
    const r = redactArgvEntries(['bash', '-c', 'API_KEY=ghp_abc123456789012345678 run'])
    // The whole entry is a shell snippet — value-pattern catches it.
    expect(r.argv[0]).toBe('bash')
    expect(r.argv[2]).toContain('API_KEY=***')
    expect(r.argv[2]).not.toContain('ghp_abc123456789012345678')
    expect(r.redactedKeys.some((k) => k.startsWith('argv.API_KEY'))).toBe(true)
  })

  it('redacts Key: Value (header / INI form)', () => {
    const r = redactArgvEntries([
      'curl',
      '-H',
      'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc',
      'https://x',
    ])
    expect(r.argv[2]).toBe('Authorization: ***')
    expect(r.redactedKeys).toContain('argv.Authorization')
  })

  it('redacts value-pattern in a bare entry (Bearer without a key)', () => {
    const r = redactArgvEntries(['curl', 'Bearer eyJabc.xyz123456789'])
    expect(r.argv[1]).toContain('Bearer ***')
    expect(r.argv[1]).not.toContain('eyJabc.xyz123456789')
    expect(r.redactedKeys).toContain('argv.bearer_token')
  })

  it('preserves argv length and order', () => {
    const argv = ['npm', '--registry=https://r.example', '--token=ghp_x'.padEnd(40, 'y'), 'install']
    const r = redactArgvEntries(argv)
    expect(r.argv.length).toBe(argv.length)
    expect(r.argv[0]).toBe('npm')
    expect(r.argv[3]).toBe('install')
  })

  it('passes through non-sensitive argv unchanged', () => {
    const argv = ['echo', 'hello', 'world']
    const r = redactArgvEntries(argv)
    expect(r.argv).toEqual(argv)
    expect(r.redactedKeys).toEqual([])
  })

  it('handles empty / non-array input safely', () => {
    expect(redactArgvEntries([])).toEqual({ argv: [], redactedKeys: [] })
    // @ts-expect-error runtime safety against malformed input
    expect(redactArgvEntries(undefined)).toEqual({ argv: [], redactedKeys: [] })
  })

  it('redacts multi-segment key (api-key)', () => {
    const r = redactArgvEntries(['curl', '--api-key=AKIAABCDEFGHIJKLMNOP'])
    expect(r.argv[1]).toBe('--api-key=***')
    expect(r.redactedKeys).toContain('argv.api-key')
  })
})

describe('redactUrlQueryString', () => {
  it('redacts a sensitive query key in a full URL', () => {
    const r = redactUrlQueryString('https://api.example.com/v1?token=secret&model=foo')
    expect(r.value).toBe('https://api.example.com/v1?token=***&model=foo')
    expect(r.value).not.toContain('secret')
    expect(r.redactedKeys).toEqual(['query.token'])
  })

  it('redacts multiple sensitive keys in a relative path', () => {
    const r = redactUrlQueryString('/v1/users?token=xxx&api_key=yyy&sid=zzz&keep=vvv')
    expect(r.value).toBe('/v1/users?token=***&api_key=***&sid=***&keep=vvv')
    expect(r.value).not.toContain('xxx')
    expect(r.value).not.toContain('yyy')
    expect(r.value).not.toContain('zzz')
    expect(r.value).toContain('keep=vvv')
    expect(r.redactedKeys).toEqual(['query.api_key', 'query.sid', 'query.token'])
  })

  it('leaves benign URLs untouched (clean control)', () => {
    const r = redactUrlQueryString('https://api.example.com/v1?model=foo&temp=0.7')
    expect(r.value).toBe('https://api.example.com/v1?model=foo&temp=0.7')
    expect(r.redactedKeys).toEqual([])
  })

  it('preserves URL-encoded values in non-sensitive keys', () => {
    // URLSearchParams.toString() would re-encode `%20` → `+` and lose
    // fidelity; the in-place regex replacement must round-trip the
    // original encoding.
    const r = redactUrlQueryString('/api?token=secret&name=hello%20world')
    expect(r.value).toContain('name=hello%20world')
    expect(r.value).toContain('token=***')
    expect(r.redactedKeys).toEqual(['query.token'])
  })

  it('handles case-insensitive query keys', () => {
    const r = redactUrlQueryString('/api?TOKEN=secret&ApiKey=yyy')
    expect(r.value).not.toContain('secret')
    expect(r.value).not.toContain('yyy')
    expect(r.redactedKeys).toContain('query.token')
    expect(r.redactedKeys).toContain('query.apikey')
  })

  it('falls back to regex when URL parse fails', () => {
    // Trailing `&&` makes the URL invalid; the regex fallback still
    // catches the obvious shapes.
    const r = redactUrlQueryString('curl https://x?token=abc&&oauth=zzz')
    expect(r.value).toContain('token=***')
    // OAuth isn't in QUERY_SECRET_KEYS — fall-through is by design.
    expect(r.value).toContain('oauth=zzz')
    expect(r.redactedKeys).toEqual(['query.token'])
  })

  it('handles empty / non-string input safely', () => {
    expect(redactUrlQueryString('')).toEqual({ value: '', redactedKeys: [] })
    // @ts-expect-error runtime safety against malformed input
    expect(redactUrlQueryString(undefined)).toEqual({ value: '', redactedKeys: [] })
  })

  it('redacts `authorization` and `access_token` shapes', () => {
    const r = redactUrlQueryString('/api?authorization=Bearer%20xxx&access_token=yyy')
    expect(r.value).toContain('authorization=***')
    expect(r.value).toContain('access_token=***')
    expect(r.redactedKeys).toEqual(['query.access_token', 'query.authorization'])
  })
})

describe('redactHttpBody ( D4)', () => {
  describe('JSON path', () => {
    it('redacts sensitive keys in a JSON object body', () => {
      const r = redactHttpBody(JSON.stringify({ user: 'alice', token: 'xxx', api_key: 'yyy' }))
      expect(r.body).toContain('"user":"alice"')
      expect(r.body).toContain('"token":"***"')
      expect(r.body).toContain('"api_key":"***"')
      expect(r.redactedKeys).toEqual(['body.api_key', 'body.token'])
    })

    it('redacts nested JSON paths with dot-prefix', () => {
      const r = redactHttpBody(JSON.stringify({ headers: { Authorization: 'Bearer xxx' } }))
      expect(r.body).toContain('"Authorization":"***"')
      expect(r.redactedKeys).toContain('body.headers.Authorization')
    })

    it('handles malformed JSON by falling through to raw-text pass', () => {
      // `redactStreamContent` retries JSON internally, so the
      // value-pattern scanner fires on the inline `Bearer xxx`.
      const r = redactHttpBody('not-json-at-all Bearer xxx-12345')
      expect(r.body).not.toContain('xxx-12345')
      expect(r.redactedKeys).toContain('body.bearer_token')
    })
  })

  describe('form-urlencoded path', () => {
    it('redacts sensitive keys in a `application/x-www-form-urlencoded` body', () => {
      const r = redactHttpBody('token=secret-xyz&user=alice&password=hunter2')
      expect(r.body).toContain('token=***')
      expect(r.body).toContain('password=***')
      expect(r.body).toContain('user=alice')
      expect(r.body).not.toContain('secret-xyz')
      expect(r.body).not.toContain('hunter2')
      expect(r.redactedKeys).toEqual(['body.password', 'body.token'])
    })

    it('handles URL-encoded values inside form keys', () => {
      const r = redactHttpBody('token=abc%20def&name=hello%20world')
      expect(r.body).toContain('token=***')
      expect(r.body).toContain('name=hello+world') // URLSearchParams.toString() normalises %20 → +
      expect(r.redactedKeys).toEqual(['body.token'])
    })

    it('passes through benign form-urlencoded bodies verbatim', () => {
      const r = redactHttpBody('user=alice&age=30&city=sf')
      expect(r.body).toBe('user=alice&age=30&city=sf')
      expect(r.redactedKeys).toEqual([])
    })

    it('redacts multiple sensitive form keys (token + api_key + sid)', () => {
      const r = redactHttpBody('token=t1&api_key=k1&sid=s1&keep=v1')
      expect(r.body).not.toContain('t1')
      expect(r.body).not.toContain('k1')
      expect(r.body).not.toContain('s1')
      expect(r.body).toContain('keep=v1')
      expect(r.redactedKeys).toEqual(['body.api_key', 'body.sid', 'body.token'])
    })
  })

  describe('raw-text path', () => {
    it('redacts Bearer tokens in raw text', () => {
      const r = redactHttpBody('Authorization: Bearer abcdefghijklmnop')
      expect(r.body).not.toContain('abcdefghijklmnop')
      expect(r.body).toContain('Bearer ***')
      expect(r.redactedKeys).toEqual(['body.bearer_token'])
    })

    it('redacts AWS access keys in raw text', () => {
      const r = redactHttpBody('creds = "AKIAABCDEFGHIJKLMNOP"')
      expect(r.body).toContain('***')
      expect(r.body).not.toContain('AKIAABCDEFGHIJKLMNOP')
      expect(r.redactedKeys).toContain('body.aws_access_key')
    })

    it('redacts URL query-string secrets inside raw text (mixed log line)', () => {
      const r = redactHttpBody('GET https://api.example.com/v1?token=secret-zzz&keep=vvv')
      expect(r.body).toContain('token=***')
      expect(r.body).not.toContain('secret-zzz')
      expect(r.body).toContain('keep=vvv')
      expect(r.redactedKeys).toEqual(['body.query.token'])
    })

    it('passes through benign raw text verbatim', () => {
      const r = redactHttpBody('hello world from a normal agent')
      expect(r.body).toBe('hello world from a normal agent')
      expect(r.redactedKeys).toEqual([])
    })
  })

  describe('safety', () => {
    it('handles empty / non-string input safely', () => {
      expect(redactHttpBody('')).toEqual({ body: '', redactedKeys: [] })
      // @ts-expect-error runtime safety against malformed input
      expect(redactHttpBody(undefined)).toEqual({ body: '', redactedKeys: [] })
      // @ts-expect-error runtime safety against malformed input
      expect(redactHttpBody(null)).toEqual({ body: '', redactedKeys: [] })
    })

    it('falls through form-urlencoded-like-but-not input to raw-text pass', () => {
      // A single `=` without a key prefix doesn't match the form detector.
      // The raw-text path then catches URL-query-shaped `?token=xxx`.
      const r = redactHttpBody('?token=secret')
      expect(r.body).toContain('token=***')
      expect(r.redactedKeys).toEqual(['body.query.token'])
    })
  })
})
