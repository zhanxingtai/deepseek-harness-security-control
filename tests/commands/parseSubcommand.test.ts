/**
 * Tests for the /security subcommand parser.
 *
 * Coverage:
 *  - empty input defaults to `status`
 *  - whitespace-only input defaults to `status`
 *  - bare subcommand names (`status`, `rules`, `reload`) parse to a
 *    no-arg call
 *  - `recent N` parses N as a string arg; `recent` alone parses to
 *    no args (the handler applies the default)
 *  - leading / trailing whitespace is trimmed
 *  - multiple internal spaces collapse
 *  - case sensitivity: `STATUS` is NOT `status` — keep the parser
 *    strict so operators don't accidentally hit the unknown branch
 */
import { describe, expect, it } from 'vitest'
import { parseSubcommand } from '../../src/commands/security.js'

describe('parseSubcommand', () => {
  it('returns status for empty input', () => {
    expect(parseSubcommand('')).toEqual({ cmd: 'status', args: [] })
  })

  it('returns status for whitespace-only input', () => {
    expect(parseSubcommand('   ')).toEqual({ cmd: 'status', args: [] })
    expect(parseSubcommand('\t\t')).toEqual({ cmd: 'status', args: [] })
  })

  it('parses a bare subcommand name', () => {
    expect(parseSubcommand('status')).toEqual({ cmd: 'status', args: [] })
    expect(parseSubcommand('rules')).toEqual({ cmd: 'rules', args: [] })
    expect(parseSubcommand('reload')).toEqual({ cmd: 'reload', args: [] })
  })

  it('parses `recent N` with N as the first arg', () => {
    expect(parseSubcommand('recent 50')).toEqual({ cmd: 'recent', args: ['50'] })
    expect(parseSubcommand('recent 1')).toEqual({ cmd: 'recent', args: ['1'] })
    expect(parseSubcommand('recent 500')).toEqual({ cmd: 'recent', args: ['500'] })
  })

  it('parses `recent` with no args', () => {
    expect(parseSubcommand('recent')).toEqual({ cmd: 'recent', args: [] })
  })

  it('trims leading and trailing whitespace', () => {
    expect(parseSubcommand('   status   ')).toEqual({ cmd: 'status', args: [] })
    expect(parseSubcommand('\treload\n')).toEqual({ cmd: 'reload', args: [] })
  })

  it('collapses multiple internal whitespace separators', () => {
    expect(parseSubcommand('recent    100')).toEqual({ cmd: 'recent', args: ['100'] })
    expect(parseSubcommand('recent\t50')).toEqual({ cmd: 'recent', args: ['50'] })
  })

  it('treats unknown commands as the literal token (handler decides)', () => {
    // The handler is the one that maps unknown subcommands to an error
    // result; the parser is intentionally dumb and just tokenizes.
    expect(parseSubcommand('frobnicate')).toEqual({ cmd: 'frobnicate', args: [] })
    expect(parseSubcommand('recent abc')).toEqual({ cmd: 'recent', args: ['abc'] })
  })

  it('is case-sensitive (status != STATUS)', () => {
    expect(parseSubcommand('STATUS')).toEqual({ cmd: 'STATUS', args: [] })
    expect(parseSubcommand('Status')).toEqual({ cmd: 'Status', args: [] })
  })

  it('drops empty tokens from consecutive whitespace', () => {
    expect(parseSubcommand('  recent   10  ')).toEqual({ cmd: 'recent', args: ['10'] })
  })
})
