/**
 * Small content-hashing helpers used to populate the `hash` field on
 * application-layer security events. MD5 is used here for fingerprinting
 * (not security) — collisions do not matter when the goal is "did the same
 * content appear twice" / "did this file change".
 */

import { createHash } from 'node:crypto'

/** Hex MD5 of a UTF-8 string. Empty input → `d41d8cd98f00b204e9800998ecf8427e`. */
export function md5Hex(content: string): string {
  return createHash('md5').update(content, 'utf8').digest('hex')
}

/**
 * Pull the most-likely "content" string out of a tool's argument bag. Used
 * for write-class events: the auditor wants to fingerprint what was
 * supposed to be written, not the wrapping argument object.
 *
 * Tries common field aliases in priority order: `content`, `data`, `body`,
 * `text`, `value`, then falls back to the JSON-stringified full args.
 *
 * Returns `undefined` when the args bag is missing or has no string
 * candidate. Hashing an empty input is fine (stable empty-string MD5) but
 * semantically uninteresting, so callers should check for undefined.
 */
export function extractContentString(args: Record<string, unknown> | undefined): string | undefined {
  if (!args) return undefined
  const candidates = ['content', 'data', 'body', 'text', 'value', 'script', 'code', 'source']
  for (const key of candidates) {
    const v = args[key]
    if (typeof v === 'string') return v
  }
  return undefined
}