/**
 * Escape every regex metacharacter in `text` so the result can be safely
 * embedded in a `new RegExp(...)` constructor or concatenated into a
 * larger pattern (e.g. `^prefix(?:.*)?$`) without becoming a backreference
 * or quantifier.
 *
 * this helper lived as a private copy
 * in both `RuleLoader.ts` and `SensitivePathGuard.ts` — duplicated
 * implementations have identical bodies (12 chars of regex character
 * class + replacement string). Centralising here keeps the two callers
 * in lock-step if the escape set ever grows (e.g. to escape the new
 * `\p{...}` Unicode property syntax that ES2018+ supports).
 */
export function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}