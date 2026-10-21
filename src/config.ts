/**
 * Config barrel — re-exports the type declarations, default constants,
 * and `normalizeConfig` entry from the three submodules
 * (`config/types.ts`, `config/defaults.ts`, `config/normalize.ts`).
 *
 * Layout:
 *   - `src/config/types.ts`     — every `interface` declaration
 *   - `src/config/defaults.ts`  — DEFAULTS_* constants + FALLBACK lists
 *   - `src/config/normalize.ts` — `withDefaults` + `normalizeConfig`
 *
 * `src/config/livePatch.ts`, `src/config/validate.ts`, `src/config/draft.ts`
 * stay as separate concerns (config mutation lifecycle + draft-file I/O
 * + patch validator) — they each import from this barrel.
 */

export * from './config/types.js'
export * from './config/defaults.js'
export * from './config/normalize.js'