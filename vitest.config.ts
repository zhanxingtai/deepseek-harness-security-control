import { defineConfig } from 'vitest/config'

/**
 * 2026-09-18 S12 (#6): the client half ships `.tsx` test files that
 * need a DOM (React + happy-dom). The host tests stay on `node`
 * (no DOM). We use `environmentMatchGlobs` to route:
 *   - `tests/client/**` → `happy-dom`
 *   - everything else  → `node`
 *
 * The host config (single environment, single include) is preserved
 * for non-client tests; the client tests opt in via path. The
 * esbuild `jsx: 'automatic'` setting matches `tsconfig.client.json`
 * (`jsx: react-jsx`) so .tsx test files compile without an explicit
 * `import React from 'react'` line in every test.
 */
export default defineConfig({
  esbuild: {
    jsx: 'automatic',
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.{ts,tsx}'],
    environmentMatchGlobs: [['tests/client/**', 'happy-dom']],
  },
})
