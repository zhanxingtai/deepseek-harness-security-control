/**
 * Safe extraction utilities for values that may be missing or have unexpected
 * shapes.
 */

export function safeExtractString(value: unknown, defaultValue = ''): string {
  if (typeof value === 'string') return value
  return defaultValue
}

export function safeExtractRecord(
  value: unknown,
  defaultValue: Record<string, unknown> = {},
): Record<string, unknown> {
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>
  }
  return defaultValue
}