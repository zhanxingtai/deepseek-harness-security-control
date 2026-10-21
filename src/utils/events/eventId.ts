import { randomUUID } from 'node:crypto'

export function generateEventId(): string {
  return `evt-${randomUUID()}`
}
