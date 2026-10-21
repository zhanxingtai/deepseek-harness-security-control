import { AsyncLocalStorage } from 'node:async_hooks'

/**
 * Lightweight session snapshot stored in AsyncLocalStorage while a Cordis
 * event handler is running. NetworkHttpCollector reads this store to correlate
 * outbound HTTP requests with the current agent session / tool invocation.
 */
export interface HttpRequestSessionContext {
  sessionId: string
  runId: string
  agentId?: string
  /** Populated when the HTTP request is made inside a tool execution. */
  toolCallId?: string
}

/**
 * AsyncLocalStorage used to propagate session context through the harness's
 * async handler chain. ApplicationCollector writes the store; NetworkHttpCollector
 * reads it. If the store is empty (e.g. a background periodic HTTP call), the
 * collector falls back to the most-recent session resolver.
 */
export const httpRequestContext = new AsyncLocalStorage<HttpRequestSessionContext>()

export function getHttpRequestSessionContext(): HttpRequestSessionContext | undefined {
  return httpRequestContext.getStore()
}
