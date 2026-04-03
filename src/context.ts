import { AsyncLocalStorage } from 'async_hooks';
import type { CapturedContext } from './types';

/**
 * D4 FIX: Per-request AsyncLocalStorage context store.
 *
 * Storing per-request context (IP, user-agent, etc.) on the shared singleton
 * SOCWardenClient instance causes concurrent requests to contaminate each
 * other's context. AsyncLocalStorage provides automatic isolation: each
 * request runs in its own async context and getStore() always returns the
 * correct context for the current request, even under high concurrency.
 */
export const requestContextStorage = new AsyncLocalStorage<CapturedContext>();
