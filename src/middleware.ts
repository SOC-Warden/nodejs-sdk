import type { SOCWardenClient } from './client';
import { requestContextStorage } from './context';
import type { CapturedContext } from './types';
export { requestContextStorage } from './context';

/**
 * Minimal Express-compatible request interface.
 * Avoids requiring Express as a dependency.
 */
interface ExpressRequest {
  method: string;
  path: string;
  ip?: string;
  query?: Record<string, unknown>;
  get(header: string): string | undefined;
}

/**
 * Minimal Express-compatible response interface.
 */
interface ExpressResponse {
  on(event: string, listener: () => void): void;
}

/**
 * Minimal Express-compatible next function.
 */
type NextFunction = (err?: unknown) => void;

/**
 * Express middleware that captures request context for SOCWarden events.
 *
 * When active, every event sent during the request lifecycle will automatically
 * include request metadata (method, path, IP, user-agent, etc.) in the
 * `context` field of the payload.
 *
 * ```ts
 * import express from 'express';
 * import { SOCWardenClient, socwardenMiddleware } from '@socwarden/sdk';
 *
 * const soc = new SOCWardenClient({ apiKey: 'sk_live_...' });
 * const app = express();
 *
 * app.use(socwardenMiddleware(soc));
 * ```
 */
export function socwardenMiddleware(client: SOCWardenClient) {
  // D4 FIX: client parameter retained for API compatibility but context is now
  // stored in AsyncLocalStorage instead of on the shared singleton instance,
  // preventing concurrent request context contamination.
  void client;

  return (req: ExpressRequest, _res: ExpressResponse, next: NextFunction): void => {
    const queryString = buildQueryString(req.query);

    const capturedContext: CapturedContext = {
      request: {
        method: req.method,
        path: req.path,
        // SEC-NOTE (M4 — IP Spoofing): req.ip is Express's pre-trusted value (set by the
      // framework after applying the `trust proxy` setting). When req.ip is absent we fall
      // back to the first value in X-Forwarded-For, which is client-controlled and can be
      // spoofed. Applications MUST configure `app.set('trust proxy', N)` (where N is the
      // number of trusted proxy hops) so that Express populates req.ip from the correct
      // hop rather than from the raw client socket. The SDK sanitizes the final IP value
      // via sanitizeIP() to reject non-IP strings, but it cannot prevent a client from
      // supplying a valid-looking but wrong IP when no trusted-proxy config is in place.
      ip: req.ip ?? req.get('x-forwarded-for')?.split(',')[0].trim(),
        userAgent: req.get('user-agent'),
        queryString,
        referer: req.get('referer'),
        origin: req.get('origin'),
        contentType: req.get('content-type'),
        acceptLanguage: req.get('accept-language'),
        requestId: req.get('x-request-id') ?? req.get('x-correlation-id'),
      },
      sdk: {
        name: 'socwarden-node',
        version: '1.0.0',
      },
    };

    // D1 FIX: X-SOCWarden-Context header removed — trusting arbitrary HTTP headers
    // allows any client to spoof server-side metadata. Server context is collected
    // locally by the SDK and must not be merged from incoming request headers.

    // D4 FIX: Run the rest of the request handling within the AsyncLocalStorage
    // context so each concurrent request has its own isolated context.
    requestContextStorage.run(capturedContext, next);
  };
}

/**
 * Reconstruct a query string from Express's parsed query object.
 */
function buildQueryString(query?: Record<string, unknown>): string | undefined {
  if (!query) return undefined;

  const entries = Object.entries(query).filter(
    ([, v]) => v !== undefined && v !== null,
  );
  if (entries.length === 0) return undefined;

  return entries
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join('&');
}
