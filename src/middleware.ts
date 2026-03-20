import type { SOCWardenClient } from './client';
import type { CapturedContext } from './types';

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
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction): void => {
    const queryString = buildQueryString(req.query);

    const capturedContext: CapturedContext = {
      request: {
        method: req.method,
        path: req.path,
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

    // Merge browser context from X-SOCWarden-Context header (sent by browser SDK relay mode)
    const browserContextHeader = req.get('x-socwarden-context');
    if (browserContextHeader) {
      try {
        const decoded = JSON.parse(
          Buffer.from(browserContextHeader, 'base64').toString('utf-8'),
        );
        if (typeof decoded === 'object' && decoded !== null) {
          capturedContext.browser = decoded;
        }
      } catch {
        // Malformed header — ignore silently
      }
    }

    client.setContext(capturedContext);

    // Clear context when the response finishes to avoid leaking between requests
    res.on('finish', () => {
      client.clearContext();
    });

    next();
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
