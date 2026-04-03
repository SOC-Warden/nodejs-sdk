import { EventBuilder } from './builder';
import {
  EventPayload,
  RequestContext,
  SOCWardenOptions,
  TrackOptions,
} from './types';
import { hostname } from 'os';
import { requestContextStorage } from './context';

const SDK_NAME = 'socwarden-node';
const SDK_VERSION = '1.0.0';

const BACKOFF_DURATION = 3600; // 1 hour in seconds
const PROBE_INTERVAL = 300; // 5 minutes in seconds

const SENSITIVE_PARAMS = ['token', 'key', 'password', 'secret', 'code', 'auth', 'session', 'csrf'];

/**
 * Returns ip if it is a valid IPv4 or IPv6 address, otherwise undefined.
 * Matches the ingestor's validate:"omitempty,ip" constraint.
 */
function sanitizeIP(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  // IPv4
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4.test(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.every((p) => p >= 0 && p <= 255)) return ip;
  }
  // IPv6: contains colon and only hex digits and colons
  if (ip.includes(':') && /^[0-9a-fA-F:]+$/.test(ip)) return ip;
  return undefined;
}

export class SOCWardenClient {
  private readonly apiKey: string;
  private readonly endpoint: string;
  private readonly timeout: number;

  /** In-memory backoff state for 429 handling. */
  private backoffUntil: number = 0;
  private lastProbe: number = 0;

  // D4 FIX: Per-request context is now stored in AsyncLocalStorage (see middleware.ts)
  // rather than on the shared instance, preventing concurrent request contamination.

  constructor(options: SOCWardenOptions) {
    if (!options.apiKey) {
      throw new Error('[SOCWarden] apiKey is required');
    }

    this.apiKey = options.apiKey;
    this.endpoint = (options.endpoint ?? 'https://ingest.socwarden.io').replace(/\/+$/, '');
    this.timeout = options.timeout ?? 5000;

    // D2 FIX: Enforce HTTPS to prevent API key transmission in cleartext.
    if (!this.endpoint.startsWith('https://')) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('[SOCWarden] Endpoint must use HTTPS in production. API keys must not be transmitted in cleartext.');
      }
      console.warn('[SOCWarden] WARNING: Endpoint is using HTTP. API keys will be transmitted in cleartext.');
    }
  }

  // ---------------------------------------------------------------------------
  //  Public API
  // ---------------------------------------------------------------------------

  /**
   * Track a security event using named arguments.
   *
   * ```ts
   * await soc.track('auth.login.success', { actor: user.id });
   * await soc.track('data.exported', {
   *   actor: { id: user.id, email: user.email },
   *   metadata: { format: 'csv' },
   *   resource: { type: 'Report', id: report.id },
   * });
   * ```
   */
  async track(event: string, options?: TrackOptions): Promise<void> {
    const data = options ? this.resolveNamedArgs(options) : {};
    await this.dispatch(event, data);
  }

  /**
   * Track a security event using a raw data object.
   *
   * ```ts
   * await soc.trackData('auth.login.success', {
   *   actor_id: user.id,
   *   actor_email: user.email,
   *   metadata: { role: 'admin' },
   * });
   * ```
   */
  async trackData(event: string, data: Record<string, unknown> = {}): Promise<void> {
    await this.dispatch(event, data);
  }

  /**
   * Start building an event with the fluent API.
   *
   * ```ts
   * await soc.event('data.exported')
   *   .actor(user.id)
   *   .resource('Report', report.id)
   *   .meta('format', 'csv')
   *   .send();
   * ```
   */
  event(name: string): EventBuilder {
    return new EventBuilder(name, this);
  }

  /**
   * @deprecated No-op — context is now stored per-request in AsyncLocalStorage.
   * Kept for API compatibility only; will be removed in a future major version.
   */
  setContext(): void {
    // D4 FIX: Context is stored in AsyncLocalStorage by the middleware.
    // This method is intentionally a no-op.
  }

  /**
   * @deprecated No-op — context is now stored per-request in AsyncLocalStorage.
   * Kept for API compatibility only; will be removed in a future major version.
   */
  clearContext(): void {
    // D4 FIX: AsyncLocalStorage context is automatically scoped to the request.
  }

  // ---------------------------------------------------------------------------
  //  Internal: argument resolution
  // ---------------------------------------------------------------------------

  private resolveNamedArgs(options: TrackOptions): Record<string, unknown> {
    const data: Record<string, unknown> = {};

    // Actor: object reads id + email; string is just id
    if (options.actor !== undefined) {
      if (typeof options.actor === 'string') {
        data.actor_id = options.actor;
      } else {
        data.actor_id = options.actor.id;
        if (options.actor.email) {
          data.actor_email = options.actor.email;
        }
      }
    }

    // Explicit scalars override actor-resolved values
    if (options.actorId !== undefined) {
      data.actor_id = options.actorId;
    }
    if (options.actorEmail !== undefined) {
      data.actor_email = options.actorEmail;
    }
    if (options.ip !== undefined) {
      data.ip = sanitizeIP(options.ip);
    }
    if (options.userAgent !== undefined) {
      data.user_agent = options.userAgent;
    }
    if (options.metadata !== undefined) {
      data.metadata = { ...options.metadata };
    }
    if (options.timestamp !== undefined) {
      data.timestamp =
        options.timestamp instanceof Date
          ? options.timestamp.toISOString()
          : options.timestamp;
    }

    // Resource: object reads type + id; string is just type
    if (options.resource !== undefined) {
      const meta = (data.metadata ?? {}) as Record<string, unknown>;
      if (typeof options.resource === 'string') {
        meta.resource_type = options.resource;
        if (options.resourceId !== undefined) {
          meta.resource_id = options.resourceId;
        }
      } else {
        meta.resource_type = options.resource.type;
        meta.resource_id = options.resource.id;
      }
      data.metadata = meta;
    }

    // Remove undefined values
    return Object.fromEntries(
      Object.entries(data).filter(([, v]) => v !== undefined && v !== null),
    );
  }

  // ---------------------------------------------------------------------------
  //  Internal: dispatch and send
  // ---------------------------------------------------------------------------

  // D3 FIX: Validate event_type format before sending to the ingestor.
  private static readonly EVENT_TYPE_REGEX = /^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$/;

  private async dispatch(event: string, data: Record<string, unknown>): Promise<void> {
    // D3 FIX: Validate event type format before sending.
    if (!SOCWardenClient.EVENT_TYPE_REGEX.test(event)) {
      console.warn(`[SOCWarden] Invalid event type format, dropping event: "${event}". ` +
        'Event types must match ^[a-z][a-z0-9]{0,29}(\\.[a-z][a-z0-9_]{0,29}){1,3}$');
      return;
    }

    const payload = this.buildPayload(event, data);
    try {
      await this.send(payload);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.warn(`[SOCWarden] Failed to send event: ${message}`);
    }
  }

  private buildPayload(event: string, data: Record<string, unknown>): EventPayload {
    const payload: EventPayload = {
      event,
      source: 'sdk',
    };

    const fields = ['actor_id', 'actor_email', 'user_agent', 'metadata', 'timestamp'] as const;
    for (const field of fields) {
      if (data[field] !== undefined) {
        (payload as unknown as Record<string, unknown>)[field] = data[field];
      }
    }
    if (data.ip !== undefined) {
      (payload as unknown as Record<string, unknown>).ip = data.ip as string;
    }

    // Attach auto-context if middleware captured it
    payload.context = this.collectContext(data);

    return payload;
  }

  private collectContext(data: Record<string, unknown>): RequestContext {
    const context: RequestContext = {
      sdk: {
        name: SDK_NAME,
        version: SDK_VERSION,
      },
      server: {
        hostname: hostname(),
        runtime: `Node.js ${process.version}`,
        pid: process.pid,
      },
    };

    // D4 FIX: Read per-request context from AsyncLocalStorage instead of the
    // shared instance property to prevent concurrent request contamination.
    const requestCtx = requestContextStorage.getStore();
    if (requestCtx?.request) {
      const req = requestCtx.request;
      context.request = {
        method: req.method,
        path: req.path,
      };

      if (req.ip) {
        context.request.ip = req.ip;
      }
      if (req.queryString) {
        context.request.query_string = this.sanitizeQueryString(req.queryString);
      }
      if (req.referer) {
        context.request.referer = req.referer;
      }
      if (req.origin) {
        context.request.origin = req.origin;
      }
      if (req.contentType) {
        context.request.content_type = req.contentType;
      }
      if (req.acceptLanguage) {
        context.request.accept_language = req.acceptLanguage;
      }
      if (req.requestId) {
        context.request.request_id = req.requestId;
      }
      if (req.userAgent) {
        context.request.user_agent = req.userAgent;
      }
    }

    // D1 FIX: Browser context from X-SOCWarden-Context header removed —
    // trusting arbitrary HTTP headers allows spoofing of server-side metadata.

    return context;
  }

  private sanitizeQueryString(qs: string): string {
    if (!qs) return '';

    return qs
      .split('&')
      .map((pair) => {
        const [key, ...rest] = pair.split('=');
        const paramName = key.toLowerCase();
        const isSensitive = SENSITIVE_PARAMS.some((s) => paramName.includes(s));
        if (isSensitive && rest.length > 0) {
          return `${key}=[REDACTED]`;
        }
        return pair;
      })
      .join('&');
  }

  /**
   * Send an event payload to the ingestor with 429 backoff handling.
   *
   * Backoff strategy (mirrors Laravel SDK):
   *  - On 429: back off for Retry-After seconds (default 1 hour).
   *  - During backoff: silently drop events, except for a probe every 5 minutes.
   *  - On successful probe: clear backoff and resume normal sending.
   */
  private async send(payload: EventPayload): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    // Check backoff
    if (this.backoffUntil > 0 && now < this.backoffUntil) {
      // During backoff, only send probes at PROBE_INTERVAL
      if (now - this.lastProbe < PROBE_INTERVAL) {
        return; // silently drop
      }
      this.lastProbe = now;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.endpoint}/v1/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('Retry-After') ?? '', 10);
        const backoffSeconds = isNaN(retryAfter) ? BACKOFF_DURATION : retryAfter;
        this.backoffUntil = now + backoffSeconds;
        console.warn(
          `[SOCWarden] Quota exceeded (429). Backing off for ${backoffSeconds}s`,
        );
        return;
      }

      // Clear backoff on any successful response
      if (response.ok && this.backoffUntil > 0) {
        this.backoffUntil = 0;
        this.lastProbe = 0;
        console.info('[SOCWarden] Quota restored, backoff cleared');
      }

      if (!response.ok) {
        const body = await response.text().catch(() => '');
        console.warn(
          `[SOCWarden] Event send failed (HTTP ${response.status}): ${body}`,
        );
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
