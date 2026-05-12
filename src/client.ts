import { EventBuilder } from './builder';
import {
  EventPayload,
  RequestContext,
  SOCWardenOptions,
  TrackOptions,
} from './types';
import { hostname } from 'os';
import { isIPv4, isIPv6 } from 'net';
import { requestContextStorage } from './context';

const SDK_NAME = 'socwarden-node';
const SDK_VERSION = '1.0.0';

const BACKOFF_DURATION = 3600; // 1 hour in seconds (default when no Retry-After header)
const MAX_BACKOFF_DURATION = 86400; // 24 hours — hard cap to prevent DoS via large Retry-After
const PROBE_INTERVAL = 300; // 5 minutes in seconds

const SENSITIVE_PARAMS = ['token', 'key', 'password', 'secret', 'code', 'auth', 'session', 'csrf'];

/**
 * Returns ip if it is a valid IPv4 or IPv6 address, otherwise undefined.
 * Matches the ingestor's validate:"omitempty,ip" constraint.
 * Uses Node.js net.isIPv4/isIPv6 for strict RFC-compliant validation instead of
 * a regex, which previously allowed malformed IPv6 strings like ':::'.
 */
function sanitizeIP(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  if (isIPv4(ip) || isIPv6(ip)) return ip;
  return undefined;
}

/**
 * Maximum number of bytes we read from an error response body before truncating.
 * Prevents memory exhaustion (DoS) when a misconfigured or malicious server
 * returns a very large response body that we would otherwise fully buffer via text().
 * Also prevents log flooding.
 */
const MAX_ERROR_BODY_BYTES = 512;

/**
 * Sanitize a string for safe inclusion in a single log line.
 * Strips ASCII control characters (including CR/LF) to prevent log injection:
 * a server-controlled body containing newlines could otherwise forge additional
 * log entries that appear to come from the SDK (e.g. fake "Auth successful" lines).
 */
function sanitizeForLog(s: string): string {
  return s.replace(/[\x00-\x1f\x7f]/g, '').slice(0, MAX_ERROR_BODY_BYTES);
}

/**
 * Validate that the configured endpoint URL:
 *   1. Uses a safe scheme (https:// or http://).
 *   2. Does NOT resolve to a private/loopback/link-local address — this prevents
 *      Server-Side Request Forgery (SSRF) where a developer passes a user-supplied
 *      URL and the SDK would send the Bearer API key to an internal service.
 *
 * Note: scheme-level validation happens here; the SSRF block covers the most
 * dangerous cases (cloud metadata endpoints, localhost, RFC-1918 ranges).
 */
function validateEndpointURL(raw: string): void {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`[SOCWarden] Invalid endpoint URL: "${raw}"`);
  }

  const scheme = parsed.protocol; // includes trailing ':'
  if (scheme !== 'https:' && scheme !== 'http:') {
    throw new Error(
      `[SOCWarden] Endpoint URL scheme must be https:// or http:// (got "${scheme}"). ` +
        'Schemes like file://, ftp://, data: or javascript: are not permitted.',
    );
  }

  // Block SSRF targets: loopback, link-local (cloud metadata), RFC-1918 ranges.
  const host = parsed.hostname;
  const ssrfPatterns: RegExp[] = [
    /^localhost$/i,
    /^127\.\d+\.\d+\.\d+$/,           // 127.0.0.0/8 (loopback)
    /^::1$/,                            // IPv6 loopback
    /^169\.254\.\d+\.\d+$/,            // 169.254.0.0/16 — link-local / cloud metadata
    /^10\.\d+\.\d+\.\d+$/,             // 10.0.0.0/8     — RFC-1918
    /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/, // 172.16.0.0/12 — RFC-1918
    /^192\.168\.\d+\.\d+$/,            // 192.168.0.0/16 — RFC-1918
    /^fd[0-9a-f]{2}:/i,                // IPv6 ULA fc00::/7
    /^fe80:/i,                          // IPv6 link-local
  ];
  for (const pattern of ssrfPatterns) {
    if (pattern.test(host)) {
      throw new Error(
        `[SOCWarden] Endpoint hostname "${host}" resolves to a private or reserved address range. ` +
          'Configuring the SDK to send events to internal network addresses is not permitted (SSRF prevention).',
      );
    }
  }
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
    const rawEndpoint = (options.endpoint ?? 'https://ingestor.socwarden.com').replace(/\/+$/, '');

    // SEC-FIX: Validate the endpoint URL for scheme safety and SSRF protection
    // before storing it. Throws on: non-http/https schemes, private/loopback IPs.
    validateEndpointURL(rawEndpoint);
    this.endpoint = rawEndpoint;

    // Warn if HTTP is used — API key will be in cleartext.
    if (!this.endpoint.startsWith('https://')) {
      console.warn('[SOCWarden] WARNING: Endpoint is using HTTP. API keys will be transmitted in cleartext.');
    }

    // Validate timeout: must be a positive finite integer in [1, 300_000] ms.
    const rawTimeout = options.timeout ?? 5000;
    if (!Number.isFinite(rawTimeout) || rawTimeout <= 0 || rawTimeout > 300_000) {
      throw new Error(
        `[SOCWarden] timeout must be a positive integer between 1 and 300000 ms (got ${rawTimeout}).`,
      );
    }
    this.timeout = rawTimeout;
  }

  /**
   * Prevent the API key from leaking via accidental serialization.
   *
   * TypeScript's `private` keyword is compile-time only — at runtime the
   * `apiKey` property is a plain enumerable JS property. If the client
   * instance is accidentally passed to JSON.stringify(), console.log() or
   * Object spread, the key would be exposed. Overriding toJSON() and the
   * Node.js inspect symbol returns a safe redacted representation instead.
   */
  toJSON(): Record<string, unknown> {
    return {
      '[SOCWardenClient]': true,
      endpoint: this.endpoint,
      apiKey: '[REDACTED]',
    };
  }

  /** Safe representation for Node.js util.inspect / console.log. */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `SOCWardenClient { endpoint: '${this.endpoint}', apiKey: '[REDACTED]' }`;
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
      // Truncate and strip control characters from event name before logging to prevent
      // log injection attacks via crafted multiline event names.
      const safeEvent = String(event).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 100);
      console.warn(`[SOCWarden] Invalid event type format, dropping event: "${safeEvent}". ` +
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

      // Sanitize context IP the same way as track()'s ip option, so a spoofed
      // X-Forwarded-For header cannot inject a malformed value.
      const sanitizedContextIp = sanitizeIP(req.ip);
      if (sanitizedContextIp) {
        context.request.ip = sanitizedContextIp;
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
        // Cap Retry-After to MAX_BACKOFF_DURATION to prevent a malicious or
        // misconfigured server from permanently blocking all event sending (DoS).
        const rawBackoff = isNaN(retryAfter) || retryAfter <= 0 ? BACKOFF_DURATION : retryAfter;
        const backoffSeconds = Math.min(rawBackoff, MAX_BACKOFF_DURATION);
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
        // SEC-FIX (H1/H2): Read only the first MAX_ERROR_BODY_BYTES of the error body to
        // prevent memory exhaustion DoS (a malicious server returning a giant response would
        // otherwise be fully buffered by text()).  Then strip control characters (CR/LF) to
        // prevent log injection — a crafted body could otherwise forge additional log lines
        // that appear to originate from the SDK itself.
        const rawBody = await response.text().catch(() => '');
        const safeBody = sanitizeForLog(rawBody);
        console.warn(
          `[SOCWarden] Event send failed (HTTP ${response.status}): ${safeBody}`,
        );
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
