/**
 * Configuration options for the SOCWarden client.
 */
export interface SOCWardenOptions {
  /** API key for authenticating with the SOCWarden ingestor. */
  apiKey: string;
  /** Ingestor endpoint URL. Defaults to https://ingest.socwarden.io */
  endpoint?: string;
  /** HTTP request timeout in milliseconds. Defaults to 5000. */
  timeout?: number;
}

/**
 * Actor identification — either a string ID or an object with id and optional email.
 */
export type ActorInput = string | { id: string; email?: string };

/**
 * Resource identification — either a string type or an object with type and id.
 */
export type ResourceInput = string | { type: string; id: string };

/**
 * Options for the `track()` method (named-args style).
 */
export interface TrackOptions {
  /** Actor (user) who triggered the event. String is treated as actor ID. */
  actor?: ActorInput;
  /** Explicit actor ID (overrides actor if both provided). */
  actorId?: string;
  /** Explicit actor email (overrides actor.email if both provided). */
  actorEmail?: string;
  /** Source IP address. Auto-detected from request context if middleware is active. */
  ip?: string;
  /** User-Agent string. Auto-detected from request context if middleware is active. */
  userAgent?: string;
  /** Custom metadata key-value pairs. */
  metadata?: Record<string, unknown>;
  /** Event timestamp (ISO 8601 string or Date object). Defaults to now. */
  timestamp?: string | Date;
  /** Resource that was acted upon. String is treated as resource type. */
  resource?: ResourceInput;
  /** Explicit resource ID (used when resource is a string type). */
  resourceId?: string;
}

/**
 * Payload sent to the SOCWarden ingestor POST /v1/events endpoint.
 */
export interface EventPayload {
  event: string;
  source: string;
  actor_id?: string;
  actor_email?: string;
  ip?: string;
  user_agent?: string;
  metadata?: Record<string, unknown>;
  timestamp?: string;
  context?: RequestContext;
}

/**
 * Auto-collected context attached to every event when middleware is active.
 */
export interface RequestContext {
  sdk: {
    name: string;
    version: string;
  };
  server?: {
    hostname: string;
    runtime: string;
    pid: number;
  };
  request?: {
    method: string;
    path: string;
    ip?: string;
    query_string?: string;
    referer?: string;
    origin?: string;
    content_type?: string;
    accept_language?: string;
    request_id?: string;
  };
  /** Browser context relayed from the browser SDK via X-SOCWarden-Context header. */
  browser?: Record<string, unknown>;
}

/**
 * Internal context captured by the Express middleware for the current request.
 */
export interface CapturedContext {
  request: {
    method: string;
    path: string;
    ip?: string;
    userAgent?: string;
    queryString?: string;
    referer?: string;
    origin?: string;
    contentType?: string;
    acceptLanguage?: string;
    requestId?: string;
  };
  sdk: {
    name: string;
    version: string;
  };
  /** Browser context decoded from X-SOCWarden-Context header (relay mode). */
  browser?: Record<string, unknown>;
}
