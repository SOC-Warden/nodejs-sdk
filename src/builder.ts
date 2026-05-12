import type { SOCWardenClient } from './client';
import type { ActorInput, ResourceInput } from './types';

/**
 * Fluent builder for constructing and sending SOCWarden events.
 *
 * ```ts
 * await soc.event('auth.login.success')
 *   .actor({ id: 'usr_123', email: 'john@example.com' })
 *   .ip('203.0.113.42')
 *   .metadata({ mfa: true })
 *   .resource('Session', 'sess_abc')
 *   .send();
 * ```
 */
export class EventBuilder {
  private readonly eventName: string;
  private readonly client: SOCWardenClient;
  private data: Record<string, unknown> = {};

  constructor(event: string, client: SOCWardenClient) {
    this.eventName = event;
    this.client = client;
  }

  // ---------------------------------------------------------------------------
  //  Actor
  // ---------------------------------------------------------------------------

  /**
   * Set the actor (user) who triggered the event.
   *
   * Accepts a string ID or an object with `id` and optional `email`.
   *
   * ```ts
   * .actor('usr_123')
   * .actor({ id: 'usr_123', email: 'john@example.com' })
   * ```
   */
  actor(actorOrId: ActorInput, email?: string): this {
    if (typeof actorOrId === 'string') {
      this.data.actor_id = actorOrId;
      if (email !== undefined) {
        this.data.actor_email = email;
      }
    } else {
      this.data.actor_id = actorOrId.id;
      if (actorOrId.email) {
        this.data.actor_email = actorOrId.email;
      }
      if (email !== undefined) {
        this.data.actor_email = email;
      }
    }
    return this;
  }

  /**
   * Set the actor ID directly.
   */
  actorId(id: string): this {
    this.data.actor_id = id;
    return this;
  }

  /**
   * Set the actor email directly.
   */
  actorEmail(email: string): this {
    this.data.actor_email = email;
    return this;
  }

  // ---------------------------------------------------------------------------
  //  Request context
  // ---------------------------------------------------------------------------

  /**
   * Set the source IP address.
   */
  ip(ip: string): this {
    this.data.ip = ip;
    return this;
  }

  /**
   * Set the User-Agent string.
   */
  userAgent(ua: string): this {
    this.data.user_agent = ua;
    return this;
  }

  // ---------------------------------------------------------------------------
  //  Metadata
  // ---------------------------------------------------------------------------

  /**
   * Merge custom metadata key-value pairs. Can be called multiple times;
   * values are merged (later calls override earlier keys).
   *
   * ```ts
   * .metadata({ role: 'admin', format: 'csv' })
   * ```
   */
  metadata(obj: Record<string, unknown>): this {
    this.data.metadata = {
      ...((this.data.metadata as Record<string, unknown>) ?? {}),
      ...obj,
    };
    return this;
  }

  /**
   * Set a single metadata key-value pair.
   *
   * ```ts
   * .meta('role', 'admin')
   * ```
   */
  meta(key: string, value: unknown): this {
    // Guard against prototype-chain keys passed via bracket-notation assignment.
    // '__proto__', 'constructor', and 'prototype' are the classic pollution vectors,
    // but inherited Object.prototype method names (valueOf, toString, hasOwnProperty,
    // isPrototypeOf, propertyIsEnumerable, toLocaleString) can also shadow built-ins
    // when set on a plain object, breaking downstream consumers that rely on them.
    // We block all of them defensively.
    const BLOCKED_KEYS = new Set([
      '__proto__',
      'constructor',
      'prototype',
      'valueOf',
      'toString',
      'toLocaleString',
      'hasOwnProperty',
      'isPrototypeOf',
      'propertyIsEnumerable',
      '__defineGetter__',
      '__defineSetter__',
      '__lookupGetter__',
      '__lookupSetter__',
    ]);
    if (BLOCKED_KEYS.has(key)) {
      console.warn(`[SOCWarden] Metadata key "${key}" is reserved and will be ignored.`);
      return this;
    }
    const existing = (this.data.metadata as Record<string, unknown>) ?? {};
    existing[key] = value;
    this.data.metadata = existing;
    return this;
  }

  // ---------------------------------------------------------------------------
  //  Timestamp & severity
  // ---------------------------------------------------------------------------

  /**
   * Set the event timestamp (ISO 8601 string or Date object).
   */
  timestamp(ts: string | Date): this {
    this.data.timestamp = ts instanceof Date ? ts.toISOString() : ts;
    return this;
  }

  /**
   * Set the event severity hint for the enricher.
   */
  severity(severity: string): this {
    const existing = (this.data.metadata as Record<string, unknown>) ?? {};
    existing._severity = severity;
    this.data.metadata = existing;
    return this;
  }

  // ---------------------------------------------------------------------------
  //  Resource
  // ---------------------------------------------------------------------------

  /**
   * Attach the resource that was acted upon.
   *
   * ```ts
   * .resource('Order', 'ord_123')
   * .resource({ type: 'Order', id: 'ord_123' })
   * ```
   */
  resource(typeOrObj: ResourceInput, id?: string): this {
    const existing = (this.data.metadata as Record<string, unknown>) ?? {};
    if (typeof typeOrObj === 'string') {
      existing.resource_type = typeOrObj;
      if (id !== undefined) {
        existing.resource_id = id;
      }
    } else {
      existing.resource_type = typeOrObj.type;
      existing.resource_id = typeOrObj.id;
    }
    this.data.metadata = existing;
    return this;
  }

  // ---------------------------------------------------------------------------
  //  Send
  // ---------------------------------------------------------------------------

  /**
   * Send the event to SOCWarden.
   */
  async send(): Promise<void> {
    await this.client.trackData(this.eventName, this.data);
  }

  /**
   * Get the built data object (for testing/inspection).
   */
  toObject(): Record<string, unknown> {
    return {
      event: this.eventName,
      ...this.data,
    };
  }
}
