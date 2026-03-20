/**
 * Cross-service contract tests verifying the Node.js SDK payload
 * matches the ingestor's expected EventPayload schema.
 */
import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { SOCWardenClient } from '../client';

// The ingestor's event type regex (from ingestor/internal/model/event.go).
const EVENT_TYPE_REGEX = /^[a-z][a-z0-9]{0,29}(\.[a-z][a-z0-9_]{0,29}){1,3}$/;

// Fields the ingestor's EventPayload struct accepts (POST /v1/events).
const INGESTOR_ALLOWED_FIELDS = new Set([
  'event',
  'source',
  'actor_id',
  'actor_email',
  'ip',
  'user_agent',
  'metadata',
  'timestamp',
  'context',
]);

/** Create a mock Response. */
function mockResponse(status: number, body = ''): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    headers: new Headers(),
    text: async () => body,
    json: async () => JSON.parse(body || '{}'),
    body: null,
    bodyUsed: false,
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob(),
    formData: async () => new FormData(),
    clone: () => mockResponse(status, body),
    type: 'basic' as ResponseType,
    url: '',
    redirected: false,
    bytes: async () => new Uint8Array(),
  };
}

describe('SDK -> Ingestor contract', () => {
  const originalFetch = globalThis.fetch;
  let capturedBody: Record<string, unknown>;

  beforeEach(() => {
    capturedBody = {};
    globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      capturedBody = JSON.parse(init?.body as string);
      return mockResponse(202, '{"status":"accepted"}');
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('track() payload matches ingestor schema with all fields', async () => {
    const client = new SOCWardenClient({
      apiKey: 'sk_test_123',
      endpoint: 'https://test.local',
    });

    await client.track('auth.login.success', {
      actorId: 'usr_123',
      actorEmail: 'alice@example.com',
      ip: '10.0.0.1',
      userAgent: 'TestAgent/1.0',
      metadata: { role: 'admin' },
      timestamp: '2026-03-18T10:30:00Z',
    });

    // Required fields
    assert.ok(capturedBody.event, 'payload must have event');
    assert.strictEqual(capturedBody.event, 'auth.login.success');
    assert.ok(
      EVENT_TYPE_REGEX.test(capturedBody.event as string),
      `event does not match ingestor regex`,
    );

    assert.ok(capturedBody.source, 'payload must have source');
    assert.strictEqual(capturedBody.source, 'sdk');

    // Optional fields
    assert.strictEqual(capturedBody.actor_id, 'usr_123');
    assert.strictEqual(capturedBody.actor_email, 'alice@example.com');
    assert.strictEqual(capturedBody.ip, '10.0.0.1');
    assert.strictEqual(capturedBody.user_agent, 'TestAgent/1.0');
    assert.strictEqual(typeof capturedBody.metadata, 'object');
    assert.strictEqual((capturedBody.metadata as Record<string, unknown>).role, 'admin');
    assert.strictEqual(capturedBody.timestamp, '2026-03-18T10:30:00Z');

    // Context must be an object with sdk block
    assert.ok(capturedBody.context, 'payload must have context');
    const ctx = capturedBody.context as Record<string, unknown>;
    assert.ok(ctx.sdk, 'context.sdk must be present');
    assert.ok(ctx.server, 'context.server must be present');
    assert.strictEqual((ctx.sdk as Record<string, string>).name, 'socwarden-node');

    // No unexpected fields
    for (const key of Object.keys(capturedBody)) {
      assert.ok(
        INGESTOR_ALLOWED_FIELDS.has(key),
        `payload contains unexpected field '${key}' not in ingestor schema`,
      );
    }
  });

  it('minimal payload has required fields and no unexpected keys', async () => {
    const client = new SOCWardenClient({
      apiKey: 'sk_test_123',
      endpoint: 'https://test.local',
    });

    await client.track('auth.logout');

    assert.strictEqual(capturedBody.event, 'auth.logout');
    assert.strictEqual(capturedBody.source, 'sdk');

    for (const key of Object.keys(capturedBody)) {
      assert.ok(
        INGESTOR_ALLOWED_FIELDS.has(key),
        `minimal payload contains unexpected field '${key}'`,
      );
    }
  });

  it('event types match ingestor regex', () => {
    const events = [
      'auth.login.success',
      'auth.login.failure',
      'auth.logout',
      'auth.mfa.enabled',
      'data.exported',
      'api.request.received',
      'page.view',
    ];
    for (const event of events) {
      assert.ok(
        EVENT_TYPE_REGEX.test(event),
        `event '${event}' does not match ingestor regex`,
      );
    }
  });

  it('source is always "sdk"', async () => {
    const client = new SOCWardenClient({
      apiKey: 'sk_test_123',
      endpoint: 'https://test.local',
    });

    await client.track('auth.login.success');
    assert.strictEqual(capturedBody.source, 'sdk');
  });
});
