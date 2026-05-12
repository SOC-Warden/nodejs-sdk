import { describe, it, beforeEach, afterEach, mock } from 'node:test';
import assert from 'node:assert';
import { SOCWardenClient } from '../client';
import { EventBuilder } from '../builder';
import { socwardenMiddleware, requestContextStorage } from '../middleware';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a mock Response object that satisfies the fetch API. */
function mockResponse(status: number, body = '', headers: Record<string, string> = {}): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    headers: new Headers(headers),
    text: async () => body,
    json: async () => JSON.parse(body || '{}'),
    body: null,
    bodyUsed: false,
    arrayBuffer: async () => new ArrayBuffer(0),
    blob: async () => new Blob(),
    formData: async () => new FormData(),
    clone: () => mockResponse(status, body, headers),
    type: 'basic' as ResponseType,
    url: '',
    redirected: false,
    bytes: async () => new Uint8Array(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SOCWardenClient', () => {
  const originalFetch = globalThis.fetch;
  let capturedUrl: string;
  let capturedInit: RequestInit;

  beforeEach(() => {
    capturedUrl = '';
    capturedInit = {};
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      capturedUrl = typeof input === 'string' ? input : (input as URL).toString();
      capturedInit = init ?? {};
      return mockResponse(202, '{"status":"accepted"}');
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // -----------------------------------------------------------------------
  // 1. track() builds correct payload
  // -----------------------------------------------------------------------
  it('track() builds correct payload', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123', endpoint: 'https://test.local' });

    await client.track('auth.login.success', {
      actor: { id: 'usr_1', email: 'alice@example.com' },
      ip: '10.0.0.1',
      metadata: { mfa: true },
    });

    assert.strictEqual(capturedUrl, 'https://test.local/v1/events');
    assert.strictEqual(capturedInit.method, 'POST');

    const body = JSON.parse(capturedInit.body as string);
    assert.strictEqual(body.event, 'auth.login.success');
    assert.strictEqual(body.source, 'sdk');
    assert.strictEqual(body.actor_id, 'usr_1');
    assert.strictEqual(body.actor_email, 'alice@example.com');
    assert.strictEqual(body.ip, '10.0.0.1');
    assert.deepStrictEqual(body.metadata, { mfa: true });

    // Authorization header
    const headers = capturedInit.headers as Record<string, string>;
    assert.strictEqual(headers['Authorization'], 'Bearer sk_test_123');
  });

  // -----------------------------------------------------------------------
  // 2. trackData() passes raw object
  // -----------------------------------------------------------------------
  it('trackData() passes raw object', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123', endpoint: 'https://test.local' });

    await client.trackData('server.ssh.login.failure', {
      actor_id: 'root',
      ip: '192.168.1.1',
      metadata: { port: 22 },
    });

    const body = JSON.parse(capturedInit.body as string);
    assert.strictEqual(body.event, 'server.ssh.login.failure');
    assert.strictEqual(body.source, 'sdk');
    assert.strictEqual(body.actor_id, 'root');
    assert.strictEqual(body.ip, '192.168.1.1');
    assert.deepStrictEqual(body.metadata, { port: 22 });
  });

  // -----------------------------------------------------------------------
  // 3. EventBuilder fluent chain
  // -----------------------------------------------------------------------
  it('EventBuilder fluent chain builds correct object', () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123' });
    const builder = new EventBuilder('data.exported', client);

    const result = builder
      .actor('usr_1')
      .actorEmail('alice@example.com')
      .ip('10.0.0.1')
      .meta('format', 'csv')
      .meta('rows', 1000)
      .resource('Report', 'rpt_42')
      .toObject();

    assert.strictEqual(result.event, 'data.exported');
    assert.strictEqual(result.actor_id, 'usr_1');
    assert.strictEqual(result.actor_email, 'alice@example.com');
    assert.strictEqual(result.ip, '10.0.0.1');
    assert.deepStrictEqual(result.metadata, {
      format: 'csv',
      rows: 1000,
      resource_type: 'Report',
      resource_id: 'rpt_42',
    });
  });

  // -----------------------------------------------------------------------
  // 4. collectContext includes SDK info
  // -----------------------------------------------------------------------
  it('collectContext includes SDK info, hostname, runtime, pid', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123', endpoint: 'https://test.local' });

    await client.track('test.event');

    const body = JSON.parse(capturedInit.body as string);
    assert.ok(body.context, 'context should be present');
    assert.strictEqual(body.context.sdk.name, 'socwarden-node');
    assert.strictEqual(body.context.sdk.version, '1.0.0');
    assert.ok(body.context.server.hostname, 'hostname should be present');
    assert.ok(body.context.server.runtime.startsWith('Node.js'), 'runtime should start with Node.js');
    assert.strictEqual(typeof body.context.server.pid, 'number');
  });

  // -----------------------------------------------------------------------
  // 5. 429 sets backoff state — subsequent calls are silently skipped
  // -----------------------------------------------------------------------
  it('429 sets backoff state and subsequent calls are skipped', async () => {
    let callCount = 0;

    globalThis.fetch = async (): Promise<Response> => {
      callCount++;
      return mockResponse(429, '', { 'Retry-After': '3600' });
    };

    const client = new SOCWardenClient({ apiKey: 'sk_test_123', endpoint: 'https://test.local' });

    // First call gets 429 — sets backoff
    await client.track('auth.login.attempt');
    assert.strictEqual(callCount, 1, 'first call should hit fetch');

    // Second call: backoff is active but lastProbe is 0 so (now - 0) >= PROBE_INTERVAL
    // triggers a probe request (this is the expected backoff probe behavior)
    await client.track('auth.login.attempt');
    assert.strictEqual(callCount, 2, 'second call should be a probe');

    // Third+ calls: within probe interval, should be silently dropped
    await client.track('auth.login.attempt');
    await client.track('auth.login.attempt');
    assert.strictEqual(callCount, 2, 'subsequent calls after probe should be silently dropped');
  });

  // -----------------------------------------------------------------------
  // 6. sanitizeQueryString redacts sensitive params
  // D4 FIX: Context is now stored in AsyncLocalStorage — inject via
  // requestContextStorage.run() instead of the deprecated client.setContext().
  // -----------------------------------------------------------------------
  it('sanitizeQueryString redacts sensitive params', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123', endpoint: 'https://test.local' });

    // D4 FIX: Use AsyncLocalStorage to set per-request context instead of
    // the shared singleton client.setContext() (which is now a no-op).
    await requestContextStorage.run(
      {
        request: {
          method: 'GET',
          path: '/api/data',
          queryString: 'token=abc123&name=test&password=hunter2&api_key=sk_live&safe=yes',
        },
        sdk: { name: 'socwarden-node', version: '1.0.0' },
      },
      async () => {
        await client.track('test.event');

        const body = JSON.parse(capturedInit.body as string);
        const qs = body.context.request.query_string;
        assert.ok(qs.includes('token=[REDACTED]'), 'token should be redacted');
        assert.ok(qs.includes('name=test'), 'name should not be redacted');
        assert.ok(qs.includes('password=[REDACTED]'), 'password should be redacted');
        assert.ok(qs.includes('api_key=[REDACTED]'), 'api_key should be redacted');
        assert.ok(qs.includes('safe=yes'), 'safe should not be redacted');
      },
    );
  });

  // -----------------------------------------------------------------------
  // 7. Middleware captures request context
  // D4 FIX: After the AsyncLocalStorage fix, context is only visible inside
  // the requestContextStorage.run() callback. In real Express usage, next()
  // continues the request handling chain synchronously within that callback,
  // so route handlers (and their track() calls) are properly covered.
  // -----------------------------------------------------------------------
  it('middleware captures request context from Express-like req/res', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123', endpoint: 'https://test.local' });
    const middleware = socwardenMiddleware(client);

    // Mock Express request
    const headers: Record<string, string> = {
      'user-agent': 'Mozilla/5.0 TestBrowser',
      'referer': 'https://example.com/dashboard',
      'origin': 'https://example.com',
      'x-request-id': 'req_abc123',
    };
    const req = {
      method: 'POST',
      path: '/api/auth/login',
      ip: '203.0.113.42',
      query: { page: '1', limit: '20' },
      get: (header: string) => headers[header.toLowerCase()],
    };

    // Mock Express response (finish callback no longer needed — AsyncLocalStorage
    // scopes context to the async context, not via explicit clearContext()).
    const res = { on: (_event: string, _cb: () => void) => {} };

    // D4 FIX: Track is called inside the next() callback, which is what Express
    // does — next() runs inside requestContextStorage.run() so the context is visible.
    let body: any;
    const next = async () => {
      // This simulates a route handler calling track() during request processing.
      await client.track('auth.login.success', { actor: 'usr_1' });
      body = JSON.parse(capturedInit.body as string);
    };

    // Invoke middleware — next() runs inside the AsyncLocalStorage context.
    await new Promise<void>((resolve) => {
      middleware(req, res, async () => {
        await next();
        resolve();
      });
    });

    assert.ok(body.context.request, 'request context should be present');
    assert.strictEqual(body.context.request.method, 'POST');
    assert.strictEqual(body.context.request.path, '/api/auth/login');
    assert.strictEqual(body.context.request.ip, '203.0.113.42');
    assert.strictEqual(body.context.request.user_agent, 'Mozilla/5.0 TestBrowser');
    assert.strictEqual(body.context.request.referer, 'https://example.com/dashboard');
    assert.strictEqual(body.context.request.origin, 'https://example.com');
    assert.strictEqual(body.context.request.request_id, 'req_abc123');
    assert.ok(body.context.request.query_string, 'query_string should be present');

    // After the middleware run() scope exits, context is automatically gone.
    // Track outside the scope — no request context should be present.
    await client.track('auth.logout');
    const body2 = JSON.parse(capturedInit.body as string);
    assert.strictEqual(body2.context.request, undefined, 'request context should be absent outside middleware scope');
  });
});

describe('EventBuilder advanced', () => {
  it('actor() accepts object with id and email', () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123' });
    const result = new EventBuilder('test.event', client)
      .actor({ id: 'usr_99', email: 'bob@example.com' })
      .toObject();

    assert.strictEqual(result.actor_id, 'usr_99');
    assert.strictEqual(result.actor_email, 'bob@example.com');
  });

  it('resource() accepts object with type and id', () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123' });
    const result = new EventBuilder('test.event', client)
      .resource({ type: 'Invoice', id: 'inv_42' })
      .toObject();

    assert.deepStrictEqual(result.metadata, {
      resource_type: 'Invoice',
      resource_id: 'inv_42',
    });
  });

  it('metadata() merges multiple calls', () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123' });
    const result = new EventBuilder('test.event', client)
      .metadata({ a: 1, b: 2 })
      .metadata({ b: 3, c: 4 })
      .toObject();

    assert.deepStrictEqual(result.metadata, { a: 1, b: 3, c: 4 });
  });

  it('timestamp() accepts Date object', () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123' });
    const dt = new Date('2025-01-15T12:00:00Z');
    const result = new EventBuilder('test.event', client)
      .timestamp(dt)
      .toObject();

    assert.strictEqual(result.timestamp, '2025-01-15T12:00:00.000Z');
  });

  it('timestamp() accepts ISO string', () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123' });
    const result = new EventBuilder('test.event', client)
      .timestamp('2025-01-15T12:00:00Z')
      .toObject();

    assert.strictEqual(result.timestamp, '2025-01-15T12:00:00Z');
  });

  it('severity() sets _severity in metadata', () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test_123' });
    const result = new EventBuilder('test.event', client)
      .severity('critical')
      .toObject();

    assert.strictEqual((result.metadata as Record<string, unknown>)._severity, 'critical');
  });
});

describe('SOCWardenClient constructor', () => {
  it('throws when apiKey is missing', () => {
    assert.throws(
      () => new SOCWardenClient({ apiKey: '' }),
      /apiKey is required/,
    );
  });

  it('throws when timeout is 0', () => {
    assert.throws(
      () => new SOCWardenClient({ apiKey: 'sk_test', timeout: 0 }),
      /timeout must be a positive integer/,
    );
  });

  it('throws when timeout is negative', () => {
    assert.throws(
      () => new SOCWardenClient({ apiKey: 'sk_test', timeout: -1 }),
      /timeout must be a positive integer/,
    );
  });

  it('throws when timeout is Infinity', () => {
    assert.throws(
      () => new SOCWardenClient({ apiKey: 'sk_test', timeout: Infinity }),
      /timeout must be a positive integer/,
    );
  });

  it('throws when timeout exceeds 300000ms', () => {
    assert.throws(
      () => new SOCWardenClient({ apiKey: 'sk_test', timeout: 300001 }),
      /timeout must be a positive integer/,
    );
  });

  it('accepts valid timeout of 1ms', () => {
    assert.doesNotThrow(() => new SOCWardenClient({ apiKey: 'sk_test', timeout: 1 }));
  });

  it('accepts valid timeout of 300000ms', () => {
    assert.doesNotThrow(() => new SOCWardenClient({ apiKey: 'sk_test', timeout: 300000 }));
  });

  it('strips trailing slashes from endpoint', async () => {
    const originalFetch = globalThis.fetch;
    let capturedUrl = '';
    globalThis.fetch = async (input: string | URL | Request): Promise<Response> => {
      capturedUrl = typeof input === 'string' ? input : (input as URL).toString();
      return mockResponse(202);
    };

    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local///' });
    await client.track('test.event');

    assert.strictEqual(capturedUrl, 'https://test.local/v1/events');
    globalThis.fetch = originalFetch;
  });
});

describe('sanitizeIP', () => {
  const originalFetch = globalThis.fetch;
  let lastBody: Record<string, unknown>;

  beforeEach(() => {
    globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      lastBody = JSON.parse(init?.body as string);
      return mockResponse(202);
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('strips invalid IP before sending', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    await client.track('auth.login.success', { ip: 'not-an-ip' });
    assert.strictEqual(lastBody.ip, undefined);
  });

  it('keeps valid IPv4 address', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    await client.track('auth.login.success', { ip: '10.0.0.1' });
    assert.strictEqual(lastBody.ip, '10.0.0.1');
  });

  it('keeps valid IPv6 address', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    await client.track('auth.login.success', { ip: '2001:db8::1' });
    assert.strictEqual(lastBody.ip, '2001:db8::1');
  });
});

describe('track() named args resolution', () => {
  const originalFetch = globalThis.fetch;
  let lastBody: Record<string, unknown>;

  beforeEach(() => {
    globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      lastBody = JSON.parse(init?.body as string);
      return mockResponse(202);
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('actor as string sets actor_id only', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    await client.track('test.event', { actor: 'usr_1' });
    assert.strictEqual(lastBody.actor_id, 'usr_1');
    assert.strictEqual(lastBody.actor_email, undefined);
  });

  it('actorId/actorEmail override actor object', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    await client.track('test.event', {
      actor: { id: 'usr_1', email: 'old@example.com' },
      actorId: 'usr_override',
      actorEmail: 'new@example.com',
    });
    assert.strictEqual(lastBody.actor_id, 'usr_override');
    assert.strictEqual(lastBody.actor_email, 'new@example.com');
  });

  it('resource as string with resourceId', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    await client.track('test.event', {
      resource: 'Order',
      resourceId: 'ord_123',
    });
    assert.strictEqual((lastBody.metadata as Record<string, unknown>).resource_type, 'Order');
    assert.strictEqual((lastBody.metadata as Record<string, unknown>).resource_id, 'ord_123');
  });

  it('resource as object sets type and id', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    await client.track('test.event', {
      resource: { type: 'Invoice', id: 'inv_42' },
    });
    assert.strictEqual((lastBody.metadata as Record<string, unknown>).resource_type, 'Invoice');
    assert.strictEqual((lastBody.metadata as Record<string, unknown>).resource_id, 'inv_42');
  });

  it('timestamp as Date is converted to ISO string', async () => {
    const client = new SOCWardenClient({ apiKey: 'sk_test', endpoint: 'https://test.local' });
    const dt = new Date('2025-06-15T10:30:00Z');
    await client.track('test.event', { timestamp: dt });
    assert.strictEqual(lastBody.timestamp, '2025-06-15T10:30:00.000Z');
  });
});
