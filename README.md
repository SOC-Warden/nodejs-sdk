# @socwarden/sdk

Node.js/TypeScript SDK for [SOCWarden](https://socwarden.com) security event tracking.

## Installation

```bash
npm install @socwarden/sdk
```

## Quick Start

```typescript
import { SOCWardenClient } from '@socwarden/sdk';

const soc = new SOCWardenClient({
  apiKey: 'sk_live_...',
  // endpoint: 'https://ingestor.socwarden.com', // default
  // timeout: 5000, // default, in ms
});
```

## Usage

### track() — Named Arguments

```typescript
// Simple event
await soc.track('auth.login.success', { actor: userId });

// With full options
await soc.track('data.exported', {
  actor: { id: user.id, email: user.email },
  metadata: { format: 'csv', rows: 1500 },
  resource: { type: 'Report', id: report.id },
  ip: '203.0.113.42',
});

// With explicit actor fields
await soc.track('auth.login.failure', {
  actorEmail: req.body.email,
  ip: req.ip,
  userAgent: req.get('user-agent'),
});
```

### trackData() — Raw Object

```typescript
await soc.trackData('auth.login.success', {
  actor_id: user.id,
  actor_email: user.email,
  metadata: { role: 'admin' },
});
```

### event() — Fluent Builder

```typescript
await soc.event('data.exported')
  .actor({ id: user.id, email: user.email })
  .resource('Report', report.id)
  .meta('format', 'csv')
  .meta('rows', 1500)
  .send();

// Chaining metadata
await soc.event('auth.mfa.enrolled')
  .actor(user.id)
  .metadata({ method: 'totp', provider: 'google' })
  .severity('info')
  .send();
```

### Express Middleware

The middleware captures request context (IP, user-agent, path, etc.) and attaches it to every event sent during the request lifecycle.

```typescript
import express from 'express';
import { SOCWardenClient, socwardenMiddleware } from '@socwarden/sdk';

const soc = new SOCWardenClient({ apiKey: 'sk_live_...' });
const app = express();

// Attach SOCWarden middleware
app.use(socwardenMiddleware(soc));

app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);

  if (user) {
    // IP, user-agent, path are auto-captured from the request
    await soc.track('auth.login.success', { actor: user.id });
    res.json({ ok: true });
  } else {
    await soc.track('auth.login.failure', {
      actorEmail: req.body.email,
    });
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

## Rate Limit Handling

The SDK automatically handles 429 (rate limit) responses:

1. On receiving a 429, it backs off for the `Retry-After` duration (default: 1 hour).
2. During backoff, events are silently dropped to avoid overwhelming the ingestor.
3. Every 5 minutes, a probe request is sent to check if the quota has been restored.
4. On a successful probe, normal sending resumes immediately.

## Requirements

- Node.js 18+ (uses native `fetch`)
- No runtime dependencies

## TypeScript

All types are exported for full TypeScript support:

```typescript
import type {
  SOCWardenOptions,
  TrackOptions,
  ActorInput,
  ResourceInput,
  EventPayload,
} from '@socwarden/sdk';
```
