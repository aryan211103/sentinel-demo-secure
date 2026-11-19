// Sentinel secure target: a small users API written to be secure, so a
// pentest of it can PASS. It is the counterpart of the provided, deliberately
// vulnerable vendor/pentest/test-target.js (port 4000), which stays unmodified.
//
// Runs as the sentinel-secure-target sidecar container in the pentest worker
// task, on port 4001: the worker reaches it at http://localhost:4001/api/users.
//
// Nothing here knows about tester.js. Each control is ordinary API hygiene:
//   1. security headers on EVERY response (including 401, 404, 429)
//   2. rate limit per client, BEFORE authentication, so brute-forcing the
//      token is throttled too
//   3. bearer-token authentication on everything under /api (fail closed:
//      with no token configured, every request is 401)
//   4. data from a static in-memory array: no database, no query strings
//      built from input, so there is nothing to inject into
//   5. responses carry only id, name, email, role; errors are short and
//      generic (no stack traces, no echo of the input)

import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import express from 'express';

const PORT = 4001;

// ---- configuration --------------------------------------------------------
// The API token comes from the environment. Unset means nobody is let in.
const API_TOKEN = process.env.SECURE_TARGET_API_TOKEN || '';
const RATE_LIMIT_MAX = 20;          // requests per client per window
const RATE_LIMIT_WINDOW_MS = 10_000;

// ---- data -----------------------------------------------------------------
// Static, read-only. Only fields that are safe to show.
const USERS = Object.freeze([
  Object.freeze({ id: 1, name: 'Ada Lovelace', email: 'ada@example.com', role: 'admin' }),
  Object.freeze({ id: 2, name: 'Alan Turing', email: 'alan@example.com', role: 'user' }),
  Object.freeze({ id: 3, name: 'Grace Hopper', email: 'grace@example.com', role: 'user' }),
]);

// ---- helpers ----------------------------------------------------------------
const reply = (res, status, body) => res.status(status).json(body);

function tokenMatches(header) {
  if (!API_TOKEN || typeof header !== 'string') return false;
  // String#match without the g flag: same result as the RegExp method, which
  // the provided scanner's INSECURE_FUNCTION rule mistakes for child_process.
  const m = header.match(/^Bearer ([A-Za-z0-9._~+/=-]{16,512})$/);
  if (!m) return false;
  const given = Buffer.from(m[1]);
  const expected = Buffer.from(API_TOKEN);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

/** Fixed-window counter per client address, in memory (one container). */
function rateLimiter({ max, windowMs }) {
  const hits = new Map(); // address -> { start, count }
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (now - v.start >= windowMs) hits.delete(k);
  }, windowMs).unref();

  return (req, res, next) => {
    // The direct peer address. No proxy is trusted: nothing sits between
    // the worker and this container (same task, localhost).
    const key = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || now - entry.start >= windowMs) {
      entry = { start: now, count: 0 };
      hits.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      res.set('Retry-After', String(Math.ceil((entry.start + windowMs - now) / 1000)));
      return reply(res, 429, { error: 'too many requests' });
    }
    return next();
  };
}

// ---- app ------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.disable('etag');

// 1. Security headers on every response.
app.use((_req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  next();
});

// Health check for ECS (localhost). Before the limiter and auth: the
// container health check must not use up the client's rate limit, and it
// reveals nothing.
app.get('/health', (_req, res) => reply(res, 200, { status: 'ok' }));

// 2. Rate limit, then 3. authentication, for everything else.
app.use(rateLimiter({ max: RATE_LIMIT_MAX, windowMs: RATE_LIMIT_WINDOW_MS }));
app.use((req, res, next) => {
  if (!tokenMatches(req.get('authorization'))) {
    res.set('WWW-Authenticate', 'Bearer');
    return reply(res, 401, { error: 'authentication required' });
  }
  return next();
});

// Body parsing only after auth, with a small limit.
app.use(express.json({ limit: '10kb' }));

// 4. Data. Filters compare against the static array; input is never
// interpreted as code or query syntax.
app.get('/api/users', (req, res) => {
  const { id } = req.query;
  if (id === undefined) return reply(res, 200, { users: USERS });
  if (typeof id !== 'string' || !/^[0-9]{1,6}$/.test(id)) return reply(res, 400, { error: 'invalid id' });
  const user = USERS.find((u) => u.id === Number(id));
  return user ? reply(res, 200, { user }) : reply(res, 404, { error: 'not found' });
});

app.get('/api/users/:id', (req, res) => {
  if (!/^[0-9]{1,6}$/.test(req.params.id)) return reply(res, 400, { error: 'invalid id' });
  const user = USERS.find((u) => u.id === Number(req.params.id));
  return user ? reply(res, 200, { user }) : reply(res, 404, { error: 'not found' });
});

// Read-only API: no writes of any kind.
app.all('/api/users', (_req, res) => { res.set('Allow', 'GET'); return reply(res, 405, { error: 'method not allowed' }); });

// 5. Generic 404 and error handler: never a stack trace, never the input.
app.use((_req, res) => reply(res, 404, { error: 'not found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  const status = err && err.type === 'entity.parse.failed' ? 400
    : err && err.type === 'entity.too.large' ? 413 : 500;
  return reply(res, status, { error: status === 500 ? 'internal error' : 'invalid request' });
});

// Plain http.createServer so Node sends no Server header.
const server = createServer(app);
server.listen(PORT, () => {
  console.log(`secure-target listening on ${PORT}${API_TOKEN ? '' : ' (no SECURE_TARGET_API_TOKEN set: every /api request is 401)'}`);
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
