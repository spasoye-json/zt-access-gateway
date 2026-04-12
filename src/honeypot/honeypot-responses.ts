/**
 * Route-specific fake response generators for honeypot decoy routes.
 *
 * Security: All values are fictional canary tokens — no real service names,
 * real database hosts, or real API keys (T-02-06). The AWS key ID format
 * 'AKIAIOSFODNN7EXAMPLE' is the canonical example key from AWS docs, not a
 * real credential. 'canary-jwt-secret' and 'db.internal' are obviously fake.
 */
export interface FakeResponse {
  contentType: string;
  body: string | object;
}

export function getFakeResponse(path: string): FakeResponse {
  switch (path) {
    case '/wp-login.php':
      return {
        contentType: 'text/html',
        body: '<html><head><title>Log In</title></head><body><form method="post" action="/wp-login.php"><label>Username</label><input name="log"/><label>Password</label><input name="pwd" type="password"/><input type="submit" value="Log In"/></form></body></html>',
      };

    case '/admin/config.json':
      return {
        contentType: 'application/json',
        body: {
          database: { host: 'db.internal', port: 5432 },
          cache: { provider: 'redis', host: 'cache.internal' },
          debug: false,
        },
      };

    case '/.env':
      return {
        contentType: 'text/plain',
        body: 'DB_PASSWORD=s3cr3t-canary-token\nAPI_KEY=AKIAIOSFODNN7EXAMPLE\nJWT_SECRET=canary-jwt-secret\nREDIS_URL=redis://cache.internal:6379\n',
      };

    case '/api/v1/debug':
      return {
        contentType: 'application/json',
        body: {
          version: '2.1.0',
          uptime: 847293,
          memory: { rss: 156000000, heapUsed: 89000000 },
          env: 'production',
        },
      };

    case '/graphql/introspection':
      return {
        contentType: 'application/json',
        body: {
          data: {
            __schema: {
              types: [{ name: 'Query' }, { name: 'User' }, { name: 'Mutation' }],
            },
          },
        },
      };

    case '/actuator/health':
      return {
        contentType: 'application/json',
        body: {
          status: 'UP',
          components: { db: { status: 'UP' }, redis: { status: 'UP' } },
        },
      };

    case '/api/v1/internal/keys':
      return {
        contentType: 'application/json',
        body: [
          { id: 'key-001', type: 'rsa', created: '2025-01-15T00:00:00Z' },
          { id: 'key-002', type: 'ec', created: '2025-06-01T00:00:00Z' },
        ],
      };

    default:
      // Additional routes from HONEYPOT_ROUTES env var
      return {
        contentType: 'application/json',
        body: { status: 'ok' },
      };
  }
}
