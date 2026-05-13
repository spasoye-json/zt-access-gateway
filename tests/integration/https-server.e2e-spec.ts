/**
 * Slice A — mTLS HTTPS server factory.
 *
 * Behavior under test:
 *   - createMtlsServer() binds on an ephemeral port and routes "METHOD /path" to handlers.
 *   - A request with a CA-signed client cert is accepted and gets the handler's JSON body.
 *   - A request without a client cert is rejected at the TLS layer (no body served).
 */
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as https from 'https';
import * as path from 'path';
import axios from 'axios';
import { createMtlsServer } from '../../microservices/shared/https-server';
import type { MtlsServerHandle } from '../../microservices/shared/https-server';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CERT_DIR = path.join(REPO_ROOT, 'certs');

function ensureCerts(): void {
  // Idempotent — generates only if missing.
  execSync(`bash ${path.join(REPO_ROOT, 'scripts', 'gen-certs.sh')}`, {
    stdio: 'pipe',
    env: { ...process.env, CERT_DIR },
  });
}

describe('createMtlsServer (microservices/shared/https-server)', () => {
  let handle: MtlsServerHandle;
  let ca: Buffer;
  let clientCert: Buffer;
  let clientKey: Buffer;

  beforeAll(async () => {
    ensureCerts();
    ca = fs.readFileSync(path.join(CERT_DIR, 'ca.crt'));
    clientCert = fs.readFileSync(path.join(CERT_DIR, 'gateway.crt'));
    clientKey = fs.readFileSync(path.join(CERT_DIR, 'gateway.key'));

    handle = await createMtlsServer({
      port: 0,
      caPath: path.join(CERT_DIR, 'ca.crt'),
      certPath: path.join(CERT_DIR, 'orders-service.crt'),
      keyPath: path.join(CERT_DIR, 'orders-service.key'),
      routes: {
        'GET /o-1': () => ({ body: { id: 'o-1', amount: 99, currency: 'USD' } }),
      },
    });
  });

  afterAll(async () => {
    if (handle) await handle.close();
  });

  it('serves a JSON body to a client presenting a CA-signed cert', async () => {
    const agent = new https.Agent({
      ca,
      cert: clientCert,
      key: clientKey,
      // Server CN is 'orders-service' but we're hitting 127.0.0.1 → SAN includes both.
      servername: 'orders-service',
    });

    const res = await axios.get(`https://127.0.0.1:${handle.port}/o-1`, { httpsAgent: agent });

    expect(res.status).toBe(200);
    expect(res.data).toEqual({ id: 'o-1', amount: 99, currency: 'USD' });
  });

  it('rejects a client that does not present a cert', async () => {
    const agent = new https.Agent({ ca, servername: 'orders-service' });

    await expect(
      axios.get(`https://127.0.0.1:${handle.port}/o-1`, { httpsAgent: agent, timeout: 2000 }),
    ).rejects.toThrow();
  });

  it('returns 404 for an unregistered route', async () => {
    const agent = new https.Agent({
      ca,
      cert: clientCert,
      key: clientKey,
      servername: 'orders-service',
    });

    await expect(
      axios.get(`https://127.0.0.1:${handle.port}/does-not-exist`, {
        httpsAgent: agent,
        validateStatus: () => true,
      }),
    ).resolves.toMatchObject({ status: 404 });
  });
});
