/**
 * Demo users-service. Listens on mTLS port 8443 and returns one deterministic
 * user body containing both safe (id, name, email) and sensitive
 * (ssn, internalRiskScore) fields, so scenario 6 can demonstrate the
 * BOPLA response-stripping stage on the gateway.
 */
import { createMtlsServer } from '../shared/https-server';

const PORT = parseInt(process.env.PORT ?? '8443', 10);
const CERT_DIR = process.env.CERT_DIR ?? '/app/certs';
const CERT_PATH = process.env.CERT_PATH ?? `${CERT_DIR}/users-service.crt`;
const KEY_PATH = process.env.KEY_PATH ?? `${CERT_DIR}/users-service.key`;
const CA_PATH = process.env.CA_PATH ?? `${CERT_DIR}/ca.crt`;

void createMtlsServer({
  port: PORT,
  certPath: CERT_PATH,
  keyPath: KEY_PATH,
  caPath: CA_PATH,
  routes: {
    'GET /u-1': () => ({
      body: {
        id: 'u-1',
        name: 'Alice Example',
        email: 'alice@example.com',
        ssn: '999-99-9999',
        internalRiskScore: 0.42,
      },
    }),
  },
})
  .then((handle) => {
    console.log(`[users-service] mTLS listening on :${handle.port}`);
  })
  .catch((err: Error) => {
    console.error('[users-service] failed to start:', err.message);
    process.exit(1);
  });
