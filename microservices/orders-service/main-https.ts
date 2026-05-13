/**
 * Demo orders-service. Listens on mTLS port 8443 and returns one deterministic
 * order body. Used by the thesis-defense walking-skeleton scenario.
 */
import { createMtlsServer } from '../shared/https-server';

const PORT = parseInt(process.env.PORT ?? '8443', 10);
const CERT_DIR = process.env.CERT_DIR ?? '/app/certs';
const CERT_PATH = process.env.CERT_PATH ?? `${CERT_DIR}/orders-service.crt`;
const KEY_PATH = process.env.KEY_PATH ?? `${CERT_DIR}/orders-service.key`;
const CA_PATH = process.env.CA_PATH ?? `${CERT_DIR}/ca.crt`;

void createMtlsServer({
  port: PORT,
  certPath: CERT_PATH,
  keyPath: KEY_PATH,
  caPath: CA_PATH,
  routes: {
    'GET /o-1': () => ({ body: { id: 'o-1', amount: 99, currency: 'USD' } }),
  },
})
  .then((handle) => {
    console.log(`[orders-service] mTLS listening on :${handle.port}`);
  })
  .catch((err: Error) => {
    console.error('[orders-service] failed to start:', err.message);
    process.exit(1);
  });
