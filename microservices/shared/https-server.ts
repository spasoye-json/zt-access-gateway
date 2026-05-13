/**
 * Reusable mTLS HTTPS server factory for demo upstream microservices.
 *
 * Demo only: keeps the TLS handshake configuration in one place so every
 * upstream (orders, users, …) is a thin handler + a call to createMtlsServer.
 *
 * Production gateway TLS lives in src/shared/mtls.service.ts; this module
 * is intentionally separate so changes here don't leak into the gateway.
 */
import * as fs from 'fs';
import * as https from 'https';
import type { IncomingMessage, ServerResponse } from 'http';
import type { AddressInfo } from 'net';

export interface RouteResult {
  status?: number;
  body: unknown;
}

export type RouteHandler = (req: IncomingMessage) => RouteResult | Promise<RouteResult>;

export interface MtlsServerOptions {
  port: number;
  certPath: string;
  keyPath: string;
  caPath: string;
  /** Map of "METHOD /path" → handler. */
  routes: Record<string, RouteHandler>;
}

export interface MtlsServerHandle {
  port: number;
  close(): Promise<void>;
}

function routeKey(req: IncomingMessage): string {
  const url = req.url ?? '/';
  const pathname = url.split('?')[0];
  return `${req.method ?? 'GET'} ${pathname}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': payload.length,
  });
  res.end(payload);
}

export async function createMtlsServer(opts: MtlsServerOptions): Promise<MtlsServerHandle> {
  const server = https.createServer({
    key: fs.readFileSync(opts.keyPath),
    cert: fs.readFileSync(opts.certPath),
    ca: fs.readFileSync(opts.caPath),
    requestCert: true,
    rejectUnauthorized: true,
  });

  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    const handler = opts.routes[routeKey(req)];
    if (!handler) {
      sendJson(res, 404, { error: 'not_found', route: routeKey(req) });
      return;
    }
    Promise.resolve()
      .then(() => handler(req))
      .then((result) => sendJson(res, result.status ?? 200, result.body))
      .catch((err: Error) => sendJson(res, 500, { error: 'handler_error', message: err.message }));
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const addr = server.address() as AddressInfo;

  return {
    port: addr.port,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
