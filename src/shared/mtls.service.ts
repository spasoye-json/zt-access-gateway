import * as crypto from 'crypto';
import * as fs from 'fs';
import * as https from 'https';
import { Inject, Injectable } from '@nestjs/common';
import { MTLS_CONFIG, type MtlsConfig } from '../config/slices';

interface CertCache {
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
  mtimes: { ca: number; cert: number; key: number };
  agent: https.Agent;
}

/**
 * Loads mTLS certificates from disk and produces an https.Agent.
 * Caches the agent until file mtimes change — no restart required on cert rotation.
 * CN validation guards against rogue downstream services (T-01-08).
 */
@Injectable()
export class MtlsService {
  private certCache: CertCache | null = null;
  // Serializes concurrent callers so only one reload runs at a time (TOCTOU guard)
  private reloadPromise: Promise<void> | null = null;

  constructor(@Inject(MTLS_CONFIG) private readonly config: MtlsConfig) {}

  /**
   * Read all three cert files from configured paths and store their contents
   * and mtimes in the cache. Uses fs.promises — never blocking readFileSync.
   */
  async loadCertificates(): Promise<void> {
    const caPath = this.config.caCertPath;
    const certPath = this.config.clientCertPath;
    const keyPath = this.config.clientKeyPath;

    const [ca, cert, key] = await Promise.all([
      fs.promises.readFile(caPath),
      fs.promises.readFile(certPath),
      fs.promises.readFile(keyPath),
    ]);

    const [caStat, certStat, keyStat] = await Promise.all([
      fs.promises.stat(caPath),
      fs.promises.stat(certPath),
      fs.promises.stat(keyPath),
    ]);

    this.certCache = {
      ca,
      cert,
      key,
      mtimes: { ca: caStat.mtimeMs, cert: certStat.mtimeMs, key: keyStat.mtimeMs },
      agent: new https.Agent({ ca, cert, key }),
    };
  }

  /**
   * Returns a cached https.Agent. Re-reads cert files if any mtime changed.
   * Always uses async fs.promises — never blocking readFileSync.
   */
  async getHttpsAgent(): Promise<https.Agent> {
    const caPath = this.config.caCertPath;
    const certPath = this.config.clientCertPath;
    const keyPath = this.config.clientKeyPath;

    const [caStat, certStat, keyStat] = await Promise.all([
      fs.promises.stat(caPath),
      fs.promises.stat(certPath),
      fs.promises.stat(keyPath),
    ]);

    const mtimesChanged =
      !this.certCache ||
      caStat.mtimeMs !== this.certCache.mtimes.ca ||
      certStat.mtimeMs !== this.certCache.mtimes.cert ||
      keyStat.mtimeMs !== this.certCache.mtimes.key;

    if (mtimesChanged) {
      if (this.reloadPromise === null) {
        this.reloadPromise = this.loadCertificates().finally(() => {
          this.reloadPromise = null;
        });
      }
      await this.reloadPromise;
    }

    return this.certCache.agent;
  }

  /**
   * Returns cached cert buffers. Throws if certs not yet loaded.
   */
  getCertificates(): { ca: Buffer; cert: Buffer; key: Buffer } {
    if (!this.certCache) {
      throw new Error('Certificates not loaded — call loadCertificates() first');
    }
    return { ca: this.certCache.ca, cert: this.certCache.cert, key: this.certCache.key };
  }

  /**
   * Forces a fresh disk read, clearing the cache regardless of mtime.
   * Called by CertMonitorService when it detects file changes.
   */
  async reload(): Promise<void> {
    this.certCache = null;
    await this.loadCertificates();
  }

  /**
   * Validates that the server cert's CN is in the MTLS_ALLOWED_SUBJECTS allowlist.
   * Rejects any CN not in the list (T-01-08).
   * @param pem - PEM-encoded X.509 certificate string
   */
  validateServerCertCN(pem: string): boolean {
    try {
      const x509 = new crypto.X509Certificate(pem);
      // subject is a multiline string like "CN=foo\nO=bar"
      const match = x509.subject.match(/CN=([^\n,]+)/);
      if (!match) {
        return false;
      }
      const cn = match[1].trim();
      return this.config.allowedSubjects.includes(cn);
    } catch {
      return false;
    }
  }
}
