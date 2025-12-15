import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import * as fs from 'fs';
import * as https from 'https';
import * as tls from 'tls';
import { ConfigService } from '../config/config.service';

type CachedCertificate = {
  path: string;
  mtimeMs: number;
  data: Buffer;
};

type CertificateBundle = {
  ca: CachedCertificate;
  cert: CachedCertificate;
  key: CachedCertificate;
};

@Injectable()
export class MtlsService {
  private readonly logger = new Logger(MtlsService.name);
  private cache: CertificateBundle | null = null;

  constructor(private readonly configService: ConfigService) {}

  createAgent(serverName?: string): https.Agent {
    const bundle = this.getOrLoadCertificates();
    return new https.Agent({
      ca: bundle.ca.data,
      cert: bundle.cert.data,
      key: bundle.key.data,
      rejectUnauthorized: true,
      requestCert: true,
      checkServerIdentity: (host, cert) =>
        this.validateServerIdentity(serverName ?? host, cert),
    });
  }

  validateCertificate(cert: tls.PeerCertificate | null): boolean {
    if (!cert) {
      return false;
    }

    const now = Date.now();
    const notBefore = Date.parse(cert.valid_from);
    const notAfter = Date.parse(cert.valid_to);

    if (Number.isNaN(notBefore) || Number.isNaN(notAfter)) {
      return false;
    }

    return now >= notBefore && now <= notAfter;
  }

  clearCache(): void {
    this.cache = null;
  }

  private getOrLoadCertificates(): CertificateBundle {
    const caPath = this.requirePath(
      this.configService.getMtlsCaCertPath(),
      'MTLS_CA_CERT_PATH',
    );
    const certPath = this.requirePath(
      this.configService.getMtlsCertPath(),
      'MTLS_CERT_PATH',
    );
    const keyPath = this.requirePath(
      this.configService.getMtlsKeyPath(),
      'MTLS_KEY_PATH',
    );

    const caStat = this.safeStat(caPath);
    const certStat = this.safeStat(certPath);
    const keyStat = this.safeStat(keyPath);

    const hasValidCache =
      this.cache &&
      this.cache.ca.path === caPath &&
      this.cache.cert.path === certPath &&
      this.cache.key.path === keyPath &&
      this.cache.ca.mtimeMs === caStat?.mtimeMs &&
      this.cache.cert.mtimeMs === certStat?.mtimeMs &&
      this.cache.key.mtimeMs === keyStat?.mtimeMs;

    if (hasValidCache) {
      return this.cache;
    }

    const ca = this.readCertificateFile(caPath, 'CA certificate');
    const cert = this.readCertificateFile(certPath, 'client certificate');
    const key = this.readCertificateFile(keyPath, 'client key');

    this.cache = { ca, cert, key };
    return this.cache;
  }

  private requirePath(path: string | undefined, envKey: string): string {
    if (!path) {
      throw new ServiceUnavailableException(`${envKey} is not configured`);
    }
    return path;
  }

  private readCertificateFile(path: string, label: string): CachedCertificate {
    try {
      const stat = fs.statSync(path);
      const data = fs.readFileSync(path);
      return { path, mtimeMs: stat.mtimeMs, data };
    } catch (error) {
      this.logger.error(`Failed to read ${label} (${path}): ${error.message}`);
      throw new ServiceUnavailableException(
        `Unable to read ${label.toLowerCase()} for mTLS`,
      );
    }
  }

  private safeStat(path: string): fs.Stats | null {
    try {
      return fs.statSync(path);
    } catch (error) {
      this.logger.warn(`Failed to stat certificate file (${path}): ${error.message}`);
      return null;
    }
  }

  private validateServerIdentity(host: string, cert: tls.PeerCertificate) {
    const allowedSubjects = this.getAllowedSubjects();
    if (allowedSubjects.length > 0) {
      const commonName = cert.subject?.CN;
      if (!commonName || !allowedSubjects.includes(commonName)) {
        return new Error(
          `mTLS certificate subject ${commonName ?? 'unknown'} is not allowed`,
        );
      }
    }

    if (!this.validateCertificate(cert)) {
      return new Error('Remote certificate is expired or not yet valid');
    }

    return tls.checkServerIdentity(host, cert);
  }

  private getAllowedSubjects(): string[] {
    if (typeof this.configService.getMtlsAllowedSubjects !== 'function') {
      return [];
    }
    return this.configService.getMtlsAllowedSubjects();
  }
}
