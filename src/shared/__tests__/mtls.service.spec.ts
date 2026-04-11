import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as https from 'https';
import { execSync } from 'child_process';
import { MtlsService } from '../mtls.service';
import { AppConfigService } from '../../config/config.service';

/**
 * Generate a minimal self-signed certificate PEM string for testing.
 * Uses a temp file because /dev/stdout is unavailable in some sandboxes.
 */
function generateSelfSignedCert(cn: string): string {
  const tmpFile = path.join(os.tmpdir(), `test-cert-${cn}-${Date.now()}.pem`);
  try {
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out "${tmpFile}" -days 1 -nodes -subj "/CN=${cn}" 2>/dev/null`,
    );
    return fs.readFileSync(tmpFile, 'utf8');
  } catch {
    throw new Error(`openssl cert generation failed for CN=${cn}`);
  } finally {
    try {
      fs.unlinkSync(tmpFile);
    } catch {
      // cleanup best-effort
    }
  }
}

async function createTempCertFiles(): Promise<{
  dir: string;
  caPath: string;
  certPath: string;
  keyPath: string;
}> {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'mtls-test-'));
  const caPath = path.join(dir, 'ca.pem');
  const certPath = path.join(dir, 'cert.pem');
  const keyPath = path.join(dir, 'key.pem');

  await fs.promises.writeFile(caPath, 'ca-content');
  await fs.promises.writeFile(certPath, 'cert-content');
  await fs.promises.writeFile(keyPath, 'key-content');

  return { dir, caPath, certPath, keyPath };
}

describe('MtlsService', () => {
  let tmpDir: string;
  let caPath: string;
  let certPath: string;
  let keyPath: string;
  let mockConfig: Partial<AppConfigService>;

  beforeEach(async () => {
    const files = await createTempCertFiles();
    tmpDir = files.dir;
    caPath = files.caPath;
    certPath = files.certPath;
    keyPath = files.keyPath;

    mockConfig = {
      mtlsCaCertPath: caPath,
      mtlsClientCertPath: certPath,
      mtlsClientKeyPath: keyPath,
      mtlsAllowedSubjects: ['test-cn'],
    };
  });

  afterEach(async () => {
    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  });

  it('loadCertificates reads all three cert files from configured paths', async () => {
    const service = new MtlsService(mockConfig as AppConfigService);
    await service.loadCertificates();
    const certs = service.getCertificates();
    expect(certs.ca).toEqual(Buffer.from('ca-content'));
    expect(certs.cert).toEqual(Buffer.from('cert-content'));
    expect(certs.key).toEqual(Buffer.from('key-content'));
  });

  it('getHttpsAgent returns an https.Agent instance', async () => {
    const service = new MtlsService(mockConfig as AppConfigService);
    await service.loadCertificates();
    const agent = await service.getHttpsAgent();
    expect(agent).toBeInstanceOf(https.Agent);
  });

  it('getHttpsAgent caches agent on second call (same mtime)', async () => {
    const service = new MtlsService(mockConfig as AppConfigService);
    await service.loadCertificates();
    const agent1 = await service.getHttpsAgent();
    const agent2 = await service.getHttpsAgent();
    expect(agent1).toBe(agent2);
  });

  it('getHttpsAgent reloads when file mtime changes', async () => {
    const service = new MtlsService(mockConfig as AppConfigService);
    await service.loadCertificates();
    const agent1 = await service.getHttpsAgent();

    // Wait a bit, then update the file to force a different mtime
    await new Promise<void>((r) => setTimeout(r, 50));
    await fs.promises.writeFile(caPath, 'ca-content-updated');

    const agent2 = await service.getHttpsAgent();
    expect(agent2).not.toBe(agent1);
  });

  it('reload() forces fresh read regardless of mtime', async () => {
    const service = new MtlsService(mockConfig as AppConfigService);
    await service.loadCertificates();
    const agent1 = await service.getHttpsAgent();
    await service.reload();
    const agent2 = await service.getHttpsAgent();
    expect(agent2).not.toBe(agent1);
  });

  describe('validateServerCertCN', () => {
    it('returns true for CN in allowlist', () => {
      const pemWithTestCn = generateSelfSignedCert('test-cn');
      const service = new MtlsService(mockConfig as AppConfigService);
      expect(service.validateServerCertCN(pemWithTestCn)).toBe(true);
    });

    it('returns false for CN not in allowlist', () => {
      const pemWithOtherCn = generateSelfSignedCert('unknown-cn');
      const service = new MtlsService(mockConfig as AppConfigService);
      expect(service.validateServerCertCN(pemWithOtherCn)).toBe(false);
    });
  });
});
