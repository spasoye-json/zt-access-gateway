import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { CertMonitorService } from '../cert-monitor.service';
import { MtlsService } from '../mtls.service';
import type { MtlsConfig } from '../../config/slices';

async function createTempCertFiles(): Promise<{
  dir: string;
  caPath: string;
  certPath: string;
  keyPath: string;
}> {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'cert-monitor-test-'));
  const caPath = path.join(dir, 'ca.pem');
  const certPath = path.join(dir, 'cert.pem');
  const keyPath = path.join(dir, 'key.pem');

  await fs.promises.writeFile(caPath, 'ca-content');
  await fs.promises.writeFile(certPath, 'cert-content');
  await fs.promises.writeFile(keyPath, 'key-content');

  return { dir, caPath, certPath, keyPath };
}

describe('CertMonitorService', () => {
  let tmpDir: string;
  let caPath: string;
  let certPath: string;
  let keyPath: string;
  let mockConfig: Partial<MtlsConfig>;
  let mockMtlsService: { reload: jest.Mock };

  beforeEach(async () => {
    jest.useFakeTimers();
    const files = await createTempCertFiles();
    tmpDir = files.dir;
    caPath = files.caPath;
    certPath = files.certPath;
    keyPath = files.keyPath;

    mockConfig = {
      caCertPath: caPath,
      clientCertPath: certPath,
      clientKeyPath: keyPath,
    };

    mockMtlsService = { reload: jest.fn().mockResolvedValue(undefined) };
  });

  afterEach(async () => {
    jest.useRealTimers();
    await fs.promises.rm(tmpDir, { recursive: true, force: true });
  });

  it('starts polling on module init and does NOT call reload when files unchanged', async () => {
    const service = new CertMonitorService(
      mockMtlsService as unknown as MtlsService,
      mockConfig as MtlsConfig,
    );
    await service.onModuleInit();

    // Advance timer past polling interval
    jest.advanceTimersByTime(30_000);
    // Let microtasks run (the async checkFiles callback)
    await Promise.resolve();

    expect(mockMtlsService.reload).not.toHaveBeenCalled();
  });

  it('calls reload when cert file mtime changes', async () => {
    jest.useRealTimers();

    const service = new CertMonitorService(
      mockMtlsService as unknown as MtlsService,
      mockConfig as MtlsConfig,
    );
    await service.onModuleInit();

    // Change a file to alter mtime
    await new Promise<void>((r) => setTimeout(r, 50));
    await fs.promises.writeFile(caPath, 'ca-content-changed');

    // Manually trigger the check (bypassing timer)
    await (service as any).checkFiles();

    expect(mockMtlsService.reload).toHaveBeenCalledTimes(1);

    await service.onModuleDestroy();
  });

  it('stops polling on module destroy', async () => {
    const service = new CertMonitorService(
      mockMtlsService as unknown as MtlsService,
      mockConfig as MtlsConfig,
    );
    await service.onModuleInit();
    await service.onModuleDestroy();

    // Advance timers — no more polling should occur
    jest.advanceTimersByTime(60_000);
    await Promise.resolve();

    expect(mockMtlsService.reload).not.toHaveBeenCalled();
  });

  it('does not call reload when files unchanged across multiple intervals', async () => {
    const service = new CertMonitorService(
      mockMtlsService as unknown as MtlsService,
      mockConfig as MtlsConfig,
    );
    await service.onModuleInit();

    // Advance through 3 polling intervals
    jest.advanceTimersByTime(90_000);
    await Promise.resolve();

    expect(mockMtlsService.reload).not.toHaveBeenCalled();

    await service.onModuleDestroy();
  });

  it('does not use fs.watch (polling only)', () => {
    // Verify the implementation file does not use fs.watch
    // This is an acceptance test — actual enforcement is in the acceptance criteria
    const serviceSource = require('fs').readFileSync(
      require('path').join(__dirname, '..', 'cert-monitor.service.ts'),
      'utf8',
    );
    expect(serviceSource).not.toContain('fs.watch');
    expect(serviceSource).toContain('setInterval');
  });
});
