import * as fs from 'fs';
import { MtlsService } from '../mtls.service';
import { ConfigService } from '../../config/config.service';

describe('MtlsService', () => {
  let service: MtlsService;
  let config: Partial<ConfigService>;

  beforeEach(() => {
    config = {
      getMtlsCaCertPath: jest.fn().mockReturnValue('/certs/ca.crt'),
      getMtlsCertPath: jest.fn().mockReturnValue('/certs/gateway.crt'),
      getMtlsKeyPath: jest.fn().mockReturnValue('/certs/gateway.key'),
      getMtlsAllowedSubjects: jest.fn().mockReturnValue([]),
    };
    service = new MtlsService(config as ConfigService);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('loads certificate files once and caches them', () => {
    const readSpy = jest
      .spyOn(fs, 'readFileSync')
      .mockReturnValue(Buffer.from('file'));
    jest
      .spyOn(fs, 'statSync')
      .mockReturnValue({ mtimeMs: 1 } as unknown as fs.Stats);

    service.createAgent('users-service');
    service.createAgent('users-service');

    // Only the first call should read the files (3 reads total)
    expect(readSpy).toHaveBeenCalledTimes(3);

    service.clearCache();
    service.createAgent('users-service');
    expect(readSpy).toHaveBeenCalledTimes(6);
  });

  it('validates certificate date ranges', () => {
    const validCert = {
      valid_from: new Date(Date.now() - 1000).toUTCString(),
      valid_to: new Date(Date.now() + 1000).toUTCString(),
    } as any;

    const expiredCert = {
      valid_from: new Date(Date.now() - 2000).toUTCString(),
      valid_to: new Date(Date.now() - 1000).toUTCString(),
    } as any;

    expect(service.validateCertificate(validCert)).toBe(true);
    expect(service.validateCertificate(expiredCert)).toBe(false);
    expect(service.validateCertificate(null)).toBe(false);
  });

  it('enforces allowed certificate subjects', () => {
    (config.getMtlsAllowedSubjects as jest.Mock).mockReturnValue(['orders-service']);
    const readSpy = jest
      .spyOn(fs, 'readFileSync')
      .mockReturnValue(Buffer.from('file'));
    jest
      .spyOn(fs, 'statSync')
      .mockReturnValue({ mtimeMs: 1 } as unknown as fs.Stats);

    const cert = {
      subject: { CN: 'users-service' },
      valid_from: new Date(Date.now() - 1000).toUTCString(),
      valid_to: new Date(Date.now() + 1000).toUTCString(),
    } as any;

    const error = (service as any).validateServerIdentity('users-service', cert);
    expect(error).toBeInstanceOf(Error);
  });
});
