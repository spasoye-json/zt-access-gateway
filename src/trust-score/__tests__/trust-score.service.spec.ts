import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { TrustScoreService } from '../trust-score.service';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';

describe('TrustScoreService', () => {
  let service: TrustScoreService;
  let mockTelemetryRepository: Partial<TrustTelemetryRepository>;
  let mockConfigService: Partial<ConfigService>;

  beforeEach(async () => {
    mockTelemetryRepository = {
      getSignal: jest.fn().mockResolvedValue(null),
      upsertSignal: jest.fn().mockResolvedValue(undefined),
      recordActivity: jest.fn().mockResolvedValue(undefined),
      cleanupActivity: jest.fn().mockResolvedValue(undefined),
      countRecentActivity: jest.fn().mockResolvedValue(0),
    };

    mockConfigService = {
      get: jest.fn().mockReturnValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TrustScoreService,
        { provide: TrustTelemetryRepository, useValue: mockTelemetryRepository },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<TrustScoreService>(TrustScoreService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('calculateTrustScore', () => {
    it('should calculate trust score based on provided factors', async () => {
      const result = await service.calculateTrustScore(
        'user123',
        'trusted-device',
        '192.168.1.100'
      );

      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('level');
      expect(result).toHaveProperty('factors');
      expect(typeof result.score).toBe('number');
      expect(result.level).toMatch(/^(LOW|MEDIUM|HIGH)$/);
      expect(result.factors).toHaveProperty('deviceReputation');
      expect(result.factors).toHaveProperty('ipReputation');
    });

    it('should return LOW level for trusted device and IP', async () => {
      (mockTelemetryRepository.getSignal as jest.Mock).mockResolvedValue({
        userId: 'user123',
        deviceId: 'trusted-device123',
        lastIp: '192.168.1.100',
        locationFingerprint: '192.168',
        lastSeenAt: new Date(),
      });

      const result = await service.calculateTrustScore(
        'user123',
        'trusted-device123',
        '192.168.1.101'
      );

      expect(result.level).toBe('LOW');
      expect(result.score).toBeLessThan(0.25);
    });

    it('should flag medium/high risk for untrusted device or IP anomalies', async () => {
      (mockTelemetryRepository.countRecentActivity as jest.Mock).mockResolvedValue(50);
      const result = await service.calculateTrustScore(
        'user123',
        'untrusted-device',
        '192.168.2.10'
      );

      expect(result.level).toBe('HIGH');
      expect(result.factors.requestFrequency).toBe('HIGH');
      expect(result.factors.ipReputation).toBe('UNTRUSTED');
    });

    it('should throw error for invalid userId', async () => {
      await expect(service.calculateTrustScore(
        null as any,
        'device123',
        '192.168.1.100'
      )).rejects.toThrow();
    });

    it('should throw error for invalid deviceId', async () => {
      await expect(service.calculateTrustScore(
        'user123',
        null as any,
        '192.168.1.100'
      )).rejects.toThrow();
    });

    it('should throw error for invalid IP', async () => {
      await expect(service.calculateTrustScore(
        'user123',
        'device123',
        null as any
      )).rejects.toThrow();
    });
  });
});
