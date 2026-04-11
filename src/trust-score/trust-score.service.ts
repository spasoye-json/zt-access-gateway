import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TrustTelemetryRepository, TrustSignalRecord } from './trust-telemetry.repository';

export interface TrustScoreResult {
  score: number; // 0.0 to 1.0
  level: 'LOW' | 'MEDIUM' | 'HIGH';
  factors: {
    deviceReputation: string;
    ipReputation: string;
    requestFrequency: string;
    geolocation: string;
    [key: string]: any;
  };
}

@Injectable()
export class TrustScoreService {
  private readonly logger = new Logger(TrustScoreService.name);
  private readonly weights: {
    base: number;
    device: number;
    ip: number;
    frequency: number;
    geolocation: number;
  };
  private readonly frequencyWindowMs: number;
  private readonly frequencyThreshold: number;
  private readonly activityRetentionMs: number;

  constructor(
    private readonly telemetryRepository: TrustTelemetryRepository,
    private readonly configService: ConfigService,
  ) {
    this.weights = this.loadWeights();
    this.frequencyWindowMs = Number(this.configService.get('TRUST_FREQUENCY_WINDOW_MS') ?? 60_000);
    this.frequencyThreshold = Number(this.configService.get('TRUST_FREQUENCY_THRESHOLD') ?? 25);
    this.activityRetentionMs = Number(this.configService.get('TRUST_ACTIVITY_RETENTION_MS') ?? 3_600_000);
  }

  async calculateTrustScore(
    userId: string,
    deviceId: string,
    ip: string,
    userAgent?: string,
    additionalContext?: any
  ): Promise<TrustScoreResult> {
    if (!userId || typeof userId !== 'string') {
      throw new BadRequestException('Valid userId is required');
    }

    if (!deviceId || typeof deviceId !== 'string') {
      throw new BadRequestException('Valid deviceId is required');
    }

    if (!ip || typeof ip !== 'string') {
      throw new BadRequestException('Valid IP address is required');
    }

    try {
      const normalizedIp = ip.trim();
      const locationFingerprint = this.deriveLocationFingerprint(normalizedIp);
      const historicalSignal = await this.telemetryRepository.getSignal(userId, deviceId);
      const trustedDevice = this.isTrustedDevice(deviceId, historicalSignal);
      const ipReputation = this.evaluateIpReputation(normalizedIp, historicalSignal);
      const ipTrusted = ipReputation === 'TRUSTED';
      const isConsistentLocation = this.isGeolocationConsistent(locationFingerprint, historicalSignal);
      const isHighFrequency = await this.detectHighFrequency(userId);

      let score = this.weights.base;

      score += trustedDevice ? -this.weights.device : this.weights.device;
      score += ipTrusted ? -this.weights.ip : this.weights.ip;
      score += isConsistentLocation ? -this.weights.geolocation : this.weights.geolocation;
      score += isHighFrequency ? this.weights.frequency : -this.weights.frequency / 2;

      score = Math.max(0, Math.min(1, score));

      let level: 'LOW' | 'MEDIUM' | 'HIGH' = 'MEDIUM';
      if (score < 0.3) {
        level = 'LOW';
      } else if (score > 0.7) {
        level = 'HIGH';
      }

      await Promise.all([
        this.telemetryRepository.upsertSignal({
          userId,
          deviceId,
          ip: normalizedIp,
          locationFingerprint,
        }),
        this.telemetryRepository.recordActivity(userId),
        this.telemetryRepository.cleanupActivity(this.activityRetentionMs),
      ]);

      return {
        score,
        level,
        factors: {
          deviceReputation: trustedDevice ? 'TRUSTED' : 'UNKNOWN',
          ipReputation,
          requestFrequency: isHighFrequency ? 'HIGH' : 'NORMAL',
          geolocation: isConsistentLocation ? 'CONSISTENT' : 'INCONSISTENT',
        },
      };
    } catch (error) {
      this.logger.error('Error calculating trust score:', error);
      throw error;
    }
  }

  private loadWeights() {
    const base = Number(this.configService.get('TRUST_WEIGHT_BASE') ?? 0.5);
    const device = Number(this.configService.get('TRUST_WEIGHT_DEVICE') ?? 0.15);
    const ip = Number(this.configService.get('TRUST_WEIGHT_IP') ?? 0.15);
    const frequency = Number(this.configService.get('TRUST_WEIGHT_FREQUENCY') ?? 0.2);
    const geolocation = Number(this.configService.get('TRUST_WEIGHT_GEO') ?? 0.2);
    return { base, device, ip, frequency, geolocation };
  }

  private deriveLocationFingerprint(ip: string): string {
    const parts = ip.split('.');
    if (parts.length < 2) return 'unknown';
    return `${parts[0]}.${parts[1]}`;
  }

  private isTrustedDevice(deviceId: string, historical: TrustSignalRecord | null): boolean {
    if (!deviceId) {
      return false;
    }
    return Boolean(historical);
  }

  private evaluateIpReputation(
    ip: string,
    historical: TrustSignalRecord | null,
  ): 'TRUSTED' | 'UNTRUSTED' | 'SUSPICIOUS' {
    if (!this.isValidIp(ip)) {
      return 'SUSPICIOUS';
    }

    if (this.isKnownUntrustedNetwork(ip)) {
      return 'UNTRUSTED';
    }

    if (historical?.lastIp === ip) {
      return 'TRUSTED';
    }

    if (this.isPrivateNetwork(ip)) {
      return 'SUSPICIOUS';
    }

    return 'SUSPICIOUS';
  }

  private isValidIp(ip: string): boolean {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipv4Regex.test(ip);
  }

  private isGeolocationConsistent(
    locationFingerprint: string,
    historical: TrustSignalRecord | null,
  ): boolean {
    if (!historical?.locationFingerprint) {
      return true;
    }
    return historical.locationFingerprint === locationFingerprint;
  }

  private isPrivateNetwork(ip: string): boolean {
    return (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)
    );
  }

  private isKnownUntrustedNetwork(ip: string): boolean {
    return (
      ip.startsWith('127.') ||
      ip.startsWith('0.') ||
      ip.startsWith('192.168.2')
    );
  }

  private async detectHighFrequency(userId: string): Promise<boolean> {
    const count = await this.telemetryRepository.countRecentActivity(
      userId,
      this.frequencyWindowMs,
    );
    return count > this.frequencyThreshold;
  }
}
