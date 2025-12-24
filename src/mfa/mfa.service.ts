import { Injectable, Logger, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { MfaRepository } from './mfa.repository';

export interface MfaChallenge {
  challengeId: string;
  expiresAt: string;
}

export interface MfaToken {
  mfaToken: string;
  expiresAt: string;
}

@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly repository: MfaRepository,
  ) {}

  async initiateChallenge(params: {
    userId: string;
    sessionId?: string;
    method: string;
    path: string;
    deviceId: string;
    ip: string;
  }): Promise<MfaChallenge> {
    await this.pruneExpired();

    if (!params.userId) {
      throw new BadRequestException('User identifier is required for MFA challenge');
    }

    const challengeId = this.generateId('chal');
    const code = this.generateCode();
    const expiresAt = new Date(Date.now() + this.getChallengeTtlMs());

    await this.repository.createChallenge({
      challengeId,
      userId: params.userId,
      code,
      expiresAt,
      metadata: {
        method: params.method,
        path: params.path,
        deviceId: params.deviceId,
        ip: params.ip,
        sessionId: params.sessionId,
      },
    });

    this.logger.log(
      `MFA challenge issued for user=${params.userId} challengeId=${challengeId} code=${code}`,
    );

    return {
      challengeId,
      expiresAt: expiresAt.toISOString(),
    };
  }

  async verifyChallenge(userId: string, challengeId: string, code: string): Promise<MfaToken> {
    await this.pruneExpired();

    const record = await this.repository.findChallenge(challengeId);
    if (!record || record.userId !== userId) {
      throw new BadRequestException('Invalid or unknown challenge');
    }

    if (record.verifiedAt) {
      throw new BadRequestException('Challenge already verified');
    }

    if (record.expiresAt.getTime() < Date.now()) {
      await this.repository.deleteChallenge(challengeId);
      throw new UnauthorizedException('Challenge has expired');
    }

    if (record.code !== code) {
      throw new UnauthorizedException('Invalid verification code');
    }

    const token = this.generateId('mfa');
    const expiresAt = new Date(Date.now() + this.getTokenTtlMs());

    await this.repository.markChallengeVerified(challengeId);
    await this.repository.createToken({
      token,
      userId,
      challengeId,
      expiresAt,
    });

    this.logger.log(`MFA challenge verified for user=${userId} challengeId=${challengeId}`);

    return {
      mfaToken: token,
      expiresAt: expiresAt.toISOString(),
    };
  }

  async isTokenValid(userId: string, token?: string | null): Promise<boolean> {
    if (!token) {
      return false;
    }

    await this.pruneExpired();

    const record = await this.repository.findToken(token);
    if (!record || record.userId !== userId) {
      return false;
    }

    if (record.expiresAt.getTime() < Date.now()) {
      await this.repository.deleteToken(token);
      return false;
    }

    return true;
  }

  private async pruneExpired() {
    await this.repository.cleanupExpired(new Date());
  }

  private generateId(prefix: string): string {
    return `${prefix}-${randomBytes(8).toString('hex')}`;
  }

  private generateCode(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  private getChallengeTtlMs(): number {
    const value = Number(this.configService.get('MFA_CHALLENGE_TTL_MS'));
    return Number.isFinite(value) && value > 0 ? value : 5 * 60 * 1000;
  }

  private getTokenTtlMs(): number {
    const value = Number(this.configService.get('MFA_TOKEN_TTL_MS'));
    return Number.isFinite(value) && value > 0 ? value : 10 * 60 * 1000;
  }
}
