import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { AppConfigService } from '../config/config.service';
import { MfaService, type MfaCreateResult, type MfaVerifyResult } from './mfa.service';
import { InitiateMfaDto } from './dto/initiate-mfa.dto';
import { VerifyMfaDto } from './dto/verify-mfa.dto';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import { extractIp, extractDeviceId, extractJa4h } from '../shared/request-context.util';

/**
 * Phase 7 — MfaController (D-01, D-04).
 *
 * Both endpoints use @UseGuards(JwtAuthGuard) — NOT @Public(). The JwtAuthGuard
 * is already an APP_GUARD; this decorator is explicit for clarity per D-04.
 * Endpoints are excluded from gateway pipeline evaluation (same exemption as /auth/revoke).
 *
 * POST /mfa/initiate — creates challenge; rate-limited per D-17.
 * POST /mfa/verify   — validates TOTP code; mints fingerprint-bound MFA JWT.
 */
@Controller('mfa')
@UseGuards(JwtAuthGuard)
export class MfaController {
  constructor(
    private readonly mfaService: MfaService,
    private readonly config: AppConfigService,
  ) {}

  @Post('initiate')
  @HttpCode(HttpStatus.CREATED)
  async initiate(
    @Body() _dto: InitiateMfaDto,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const user = (req as Request & { user: UserClaims }).user;
    const ip = extractIp(req);
    const ja4h = extractJa4h(req as never);

    const result = await this.mfaService.createChallenge(user.userId, ip, ja4h);

    if (!result.ok) {
      const failResult = result as Extract<MfaCreateResult, { ok: false }>;
      if (failResult.reason === 'rate_limited') {
        // D-17: Retry-After from config, not hardcoded
        const windowSec = Math.ceil(this.config.mfaRateLimitWindowMs / 1000);
        res
          .status(429)
          .header('Retry-After', String(windowSec))
          .json({ error: 'mfa_rate_limited' });
        return;
      }
      res.status(500).json({ error: 'mfa_internal' });
      return;
    }

    res.status(201).json({ challengeId: result.challengeId, expiresAt: result.expiresAt });
  }

  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verify(
    @Body() dto: VerifyMfaDto,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const user = (req as Request & { user: UserClaims }).user;
    const ip = extractIp(req);
    const deviceId = extractDeviceId(req);
    const ja4h = extractJa4h(req as never);

    const result = await this.mfaService.verifyTotp(
      dto.challengeId,
      dto.totpCode,
      user.userId,
      ip,
      deviceId ?? '',
      ja4h,
    );

    if (!result.ok) {
      const failResult = result as Extract<MfaVerifyResult, { ok: false }>;
      res.status(401).json({ error: 'mfa_invalid', reason: failResult.reason });
      return;
    }

    res.status(200).json({ token: result.token, expiresAt: result.expiresAt });
  }
}
