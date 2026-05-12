import {
  Controller,
  Post,
  Delete,
  Body,
  Param,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  UseGuards,
  InternalServerErrorException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { AppConfigService } from '../config/config.service';
import {
  MfaService,
  type MfaCreateResult,
  type MfaVerifyResult,
  type MfaEnrollResult,
  type MfaConfirmResult,
} from './mfa.service';
import { InitiateMfaDto } from './dto/initiate-mfa.dto';
import { VerifyMfaDto } from './dto/verify-mfa.dto';
import { EnrollConfirmDto } from './dto/enroll-confirm.dto';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import { extractIp, extractDeviceId, extractJa4h } from '../shared/request-context.util';
import { Roles } from '../auth/roles.decorator';

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

  // ──────────────────────────────────────────────────────────────────────────
  // Phase 11 — Enrollment routes (D-09)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Phase 11 — POST /mfa/enroll (D-01).
   * Authenticated user requests a new TOTP secret. Server stashes pending entry,
   * returns enrollmentId + otpauthUri. Client renders QR; secret never leaves server
   * memory until confirmEnrollment commits it (D-05).
   */
  @Post('enroll')
  async enroll(@Req() req: Request, @Res() res: Response): Promise<void> {
    const user = (req as Request & { user: UserClaims }).user;
    const result = await this.mfaService.createEnrollment(user.userId, user.email);

    if (!result.ok) {
      const failResult = result as Extract<MfaEnrollResult, { ok: false }>;
      if (failResult.reason === 'already_enrolled') {
        // D-06: 409 Conflict, not 400 (Pitfall 2)
        res.status(409).json({ error: 'already_enrolled' });
        return;
      }
      res.status(500).json({ error: 'enrollment_internal' });
      return;
    }

    res.status(201).json({
      enrollmentId: result.enrollmentId,
      otpauthUri: result.otpauthUri,
    });
  }

  /**
   * Phase 11 — POST /mfa/enroll/confirm (D-04).
   * User submits the TOTP code from their authenticator app to commit enrollment.
   * Failures (expired_enrollment / invalid_totp / user_mismatch) → 400. Internal → 500.
   */
  @Post('enroll/confirm')
  async confirmEnrollment(
    @Body() dto: EnrollConfirmDto,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const user = (req as Request & { user: UserClaims }).user;
    // IN-04 (phase 14, iter3): plumb ip + ja4h into confirmEnrollment so the
    // MFA_FAILED / MFA_RATE_LIMITED emissions carry network identity (parity
    // with /mfa/verify).
    const ip = extractIp(req);
    const ja4h = extractJa4h(req as never);
    const result = await this.mfaService.confirmEnrollment(
      dto.enrollmentId,
      dto.totpCode,
      user.userId,
      ip,
      ja4h,
    );

    if (!result.ok) {
      const failResult = result as Extract<MfaConfirmResult, { ok: false }>;
      if (failResult.reason === 'internal') {
        res.status(500).json({ error: 'enrollment_internal' });
        return;
      }
      res.status(400).json({ error: 'enrollment_failed', reason: failResult.reason });
      return;
    }

    res.status(200).json({});
  }

  /**
   * Phase 11 — DELETE /mfa/admin/enrollment/:userId (D-07).
   *
   * Method-level @Roles('admin') (Pitfall 5) — class-level would block /mfa/enroll
   * for non-admin users. RolesGuard.getAllAndOverride picks the method metadata first.
   * Returns { deleted: true|false }; does NOT distinguish 404 vs success because the
   * admin's intent is "ensure this user has no enrollment", which is satisfied either way.
   */
  @Delete('admin/enrollment/:userId')
  @Roles('admin')
  @HttpCode(HttpStatus.OK)
  async adminDeleteEnrollment(@Param('userId') userId: string): Promise<{ deleted: boolean }> {
    const result = await this.mfaService.deleteEnrollment(userId);
    if (!result.ok) {
      throw new InternalServerErrorException();
    }
    return { deleted: result.deleted };
  }
}
