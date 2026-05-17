import { Controller, Post, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { MfaChallenger } from '../mfa/mfa-challenger.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { extractIp, extractDeviceId } from '../shared/request-context.util';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';

/**
 * Slice E (#6) — DEMO_MODE-only shortcut for the thesis defense demo.
 *
 * Registered conditionally by DemoMfaModule.forRoot() so the route is
 * physically absent (404) when DEMO_MODE !== 'true'. The minted token is
 * indistinguishable from one produced by the production /mfa/verify flow —
 * this controller bypasses enrollment, NOT validation (PRD #1 user story 13).
 */
@Controller('demo')
@UseGuards(JwtAuthGuard)
export class DemoMfaController {
  constructor(private readonly challenger: MfaChallenger) {}

  @Post('mfa-token')
  async mint(@Req() req: Request): Promise<{ mfaToken: string; expiresAt: number }> {
    const user = (req as Request & { user: UserClaims }).user;
    const ip = extractIp(req);
    const deviceId = extractDeviceId(req) ?? '';

    const { token, expiresAt } = await this.challenger.mintDemoMfaToken({
      userId: user.userId,
      deviceId,
      ip,
    });

    return { mfaToken: token, expiresAt };
  }
}
