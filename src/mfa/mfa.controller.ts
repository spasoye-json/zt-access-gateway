import { Body, Controller, Post, Request, UnauthorizedException } from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import { VerifyMfaDto } from './dto/verify-mfa.dto';
import { MfaService } from './mfa.service';
import { UserClaims } from '../auth/auth.service';

@Controller('mfa')
export class MfaController {
  constructor(private readonly mfaService: MfaService) {}

  @Post('verify')
  async verifyChallenge(
    @Request() req: ExpressRequest & { userClaims?: UserClaims },
    @Body() payload: VerifyMfaDto,
  ) {
    const user = req.userClaims;
    if (!user) {
      throw new UnauthorizedException('Authentication required for MFA verification');
    }

    return this.mfaService.verifyChallenge(user.userId, payload.challengeId, payload.code);
  }
}
