import {
  Controller,
  Post,
  Body,
  Req,
  ForbiddenException,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { TokenRevocationService } from './token-revocation.service';
import { RevokeTokenDto } from './dto/revoke-token.dto';
import { UserClaims } from './interfaces/user-claims.interface';

/**
 * Auth controller -- POST /auth/revoke endpoint (TREV-03).
 *
 * Ownership rules (D-07):
 * - Any authenticated user can revoke their OWN tokens
 * - Admin role can revoke ANY token
 * - Non-admin revoking another user's token -> 403 ForbiddenException
 *
 * Idempotent -- revoking the same jti twice overwrites cleanly (Pitfall 7).
 * Uniform response for new and already-revoked JTIs prevents enumeration (T-3-10).
 */
@Controller('auth')
export class AuthController {
  constructor(private readonly revocationService: TokenRevocationService) {}

  /**
   * Revoke a JWT by its jti claim.
   * @param dto - { jti, exp } where exp is Unix seconds
   * @param req - Express request with user attached by JwtAuthGuard
   */
  @Post('revoke')
  @HttpCode(HttpStatus.OK)
  revoke(@Body() dto: RevokeTokenDto, @Req() req: any): { message: string } {
    const user = req.user as UserClaims;

    // Convert exp from seconds (JWT standard) to milliseconds (internal storage)
    const expiresAtMs = dto.exp * 1000;

    // D-07: ownership check -- non-admin can only revoke own tokens
    const isAdmin = user.roles.includes('admin');

    if (!isAdmin) {
      // Check if this jti was already revoked by someone else
      const existing = this.revocationService.getEntry(dto.jti);
      if (existing && existing.userId !== user.userId) {
        throw new ForbiddenException("Cannot revoke another user's token");
      }
    }

    this.revocationService.revoke(dto.jti, expiresAtMs, user.userId);

    return { message: 'Token revoked' };
  }
}
