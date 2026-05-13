import {
  Controller,
  Post,
  Body,
  Req,
  ForbiddenException,
  UnauthorizedException,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import type { Request } from 'express';
import { TokenRevocationService } from './token-revocation.service';
import { RevokeTokenDto } from './dto/revoke-token.dto';
import { UserClaims } from './interfaces/user-claims.interface';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AUTH_TOKEN_REVOKED } from '../metrics/metrics-events';
import { TypedEvents } from '../shared/typed-events';

/**
 * Auth controller -- POST /auth/revoke endpoint (TREV-03).
 *
 * Phase 10 (D-02 + D-04): JwtAuthGuard was previously global via APP_GUARD;
 * now applied per-method with @UseGuards because /auth/revoke is an AUTH_ONLY
 * path (D-04) -- GatewayMiddleware runs auth+revocation on the AUTH_ONLY
 * codepath but does NOT attach the guard, so we re-attach explicitly here.
 * Idempotent -- the guard recognizes when req.user is already populated.
 *
 * Ownership rules (D-07):
 * - Any authenticated user can revoke their OWN tokens
 * - Admin role can revoke ANY token
 * - Non-admin revoking another user's token -> 403 ForbiddenException
 *
 * Idempotent -- revoking the same jti twice overwrites cleanly (Pitfall 7).
 * Uniform response for new and already-revoked JTIs prevents enumeration (T-3-10).
 *
 * Phase 14 Plan 01: emits AUTH_TOKEN_REVOKED after a successful revoke so
 * MetricsService.incrementTokenRevocation increments the counter via @OnEvent.
 */
@Controller('auth')
export class AuthController {
  constructor(
    private readonly revocationService: TokenRevocationService,
    private readonly events: TypedEvents,
  ) {}

  /**
   * Revoke a JWT by its jti claim.
   * @param dto - { jti, exp } where exp is Unix seconds
   * @param req - Express request with user attached by JwtAuthGuard
   */
  @UseGuards(JwtAuthGuard)
  @Post('revoke')
  @HttpCode(HttpStatus.OK)
  revoke(@Body() dto: RevokeTokenDto, @Req() req: Request): { message: string } {
    // WR-06 (phase 14): req.user is typed via src/shared/express.d.ts. Keep a
    // defensive check so this endpoint fails closed if JwtAuthGuard is ever
    // misconfigured (e.g., AUTH_ONLY pipeline skipped) instead of crashing on
    // .roles.includes at runtime.
    const user: UserClaims | undefined = req.user;
    if (!user) {
      throw new UnauthorizedException('Missing authenticated user');
    }

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
    this.events.emit(AUTH_TOKEN_REVOKED, {});

    return { message: 'Token revoked' };
  }
}
