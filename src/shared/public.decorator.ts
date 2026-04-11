import { SetMetadata } from '@nestjs/common';

/**
 * Constant key used by guards (Phase 3 JwtAuthGuard) to detect public routes.
 */
export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Mark a route as public — it bypasses the authentication guard.
 * The JwtAuthGuard checks this via NestJS Reflector.
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
