import { Injectable } from '@nestjs/common';
import { RevocationEntry } from './interfaces/revocation-entry.interface';

/**
 * STUB -- Compilation placeholder for JwtAuthGuard injection.
 * isRevoked() always returns false; revoke() is a no-op.
 * Plan 03-03 REPLACES this body with real D-06 implementation
 * (Map<string, RevocationEntry>, lazy eviction, TREV-01/TREV-02).
 */
@Injectable()
export class TokenRevocationService {
  revoke(jti: string, expiresAt: number, userId: string): void {
    // No-op stub -- real implementation in Plan 03-03
  }

  isRevoked(jti: string): boolean {
    return false; // Stub -- always allows. Real check in Plan 03-03.
  }

  getEntry(jti: string): RevocationEntry | undefined {
    return undefined; // Stub -- real lookup in Plan 03-03
  }

  size(): number {
    return 0;
  }
}
