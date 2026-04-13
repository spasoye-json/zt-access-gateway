/**
 * Entry in the token revocation blacklist (D-06).
 * Stored in Map<jti, RevocationEntry> with lazy eviction on lookup.
 */
export interface RevocationEntry {
  /** Unix ms -- when the original token expires (eviction threshold) */
  expiresAt: number;
  /** Who owns the token -- for D-07 ownership checks on revoke endpoint */
  userId: string;
}
