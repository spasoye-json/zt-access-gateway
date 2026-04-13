import { TokenRevocationService } from '../token-revocation.service';

/**
 * TokenRevocationService unit tests -- TDD RED phase.
 * Tests will fail on import until token-revocation.service.ts is created in Wave 2.
 *
 * Coverage: TREV-01, TREV-02, D-06, D-07
 */
describe('TokenRevocationService', () => {
  let service: TokenRevocationService;
  let dateSpy: jest.SpyInstance;

  beforeEach(() => {
    service = new TokenRevocationService();
    dateSpy = jest.spyOn(Date, 'now');
  });

  afterEach(() => {
    dateSpy.mockRestore();
  });

  describe('revoke (TREV-01, D-06)', () => {
    it('adds jti to blacklist with expiresAt and userId', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);

      service.revoke('jti-1', now + 3600_000, 'user-1');
      expect(service.isRevoked('jti-1')).toBe(true);
      expect(service.size()).toBe(1);
    });

    it('isRevoked returns true for revoked jti', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);

      service.revoke('jti-revoked', now + 3600_000, 'user-1');
      expect(service.isRevoked('jti-revoked')).toBe(true);
    });

    it('isRevoked returns false for unknown jti', () => {
      expect(service.isRevoked('jti-unknown')).toBe(false);
    });
  });

  describe('lazy eviction (TREV-02, D-06)', () => {
    it('returns false for expired entries (lazy eviction)', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);

      service.revoke('jti-expired', now + 5000, 'user-1');

      // Advance time past expiresAt
      dateSpy.mockReturnValue(now + 5001);
      expect(service.isRevoked('jti-expired')).toBe(false);
    });

    it('removes expired entry from map on lookup', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);

      service.revoke('jti-to-evict', now + 5000, 'user-1');
      expect(service.size()).toBe(1);

      // Advance past expiry and trigger eviction via lookup
      dateSpy.mockReturnValue(now + 5001);
      service.isRevoked('jti-to-evict');
      expect(service.size()).toBe(0);
    });

    it('size decreases after lazy eviction', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);

      service.revoke('jti-a', now + 5000, 'user-1');
      service.revoke('jti-b', now + 10000, 'user-2');
      expect(service.size()).toBe(2);

      // Expire only jti-a
      dateSpy.mockReturnValue(now + 5001);
      service.isRevoked('jti-a');
      expect(service.size()).toBe(1);

      // jti-b still active
      expect(service.isRevoked('jti-b')).toBe(true);
    });
  });

  describe('getEntry (D-07 ownership support)', () => {
    it('returns RevocationEntry with userId for active revocation', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);

      service.revoke('jti-owned', now + 3600_000, 'owner-1');
      const entry = service.getEntry('jti-owned');

      expect(entry).toBeDefined();
      expect(entry!.userId).toBe('owner-1');
      expect(entry!.expiresAt).toBe(now + 3600_000);
    });

    it('returns undefined for expired revocation', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);

      service.revoke('jti-old', now + 5000, 'user-1');

      dateSpy.mockReturnValue(now + 5001);
      expect(service.getEntry('jti-old')).toBeUndefined();
    });

    it('returns undefined for unknown jti', () => {
      expect(service.getEntry('jti-nonexistent')).toBeUndefined();
    });
  });
});
