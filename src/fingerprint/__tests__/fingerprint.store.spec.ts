import { FingerprintStore } from '../fingerprint.store';

describe('FingerprintStore', () => {
  let store: FingerprintStore;
  let dateSpy: jest.SpyInstance;

  beforeEach(() => {
    store = new FingerprintStore();
    dateSpy = jest.spyOn(Date, 'now');
  });

  afterEach(() => {
    dateSpy.mockRestore();
  });

  describe('add / isBlacklisted', () => {
    it('stores a fingerprint and isBlacklisted returns true before TTL expires', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);
      store.add('fp-abc', { ttlMs: 5000, isTerminal: false });

      dateSpy.mockReturnValue(now + 4999);
      expect(store.isBlacklisted('fp-abc')).toBe(true);
    });

    it('isBlacklisted returns false for unknown fingerprints', () => {
      expect(store.isBlacklisted('unknown-fp')).toBe(false);
    });

    it('isBlacklisted returns false and deletes entry after TTL expires (lazy eviction)', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);
      store.add('fp-expired', { ttlMs: 5000, isTerminal: false });

      // Advance time past TTL
      dateSpy.mockReturnValue(now + 5001);
      expect(store.isBlacklisted('fp-expired')).toBe(false);

      // Confirm lazy eviction: entry removed from map
      expect(store.size()).toBe(0);
    });
  });

  describe('isTerminal', () => {
    it('returns true for entries added with isTerminal: true', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);
      store.add('fp-terminal', { ttlMs: 5000, isTerminal: true });

      dateSpy.mockReturnValue(now + 1000);
      expect(store.isTerminal('fp-terminal')).toBe(true);
    });

    it('returns false for entries added with isTerminal: false', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);
      store.add('fp-nonterminal', { ttlMs: 5000, isTerminal: false });

      dateSpy.mockReturnValue(now + 1000);
      expect(store.isTerminal('fp-nonterminal')).toBe(false);
    });

    it('returns false for expired entries', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);
      store.add('fp-expired-terminal', { ttlMs: 5000, isTerminal: true });

      dateSpy.mockReturnValue(now + 5001);
      expect(store.isTerminal('fp-expired-terminal')).toBe(false);
    });

    it('returns false for unknown fingerprints', () => {
      expect(store.isTerminal('unknown-fp')).toBe(false);
    });
  });

  describe('size', () => {
    it('returns current Map size (includes expired until evicted)', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);
      expect(store.size()).toBe(0);

      store.add('fp-1', { ttlMs: 5000, isTerminal: false });
      store.add('fp-2', { ttlMs: 5000, isTerminal: true });
      expect(store.size()).toBe(2);

      // Even after expiry, size reflects map until lazy eviction
      dateSpy.mockReturnValue(now + 5001);
      expect(store.size()).toBe(2);

      // After a read triggers eviction for fp-1
      store.isBlacklisted('fp-1');
      expect(store.size()).toBe(1);
    });
  });

  describe('clear', () => {
    it('empties the entire blacklist', () => {
      const now = 1_000_000;
      dateSpy.mockReturnValue(now);
      store.add('fp-1', { ttlMs: 5000, isTerminal: false });
      store.add('fp-2', { ttlMs: 5000, isTerminal: true });
      expect(store.size()).toBe(2);

      store.clear();
      expect(store.size()).toBe(0);
      expect(store.isBlacklisted('fp-1')).toBe(false);
      expect(store.isBlacklisted('fp-2')).toBe(false);
    });
  });
});
