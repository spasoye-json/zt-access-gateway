import { UsedNonceStore } from '../used-nonce-store';

describe('UsedNonceStore', () => {
  const nowSec = () => Math.floor(Date.now() / 1000);

  describe('has', () => {
    it('returns false for unknown nonce', () => {
      const store = new UsedNonceStore(10);
      expect(store.has('unknown')).toBe(false);
    });

    it('returns true within TTL after add', () => {
      const store = new UsedNonceStore(10);
      store.add('n1', nowSec() + 60);
      expect(store.has('n1')).toBe(true);
    });

    it('lazy-evicts expired entries (exp uses Unix seconds)', () => {
      const store = new UsedNonceStore(10);
      store.add('expired', nowSec() - 1);
      expect(store.has('expired')).toBe(false);
      expect(store.size()).toBe(0); // evicted
    });
  });

  describe('add', () => {
    it('FIFO-evicts oldest entry when at capacity (Map insertion order)', () => {
      const store = new UsedNonceStore(3);
      const exp = nowSec() + 60;
      store.add('a', exp);
      store.add('b', exp);
      store.add('c', exp);
      expect(store.size()).toBe(3);
      store.add('d', exp);
      expect(store.size()).toBe(3);
      expect(store.has('a')).toBe(false); // evicted
      expect(store.has('b')).toBe(true);
      expect(store.has('c')).toBe(true);
      expect(store.has('d')).toBe(true);
    });
  });

  describe('size + clear', () => {
    it('size reflects current entries', () => {
      const store = new UsedNonceStore(10);
      store.add('a', nowSec() + 60);
      store.add('b', nowSec() + 60);
      expect(store.size()).toBe(2);
    });

    it('clear empties the store', () => {
      const store = new UsedNonceStore(10);
      store.add('a', nowSec() + 60);
      store.clear();
      expect(store.size()).toBe(0);
      expect(store.has('a')).toBe(false);
    });
  });
});
