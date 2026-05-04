/**
 * Unit tests for DnsRebindingGuard.
 * Covers: PRXY-07 (block loopback/metadata IPs), PRXY-08 (DNS cross-check before connect), D-08/D-09.
 */
import { ForbiddenException, Logger } from '@nestjs/common';

jest.mock('node:dns', () => ({
  promises: { lookup: jest.fn() },
}));

import * as dns from 'node:dns';
import { DnsRebindingGuard } from '../dns-rebinding.guard';

const lookupMock = dns.promises.lookup as unknown as jest.Mock;

describe('DnsRebindingGuard', () => {
  let guard: DnsRebindingGuard;

  beforeEach(() => {
    guard = new DnsRebindingGuard();
    lookupMock.mockReset();
  });

  describe('assertSafe(hostname) (PRXY-07)', () => {
    it('resolves to 127.0.0.1 → throws ForbiddenException (IPv4 loopback CIDR 127.0.0.0/8)', async () => {
      lookupMock.mockResolvedValueOnce({ address: '127.0.0.1', family: 4 });
      await expect(guard.assertSafe('localhost')).rejects.toThrow(ForbiddenException);
    });

    it('resolves to 127.5.5.5 → throws ForbiddenException (still inside 127.0.0.0/8)', async () => {
      lookupMock.mockResolvedValueOnce({ address: '127.5.5.5', family: 4 });
      await expect(guard.assertSafe('host')).rejects.toThrow(ForbiddenException);
    });

    it('resolves to ::1 → throws ForbiddenException (IPv6 loopback exact)', async () => {
      lookupMock.mockResolvedValueOnce({ address: '::1', family: 6 });
      await expect(guard.assertSafe('host')).rejects.toThrow(ForbiddenException);
    });

    it('resolves to 169.254.169.254 → throws ForbiddenException (cloud metadata)', async () => {
      lookupMock.mockResolvedValueOnce({ address: '169.254.169.254', family: 4 });
      await expect(guard.assertSafe('aws')).rejects.toThrow(ForbiddenException);
    });

    it('resolves to 10.0.0.5 → returns void (RFC1918 allowed per D-09)', async () => {
      lookupMock.mockResolvedValueOnce({ address: '10.0.0.5', family: 4 });
      await expect(guard.assertSafe('users')).resolves.toBeUndefined();
    });

    it('resolves to 192.168.1.1 → returns void (RFC1918 allowed per D-09)', async () => {
      lookupMock.mockResolvedValueOnce({ address: '192.168.1.1', family: 4 });
      await expect(guard.assertSafe('users')).resolves.toBeUndefined();
    });

    it('resolves to a public IP 1.1.1.1 → returns void', async () => {
      lookupMock.mockResolvedValueOnce({ address: '1.1.1.1', family: 4 });
      await expect(guard.assertSafe('cf')).resolves.toBeUndefined();
    });

    it('logs warn when blocking a resolved address', async () => {
      const warnSpy = jest.spyOn(Logger.prototype, 'warn');
      lookupMock.mockResolvedValueOnce({ address: '127.0.0.1', family: 4 });
      await expect(guard.assertSafe('localhost')).rejects.toThrow(ForbiddenException);
      expect(warnSpy).toHaveBeenCalled();
      warnSpy.mockRestore();
    });
  });

  describe('per-request resolution (PRXY-08, D-08)', () => {
    it('does NOT cache resolution — each call hits dns.promises.lookup', async () => {
      lookupMock.mockResolvedValue({ address: '1.1.1.1', family: 4 });
      await guard.assertSafe('cf');
      await guard.assertSafe('cf');
      expect(lookupMock.mock.calls.length).toBe(2);
    });
  });
});
