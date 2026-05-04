/**
 * Wave 0 RED stubs for DnsRebindingGuard.
 * Covers: PRXY-07 (block loopback/metadata IPs), PRXY-08 (DNS cross-check before connect).
 */
describe('DnsRebindingGuard', () => {
  describe('assertSafe(hostname) (PRXY-07)', () => {
    it.todo('resolves to 127.0.0.1 → throws ForbiddenException (IPv4 loopback CIDR 127.0.0.0/8)');
    it.todo('resolves to 127.5.5.5 → throws ForbiddenException (still inside 127.0.0.0/8)');
    it.todo('resolves to ::1 → throws ForbiddenException (IPv6 loopback exact)');
    it.todo('resolves to 169.254.169.254 → throws ForbiddenException (cloud metadata)');
    it.todo('resolves to 10.0.0.5 → returns void (RFC1918 allowed per D-09)');
    it.todo('resolves to 192.168.1.1 → returns void (RFC1918 allowed per D-09)');
    it.todo('resolves to a public IP 1.1.1.1 → returns void');
  });
  describe('per-request resolution (PRXY-08, D-08)', () => {
    it.todo('does NOT cache resolution — each call hits dns.promises.lookup');
  });
});
