import { extractIp, extractUserAgent, extractDeviceId, extractJa4h } from '../request-context.util';
import { Request } from 'express';

function makeReq(overrides: Partial<{
  headers: Record<string, string | string[]>;
  socket: { remoteAddress?: string };
}>): Request {
  return {
    headers: {},
    socket: {},
    ...overrides,
  } as unknown as Request;
}

describe('extractIp', () => {
  it('returns first IP from x-forwarded-for', () => {
    const req = makeReq({ headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' } });
    expect(extractIp(req)).toBe('1.2.3.4');
  });

  it('returns socket remoteAddress when no x-forwarded-for', () => {
    const req = makeReq({ socket: { remoteAddress: '10.0.0.1' } });
    expect(extractIp(req)).toBe('10.0.0.1');
  });

  it("returns 'unknown' when no IP source available", () => {
    const req = makeReq({ headers: {}, socket: {} });
    expect(extractIp(req)).toBe('unknown');
  });

  it("returns 'unknown' when x-forwarded-for is an empty string (WR-01)", () => {
    const req = makeReq({ headers: { 'x-forwarded-for': '' }, socket: {} });
    expect(extractIp(req)).toBe('unknown');
  });

  it("returns 'unknown' when x-forwarded-for contains only commas/spaces (WR-01)", () => {
    const req = makeReq({ headers: { 'x-forwarded-for': ', ,' }, socket: {} });
    expect(extractIp(req)).toBe('unknown');
  });

  it("returns 'unknown' when x-forwarded-for contains an invalid/injected value (WR-02)", () => {
    const req = makeReq({ headers: { 'x-forwarded-for': "'; DROP TABLE trust_signals;--" }, socket: {} });
    expect(extractIp(req)).toBe('unknown');
  });

  it('accepts a valid IPv6 address from x-forwarded-for (WR-02)', () => {
    const req = makeReq({ headers: { 'x-forwarded-for': '2001:db8::1' } });
    expect(extractIp(req)).toBe('2001:db8::1');
  });

  it("returns 'unknown' when x-forwarded-for is bare hex (WR-02 net.isIP regression)", () => {
    const req = makeReq({ headers: { 'x-forwarded-for': 'aaaaaaaa' }, socket: {} });
    expect(extractIp(req)).toBe('unknown');
  });

  it("returns 'unknown' when x-forwarded-for has out-of-range IPv4 octets (WR-02 net.isIP regression)", () => {
    const req = makeReq({ headers: { 'x-forwarded-for': '999.999.999.999' }, socket: {} });
    expect(extractIp(req)).toBe('unknown');
  });
});

describe('extractUserAgent', () => {
  it('returns user-agent header', () => {
    const req = makeReq({ headers: { 'user-agent': 'TestAgent/1.0' } });
    expect(extractUserAgent(req)).toBe('TestAgent/1.0');
  });

  it("returns 'unknown' when no user-agent header", () => {
    const req = makeReq({});
    expect(extractUserAgent(req)).toBe('unknown');
  });
});

describe('extractDeviceId', () => {
  it('returns x-device-id header', () => {
    const req = makeReq({ headers: { 'x-device-id': 'device-abc' } });
    expect(extractDeviceId(req)).toBe('device-abc');
  });

  it('returns null when no x-device-id header', () => {
    const req = makeReq({});
    expect(extractDeviceId(req)).toBeNull();
  });
});

describe('extractJa4h', () => {
  it('returns the fingerprint when Ja4hMiddleware has attached it', () => {
    const r = {} as Request;
    (r as any)['x-ja4h'] = 'ja4h_test_fp';
    expect(extractJa4h(r)).toBe('ja4h_test_fp');
  });

  it('returns undefined when the field is absent', () => {
    const r = {} as Request;
    expect(extractJa4h(r)).toBeUndefined();
  });

  it('returns undefined when the field is an empty string', () => {
    const r = {} as Request;
    (r as any)['x-ja4h'] = '';
    expect(extractJa4h(r)).toBeUndefined();
  });

  it('does NOT read from req.headers (production wiring writes to req itself, not headers)', () => {
    const r = { headers: { 'x-ja4h': 'wrong-place' } } as unknown as Request;
    // Header value must be ignored — only req['x-ja4h'] counts
    expect(extractJa4h(r)).toBeUndefined();
  });
});
