import { extractIp, extractUserAgent, extractDeviceId } from '../request-context.util';
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
