import { createHash } from 'crypto';
import { computeJa4h } from '../ja4h.util';

function makeHash(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function mockReq(
  rawHeaders: string[],
  headers: Record<string, string>,
  method: string,
  httpVersion: string,
): any {
  return { rawHeaders, headers, method, httpVersion };
}

describe('computeJa4h', () => {
  it('produces correct SHA-256 from method|httpVersion|headerNames|accept|contentType', () => {
    const req = mockReq(
      ['Host', 'example.com', 'Accept', 'text/html', 'Content-Type', 'application/json'],
      { host: 'example.com', accept: 'text/html', 'content-type': 'application/json' },
      'GET',
      '1.1',
    );
    const expected = makeHash('GET|1.1|Host,Accept,Content-Type|text/html|application/json');
    expect(computeJa4h(req)).toBe(expected);
  });

  it('preserves original header name casing from rawHeaders', () => {
    // rawHeaders has mixed case; headers (parsed) are lowercased
    const req = mockReq(
      ['X-Custom-Header', 'foo', 'Accept', 'text/plain'],
      { 'x-custom-header': 'foo', accept: 'text/plain' },
      'POST',
      '1.1',
    );
    const expected = makeHash('POST|1.1|X-Custom-Header,Accept|text/plain|');
    expect(computeJa4h(req)).toBe(expected);
  });

  it('returns different hashes for same headers in different order (order-sensitive)', () => {
    const req1 = mockReq(
      ['Accept', 'text/html', 'Host', 'example.com'],
      { accept: 'text/html', host: 'example.com' },
      'GET',
      '1.1',
    );
    const req2 = mockReq(
      ['Host', 'example.com', 'Accept', 'text/html'],
      { host: 'example.com', accept: 'text/html' },
      'GET',
      '1.1',
    );
    expect(computeJa4h(req1)).not.toBe(computeJa4h(req2));
  });

  it('handles missing Accept header (uses empty string)', () => {
    const req = mockReq(['Host', 'example.com'], { host: 'example.com' }, 'GET', '1.1');
    const expected = makeHash('GET|1.1|Host||');
    expect(computeJa4h(req)).toBe(expected);
  });

  it('handles missing Content-Type header (uses empty string)', () => {
    const req = mockReq(['Accept', 'text/html'], { accept: 'text/html' }, 'GET', '1.1');
    const expected = makeHash('GET|1.1|Accept|text/html|');
    expect(computeJa4h(req)).toBe(expected);
  });

  it('uses req.httpVersion, falls back to 1.1 if undefined', () => {
    const req = mockReq([], {}, 'GET', undefined);
    const expected = makeHash('GET|1.1|||');
    expect(computeJa4h(req)).toBe(expected);
  });

  it('handles empty rawHeaders (produces valid hash, does not throw)', () => {
    const req = mockReq([], {}, 'GET', '1.1');
    const expected = makeHash('GET|1.1|||');
    expect(() => computeJa4h(req)).not.toThrow();
    expect(computeJa4h(req)).toBe(expected);
  });
});
