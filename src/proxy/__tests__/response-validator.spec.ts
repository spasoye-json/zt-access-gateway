/**
 * Unit tests for ResponseValidator pure function.
 * Covers: PRXY-09 (validates downstream response status + Content-Type before returning).
 */
import { BadGatewayException, ServiceUnavailableException } from '@nestjs/common';
import type { AxiosResponse } from 'axios';
import { assertValidProxyResponse } from '../response-validator';

function makeResponse(status: number, contentType?: string): AxiosResponse {
  return {
    status,
    headers: contentType ? { 'content-type': contentType } : {},
    data: {},
    statusText: 'OK',
    config: {} as AxiosResponse['config'],
  };
}

describe('assertValidProxyResponse', () => {
  it('200 + application/json → returns void', () => {
    const res = makeResponse(200, 'application/json');
    expect(() => assertValidProxyResponse(res)).not.toThrow();
  });

  it('200 + application/json; charset=utf-8 → returns void (substring match)', () => {
    const res = makeResponse(200, 'application/json; charset=utf-8');
    expect(() => assertValidProxyResponse(res)).not.toThrow();
  });

  it('500 status → throws ServiceUnavailableException', () => {
    const res = makeResponse(500, 'application/json');
    expect(() => assertValidProxyResponse(res)).toThrow(ServiceUnavailableException);
  });

  it('502 status → throws ServiceUnavailableException', () => {
    const res = makeResponse(502, 'application/json');
    expect(() => assertValidProxyResponse(res)).toThrow(ServiceUnavailableException);
  });

  it('200 + text/html Content-Type → throws BadGatewayException', () => {
    const res = makeResponse(200, 'text/html');
    expect(() => assertValidProxyResponse(res)).toThrow(BadGatewayException);
  });

  it('200 + missing Content-Type header → throws BadGatewayException', () => {
    const res = makeResponse(200);
    expect(() => assertValidProxyResponse(res)).toThrow(BadGatewayException);
  });
});
