import { ForbiddenException, HttpException, NotFoundException } from '@nestjs/common';
import { HttpExceptionFilter } from '../http-exception.filter';
import { ArgumentsHost } from '@nestjs/common';

function makeHost(statusFn: jest.Mock, jsonFn: jest.Mock, headersSent = false): ArgumentsHost {
  return {
    switchToHttp: () => ({
      getResponse: () => ({
        status: statusFn,
        headersSent,
      }),
      getRequest: () => ({}),
    }),
  } as unknown as ArgumentsHost;
}

describe('HttpExceptionFilter', () => {
  let filter: HttpExceptionFilter;
  let statusMock: jest.Mock;
  let jsonMock: jest.Mock;

  beforeEach(() => {
    filter = new HttpExceptionFilter();
    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });
  });

  it('returns correct status and message for HttpException(403, "Forbidden")', () => {
    const host = makeHost(statusMock, jsonMock);
    filter.catch(new HttpException('Forbidden', 403), host);
    expect(statusMock).toHaveBeenCalledWith(403);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({ statusCode: 403, message: 'Forbidden' }),
    );
  });

  it('returns correct status and message for NotFoundException', () => {
    const host = makeHost(statusMock, jsonMock);
    filter.catch(new NotFoundException('not found'), host);
    expect(statusMock).toHaveBeenCalledWith(404);
    expect(jsonMock).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 404 }));
  });

  it("returns 500 with 'Internal server error' for unknown Error", () => {
    const host = makeHost(statusMock, jsonMock);
    filter.catch(new Error('secret db password'), host);
    expect(statusMock).toHaveBeenCalledWith(500);
    expect(jsonMock).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 500,
        message: 'Internal server error',
      }),
    );
    // Must NOT leak the real error message
    const callArg = jsonMock.mock.calls[0][0];
    expect(JSON.stringify(callArg)).not.toContain('secret db password');
  });

  it('includes ISO timestamp in response', () => {
    const host = makeHost(statusMock, jsonMock);
    filter.catch(new HttpException('Bad Request', 400), host);
    const callArg = jsonMock.mock.calls[0][0];
    expect(callArg.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it('does not include stack trace in response body', () => {
    const host = makeHost(statusMock, jsonMock);
    filter.catch(new Error('crash'), host);
    const callArg = jsonMock.mock.calls[0][0];
    expect(callArg).not.toHaveProperty('stack');
  });

  it('no-ops when response.headersSent is true (prevents ERR_HTTP_HEADERS_SENT)', () => {
    // Regression: a guard that wrote the response and returned `false` caused
    // Nest to throw an implicit ForbiddenException, which re-entered this filter
    // and crashed when status() tried to set headers on an already-ended socket.
    const host = makeHost(statusMock, jsonMock, /* headersSent */ true);
    expect(() => filter.catch(new ForbiddenException('Forbidden resource'), host)).not.toThrow();
    expect(statusMock).not.toHaveBeenCalled();
    expect(jsonMock).not.toHaveBeenCalled();
  });
});
