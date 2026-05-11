import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';

/**
 * Global exception filter — returns structured JSON for all errors.
 * Unknown errors return 500 with 'Internal server error' to prevent
 * leaking stack traces or internal details to clients (T-01-05).
 * Full error is logged server-side via console.error for diagnostics.
 */
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    // A guard or interceptor that wrote the response itself (e.g. a 429 challenge issuer
    // issuing a 429 challenge directly) and then returned `false` causes Nest
    // to throw an implicit ForbiddenException. Trying to set headers again
    // produces ERR_HTTP_HEADERS_SENT. The first write is the truth — no-op here.
    if (response.headersSent) return;

    const isHttp = exception instanceof HttpException;
    const statusCode = isHttp
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    if (!isHttp) {
      // Log full error server-side only — never in the response body.
      // T-01-05: never leak stack traces or internal messages to clients.
      console.error('Unhandled exception:', exception);
      response.status(statusCode).json({
        statusCode,
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      });
      return;
    }

    // WR-05: HttpException.message is the constant 'Bad Request Exception'
    // for class-validator pipe failures; the real constraint violations live
    // in getResponse(). Prefer the structured response body so API consumers
    // see which field failed. Fall back to exception.message for plain
    // HttpException instances whose response body is a string equal to
    // the message (e.g. new HttpException('Forbidden', 403)).
    const body = exception.getResponse();
    const message =
      typeof body === 'string'
        ? body
        : ((body as { message?: unknown }).message ?? exception.message);

    response.status(statusCode).json({
      statusCode,
      message,
      timestamp: new Date().toISOString(),
    });
  }
}
