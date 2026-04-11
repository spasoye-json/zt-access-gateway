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

    const isHttp = exception instanceof HttpException;
    const statusCode = isHttp
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const message = isHttp ? exception.message : 'Internal server error';

    if (!isHttp) {
      // Log full error server-side only — never in the response body
      console.error('Unhandled exception:', exception);
    }

    response.status(statusCode).json({
      statusCode,
      message,
      timestamp: new Date().toISOString(),
    });
  }
}
