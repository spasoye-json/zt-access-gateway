import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const exceptionAny = exception as any;
    const isHttpException = exception instanceof HttpException;
    const status = isHttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse = isHttpException
      ? exception.getResponse()
      : undefined;
    const exceptionMessage =
      exception instanceof Error
        ? exception.message
        : typeof exceptionAny?.message === 'string'
        ? exceptionAny.message
        : undefined;
    const exceptionName =
      exception instanceof Error
        ? exception.name
        : typeof exceptionAny?.name === 'string'
        ? exceptionAny.name
        : 'Error';
    const exceptionConstructorName =
      typeof exceptionAny?.constructor?.name === 'string'
        ? exceptionAny.constructor.name
        : 'Error';

    const rawMessage =
      typeof exceptionResponse === 'object' && exceptionResponse !== null
        ? (exceptionResponse as any).message ?? exceptionMessage
        : isHttpException
        ? exceptionMessage
        : 'Internal server error';

    const message = Array.isArray(rawMessage)
      ? rawMessage.join('; ')
      : rawMessage;

    const error =
      typeof exceptionResponse === 'object' && exceptionResponse !== null
        ? (exceptionResponse as any).error ?? exceptionConstructorName
        : isHttpException
        ? exceptionName
        : 'InternalServerError';

    const requestId =
      (request.headers['x-request-id'] as string | undefined) || undefined;

    response.status(status).json({
      statusCode: status,
      error,
      message,
      path: request.url,
      requestId,
      timestamp: new Date().toISOString(),
    });
  }
}
