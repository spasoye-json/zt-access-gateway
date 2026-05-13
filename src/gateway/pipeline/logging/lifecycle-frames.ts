import chalk from 'chalk';
import type { Request, Response } from 'express';
import { extractIp, extractUserAgent } from '../../../shared/request-context.util';

const SHORT_LEN = 8;

export function shortenReqId(reqId: string): string {
  return reqId.replace(/-/g, '').slice(0, SHORT_LEN).padEnd(SHORT_LEN, '?');
}

export function openingFrame(req: Request, requestId: string, reqPath: string): string {
  const id = chalk.gray(shortenReqId(requestId));
  const arrow = chalk.bold.blue('──▶');
  const method = chalk.bold(req.method);
  const path = chalk.cyan(reqPath);
  const ip = chalk.gray(`ip=${extractIp(req)}`);
  const ua = chalk.gray(`ua=${extractUserAgent(req)}`);
  return `${id}  ${arrow} ${method} ${path}  ${ip} ${ua}`;
}

export function closingFrame(requestId: string, res: Response, totalMs: number): string {
  const id = chalk.gray(shortenReqId(requestId));
  const arrow = chalk.bold.blue('◀──');
  const status = res.statusCode ?? 0;
  const statusCol =
    status >= 500
      ? chalk.red(String(status))
      : status >= 400
        ? chalk.yellow(String(status))
        : chalk.green(String(status));
  const total = chalk.gray(`total=${totalMs}ms`);
  return `${id}  ${arrow} ${statusCol}  ${total}`;
}
