import type { Request } from 'express';

const UNKNOWN_IP = 'unknown';
const UNKNOWN_DEVICE = 'unknown-device';

const normalizeIp = (ip?: string | null): string => {
  if (!ip) {
    return UNKNOWN_IP;
  }

  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
};

export const extractClientIp = (req: Request): string => {
  if (!req) {
    return UNKNOWN_IP;
  }

  if (Array.isArray(req.ips) && req.ips.length > 0) {
    return normalizeIp(req.ips[0]);
  }

  const connectionIp = req.ip || req.socket?.remoteAddress;

  return normalizeIp(connectionIp);
};

export const resolveDeviceId = (value?: unknown): string => {
  if (Array.isArray(value)) {
    return resolveDeviceId(value[0]);
  }

  if (typeof value !== 'string') {
    return UNKNOWN_DEVICE;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return UNKNOWN_DEVICE;
  }

  return trimmed.slice(0, 128);
};
