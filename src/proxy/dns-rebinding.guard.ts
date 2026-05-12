import * as dns from 'node:dns';
import * as net from 'node:net';
import { ForbiddenException, Injectable, Logger } from '@nestjs/common';

/** D-09: block loopback + cloud metadata only. RFC1918 NOT blocked (Docker/K8s services live there). */
const BLOCKED_EXACT = new Set<string>(['::1', '169.254.169.254']);

function ipv4ToUint32(ip: string): number {
  return ip.split('.').reduce((acc, oct) => ((acc << 8) | parseInt(oct, 10)) >>> 0, 0);
}

function inCidr(ip: string, base: number, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToUint32(ip) & mask) === (base & mask);
}

/** IPv4 loopback: 127.0.0.0/8 */
const LOOPBACK_BASE = ipv4ToUint32('127.0.0.0');
const LOOPBACK_BITS = 8;

@Injectable()
export class DnsRebindingGuard {
  private readonly logger = new Logger(DnsRebindingGuard.name);

  /**
   * Resolves the hostname and throws ForbiddenException if the resolved IP is in a
   * blocked range. D-08: NO CACHING — fresh dns.promises.lookup per call. (PRXY-07, PRXY-08)
   */
  async assertSafe(hostname: string): Promise<void> {
    const { address } = await dns.promises.lookup(hostname, { all: false });

    if (BLOCKED_EXACT.has(address)) {
      this.logger.warn(`DNS rebinding blocked: ${hostname} → ${address} (exact-block list)`);
      throw new ForbiddenException(
        `DNS rebinding guard: ${hostname} resolves to blocked address ${address}`,
      );
    }

    if (net.isIPv4(address)) {
      if (inCidr(address, LOOPBACK_BASE, LOOPBACK_BITS)) {
        this.logger.warn(
          `DNS rebinding blocked: ${hostname} → ${address} (CIDR block 127.0.0.0/8)`,
        );
        throw new ForbiddenException(
          `DNS rebinding guard: ${hostname} resolves to blocked address ${address}`,
        );
      }
    }
    // RFC1918 (10.x, 172.16.x, 192.168.x) and public IPs intentionally allowed per D-09.
  }
}
