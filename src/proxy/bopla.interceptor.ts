import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as fs from 'node:fs';
import * as micromatch from 'micromatch';
import { AppConfigService } from '../config/config.service';
import type { FieldPolicy } from './interfaces/field-policy.interface';

/** Wildcard role token meaning "all fields pass through". (D-06) */
const PASS_THROUGH = '*';

@Injectable()
export class BoPlaInterceptor implements OnModuleInit {
  private readonly logger = new Logger(BoPlaInterceptor.name);
  private fieldPolicy!: FieldPolicy;

  constructor(private readonly cfg: AppConfigService) {}

  async onModuleInit(): Promise<void> {
    const path = this.cfg.boplaPolicyPath;
    let raw: string;
    try {
      raw = await fs.promises.readFile(path, 'utf-8');
    } catch (err) {
      throw new Error(
        `BoPlaInterceptor: cannot read field policy at ${path}: ${(err as Error).message}`,
      );
    }
    try {
      this.fieldPolicy = JSON.parse(raw) as FieldPolicy;
    } catch (err) {
      throw new Error(
        `BoPlaInterceptor: field policy at ${path} is not valid JSON: ${(err as Error).message}`,
      );
    }
    this.logger.log(
      `BOPLA field policy loaded from ${path} — ${Object.keys(this.fieldPolicy).length} pattern(s)`,
    );
  }

  /**
   * Strip unauthorized fields from `data` based on the caller's roles and the request path.
   * Returns:
   *   - data unchanged when caller has admin role (D-07 admin-always-allow)
   *   - data unchanged when matched policy entry returns ['*'] for the role
   *   - object containing only allowed fields when role has explicit field list
   *   - {} when no pattern matches and caller is non-admin (D-07 fail-closed default)
   *   - data unchanged for non-JSON body shapes (Pitfall 4)
   */
  strip(data: unknown, requestPath: string, roles: string[]): unknown {
    // Admin-always-allow (D-07)
    if (roles.includes('admin')) return data;

    const allowed = this.findAllowedFields(requestPath, roles);
    if (allowed === null) return {}; // fail-closed (D-07)
    if (allowed[0] === PASS_THROUGH) return data;

    return this.applyAllowList(data, allowed);
  }

  /**
   * First-match wins policy lookup (D-06). Iterates patterns in object insertion order.
   * Returns null when no pattern matches OR when the matching pattern has no entry for any
   * of the caller's roles. Returns the allowed-fields array for the highest-privilege role
   * that has an entry.
   */
  private findAllowedFields(requestPath: string, roles: string[]): string[] | null {
    for (const [pattern, roleMap] of Object.entries(this.fieldPolicy)) {
      if (micromatch.isMatch(requestPath, pattern)) {
        // Highest-privilege role wins among the caller's roles.
        // Admin already short-circuited in strip().
        for (const role of roles) {
          const fields = roleMap[role];
          if (fields) return fields;
        }
        return null; // pattern matched but no role mapping → fail-closed
      }
    }
    return null; // no pattern matched → fail-closed
  }

  /**
   * Recursive walk that returns a new object containing only `allowed` keys.
   * Arrays: apply policy to each element. Primitives: return as-is.
   * Non-plain-object types (Buffer, null, undefined): return as-is (Pitfall 4).
   */
  private applyAllowList(data: unknown, allowed: string[]): unknown {
    if (data === null || data === undefined) return data;
    if (Array.isArray(data)) {
      return data.map((item) => this.applyAllowList(item, allowed));
    }
    if (typeof data !== 'object') return data; // primitive
    if (this.isNonPlainObject(data)) return data; // Buffer, Date, etc.

    const out: Record<string, unknown> = {};
    for (const field of allowed) {
      if (field in (data as Record<string, unknown>)) {
        const value = (data as Record<string, unknown>)[field];
        // Apply same allowed list recursively to nested objects/arrays (BOPL-03)
        out[field] =
          value !== null && typeof value === 'object' ? this.applyAllowList(value, allowed) : value;
      }
    }
    return out;
  }

  private isNonPlainObject(value: object): boolean {
    if (Buffer.isBuffer(value)) return true;
    if (value instanceof Date) return true;
    const proto = Object.getPrototypeOf(value);
    return proto !== Object.prototype && proto !== null;
  }
}
