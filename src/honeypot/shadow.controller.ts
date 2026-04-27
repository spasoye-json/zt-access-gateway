import { Controller, Get, Req, Res } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Request, Response } from 'express';
import { FingerprintStore } from '../fingerprint/fingerprint.store';
import { SecurityMetricsService } from './security-metrics.service';
import { AppConfigService } from '../config/config.service';
import { Honeypot } from './honeypot.decorator';
import { getFakeResponse } from './honeypot-responses';
import { sleep, randomDelay } from '../shared/sleep.util';
import { extractIp, extractJa4h } from '../shared/request-context.util';
import { Public } from '../shared/public.decorator';
import {
  HONEYPOT_TRIGGER,
  type ThreatSignalPayload,
} from '../policy/policy-events';

/**
 * ShadowController — deception layer of the zero-trust pipeline.
 *
 * Registers 7 common scanner-target paths as decoy routes. Any request to these
 * paths means the client is probing for vulnerabilities, so we:
 *   1. Blacklist their JA4H fingerprint immediately (isTerminal: true).
 *   2. Tarpit the connection 2-5s before responding (D-05).
 *   3. Return a realistic fake response to keep the scanner engaged.
 *   4. Emit a structured HONEYPOT_TRIGGERED audit log.
 *   5. Increment the Prometheus honeypot counter.
 *
 * Security notes:
 * - These routes must remain reachable without auth (Phase 3 JwtAuthGuard is
 *   route-per-guard, not global — so no exclusion needed at this phase).
 * - No real business logic executes here — only blacklist write + fake response.
 * - HoneypotModule is imported last in AppModule to prevent shadowing real routes (T-02-11).
 */
@Controller()
@Public()
export class ShadowController {
  constructor(
    private readonly store: FingerprintStore,
    private readonly metrics: SecurityMetricsService,
    private readonly config: AppConfigService,
    private readonly events: EventEmitter2,
  ) {}

  /**
   * Core trap sequence — shared by all 7 handlers.
   * Extracted to avoid 7x duplication of the same tarpit+blacklist+audit logic.
   */
  private async trapAndRespond(
    req: Request,
    res: Response,
    path: string,
  ): Promise<void> {
    // WR-05: route both reads through extractJa4h. Direct (req as any)['x-ja4h']
    // returned '' for empty fingerprints, registering the empty string as a
    // terminal blacklist key — trapping every later request with no JA4H at
    // score 1.0. extractJa4h coerces empty to undefined so '?? 'unknown''
    // produces a consistent key.
    const ja4h: string = extractJa4h(req) ?? 'unknown';

    // Blacklist the fingerprint immediately — isTerminal ensures Phase 4 trust score = 1.0
    this.store.add(ja4h, { ttlMs: this.config.blacklistTtlMs, isTerminal: true });

    // Increment Prometheus counter (HPOT-07)
    this.metrics.incrementHoneypotTriggers();

    // Phase 6 D-14: emit honeypot.trigger to threat-signal bus.
    // Emit lives in the controller (not SecurityMetricsService) because the
    // controller has request context; service stays request-agnostic.
    // WR-01: extractIp honors x-forwarded-for so honeypot signals attribute
    // to the real client when the gateway sits behind a reverse proxy.
    const payload: ThreatSignalPayload = {
      type: HONEYPOT_TRIGGER,
      ip: extractIp(req),
      ja4h: extractJa4h(req),
      ts: Date.now(),
      resource: path,
    };
    this.events.emit(HONEYPOT_TRIGGER, payload);

    // Structured audit log — IP and user-agent are client-controlled but logged for forensics
    // The JA4H fingerprint (not IP) is the enforcement key (T-02-10)
    console.warn(
      JSON.stringify({
        event: 'HONEYPOT_TRIGGERED',
        path,
        ip: req.ip,
        userAgent: req.headers['user-agent'] ?? 'unknown',
        ja4h,
        timestamp: new Date().toISOString(),
      }),
    );

    // Tarpit: hold the connection to slow down scanners (D-05, HPOT-05)
    await sleep(randomDelay(2000, 5000));

    const fakeResponse = getFakeResponse(path);
    if (typeof fakeResponse.body === 'string') {
      res.type(fakeResponse.contentType).status(200).send(fakeResponse.body);
    } else {
      res.status(200).json(fakeResponse.body);
    }
  }

  @Get('/wp-login.php')
  @Honeypot()
  async wpLogin(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.trapAndRespond(req, res, '/wp-login.php');
  }

  @Get('/admin/config.json')
  @Honeypot()
  async adminConfig(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.trapAndRespond(req, res, '/admin/config.json');
  }

  @Get('/.env')
  @Honeypot()
  async dotEnv(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.trapAndRespond(req, res, '/.env');
  }

  @Get('/api/v1/debug')
  @Honeypot()
  async apiDebug(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.trapAndRespond(req, res, '/api/v1/debug');
  }

  @Get('/graphql/introspection')
  @Honeypot()
  async graphqlIntrospection(
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    await this.trapAndRespond(req, res, '/graphql/introspection');
  }

  @Get('/actuator/health')
  @Honeypot()
  async actuatorHealth(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.trapAndRespond(req, res, '/actuator/health');
  }

  @Get('/api/v1/internal/keys')
  @Honeypot()
  async internalKeys(@Req() req: Request, @Res() res: Response): Promise<void> {
    await this.trapAndRespond(req, res, '/api/v1/internal/keys');
  }
}
