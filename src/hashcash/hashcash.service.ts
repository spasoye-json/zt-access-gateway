import { Injectable } from '@nestjs/common';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { AppConfigService } from '../config/config.service';
import { UsedNonceStore } from './used-nonce-store';
import { HashcashMetrics } from './hashcash-metrics';
import {
  difficultyForScore,
  countLeadingZeroBits,
  hashSolution,
} from './hashcash.util';

interface NoncePayload {
  v: 1;
  exp: number; // Unix seconds
  diff: number; // bits
  sub: string; // userId (D-02)
  dev: string; // deviceId (D-02)
  iat: number; // Unix seconds
}

/**
 * Returned by issueChallenge. Single source of truth: `difficulty` and `expiresAt`
 * are the EXACT values encoded in the payload — the guard MUST use these directly
 * for the X-Hashcash-Challenge response header / body and MUST NOT recompute via
 * difficultyForScore independently. This prevents the "header difficulty drifts
 * from payload.diff" class of bugs that would cause every D-11 verify to fail.
 */
export interface IssuedChallenge {
  nonce: string;
  difficulty: number;
  expiresAt: number;
}

export type VerifyResult =
  | { ok: true; iat: number }
  | {
      ok: false;
      reason:
        | 'malformed'
        | 'invalid_hmac'
        | 'expired'
        | 'difficulty_mismatch'
        | 'replay'
        | 'length_bound'
        | 'insufficient_zeros'
        | 'identity_mismatch';
    };

/**
 * Phase 5 — HashcashService: stateless HMAC PoW issue + verify (D-01).
 *
 * issueChallenge(userId, deviceId, score):
 *   - computes difficulty = difficultyForScore(score, cfg.hashcashDifficultyMin, cfg.hashcashDifficultyMax)
 *   - builds payload, signs with HASHCASH_HMAC_SECRET, returns { nonce, difficulty, expiresAt }
 *     where the returned values match the encoded payload exactly.
 *
 * verifySolution(nonce, solution, liveScore):
 *   - parses, constant-time HMAC verify, expiry, D-11 difficulty re-derive (using SAME cfg bounds), single-use, leading-zero check.
 *
 * NEVER throws — returns a discriminated union for predictable guard handling.
 */
@Injectable()
export class HashcashService {
  private readonly secret: Buffer;
  private readonly ttlSec: number;
  private readonly diffMin: number;
  private readonly diffMax: number;

  constructor(
    cfg: AppConfigService,
    private readonly nonceStore: UsedNonceStore,
    private readonly metrics: HashcashMetrics,
  ) {
    this.secret = Buffer.from(cfg.hashcashHmacSecret, 'utf8');
    this.ttlSec = Math.max(0, Math.floor(cfg.hashcashChallengeTtlMs / 1000));
    this.diffMin = cfg.hashcashDifficultyMin;
    this.diffMax = cfg.hashcashDifficultyMax;
  }

  issueChallenge(userId: string, deviceId: string, score: number): IssuedChallenge {
    const difficulty = difficultyForScore(score, this.diffMin, this.diffMax);
    const iat = Math.floor(Date.now() / 1000);
    const expiresAt = iat + this.ttlSec;
    const payload: NoncePayload = {
      v: 1,
      exp: expiresAt,
      diff: difficulty,
      sub: userId,
      dev: deviceId,
      iat,
    };
    const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');
    const mac = createHmac('sha256', this.secret).update(payloadBytes).digest();
    const nonce = `${payloadBytes.toString('base64url')}.${mac.toString('base64url')}`;
    this.metrics.total.inc({ outcome: 'issued', difficulty: String(difficulty) });
    return { nonce, difficulty, expiresAt };
  }

  verifySolution(
    nonce: string,
    solution: string,
    liveScore: number,
    expectedUserId: string,
    expectedDeviceId: string,
  ): VerifyResult {
    // 1. length bound — before any hashing (T-5-HBOMB)
    if (typeof solution !== 'string' || solution.length < 1 || solution.length > 256) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: '0' });
      return { ok: false, reason: 'length_bound' };
    }

    // 2. structural parse
    const dot = nonce.lastIndexOf('.');
    if (dot <= 0 || dot === nonce.length - 1) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: '0' });
      return { ok: false, reason: 'malformed' };
    }
    const payloadB64 = nonce.slice(0, dot);
    const macB64 = nonce.slice(dot + 1);
    const payloadBytes = Buffer.from(payloadB64, 'base64url');
    const providedMac = Buffer.from(macB64, 'base64url');

    // 3. HMAC verify (length pre-check prevents ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH — Pitfall 1)
    const computed = createHmac('sha256', this.secret).update(payloadBytes).digest();
    if (providedMac.length !== computed.length || !timingSafeEqual(computed, providedMac)) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: '0' });
      return { ok: false, reason: 'invalid_hmac' };
    }

    // 4. payload parse
    let payload: NoncePayload;
    try {
      payload = JSON.parse(payloadBytes.toString('utf8')) as NoncePayload;
      if (
        typeof payload.exp !== 'number' ||
        typeof payload.diff !== 'number' ||
        typeof payload.iat !== 'number' ||
        typeof payload.sub !== 'string' ||
        typeof payload.dev !== 'string'
      ) {
        throw new Error('shape');
      }
    } catch {
      this.metrics.total.inc({ outcome: 'failed', difficulty: '0' });
      return { ok: false, reason: 'malformed' };
    }
    const diffLabel = String(payload.diff);

    // 4b. identity binding (D-02) — payload.sub/dev encoded at issue must match the calling user.
    // Placed BEFORE replay-store add (step 9) so a mismatched verify does NOT consume the slot
    // for the legitimate user.
    if (payload.sub !== expectedUserId || payload.dev !== expectedDeviceId) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: diffLabel });
      return { ok: false, reason: 'identity_mismatch' };
    }

    // 5. expiry
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp <= nowSec) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: diffLabel });
      return { ok: false, reason: 'expired' };
    }

    // 6. difficulty re-derive (D-11) — uses SAME cfg bounds as issueChallenge.
    // Closes "low-difficulty replay after score escalates" gap.
    const expectedDiff = difficultyForScore(liveScore, this.diffMin, this.diffMax);
    if (payload.diff !== expectedDiff) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: diffLabel });
      return { ok: false, reason: 'difficulty_mismatch' };
    }

    // 7. replay
    if (this.nonceStore.has(nonce)) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: diffLabel });
      return { ok: false, reason: 'replay' };
    }

    // 8. leading-zero check
    const digest = hashSolution(nonce, solution);
    if (countLeadingZeroBits(digest) < payload.diff) {
      this.metrics.total.inc({ outcome: 'failed', difficulty: diffLabel });
      return { ok: false, reason: 'insufficient_zeros' };
    }

    // 9. success — atomic single-use mark + metrics
    this.nonceStore.add(nonce, payload.exp);
    this.metrics.total.inc({ outcome: 'solved', difficulty: diffLabel });
    this.metrics.solveSeconds.observe(nowSec - payload.iat);
    return { ok: true, iat: payload.iat };
  }
}
