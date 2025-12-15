import { Injectable, Logger } from '@nestjs/common';
import { SignJWT, jwtVerify, JWTVerifyResult } from 'jose';

@Injectable()
export class JwtService {
  private readonly logger = new Logger(JwtService.name);

  async sign(payload: any, secret: string, expiresIn?: string): Promise<string> {
    // Validate inputs
    if (!secret || typeof secret !== 'string') {
      throw new Error('Secret must be a non-empty string');
    }

    if (!payload || typeof payload !== 'object') {
      throw new Error('Payload must be a valid object');
    }

    try {
      const secretKey = new TextEncoder().encode(secret);
      const iat = Math.floor(Date.now() / 1000);
      const exp = expiresIn ? iat + this.parseTime(expiresIn) : iat + 60 * 60; // Default 1 hour

      return new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt(iat)
        .setExpirationTime(exp)
        .sign(secretKey);
    } catch (error) {
      this.logger.error('JWT signing failed:', error);
      throw error;
    }
  }

  async verify(token: string, secret: string): Promise<any> {
    // Validate inputs
    if (!token || typeof token !== 'string') {
      throw new Error('Token must be a non-empty string');
    }

    if (!secret || typeof secret !== 'string') {
      throw new Error('Secret must be a non-empty string');
    }

    try {
      const secretKey = new TextEncoder().encode(secret);
      const result: JWTVerifyResult = await jwtVerify(token, secretKey);

      // Validate the payload structure if needed
      if (!result.payload || typeof result.payload !== 'object') {
        throw new Error('Invalid token payload');
      }

      return result.payload;
    } catch (error) {
      this.logger.error('JWT verification failed:', error);

      // Re-throw with more specific error based on the original error
      if (error?.message?.includes('JWS signature verification failed')) {
        throw new Error('Invalid token signature');
      } else if (error?.message?.includes('JWE decryption failed')) {
        throw new Error('Invalid token encryption');
      } else if (error?.message?.includes('Token expired')) {
        throw new Error('Token expired');
      } else {
        throw new Error('Invalid token');
      }
    }
  }

  private parseTime(timeStr: string): number {
    if (!timeStr || typeof timeStr !== 'string') {
      return 60 * 60; // Default to 1 hour
    }

    const time = parseInt(timeStr);
    if (isNaN(time)) {
      return 60 * 60; // Default to 1 hour
    }

    const unit = timeStr.match(/[a-zA-Z]+/)?.[0] || 's';

    switch (unit) {
      case 's':
        return time;
      case 'm':
        return time * 60;
      case 'h':
        return time * 60 * 60;
      case 'd':
        return time * 24 * 60 * 60;
      default:
        return time;
    }
  }
}