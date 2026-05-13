/**
 * Phase C (260513-mar) — MfaErrorRecorder util spec.
 *
 * Replaces the inline `recordInfraError` private method on the old MfaService.
 * Preserves the WR-03 (phase 14) observability contract: every swallowed infra
 * error must (1) emit MFA_INFRA_ERROR with { userId, op, ts } and (2) call
 * Logger.error with (string-message, string-stack) so structured log aggregators
 * keep the full stack trace.
 */
import { Logger } from '@nestjs/common';
import { TypedEvents } from '../../shared/typed-events';
import { MFA_INFRA_ERROR } from '../../policy/policy-events';
import { MfaErrorRecorder } from '../mfa-error-recorder.util';

describe('MfaErrorRecorder', () => {
  let emitter: jest.Mocked<TypedEvents>;
  let recorder: MfaErrorRecorder;
  let errSpy: jest.SpyInstance;

  beforeEach(() => {
    emitter = { emit: jest.fn() } as unknown as jest.Mocked<TypedEvents>;
    recorder = new MfaErrorRecorder(emitter);
    errSpy = jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errSpy.mockRestore();
  });

  it('passes string message + string stack to Logger.error for Error inputs', () => {
    const boom = new Error('db down');
    boom.stack = 'Error: db down\n    at frame-1\n    at frame-2';

    recorder.record('MfaChallenger', 'createChallenge', 'user-x', boom);

    expect(errSpy).toHaveBeenCalledTimes(1);
    const [message, stack] = errSpy.mock.calls[0] as [unknown, unknown];
    expect(typeof message).toBe('string');
    expect(message).toEqual(expect.stringContaining('MfaChallenger.createChallenge'));
    expect(message).toEqual(expect.stringContaining('db down'));
    expect(typeof stack).toBe('string');
    expect(stack).toEqual(expect.stringContaining('frame-1'));
    expect(stack).not.toBeInstanceOf(Error);
  });

  it('wraps string throwables and still emits a string stack', () => {
    recorder.record('MfaEnroller', 'createEnrollment', 'user-y', 'plain-string-error');

    expect(errSpy).toHaveBeenCalledTimes(1);
    const [message, stack] = errSpy.mock.calls[0] as [unknown, unknown];
    expect(typeof message).toBe('string');
    expect(message).toEqual(expect.stringContaining('MfaEnroller.createEnrollment'));
    expect(message).toEqual(expect.stringContaining('plain-string-error'));
    expect(typeof stack).toBe('string');
  });

  it('wraps object throwables via JSON.stringify', () => {
    recorder.record('MfaChallenger', 'verifyTotp', undefined, { code: 500, detail: 'kaboom' });

    expect(errSpy).toHaveBeenCalledTimes(1);
    const [message] = errSpy.mock.calls[0] as [unknown];
    expect(message).toEqual(expect.stringContaining('"code":500'));
    expect(message).toEqual(expect.stringContaining('kaboom'));
  });

  it('emits MFA_INFRA_ERROR with { userId, op, ts } on every call', () => {
    const before = Date.now();
    recorder.record('MfaChallenger', 'validateMfaToken', 'user-z', new Error('x'));
    const after = Date.now();

    expect(emitter.emit).toHaveBeenCalledTimes(1);
    const [eventName, payload] = emitter.emit.mock.calls[0] as unknown as [
      string,
      Record<string, unknown>,
    ];
    expect(eventName).toBe(MFA_INFRA_ERROR);
    expect(payload.userId).toBe('user-z');
    expect(payload.op).toBe('validateMfaToken');
    expect(typeof payload.ts).toBe('number');
    expect(payload.ts as number).toBeGreaterThanOrEqual(before);
    expect(payload.ts as number).toBeLessThanOrEqual(after);
  });

  it('emits MFA_INFRA_ERROR even when userId is undefined', () => {
    recorder.record('MfaEnroller', 'deleteEnrollment', undefined, new Error('x'));
    expect(emitter.emit).toHaveBeenCalledTimes(1);
    const [, payload] = emitter.emit.mock.calls[0] as unknown as [
      string,
      Record<string, unknown>,
    ];
    expect(payload.userId).toBeUndefined();
  });

  it('uses the supplied serviceName as the log message prefix (replaces hardcoded "MfaService.")', () => {
    recorder.record('MfaEnroller', 'confirmEnrollment', 'u', new Error('x'));
    const [message] = errSpy.mock.calls[0] as [string];
    expect(message.startsWith('MfaEnroller.confirmEnrollment')).toBe(true);
  });
});
