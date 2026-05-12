import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolesGuard } from '../roles.guard';
import { ROLES_KEY } from '../roles.decorator';

/**
 * RolesGuard unit tests -- TDD RED phase.
 * Tests will fail on import until roles.guard.ts and roles.decorator.ts
 * are created in Wave 1.
 *
 * Coverage: AUTH-08
 */
describe('RolesGuard', () => {
  let guard: RolesGuard;
  let reflector: Reflector;

  function createMockContext(user?: { roles: string[] }): ExecutionContext {
    const request = { user };
    const handler = {} as () => void;
    const classRef = {} as () => void;

    return {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({}),
        getNext: () => ({}),
      }),
      getHandler: () => handler,
      getClass: () => classRef,
      getType: () => 'http',
      getArgs: () => [],
      getArgByIndex: () => undefined,
      switchToRpc: () => ({}) as ReturnType<ExecutionContext['switchToRpc']>,
      switchToWs: () => ({}) as ReturnType<ExecutionContext['switchToWs']>,
    } as unknown as ExecutionContext;
  }

  beforeEach(() => {
    reflector = new Reflector();
    guard = new RolesGuard(reflector);
  });

  describe('role enforcement (AUTH-08)', () => {
    it('allows request when user has required role', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin']);

      const ctx = createMockContext({ roles: ['admin', 'user'] });
      expect(guard.canActivate(ctx)).toBe(true);
    });

    it('rejects request (returns false) when user lacks required role', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin']);

      const ctx = createMockContext({ roles: ['user'] });
      expect(guard.canActivate(ctx)).toBe(false);
    });

    it('allows request when no @Roles() decorator is present (no restriction)', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);

      const ctx = createMockContext({ roles: ['user'] });
      expect(guard.canActivate(ctx)).toBe(true);
    });

    it('rejects request when user object is missing (guard returns false)', () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['admin']);

      const ctx = createMockContext(undefined);
      expect(guard.canActivate(ctx)).toBe(false);
    });
  });
});
