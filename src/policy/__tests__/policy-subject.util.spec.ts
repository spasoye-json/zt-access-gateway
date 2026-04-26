import { buildSubjects, normalizeResource, normalizeAction } from '../policy-subject.util';
import type { UserClaims } from '../../auth/interfaces/user-claims.interface';

describe('policy-subject.util', () => {
  describe('buildSubjects (D-04)', () => {
    it.each<[string, UserClaims, string[]]>([
      ['single role', { userId: '42', roles: ['user'] } as UserClaims, ['user:42', 'role:user']],
      [
        'multiple roles',
        { userId: '42', roles: ['user', 'admin'] } as UserClaims,
        ['user:42', 'role:user', 'role:admin'],
      ],
      ['empty roles', { userId: '42', roles: [] } as UserClaims, ['user:42']],
      ['undefined roles', { userId: '42' } as unknown as UserClaims, ['user:42']],
    ])('%s', (_name, claims, expected) => {
      expect(buildSubjects(claims)).toEqual(expected);
    });
  });

  describe('normalizeResource (D-07, Pitfall 5, Pitfall 9)', () => {
    it.each<[string, string, string]>([
      ['plain path', '/users', '/users'],
      ['trailing slash', '/users/', '/users'],
      ['query string', '/users?x=1', '/users'],
      ['both trailing + query', '/users/?x=1', '/users'],
      ['mixed case preserved', '/Users', '/Users'],
      ['root path', '/', '/'],
      ['nested path', '/users/42', '/users/42'],
    ])('%s: %s -> %s', (_name, input, expected) => {
      expect(normalizeResource(input)).toBe(expected);
    });
  });

  describe('normalizeAction (D-06)', () => {
    it.each<[string, string]>([
      ['GET', 'GET'],
      ['post', 'POST'],
      ['DeLeTe', 'DELETE'],
    ])('%s -> uppercase', (input, expected) => {
      expect(normalizeAction(input)).toBe(expected);
    });
  });
});
