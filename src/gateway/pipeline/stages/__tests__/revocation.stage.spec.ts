import { RevocationStage } from '../revocation.stage';
import type { StageContext } from '../../stage-context';
import type { TokenRevocationService } from '../../../../auth/token-revocation.service';

function build(): { stage: RevocationStage; rev: jest.Mocked<TokenRevocationService> } {
  const rev = { isRevoked: jest.fn() } as unknown as jest.Mocked<TokenRevocationService>;
  return { stage: new RevocationStage(rev), rev };
}

function makeCtx(claims: { jti: string; userId: string; roles?: string[]; exp?: number; deviceId?: string }): StageContext {
  return {
    req: { headers: {} } as unknown as StageContext['req'],
    claims: {
      jti: claims.jti,
      userId: claims.userId,
      roles: claims.roles ?? ['user'],
      exp: claims.exp ?? 9,
      deviceId: claims.deviceId ?? 'd1',
    },
    requestId: 'req-1',
    reqPath: '/x',
  } as unknown as StageContext;
}

describe('RevocationStage', () => {
  it('id is "revocation"', () => {
    expect(build().stage.id).toBe('revocation');
  });

  it('isRevoked(jti) true → 401 token_revoked', async () => {
    const { stage, rev } = build();
    rev.isRevoked.mockReturnValue(true);
    const out = await stage.run(makeCtx({ jti: 'j1', userId: 'u1' }));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 401,
      body: { error: 'token_revoked', requestId: 'req-1' },
    });
  });

  it('isRevoked false → continue + writes branded req.user', async () => {
    const { stage, rev } = build();
    rev.isRevoked.mockReturnValue(false);
    const ctx = makeCtx({ jti: 'j1', userId: 'u1', roles: ['admin'] });
    const out = await stage.run(ctx);
    expect(out).toEqual({ kind: 'continue' });
    expect(
      (ctx.req as unknown as { user: { __authenticatedByGateway: true; userId: string } }).user,
    ).toEqual({
      jti: 'j1',
      userId: 'u1',
      roles: ['admin'],
      exp: 9,
      deviceId: 'd1',
      __authenticatedByGateway: true,
    });
  });

  it('throws if ctx.claims missing (stage ordering bug)', async () => {
    const { stage } = build();
    await expect(
      stage.run({ req: { headers: {} } } as unknown as StageContext),
    ).rejects.toThrow(/ordering bug/);
  });
});
