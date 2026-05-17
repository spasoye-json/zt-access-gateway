import { GATEWAY_VALIDATED } from '../gateway-validated.symbol';

/**
 * Issue #16 — the Symbol-keyed brand that #18 will use to mark a request as
 * already authenticated by the gateway. Symbol identity must be stable
 * (single export, no Symbol.for) so request bodies cannot forge the brand.
 */
describe('GATEWAY_VALIDATED symbol', () => {
  it('is a Symbol with description "gateway:validated"', () => {
    expect(typeof GATEWAY_VALIDATED).toBe('symbol');
    expect(GATEWAY_VALIDATED.description).toBe('gateway:validated');
  });

  it('is not Symbol.for-registered (cannot be retrieved by description)', () => {
    expect(Symbol.for('gateway:validated')).not.toBe(GATEWAY_VALIDATED);
  });
});
