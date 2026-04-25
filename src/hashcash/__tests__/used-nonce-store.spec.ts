/**
 * Phase 5 Wave 0 stubs — HCSH-04 replay defense (TTL + capacity FIFO).
 * Filled in by 05-02-PLAN.md.
 */
describe('UsedNonceStore', () => {
  it.todo('has(nonce) returns false for unknown nonce');
  it.todo('add(nonce, exp) then has(nonce) returns true within TTL');
  it.todo('has(nonce) lazy-evicts and returns false when Math.floor(Date.now()/1000) >= exp');
  it.todo('add() over capacity FIFO-evicts the oldest entry (Map insertion order)');
  it.todo('exp uses Unix seconds (matches nonce payload exp field)');
});
