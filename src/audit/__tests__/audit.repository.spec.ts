/**
 * Phase 9 Wave 0 RED stubs for AuditRepository (AUDT-02). DB tests gated by describeDb.
 * Implementation lands in Plan 09-01.
 */
const describeDb = process.env.DATABASE_URL ? describe : describe.skip;

describeDb('AuditRepository', () => {
  describe('insert(entry) — AUDT-02', () => {
    it.todo('writes user_id, resource, action, decision, trust_score, ja4h_fingerprint, ip_address, user_agent, request_id, event_type, created_at');
    it.todo('accepts decision values: allow | challenge | deny');
    it.todo('rejects decision value outside the CHECK constraint');
    it.todo('persists null trust_score when entry.trustScore is undefined');
  });

  describe('findLogs(filters) — AUDT-05', () => {
    it.todo('returns rows ordered by created_at DESC');
    it.todo('filters by userId when provided');
    it.todo('filters by decision when provided');
    it.todo('honors limit (default 50, max 200) + offset (default 0)');
    it.todo('returns total count alongside items');
  });
});
