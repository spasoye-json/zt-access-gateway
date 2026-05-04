/**
 * Phase 9 Wave 0 RED stubs for AuditController (AUDT-05). Implementation lands in Plan 09-01.
 */
describe('AuditController', () => {
  describe('class-level @Roles("admin") (AUDT-05)', () => {
    it.todo('Reflector.get(ROLES_KEY, AuditController) returns ["admin"]');
  });

  describe('GET /audit/logs (AUDT-05)', () => {
    it.todo('delegates to AuditService.queryLogs(query)');
    it.todo('returns { items, total }');
    it.todo('uses AuditLogsQueryDto for query validation');
  });

  describe('AuditLogsQueryDto validation (AUDT-05)', () => {
    it.todo('accepts decision in [allow, challenge, deny]');
    it.todo('rejects decision outside whitelist');
    it.todo('rejects limit < 1');
    it.todo('rejects limit > 200');
    it.todo('rejects offset < 0');
    it.todo('coerces numeric strings via @Type(() => Number)');
  });
});
