/**
 * Wave 0 RED stubs for BoPlaInterceptor.
 * Covers: BOPL-01 (strip unauthorized fields), BOPL-02 (field-policy.json loaded at init),
 *         BOPL-03 (recursive nested + array handling), BOPL-04 (admin all-fields, lower roles restricted).
 */
describe('BoPlaInterceptor', () => {
  describe('onModuleInit (BOPL-02)', () => {
    it.todo('reads field-policy.json from boplaPolicyPath at init');
    it.todo('parses JSON into typed FieldPolicy structure');
    it.todo('throws on missing file (fail-fast at startup)');
    it.todo('throws on malformed JSON');
  });
  describe('strip(data, path, roles) — admin (BOPL-04)', () => {
    it.todo('admin role + ["*"] → returns data unchanged');
    it.todo('admin role even when no policy entry matches → returns data unchanged (D-07)');
  });
  describe('strip(data, path, roles) — restricted role (BOPL-01)', () => {
    it.todo('user role + ["id","email"] → object retains only id and email keys');
    it.todo('user role + missing-key in allowed list → returned object lacks that key (no crash)');
  });
  describe('strip(data, path, roles) — fail-closed (D-07)', () => {
    it.todo('non-admin role + no matching pattern → returns {} (empty object)');
    it.todo('non-admin role + matching pattern but role not in roleMap → returns {}');
  });
  describe('strip(data, path, roles) — recursive (BOPL-03)', () => {
    it.todo('nested object — applies same allowed-fields list to nested object keys');
    it.todo('array of objects — applies policy to each element');
    it.todo('primitive value — returned as-is');
  });
  describe('strip(data, path, roles) — non-JSON safety (Pitfall 4)', () => {
    it.todo('string body → returned as-is, no Object.entries crash');
  });
  describe('first-match wins (D-06)', () => {
    it.todo('iterates patterns in JSON declaration order; first micromatch.isMatch hit returns');
  });
});
