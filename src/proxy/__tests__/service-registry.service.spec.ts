/**
 * Wave 0 RED stubs for ServiceRegistryService.
 * Covers: PRXY-03 (registry allowlist), PRXY-06 (unknown service rejected before I/O).
 */
describe('ServiceRegistryService', () => {
  describe('onModuleInit (PRXY-03)', () => {
    it.todo('parses PROXY_SERVICE_REGISTRY JSON into Map<serviceName, baseUrl>');
    it.todo('throws Error when PROXY_SERVICE_REGISTRY is empty {}');
    it.todo('throws Error when PROXY_SERVICE_REGISTRY is malformed JSON');
  });
  describe('resolve(serviceName) (PRXY-06)', () => {
    it.todo('returns baseUrl when serviceName is in registry');
    it.todo('throws NotFoundException when serviceName is NOT in registry');
    it.todo('rejects before any DNS or network call');
  });
  describe('extractServiceName(path) (D-04 path-prefix routing)', () => {
    it.todo('returns first path segment for /users/profile → users');
    it.todo('returns null for empty path /');
  });
});
