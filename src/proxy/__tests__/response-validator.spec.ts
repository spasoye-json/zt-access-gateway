/**
 * Wave 0 RED stubs for ResponseValidator.
 * Covers: PRXY-09 (validates downstream response status + Content-Type before returning).
 */
describe('assertValidProxyResponse', () => {
  it.todo('200 + application/json → returns void');
  it.todo('200 + application/json; charset=utf-8 → returns void (substring match)');
  it.todo('500 status → throws ServiceUnavailableException');
  it.todo('502 status → throws ServiceUnavailableException');
  it.todo('200 + text/html Content-Type → throws BadGatewayException');
  it.todo('200 + missing Content-Type header → throws BadGatewayException');
});
