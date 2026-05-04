import { BadGatewayException, ServiceUnavailableException } from '@nestjs/common';
import type { AxiosResponse } from 'axios';

/**
 * PRXY-09 — lightweight downstream response check.
 * Per RESEARCH.md Open Question #1, scope is intentionally narrow: status code
 * and Content-Type only. Deep JSON schema validation is the responsibility of
 * BoPlaInterceptor (which already needs the parsed body) — this function
 * simply guards against propagating obvious upstream failures.
 *
 * Note: 4xx statuses pass through — they are deterministic upstream responses
 * that BOPLA may still need to filter. Only 5xx fails (request did not complete normally).
 */
export function assertValidProxyResponse(response: AxiosResponse): void {
  if (response.status >= 500) {
    throw new ServiceUnavailableException(
      `Upstream returned ${response.status}`,
    );
  }

  const ct = response.headers?.['content-type'];
  const ctStr = Array.isArray(ct) ? ct[0] : ct;
  if (!ctStr || !String(ctStr).toLowerCase().includes('application/json')) {
    throw new BadGatewayException(
      `Unexpected Content-Type from upstream: ${ctStr ?? 'missing'}`,
    );
  }
}
