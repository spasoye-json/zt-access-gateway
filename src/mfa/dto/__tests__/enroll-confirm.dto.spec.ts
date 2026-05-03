/**
 * Phase 11 Plan 02 — EnrollConfirmDto validation (RED).
 * Tests fail until src/mfa/dto/enroll-confirm.dto.ts is created.
 */

import { validate } from 'class-validator';

// Dynamic import so spec compiles even before the file exists
const loadDto = async (): Promise<typeof import('../enroll-confirm.dto')> => {
  return import('../enroll-confirm.dto');
};

async function makeDto(
  data: Record<string, unknown>,
): Promise<InstanceType<Awaited<ReturnType<typeof loadDto>>['EnrollConfirmDto']>> {
  const { EnrollConfirmDto } = await loadDto();
  const dto = new EnrollConfirmDto();
  Object.assign(dto, data);
  return dto;
}

describe('EnrollConfirmDto', () => {
  it('T-11-DTO-01: accepts valid enrollmentId and 6-digit totpCode', async () => {
    const dto = await makeDto({
      enrollmentId: 'eid-550e8400-e29b-41d4-a716-446655440000',
      totpCode: '123456',
    });
    const errors = await validate(dto);
    expect(errors).toHaveLength(0);
  });

  it('T-11-DTO-01: rejects empty enrollmentId', async () => {
    const dto = await makeDto({ enrollmentId: '', totpCode: '123456' });
    const errors = await validate(dto);
    const field = errors.find((e) => e.property === 'enrollmentId');
    expect(field).toBeDefined();
  });

  it('T-11-DTO-01: rejects missing enrollmentId', async () => {
    const dto = await makeDto({ totpCode: '123456' });
    const errors = await validate(dto);
    const field = errors.find((e) => e.property === 'enrollmentId');
    expect(field).toBeDefined();
  });

  it('T-11-DTO-01: rejects totpCode shorter than 6 chars', async () => {
    const dto = await makeDto({ enrollmentId: 'eid-123', totpCode: '12345' });
    const errors = await validate(dto);
    const field = errors.find((e) => e.property === 'totpCode');
    expect(field).toBeDefined();
  });

  it('T-11-DTO-01: rejects totpCode longer than 6 chars', async () => {
    const dto = await makeDto({ enrollmentId: 'eid-123', totpCode: '1234567' });
    const errors = await validate(dto);
    const field = errors.find((e) => e.property === 'totpCode');
    expect(field).toBeDefined();
  });

  it('T-11-DTO-01: rejects empty totpCode', async () => {
    const dto = await makeDto({ enrollmentId: 'eid-123', totpCode: '' });
    const errors = await validate(dto);
    const field = errors.find((e) => e.property === 'totpCode');
    expect(field).toBeDefined();
  });
});
