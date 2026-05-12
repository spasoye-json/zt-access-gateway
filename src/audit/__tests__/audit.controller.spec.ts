import { Reflector } from '@nestjs/core';
import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { AuditController } from '../audit.controller';
import { AuditLogsQueryDto } from '../dto/audit-logs-query.dto';
import type { AuditService } from '../audit.service';
import { ROLES_KEY } from '../../auth/roles.decorator';

describe('AuditController', () => {
  let svc: jest.Mocked<AuditService>;
  let ctrl: AuditController;

  beforeEach(() => {
    svc = { queryLogs: jest.fn() } as unknown as jest.Mocked<AuditService>;
    ctrl = new AuditController(svc);
  });

  describe('class-level @Roles("admin") (AUDT-05)', () => {
    it('Reflector returns ["admin"] for AuditController class', () => {
      const reflector = new Reflector();
      const meta = reflector.get<string[]>(ROLES_KEY, AuditController);
      expect(meta).toEqual(['admin']);
    });
  });

  describe('GET /audit/logs delegation (AUDT-05)', () => {
    it('forwards DTO to AuditService.queryLogs and returns { items, total }', async () => {
      svc.queryLogs.mockResolvedValueOnce({ items: [], total: 7 });
      const out = await ctrl.getLogs({ userId: 'u', limit: 10, offset: 0 });
      expect(svc.queryLogs).toHaveBeenCalledWith({ userId: 'u', limit: 10, offset: 0 });
      expect(out).toEqual({ items: [], total: 7 });
    });
  });

  describe('AuditLogsQueryDto validation (AUDT-05)', () => {
    const validateDto = async (raw: Record<string, unknown>) => {
      const dto = plainToInstance(AuditLogsQueryDto, raw);
      return validate(dto);
    };

    it('accepts decision = allow|challenge|deny', async () => {
      for (const d of ['allow', 'challenge', 'deny']) {
        expect(await validateDto({ decision: d })).toEqual([]);
      }
    });

    it('rejects decision outside whitelist', async () => {
      const errs = await validateDto({ decision: 'bogus' });
      expect(errs.length).toBeGreaterThan(0);
    });

    it('rejects limit < 1', async () => {
      const errs = await validateDto({ limit: 0 });
      expect(errs.length).toBeGreaterThan(0);
    });

    it('rejects limit > 200', async () => {
      const errs = await validateDto({ limit: 201 });
      expect(errs.length).toBeGreaterThan(0);
    });

    it('rejects offset < 0', async () => {
      const errs = await validateDto({ offset: -1 });
      expect(errs.length).toBeGreaterThan(0);
    });

    it('coerces numeric strings via @Type(() => Number)', async () => {
      const dto = plainToInstance(AuditLogsQueryDto, { limit: '100', offset: '5' });
      const errs = await validate(dto);
      expect(errs).toEqual([]);
      expect(typeof dto.limit).toBe('number');
      expect(typeof dto.offset).toBe('number');
    });
  });
});
