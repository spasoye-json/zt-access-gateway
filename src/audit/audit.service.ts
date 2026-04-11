import { Injectable, Logger } from '@nestjs/common';
import { AuditRepository } from './audit.repository';

export interface AuditLog {
  id: string;
  requestId: string;
  timestamp: Date;
  userId: string;
  microservice: string;
  decision: 'ALLOW' | 'DENY' | 'CHALLENGE';
  riskScore: number;
  policyApplied: string;
  metadata: Record<string, any>;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly auditRepository: AuditRepository) {}

  async logAccessDecision(logEntry: Omit<AuditLog, 'id' | 'timestamp'>): Promise<void> {
    try {
      // Validate inputs
      if (!logEntry || typeof logEntry !== 'object') {
        throw new Error('Invalid log entry provided');
      }

      if (!logEntry.requestId || typeof logEntry.requestId !== 'string') {
        throw new Error('Valid requestId is required for audit logging');
      }

      if (!logEntry.userId || typeof logEntry.userId !== 'string') {
        throw new Error('Valid userId is required for audit logging');
      }

      if (!logEntry.microservice || typeof logEntry.microservice !== 'string') {
        throw new Error('Valid microservice is required for audit logging');
      }

      if (!logEntry.decision || !['ALLOW', 'DENY', 'CHALLENGE'].includes(logEntry.decision)) {
        throw new Error('Valid decision (ALLOW/DENY/CHALLENGE) is required for audit logging');
      }

      if (typeof logEntry.riskScore !== 'number' || logEntry.riskScore < 0 || logEntry.riskScore > 1) {
        throw new Error('Valid riskScore (0-1) is required for audit logging');
      }

      if (!logEntry.policyApplied || typeof logEntry.policyApplied !== 'string') {
        throw new Error('Valid policyApplied is required for audit logging');
      }

      // Create audit log with proper ID and timestamp
      const auditLog: AuditLog = {
        ...logEntry,
        id: this.generateId(),
        timestamp: new Date(),
      };

      this.logger.debug(`Audit decision recorded for request ${auditLog.requestId}`);
      await this.auditRepository.persist(auditLog);
    } catch (error) {
      this.logger.error('Failed to log audit entry:', error.message);
    }
  }

  private generateId(): string {
    // Generate a UUID-like ID for the audit log
    return 'audit-' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  }
}
