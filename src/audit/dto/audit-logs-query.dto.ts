import { IsIn, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';
import { Type } from 'class-transformer';

/** Phase 9 — GET /audit/logs query params (D-07, validated by global ValidationPipe). */
export class AuditLogsQueryDto {
  @IsOptional()
  @IsString()
  userId?: string;

  @IsOptional()
  @IsIn(['allow', 'challenge', 'deny'])
  decision?: 'allow' | 'challenge' | 'deny';

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(200)
  limit?: number = 50;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(0)
  offset?: number = 0;
}
