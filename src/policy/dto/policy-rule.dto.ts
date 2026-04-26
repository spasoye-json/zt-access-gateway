import { IsNotEmpty, IsString, MaxLength } from 'class-validator';

/**
 * Phase 6 — Body DTO for /policy/admin/rules POST + DELETE (D-22).
 * `sub` is the Casbin subject (e.g., 'role:user', 'user:42').
 * `obj` is the resource path (use the same canonical form normalizeResource produces).
 * `act` is the HTTP method (uppercase) or a regex compatible with policy/model.conf matchers.
 */
export class PolicyRuleDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(200)
  sub!: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(500)
  obj!: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  act!: string;
}
