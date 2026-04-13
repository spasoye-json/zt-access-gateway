import { IsString, IsNumber, IsNotEmpty } from 'class-validator';

/**
 * Request DTO for POST /auth/revoke (TREV-03).
 * Caller provides the jti and exp from the token they want to revoke.
 */
export class RevokeTokenDto {
  /** JWT ID (jti claim) of the token to revoke */
  @IsString()
  @IsNotEmpty()
  jti: string;

  /** Token expiration as Unix timestamp in SECONDS (from JWT exp claim).
   *  Converted to milliseconds before storage. */
  @IsNumber()
  exp: number;
}
