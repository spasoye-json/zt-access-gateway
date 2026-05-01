import { IsString, IsNotEmpty, Length } from 'class-validator';

export class VerifyMfaDto {
  @IsString()
  @IsNotEmpty()
  challengeId: string;

  /** TOTP code — exactly 6 digits (D-14: RFC 6238 standard length). */
  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  totpCode: string;
}
