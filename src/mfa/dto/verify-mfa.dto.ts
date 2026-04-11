import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class VerifyMfaDto {
  @IsString()
  @IsNotEmpty()
  challengeId!: string;

  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'MFA code must be 6 digits' })
  @Matches(/^\d+$/, { message: 'MFA code must be numeric' })
  code!: string;
}
