import { IsString, IsNotEmpty, Length, IsNumberString } from 'class-validator';

/**
 * Phase 11 — Body for POST /mfa/enroll/confirm.
 *
 * enrollmentId: UUIDv4 returned from POST /mfa/enroll (D-02). We do NOT
 * @IsUUID-validate because that would couple the contract to UUIDv4 forever;
 * non-empty + string is sufficient — invalid IDs simply fail the
 * PendingEnrollmentStore.get() lookup with reason 'expired_enrollment'.
 *
 * totpCode: RFC 6238 6-digit code from the user's authenticator app (D-04).
 */
export class EnrollConfirmDto {
  @IsString()
  @IsNotEmpty()
  enrollmentId!: string;

  @IsString()
  @IsNotEmpty()
  @IsNumberString()
  @Length(6, 6)
  totpCode!: string;
}
