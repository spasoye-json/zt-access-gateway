import { IsNotEmpty, IsString } from 'class-validator';

export class PolicyBindingDto {
  @IsString()
  @IsNotEmpty()
  subject!: string;

  @IsString()
  @IsNotEmpty()
  resource!: string;

  @IsString()
  @IsNotEmpty()
  action!: string;
}

