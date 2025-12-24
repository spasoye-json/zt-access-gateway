import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MfaService } from './mfa.service';
import { MfaController } from './mfa.controller';
import { MfaRepository } from './mfa.repository';

@Module({
  imports: [ConfigModule],
  controllers: [MfaController],
  providers: [MfaService, MfaRepository],
  exports: [MfaService],
})
export class MfaModule {}
