import { Module } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwtStrategy } from './jwt.strategy';
import { AuthService } from './auth.service';
import {SharedModule} from "../shared/shared.module";
import { JwtService } from './jwt.service';

@Module({
  imports: [SharedModule],
  providers: [AuthService, JwtStrategy, JwtAuthGuard, JwtService],
  exports: [AuthService, JwtAuthGuard, JwtService],
})
export class AuthModule {}