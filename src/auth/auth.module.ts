import { Module } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { JwtStrategy } from './jwt.strategy';
import { AuthService } from './auth.service';
import {SharedModule} from "../shared/shared.module";

@Module({
  imports: [SharedModule],
  providers: [AuthService, JwtStrategy, JwtAuthGuard],
  exports: [AuthService, JwtAuthGuard],
})
export class AuthModule {}