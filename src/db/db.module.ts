import { Global, Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { DB } from './db.port';
import { DbService } from './db.service';

/**
 * Phase B2 — global DbModule.
 *
 * Provides a single shared `DbService` (and the `DB` injection token bound to
 * it) for the entire app. Marked @Global() so individual modules don't need
 * to import it explicitly — the `DB` token resolves anywhere.
 */
@Global()
@Module({
  imports: [ConfigAppModule],
  providers: [DbService, { provide: DB, useExisting: DbService }],
  exports: [DB, DbService],
})
export class DbModule {}
