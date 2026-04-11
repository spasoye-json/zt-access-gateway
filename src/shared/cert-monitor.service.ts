import * as fs from 'fs';
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { AppConfigService } from '../config/config.service';
import { MtlsService } from './mtls.service';

const POLL_INTERVAL_MS = 30_000;

/**
 * Polls cert files at a fixed interval and triggers MtlsService.reload()
 * when any file's mtime changes.
 *
 * Uses setInterval (polling) — native file-watching APIs are unreliable on
 * Docker volumes and some Linux kernels (inotify quirks). See RESEARCH.md Pitfall 1.
 */
@Injectable()
export class CertMonitorService implements OnModuleInit, OnModuleDestroy {
  private pollInterval: ReturnType<typeof setInterval> | null = null;
  private lastMtimes: Record<string, number> = {};

  constructor(
    private readonly mtlsService: MtlsService,
    private readonly config: AppConfigService,
  ) {}

  async onModuleInit(): Promise<void> {
    // Record initial mtimes so first poll has a baseline to compare against
    await this.initMtimes();
    this.pollInterval = setInterval(() => {
      void this.checkFiles();
    }, POLL_INTERVAL_MS);
  }

  onModuleDestroy(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  /** Exposed for testing: force an immediate check outside the timer. */
  async checkFiles(): Promise<void> {
    const paths = this.certPaths();
    let changed = false;

    for (const p of paths) {
      try {
        const stat = await fs.promises.stat(p);
        if (stat.mtimeMs !== this.lastMtimes[p]) {
          this.lastMtimes[p] = stat.mtimeMs;
          changed = true;
        }
      } catch {
        // File unreadable — skip this cycle, reload will surface the error
      }
    }

    if (changed) {
      await this.mtlsService.reload();
    }
  }

  private async initMtimes(): Promise<void> {
    for (const p of this.certPaths()) {
      try {
        const stat = await fs.promises.stat(p);
        this.lastMtimes[p] = stat.mtimeMs;
      } catch {
        this.lastMtimes[p] = 0;
      }
    }
  }

  private certPaths(): string[] {
    return [
      this.config.mtlsCaCertPath,
      this.config.mtlsClientCertPath,
      this.config.mtlsClientKeyPath,
    ];
  }
}
