import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';
import { MetricsService } from './metrics.service';
import { Public } from '../auth/public.decorator';

@Public()
@Controller('metrics')
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  @Get()
  async getMetrics(@Res() res: Response) {
    res.setHeader('Content-Type', this.metricsService.getContentType());
    res.send(await this.metricsService.getMetrics());
  }
}
