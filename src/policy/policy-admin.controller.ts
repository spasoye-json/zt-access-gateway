import { Body, Controller, Delete, Get, Post } from '@nestjs/common';
import { PolicyService, PolicyBinding } from './policy.service';
import { PolicyBindingDto } from './dto/policy-binding.dto';
import { Roles } from '../auth/roles.decorator';

@Roles('admin')
@Controller('policy/admin')
export class PolicyAdminController {
  constructor(private readonly policyService: PolicyService) {}

  @Get('rules')
  async listPolicies(): Promise<PolicyBinding[]> {
    return this.policyService.listPolicies();
  }

  @Post('rules')
  async addPolicy(@Body() binding: PolicyBindingDto) {
    const success = await this.policyService.addPolicy(binding);
    return { success };
  }

  @Delete('rules')
  async removePolicy(@Body() binding: PolicyBindingDto) {
    const success = await this.policyService.removePolicy(binding);
    return { success };
  }

  @Post('reload')
  async reloadPolicies() {
    await this.policyService.reloadPolicies();
    return { reloaded: true };
  }
}

