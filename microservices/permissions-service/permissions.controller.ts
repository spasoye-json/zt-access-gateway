import { Controller, Get, Post, Put, Delete, Param, Body, Query } from '@nestjs/common';

export interface Permission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: string;
}

@Controller('permissions')
export class PermissionsController {
  private permissions: Permission[] = [
    { id: '1', name: 'read-users', description: 'Read user information', resource: 'users', action: 'read' },
    { id: '2', name: 'write-orders', description: 'Create and update orders', resource: 'orders', action: 'write' },
  ];

  @Get()
  getPermissions(
    @Query('resource') resource?: string,
    @Query('action') action?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ): Permission[] {
    let filteredPermissions = this.permissions;
    
    if (resource) {
      filteredPermissions = filteredPermissions.filter(p => p.resource === resource);
    }
    
    if (action) {
      filteredPermissions = filteredPermissions.filter(p => p.action === action);
    }
    
    const limitNum = limit ? parseInt(limit, 10) : filteredPermissions.length;
    const offsetNum = offset ? parseInt(offset, 10) : 0;
    
    return filteredPermissions.slice(offsetNum, offsetNum + limitNum);
  }

  @Get(':id')
  getPermission(@Param('id') id: string): Permission {
    const permission = this.permissions.find(p => p.id === id);
    if (!permission) {
      throw new Error(`Permission with id ${id} not found`);
    }
    return permission;
  }

  @Post()
  createPermission(@Body() createPermissionDto: Omit<Permission, 'id'>): Permission {
    const newPermission: Permission = {
      id: (this.permissions.length + 1).toString(),
      ...createPermissionDto,
    };
    
    this.permissions.push(newPermission);
    return newPermission;
  }

  @Put(':id')
  updatePermission(@Param('id') id: string, @Body() updatePermissionDto: Partial<Permission>): Permission {
    const permissionIndex = this.permissions.findIndex(p => p.id === id);
    if (permissionIndex === -1) {
      throw new Error(`Permission with id ${id} not found`);
    }
    
    this.permissions[permissionIndex] = { ...this.permissions[permissionIndex], ...updatePermissionDto };
    return this.permissions[permissionIndex];
  }

  @Delete(':id')
  deletePermission(@Param('id') id: string): { message: string } {
    const permissionIndex = this.permissions.findIndex(p => p.id === id);
    if (permissionIndex === -1) {
      throw new Error(`Permission with id ${id} not found`);
    }
    
    this.permissions.splice(permissionIndex, 1);
    return { message: `Permission with id ${id} has been deleted` };
  }
}