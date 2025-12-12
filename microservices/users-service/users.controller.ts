import { Controller, Get, Post, Put, Delete, Param, Body, Query } from '@nestjs/common';

export interface User {
  id: string;
  name: string;
  email: string;
  roles: string[];
}

@Controller('users')
export class UsersController {
  private users: User[] = [
    { id: '1', name: 'John Doe', email: 'john@example.com', roles: ['user'] },
    { id: '2', name: 'Jane Smith', email: 'jane@example.com', roles: ['admin'] },
  ];

  @Get()
  getUsers(
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ): User[] {
    const limitNum = limit ? parseInt(limit, 10) : this.users.length;
    const offsetNum = offset ? parseInt(offset, 10) : 0;
    
    return this.users.slice(offsetNum, offsetNum + limitNum);
  }

  @Get(':id')
  getUser(@Param('id') id: string): User {
    const user = this.users.find(u => u.id === id);
    if (!user) {
      throw new Error(`User with id ${id} not found`);
    }
    return user;
  }

  @Post()
  createUser(@Body() createUserDto: Omit<User, 'id'>): User {
    const newUser: User = {
      id: (this.users.length + 1).toString(),
      ...createUserDto,
    };
    
    this.users.push(newUser);
    return newUser;
  }

  @Put(':id')
  updateUser(@Param('id') id: string, @Body() updateUserDto: Partial<User>): User {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new Error(`User with id ${id} not found`);
    }
    
    this.users[userIndex] = { ...this.users[userIndex], ...updateUserDto };
    return this.users[userIndex];
  }

  @Delete(':id')
  deleteUser(@Param('id') id: string): { message: string } {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex === -1) {
      throw new Error(`User with id ${id} not found`);
    }
    
    this.users.splice(userIndex, 1);
    return { message: `User with id ${id} has been deleted` };
  }
}