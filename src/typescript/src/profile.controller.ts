// src/typescript/src/profile.controller.ts
// PASO 29: Mass Assignment — whitelist de campos actualizables con DTO tipado

import { Body, Controller, Put, Request } from '@nestjs/common';
import { instanceToPlain } from 'class-transformer';
import { IsEmail, IsOptional, IsString } from 'class-validator';

class UpdateProfileDto {
  @IsOptional() @IsString() username?: string;
  @IsOptional() @IsEmail() email?: string;
}

@Controller('users')
export class ProfileController {
  private readonly users: Record<string, Record<string, unknown>> = {
    'user-1': { id: 'user-1', username: 'alice', email: 'alice@example.com', isAdmin: false, role: 'user' },
    'user-2': { id: 'user-2', username: 'bob', email: 'bob@example.com', isAdmin: false, role: 'user' },
  };

  @Put('/profile')
  async updateProfile(
    @Request() req: any,
    @Body() dto: UpdateProfileDto,
  ): Promise<{ message: string }> {
    const userId = req.user?.id ?? 'user-1';
    const safe = instanceToPlain(dto);
    if (safe.username !== undefined) this.users[userId]['username'] = safe.username;
    if (safe.email !== undefined) this.users[userId]['email'] = safe.email;
    return { message: 'Perfil actualizado' };
  }
}
