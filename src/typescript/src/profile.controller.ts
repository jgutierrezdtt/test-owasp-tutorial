// src/typescript/src/profile.controller.ts
// PASO 29: Mass Assignment — whitelist de campos actualizables con DTO tipado

import { Body, Controller, Put, Request } from '@nestjs/common';

@Controller('users')
export class ProfileController {
  private readonly users: Record<string, Record<string, unknown>> = {
    'user-1': { id: 'user-1', username: 'alice', email: 'alice@example.com', isAdmin: false, role: 'user' },
    'user-2': { id: 'user-2', username: 'bob', email: 'bob@example.com', isAdmin: false, role: 'user' },
  };

  // VULNERABLE (punto de inicio del ejercicio):
  // @Put('/profile')
  // async updateProfile(
  //   @Request() req: any,
  //   @Body() body: any,
  // ): Promise<{ message: string }> {
  //   const userId = req.user?.id ?? 'user-1';
  //   Object.assign(this.users[userId], body);
  //   return { message: 'Perfil actualizado' };
  // }
  //
  // El body del atacante: {"isAdmin": true, "role": "admin"}
  // Object.assign copia TODAS las propiedades del body al objeto de usuario.
  // Resultado: el usuario normal escala a administrador sin que el servidor lo impida.
  // En frameworks como Rails, Django, Spring y NestJS esto es un vector clasico
  // para escalada de privilegios sin vulnerar autenticacion.

  @Put('/profile')
  async updateProfile(
    @Request() req: any,
    @Body() body: any,
  ): Promise<{ message: string }> {
    const userId = req.user?.id ?? 'user-1';
    Object.assign(this.users[userId], body);
    return { message: 'Perfil actualizado' };
  }
}
