// src/typescript/src/merge.controller.ts
// PASO 16: Prototype Pollution — validar con DTO y Object.create(null) en lugar de Object.assign

import { Body, Controller, Post } from '@nestjs/common';

// VULNERABLE (punto de inicio del ejercicio):
// @Post('/preferences')
// updatePreferences(@Body() body: any) {
//   const prefs = {};
//   Object.assign(prefs, body);  // prototype pollution: body puede contener __proto__
//   return prefs;
// }
//
// Un atacante puede enviar: { "__proto__": { "isAdmin": true } }
// Esto modifica Object.prototype, contaminando todos los objetos de la aplicacion.
// Si algun codigo hace: if (user.isAdmin) → ahora todos los usuarios son admin.

@Controller('user')
export class MergeController {
  @Post('/preferences')
  updatePreferences(@Body() body: any): Record<string, unknown> {
    const prefs = {};
    Object.assign(prefs, body);
    return prefs;
  }
}
