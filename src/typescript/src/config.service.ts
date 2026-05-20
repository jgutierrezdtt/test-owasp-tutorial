// src/typescript/src/config.service.ts
// PASO 19: Hardcoded Secrets — secretos en variables de entorno con validacion al arranque

import { Injectable } from '@nestjs/common';

// VULNERABLE (punto de inicio del ejercicio):
// const JWT_SECRET = "super-secret-key-hardcoded-123";
// const DB_PASSWORD = "admin1234";
// const STRIPE_KEY = "sk_live_hardcoded_key_abc123";
//
// Los secretos hardcodeados aparecen en el historial de git para siempre.
// Cualquier persona con acceso al repositorio (empleado, contratista, atacante que
// haya hecho un leak) obtiene acceso total a la base de datos, JWT y pagos.

const JWT_SECRET = 'super-secret-key-hardcoded-123';
const DB_PASSWORD = 'admin1234';
const STRIPE_KEY = 'sk_live_hardcoded_key_abc123';

@Injectable()
export class ConfigService {
  get jwtSecret(): string {
    return JWT_SECRET;
  }

  get dbPassword(): string {
    return DB_PASSWORD;
  }

  get stripeKey(): string {
    return STRIPE_KEY;
  }
}
