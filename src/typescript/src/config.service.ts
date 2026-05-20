// src/typescript/src/config.service.ts
// PASO 19: Hardcoded Secrets — secretos en variables de entorno con validacion al arranque

import { Injectable } from '@nestjs/common';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

@Injectable()
export class ConfigService {
  get jwtSecret(): string {
    return requireEnv('JWT_SECRET');
  }

  get dbPassword(): string {
    return requireEnv('DB_PASSWORD');
  }

  get stripeKey(): string {
    return requireEnv('STRIPE_API_KEY');
  }
}
