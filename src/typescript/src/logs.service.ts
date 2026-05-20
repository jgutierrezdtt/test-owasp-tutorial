// src/typescript/src/logs.service.ts
// PASO 18: Sensitive Data in Logs — filtrar campos sensibles antes de loguear

import { Injectable, Logger } from '@nestjs/common';

// VULNERABLE (punto de inicio del ejercicio):
// logRequest(body: unknown): void {
//   this.logger.log(JSON.stringify(body));
// }
//
// Si el body contiene { "username": "alice", "password": "s3cr3t" }
// la contrasena queda en texto plano en los logs.
// Un atacante con acceso a los logs (SIEM, Splunk, CloudWatch) obtiene credenciales reales.

@Injectable()
export class LogsService {
  private readonly logger = new Logger(LogsService.name);

  logRequest(body: unknown): void {
    this.logger.log(JSON.stringify(body));
  }
}
