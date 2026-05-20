// src/typescript/src/logs.service.ts
// PASO 18: Sensitive Data in Logs — filtrar campos sensibles antes de loguear

import { Injectable, Logger } from '@nestjs/common';

const SENSITIVE_FIELDS = new Set(['password', 'token', 'secret', 'authorization', 'cookie']);

@Injectable()
export class LogsService {
  private readonly logger = new Logger(LogsService.name);

  private redact(body: unknown): unknown {
    if (typeof body !== 'object' || body === null) return body;
    const redacted: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
      redacted[k] = SENSITIVE_FIELDS.has(k.toLowerCase()) ? '[REDACTED]' : v;
    }
    return redacted;
  }

  logRequest(body: unknown): void {
    this.logger.log(JSON.stringify(this.redact(body)));
  }
}
