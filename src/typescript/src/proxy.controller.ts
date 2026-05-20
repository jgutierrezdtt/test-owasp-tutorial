// src/typescript/src/proxy.controller.ts
// PASO 28: SSRF — validar host contra allowlist antes de proxificar requests

import { BadRequestException, Controller, Get, Query } from '@nestjs/common';
import axios from 'axios';

const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);
const MAX_REDIRECTS = 0;

@Controller('proxy')
export class ProxyController {
  @Get('/fetch')
  async fetch(@Query('url') url: string): Promise<string> {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new BadRequestException('URL invalida');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new BadRequestException('Esquema no permitido');
    }
    if (!ALLOWED_HOSTS.has(parsed.hostname)) {
      throw new BadRequestException('Host no permitido');
    }
    const response = await axios.get(url, { maxRedirects: MAX_REDIRECTS, timeout: 5000 });
    return response.data;
  }
}
