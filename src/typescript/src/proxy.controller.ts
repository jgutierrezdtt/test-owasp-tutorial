// src/typescript/src/proxy.controller.ts
// PASO 28: SSRF — validar host contra allowlist antes de proxificar requests

import { BadRequestException, Controller, Get, Query } from '@nestjs/common';
import axios from 'axios';

@Controller('proxy')
export class ProxyController {
  // VULNERABLE (punto de inicio del ejercicio):
  // @Get('/fetch')
  // async fetch(@Query('url') url: string): Promise<string> {
  //   const response = await axios.get(url);
  //   return response.data;
  // }
  //
  // Vectores de ataque:
  // 1. AWS IMDSv1: GET /proxy/fetch?url=http://169.254.169.254/latest/meta-data/
  //    Devuelve credenciales IAM del rol asignado a la instancia EC2.
  // 2. GCP metadata: GET /proxy/fetch?url=http://metadata.google.internal/computeMetadata/v1/
  // 3. Servicios internos: GET /proxy/fetch?url=http://redis:6379/ o http://elasticsearch:9200/
  // 4. Escaneo de red interna: midiendo tiempos de respuesta se puede mapear la red interna.
  // 5. Con redirects: empezar con un host permitido que redirecciona a 169.254.169.254.

  @Get('/fetch')
  async fetch(@Query('url') url: string): Promise<string> {
    const response = await axios.get(url);
    return response.data;
  }
}
