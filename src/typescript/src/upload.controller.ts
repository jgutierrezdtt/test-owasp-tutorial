// src/typescript/src/upload.controller.ts
// PASO 20: Insecure File Upload — validar MIME type, extension y usar nombre generado

import { Controller, Post, UploadedFile, UseInterceptors } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';

// VULNERABLE (punto de inicio del ejercicio):
// @Post('/upload')
// @UseInterceptors(FileInterceptor('file'))
// upload(@UploadedFile() file: Express.Multer.File) {
//   return { filename: file.originalname };
// }
//
// Sin validacion, un atacante puede subir:
// - Un archivo .php/.jsp que el servidor ejecuta si sirve archivos estaticos
// - Un archivo con nombre ../../../../etc/cron.d/backdoor (path traversal)
// - Archivos de tamano arbitrario (DoS por disco lleno)

@Controller('files')
export class UploadController {
  @Post('/upload')
  @UseInterceptors(FileInterceptor('file'))
  upload(@UploadedFile() file: Express.Multer.File): { filename: string } {
    return { filename: file.originalname };
  }
}
