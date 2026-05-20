// src/typescript/src/upload.controller.ts
// PASO 20: Insecure File Upload — validar MIME type, extension y usar nombre generado

import { BadRequestException, Controller, Post, UploadedFile, UseInterceptors } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { randomUUID } from 'crypto';
import * as path from 'path';

const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const ALLOWED_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp']);
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

@Controller('files')
export class UploadController {
  @Post('/upload')
  @UseInterceptors(FileInterceptor('file'))
  upload(@UploadedFile() file: Express.Multer.File): { filename: string } {
    if (!file) throw new BadRequestException('No se recibio archivo');
    const ext = path.extname(file.originalname).toLowerCase();
    const fileSize = file.size;
    if (!ALLOWED_MIME_TYPES.has(file.mimetype)) throw new BadRequestException('Tipo MIME no permitido');
    if (!ALLOWED_EXTENSIONS.has(ext)) throw new BadRequestException('Extension no permitida');
    if (fileSize > MAX_FILE_SIZE) throw new BadRequestException('Archivo demasiado grande');
    const safeFilename = `${randomUUID()}${ext}`;
    return { filename: safeFilename };
  }
}
