// src/typescript/src/merge.controller.ts
// PASO 16: Prototype Pollution — validar con DTO y Object.create(null) en lugar de Object.assign

import { Body, Controller, Post } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { IsString, validateSync } from 'class-validator';

class UserPreferencesDto {
  @IsString() theme?: string;
  @IsString() language?: string;
}

@Controller('user')
export class MergeController {
  @Post('/preferences')
  updatePreferences(@Body() body: unknown): Record<string, unknown> {
    const dto = plainToInstance(UserPreferencesDto, body);
    const errors = validateSync(dto);
    if (errors.length > 0) throw new Error('Invalid preferences');
    const prefs: Record<string, unknown> = Object.create(null);
    if (dto.theme !== undefined) prefs['theme'] = dto.theme;
    if (dto.language !== undefined) prefs['language'] = dto.language;
    return prefs;
  }
}
