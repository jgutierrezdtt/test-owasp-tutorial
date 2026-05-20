// src/typescript/src/search.controller.ts
// PASO 17: Regex Injection — escapar metacaracteres del input antes de construir RegExp

import { BadRequestException, Controller, Get, Query } from '@nestjs/common';

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

@Controller('products')
export class SearchController {
  private readonly products = ['laptop', 'phone', 'tablet', 'monitor', 'keyboard'];

  @Get('/search')
  search(@Query('q') q: string): string[] {
    if (!q || q.length > 100) throw new BadRequestException('Query invalida');
    const pattern = new RegExp(escapeRegExp(q), 'i');
    return this.products.filter(p => pattern.test(p));
  }
}
