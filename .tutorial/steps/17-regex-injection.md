# Paso 17 — Regex Injection
**Tecnologia:** TypeScript / NestJS | **OWASP:** A03:2021 - Injection | **CWE-625**

---

## Que es esta vulnerabilidad?

Regex Injection ocurre cuando input del usuario se usa para construir una expresion regular sin escapar sus metacaracteres. El impacto es doble:

1. **DoS via ReDoS:** el atacante puede enviar un patron con backtracking catastrofico que bloquea el event loop de Node.js (que es single-threaded). A diferencia del step 13 en Go, en Node.js un event loop bloqueado es devastador: todas las peticiones al servidor se cuelgan hasta que el regex termina.

2. **Comportamiento inesperado:** metacaracteres como `.` (cualquier caracter), `*` (cero o mas), `^` y `$` pueden hacer que el regex matchee cosas que no deberia, causando falsos positivos en validaciones o bypass de filtros de seguridad.

En JavaScript, `new RegExp(userInput)` acepta cualquier patron valido o invalido. Si el patron es invalido (por ejemplo `[unterminated`), lanza una excepcion que puede exponer informacion del stack trace al atacante.

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/search.controller.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
@Controller('products')
export class SearchController {
  private readonly products = ['laptop', 'phone', 'tablet', 'monitor', 'keyboard'];

  @Get('/search')
  search(@Query('q') q: string): string[] {
    const pattern = new RegExp(q, 'i');  // q del usuario como patron directo
    return this.products.filter(p => pattern.test(p));
  }
}
```

Cuando `q` contiene metacaracteres o cuantificadores anidados:
- `q=((a+)+)z`: crea un regex con backtracking catastrofico que bloquea el event loop
- `q=[invalido`: lanza `SyntaxError: Invalid regular expression`, exponiendo el stack trace
- `q=.`: matchea todos los productos (bypass de filtro)
- `q=.*`: devuelve todos los resultados independientemente del input

---

## Como lo explotaria un atacante

**DoS bloqueando el event loop de Node.js:**
```
GET /products/search?q=((a%2B)%2B)z
```

Node.js tiene un solo event loop. Mientras el regex evalua el patron catastrofico, ninguna otra peticion puede ser procesada. Con 2-3 peticiones concurrentes de este tipo, el servidor queda completamente inoperativo.

**Demostrar el impacto:**
```javascript
// En Node.js: este regex bloquea el process durante segundos
const start = Date.now();
new RegExp('((a+)+)z', 'i').test('a'.repeat(30) + 'X');
console.log(`Tiempo: ${Date.now() - start}ms`);  // ~30.000ms con 30 caracteres
```

**Bypass de filtro con metacaracteres:**
```
GET /products/search?q=.*    # devuelve todos los productos
GET /products/search?q=.     # devuelve todos los productos (. = cualquier caracter)
```

**Error con regex invalido:**
```
GET /products/search?q=[unclosed
# SyntaxError: Invalid regular expression: /[unclosed/i: Unterminated character class
# El stack trace puede exponer rutas internas del servidor
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/search.controller.ts` para escapar metacaracteres y limitar la longitud:

```typescript
// CODIGO SEGURO
import { Controller, Get, Query, BadRequestException } from '@nestjs/common';

// Escapar todos los metacaracteres de regex en el input del usuario
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Los caracteres . * + ? ^ $ { } ( ) | [ ] \ son escapados con \
  // Asi, '.' se convierte en '\.' que solo matchea un punto literal
}

@Controller('products')
export class SearchController {
  private readonly products = ['laptop', 'phone', 'tablet', 'monitor', 'keyboard'];

  @Get('/search')
  search(@Query('q') q: string): string[] {
    if (!q || q.length === 0) {
      return [];
    }
    if (q.length > 100) {
      throw new BadRequestException('Query demasiado larga');
    }

    // Escapar metacaracteres: el usuario solo puede buscar texto literal
    const safePattern = escapeRegExp(q);
    const pattern = new RegExp(safePattern, 'i');
    return this.products.filter(p => pattern.test(p));
  }
}
```

### Por que funciona esta mitigacion?

- **`escapeRegExp`:** antepone `\` a todos los metacaracteres de regex. El input `((a+)+)z` se convierte en `\(\(a\+\)\+\)z`, que busca literalmente esa cadena de texto. No hay cuantificadores ni grupos que puedan causar backtracking.
- **Limite de longitud `q.length > 100`:** incluso con un patron potencialmente costoso, limitar el input a 100 caracteres pone un techo al tiempo de evaluacion. Ademas, consultas de busqueda legitimas raramente necesitan mas de 100 caracteres.
- **Validacion de input vacio:** devolver `[]` para input vacio en lugar de lanzar excepcion es mas apropiado semanticamente para un endpoint de busqueda.

---

## Variantes de la misma categoria (Injection en motores de busqueda — mas complejas)

### Variante A: MongoDB Operator Injection

```typescript
// VULNERABLE — query de MongoDB construida con input del usuario
@Get('/users')
async findUsers(@Query('role') role: string) {
  // Si role = { "$gt": "" }, MongoDB devuelve todos los usuarios
  // porque todos los roles son "mayor que" una cadena vacia
  return this.userModel.find({ role: role }).exec();
}
```

Payload: `GET /users?role[$gt]=`  
Mongoose convierte esto a `{ role: { $gt: '' } }` si no hay proteccion, devolviendo todos los usuarios.

```typescript
// SEGURO — validar tipo y usar cast explicito a string
@Get('/users')
async findUsers(@Query('role') role: unknown) {
  const VALID_ROLES = ['admin', 'user', 'moderator'];
  if (typeof role !== 'string' || !VALID_ROLES.includes(role)) {
    throw new BadRequestException('Rol invalido');
  }
  return this.userModel.find({ role: String(role) }).exec();  // cast a string garantizado
}
```

---

### Variante B: Elasticsearch Query Injection

```typescript
// VULNERABLE — query DSL de Elasticsearch construida con input sin sanitizar
@Get('/search')
async searchDocuments(@Query('q') q: string) {
  const query = {
    query: {
      query_string: {
        query: q  // query_string acepta sintaxis Lucene avanzada con OR, AND, campos
      }
    }
  };
  return this.elastic.search({ index: 'documents', body: query });
}
```

Payload: `q=* OR creator:admin` devuelve documentos de todos los creadores.  
Payload: `q=_exists_:password` enumera documentos que tienen el campo `password`.

```typescript
// SEGURO — usar match query que no interpreta sintaxis Lucene
@Get('/search')
async searchDocuments(@Query('q') q: string) {
  if (q.length > 200) throw new BadRequestException('Query muy larga');
  const query = {
    query: {
      match: {           // match: busqueda de texto, no interpreta sintaxis Lucene
        content: q       // q es texto literal, no query DSL
      }
    }
  };
  return this.elastic.search({ index: 'documents', body: query });
}
```

---

### Variante C: GraphQL Injection (Introspection y Query Abuse)

```typescript
// VULNERABLE — campo de busqueda en GraphQL sin limite de profundidad ni complejidad
const resolvers = {
  Query: {
    search: (_, { query }) => db.search(query)  // sin limite de recursion
  }
};

// Payload de DoS via consulta profundamente anidada:
// query { user { friends { friends { friends { friends { name } } } } } }
// Con profundidad N, el servidor hace 4^N queries a la base de datos
```

```typescript
// SEGURO — limitar profundidad y complejidad de queries GraphQL
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5),                    // maximo 5 niveles de anidamiento
    createComplexityLimitRule(1000),  // max 1000 puntos de complejidad por query
  ],
});
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-625: Permissive Regular Expression](https://cwe.mitre.org/data/definitions/625.html)
- [OWASP ReDoS Prevention](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [MDN - Escaping in regular expressions](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 17** exige que `src/typescript/src/search.controller.ts` contenga:
- `escapeRegExp`
- El limite `q.length > 100`
- La desaparicion de `new RegExp(q, 'i')`