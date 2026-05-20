# Paso 16 — Prototype Pollution
**Tecnologia:** TypeScript / NestJS | **OWASP:** A03:2021 - Injection | **CWE-1321**

---

## Que es esta vulnerabilidad?

Prototype Pollution es una vulnerabilidad especifica de JavaScript donde un atacante puede modificar `Object.prototype`, el prototipo raiz del que heredan todos los objetos JavaScript. Como todos los objetos heredan propiedades de su prototipo via la cadena de herencia, anadir una propiedad a `Object.prototype` hace que esa propiedad aparezca en todos los objetos del programa.

El vector de ataque mas comun es una funcion de merge o deep-copy que no protege contra claves especiales como `__proto__`, `constructor` o `prototype`. Cuando el code hace `obj["__proto__"]["isAdmin"] = true`, en realidad modifica `Object.prototype.isAdmin`, haciendo que todos los objetos tengan `isAdmin = true`.

El impacto real depende del codigo de la aplicacion: si en algun lugar se comprueba `if (user.isAdmin)` sin verificar la fuente del valor, un atacante sin privilegios puede escalar a administrador.

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/merge.controller.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
@Controller('user')
export class MergeController {
  @Post('/preferences')
  updatePreferences(@Body() body: any): Record<string, unknown> {
    const prefs = {};
    Object.assign(prefs, body);  // body puede contener __proto__
    return prefs;
  }
}
```

Cuando `body` es `{ "__proto__": { "isAdmin": true } }`, `Object.assign` itera las claves del objeto `body`. Al llegar a la clave `__proto__`, accede al prototipo de `prefs` (que es `Object.prototype`) y asigna `isAdmin: true` a el.

Desde ese momento, cualquier objeto creado con `{}` o via literales en el proceso Node.js tendra `isAdmin = true` hasta que el proceso se reinicie.

---

## Como lo explotaria un atacante

**Payload de contaminacion:**
```json
POST /user/preferences
Content-Type: application/json

{
  "__proto__": {
    "isAdmin": true
  }
}
```

**Verificacion del impacto:**
```javascript
// Despues del ataque, en cualquier parte del codigo Node.js
const obj = {};
console.log(obj.isAdmin);  // true (heredado de Object.prototype contaminado)

// Si el codigo hace:
if (request.user.isAdmin) {  // true para cualquier usuario
    return adminData;
}
```

**Payload via constructor:**
```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

**Impacto en templates (RCE en Handlebars/Pug via prototype pollution):**
En algunos motores de templates vulnerables, la contaminacion del prototipo con `__lookupGetter__` o propiedades especificas puede derivar en RCE. CVE-2019-7609 (Kibana) fue explotado de esta forma.

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/merge.controller.ts` para validar con DTO y usar `Object.create(null)`:

```typescript
// CODIGO SEGURO
import { Body, Controller, Post } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { IsBoolean, IsOptional, IsString, validateSync } from 'class-validator';

class UserPreferencesDto {
  @IsOptional()
  @IsString()
  theme?: string;

  @IsOptional()
  @IsString()
  language?: string;

  @IsOptional()
  @IsBoolean()
  notifications?: boolean;
}

@Controller('user')
export class MergeController {
  @Post('/preferences')
  updatePreferences(@Body() body: Record<string, unknown>): Record<string, unknown> {
    // Validar contra DTO tipado: rechaza claves no definidas en la clase
    const dto = plainToInstance(UserPreferencesDto, body);
    const errors = validateSync(dto);
    if (errors.length > 0) {
      throw new Error('Invalid input');
    }

    // Object.create(null) crea un objeto SIN prototipo (no hereda de Object.prototype)
    // Un atacante no puede contaminar Object.prototype a traves de este objeto
    const prefs = Object.create(null) as Record<string, unknown>;
    if (dto.theme !== undefined) prefs['theme'] = dto.theme;
    if (dto.language !== undefined) prefs['language'] = dto.language;
    if (dto.notifications !== undefined) prefs['notifications'] = dto.notifications;
    return prefs;
  }
}
```

### Por que funciona esta mitigacion?

- **`plainToInstance` + `validateSync`:** transforma el body en una instancia del DTO y rechaza propiedades no declaradas en la clase. `__proto__`, `constructor` y cualquier clave no definida en `UserPreferencesDto` son ignoradas o generan error de validacion.
- **`Object.create(null)`:** crea un objeto sin prototipo. Su `[[Prototype]]` es `null`, no `Object.prototype`. Incluso si alguien intentara mutar `prefs["__proto__"]`, no afectaria a `Object.prototype` global porque `prefs` no tiene esa cadena de herencia.
- **Tipado estricto:** usar tipos especificos (`string`, `boolean`) en el DTO evita que valores inesperados lleguen a la logica de negocio.

---

## Variantes de la misma categoria (Prototype Pollution / Injection — mas complejas)

### Variante A: Prototype Pollution via lodash.merge (CVE-2019-10744)

Lodash < 4.17.12 tenia una funcion `merge` vulnerable:

```javascript
// VULNERABLE — lodash.merge en versiones antiguas
const _ = require('lodash');  // version < 4.17.12

app.post('/settings', (req, res) => {
    const userSettings = {};
    _.merge(userSettings, req.body);  // contamina Object.prototype si body tiene __proto__
    res.json(userSettings);
});
```

Payload: `{"__proto__": {"polluted": "yes"}}`  
Despues: `{}.polluted === "yes"` // true

```javascript
// SEGURO — actualizar lodash + sanitizar claves peligrosas
function safeMerge(target, source) {
    const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
    for (const [key, value] of Object.entries(source)) {
        if (FORBIDDEN_KEYS.has(key)) continue;  // ignorar claves peligrosas
        if (typeof value === 'object' && value !== null) {
            target[key] = target[key] || {};
            safeMerge(target[key], value);
        } else {
            target[key] = value;
        }
    }
    return target;
}
```

---

### Variante B: AST Injection via Prototype Pollution (RCE)

Algunos frameworks usan `hasOwnProperty` o acceden a propiedades que pueden ser sobreescritas via prototipo:

```javascript
// VULNERABLE — framework que usa obj.hasOwnProperty sin proteccion
// Si Object.prototype.hasOwnProperty es sobreescrito por prototype pollution:
const payload = { "__proto__": { "hasOwnProperty": function() { return true; } } };
_.merge({}, payload);

// Ahora cualquier comprobacion obj.hasOwnProperty('x') devuelve true
// en cualquier objeto del proceso
```

En frameworks que construyen ASTs (como template engines o query builders), esto puede derivar en RCE.

```javascript
// SEGURO — usar Object.prototype.hasOwnProperty.call() en lugar de obj.hasOwnProperty()
// Esto no puede ser sobreescrito por prototype pollution
if (Object.prototype.hasOwnProperty.call(obj, key)) {
    // procesamiento seguro
}
// O usar Object.hasOwn() disponible en Node.js >= 16
if (Object.hasOwn(obj, key)) {
    // procesamiento seguro
}
```

---

### Variante C: Prototype Pollution en JSON.parse con revivers

```javascript
// VULNERABLE — JSON.parse con reviver que puede ser manipulado
const data = JSON.parse(userInput, (key, value) => {
    if (key === '__proto__') return value;  // no filtrar __proto__
    return value;
});
Object.assign({}, data);  // la contaminacion ocurre aqui
```

```javascript
// SEGURO — JSON.parse con reviver que filtra claves peligrosas
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);

const data = JSON.parse(userInput, (key, value) => {
    if (FORBIDDEN.has(key)) return undefined;  // filtrar claves peligrosas
    return value;
});
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-1321: Improperly Controlled Modification of Object Prototype](https://cwe.mitre.org/data/definitions/1321.html)
- [Prototype Pollution Attack - Portswigger](https://portswigger.net/web-security/prototype-pollution)
- [CVE-2019-10744 - lodash prototype pollution](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10744)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 16** exige que `src/typescript/src/merge.controller.ts` contenga:
- `plainToInstance`
- `validateSync`
- `Object.create(null)`
- La ausencia de `Object.assign(prefs, body)`