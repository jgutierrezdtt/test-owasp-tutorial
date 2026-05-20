# Paso 18 — Sensitive Data in Logs
**Tecnologia:** TypeScript / NestJS | **OWASP:** A02:2021 - Cryptographic Failures | **CWE-532**

---

## Que es esta vulnerabilidad?

Sensitive Data in Logs ocurre cuando una aplicacion escribe en sus registros datos que deben permanecer confidenciales: contrasenas, tokens de autenticacion, numeros de tarjeta, PINs, claves API, codigos OTP, respuestas de seguridad o cualquier dato de identificacion personal (PII).

Los sistemas de logging centralizado (Splunk, ELK Stack, CloudWatch, Datadog, Grafana Loki) almacenan logs de muchos servicios y son accedidos por equipos de operaciones, seguridad y desarrollo. Un ingeniero con acceso al sistema de observabilidad puede ver accidentalmente (o intencionadamente) credenciales reales de usuarios.

Aunque el programador no tiene intencion maliciosa, un `console.log(request.body)` o `logger.info(JSON.stringify(payload))` puede exponer contrasenas de miles de usuarios. Las brechas de datos por logs mal configurados son frecuentes y de dificil deteccion porque el log suele considerarse "seguro por estar en el backend".

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/logs.service.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
@Injectable()
export class LogsService {
  private readonly logger = new Logger(LogsService.name);

  logRequest(body: unknown): void {
    this.logger.log(JSON.stringify(body));  // serializa el body completo, incluyendo contrasenas
  }
}
```

Si un controlador llama a `logRequest({ username: 'alice', password: 's3cr3t' })`, el log contendra:
```
INFO [LogsService] {"username":"alice","password":"s3cr3t"}
```

Esta linea queda persistida en el sistema de logging y es accesible para cualquier persona con acceso a los logs, para siempre.

---

## Como lo explotaria un atacante

**Escenario 1: Insider threat — empleado con acceso a Splunk/ELK:**
```
SPL (Splunk): index=api sourcetype=nodejs "password"
# Devuelve miles de registros con contrasenas en texto plano
```

**Escenario 2: Brecha en el sistema de logging:**
Si el atacante obtiene acceso al sistema de logging (credenciales robadas, vulnerabilidad en Kibana, S3 bucket publico), consigue un dump masivo de credenciales sin necesidad de atacar la aplicacion principal.

**Escenario 3: Logs en S3 sin cifrar:**
Muchas empresas almacenan logs en S3 para retension a largo plazo. Un bucket mal configurado puede exponer meses o anos de logs con datos sensibles.

**Escenario 4: Logs en entornos de CI/CD:**
Si los tests de integracion hacen requests con datos reales y los logs se exponen en GitHub Actions, Circle CI o similar, las contrasenas quedan en los logs publicos del build.

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/logs.service.ts` para redactar campos sensibles antes de loguear:

```typescript
// CODIGO SEGURO
import { Injectable, Logger } from '@nestjs/common';

// Conjunto de campos que nunca deben aparecer en logs
const SENSITIVE_FIELDS = new Set([
  'password', 'passwd', 'secret', 'token', 'apiKey', 'api_key',
  'authorization', 'creditCard', 'cardNumber', 'cvv', 'ssn',
  'pin', 'otp', 'privateKey', 'accessToken', 'refreshToken',
]);

@Injectable()
export class LogsService {
  private readonly logger = new Logger(LogsService.name);

  // Redactar campos sensibles de forma recursiva en objetos anidados
  private redact(obj: unknown): unknown {
    if (typeof obj !== 'object' || obj === null) return obj;
    if (Array.isArray(obj)) return obj.map(item => this.redact(item));

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = this.redact(value);
      }
    }
    return result;
  }

  logRequest(body: unknown): void {
    this.logger.log(JSON.stringify(this.redact(body)));  // body redactado
  }
}
```

### Por que funciona esta mitigacion?

- **`SENSITIVE_FIELDS`:** lista de claves conocidas que contienen datos sensibles. Cualquier campo cuyo nombre este en esta lista sera reemplazado por `[REDACTED]` antes de serializar.
- **`redact` recursivo:** procesa objetos anidados. Si el body tiene `{ user: { credentials: { password: 'x' } } }`, el `password` anidado tambien sera redactado.
- **Case-insensitive (`key.toLowerCase()`):** un campo llamado `Password`, `PASSWORD` o `pAsSwOrD` tambien sera redactado. Los desarrolladores usan convenciones diferentes.
- **Redaccion en la fuente, no en el destino:** es mejor no escribir el dato que filtrarlo despues. Los sistemas SIEM con reglas de redaccion son una segunda linea de defensa, nunca la primera.

---

## Variantes de la misma categoria (Cryptographic Failures / Data Exposure — mas complejas)

### Variante A: Datos sensibles en mensajes de error

```typescript
// VULNERABLE — exponer stack trace y datos internos en respuestas de error
@Controller('payments')
export class PaymentsController {
  @Post('/charge')
  async charge(@Body() body: ChargeDto) {
    try {
      return await this.stripeService.charge(body);
    } catch (error) {
      // El error puede incluir el payload completo enviado a Stripe (con datos de tarjeta)
      throw new HttpException(error.message, 500);  // expone info de Stripe
    }
  }
}
```

Si Stripe devuelve un error que incluye los datos de la peticion (numero de tarjeta, CVV), estos se propagan al cliente.

```typescript
// SEGURO — loguear el error internamente, devolver mensaje generico al cliente
@Post('/charge')
async charge(@Body() body: ChargeDto) {
  try {
    return await this.stripeService.charge(body);
  } catch (error) {
    // Loguear el error completo internamente (sin datos de tarjeta en el body)
    this.logger.error('Stripe charge failed', { errorCode: error.code });
    // Al cliente solo un mensaje generico sin detalles internos
    throw new HttpException('Payment processing failed', 500);
  }
}
```

---

### Variante B: JWT payload almacenado en logs

```typescript
// VULNERABLE — loguear el token JWT completo
@Get('/profile')
async getProfile(@Headers('authorization') auth: string) {
  this.logger.log(`Request with token: ${auth}`);  // Bearer eyJhbG...
  const user = this.jwtService.verify(auth.replace('Bearer ', ''));
  return user;
}
```

El token JWT en los logs puede ser reutilizado por alguien con acceso a los logs para autenticarse hasta que expire.

```typescript
// SEGURO — loguear solo el subject del token, nunca el token completo
@Get('/profile')
async getProfile(@Headers('authorization') auth: string) {
  const token = auth?.replace('Bearer ', '') || '';
  const payload = this.jwtService.verify(token);
  // Solo loguear el ID del usuario, nunca el token completo
  this.logger.log(`Profile request for user: ${payload.sub}`);
  return payload;
}
```

---

### Variante C: PII en query parameters que van a access logs

```
# VULNERABLE — datos sensibles en la URL que el servidor web registra automaticamente
GET /api/users/search?ssn=123-45-6789&dob=1980-01-01
```

Los servidores web (Nginx, Apache, AWS ALB) registran la URL completa en access logs. El numero de seguro social va a los access logs automaticamente, sin que el desarrollador haga nada.

```
# SEGURO — datos sensibles en el cuerpo de la peticion POST, no en la URL
POST /api/users/search
Content-Type: application/json

{"ssn": "123-45-6789", "dob": "1980-01-01"}

# Y configurar el servidor para no loguear el cuerpo de la peticion
# O usar log scrubbing en el pipeline de ingestion de logs
```

---

## Referencias

- [OWASP A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 18** exige que `src/typescript/src/logs.service.ts` contenga:
- `SENSITIVE_FIELDS`
- `[REDACTED]`
- `this.redact(body)`
- La ausencia de `JSON.stringify(body)`