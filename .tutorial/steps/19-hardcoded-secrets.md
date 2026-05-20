# Paso 19 — Hardcoded Secrets
**Tecnologia:** TypeScript / NestJS | **OWASP:** A02:2021 - Cryptographic Failures | **CWE-798**

---

## Que es esta vulnerabilidad?

Hardcoded Secrets ocurre cuando credenciales, claves criptograficas, tokens o contrasenas se escriben directamente en el codigo fuente. El problema fundamental es que el codigo fuente es compartido: entre desarrolladores, en repositorios (incluyendo GitHub), en builds, en contenedores Docker y en backups.

A diferencia de una contrasena de usuario que puede cambiarse, un secreto hardcodeado en el historial de git es permanente: aunque se elimine en un commit posterior, sigue siendo accesible en los commits anteriores. Herramientas como `git log`, `git show` o servicios como GitGuardian o TruffleHog escanean repositorios buscando patrones de secretos.

Según el State of Secrets Sprawl 2023 de GitGuardian, se detectan mas de 10 millones de secretos hardcodeados en repositorios publicos de GitHub cada ano. Las consecuencias van desde acceso no autorizado a APIs de pago (coste economico directo) hasta robo de datos de usuarios y clientes.

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/config.service.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
const JWT_SECRET = 'super-secret-key-hardcoded-123';  // en el historial de git para siempre
const DB_PASSWORD = 'admin1234';                       // visible para todos los desarrolladores
const STRIPE_KEY = 'sk_live_hardcoded_key_abc123';     // clave de produccion en el codigo

@Injectable()
export class ConfigService {
  get jwtSecret(): string { return JWT_SECRET; }
  get dbPassword(): string { return DB_PASSWORD; }
  get stripeKey(): string { return STRIPE_KEY; }
}
```

Cualquier desarrollador que haga `git clone` o `git log` tiene acceso a `sk_live_hardcoded_key_abc123`, una clave de Stripe de produccion que permite hacer cargos y acceder a datos de clientes.

---

## Como lo explotaria un atacante

**Busqueda en repositorios publicos:**
```bash
# GitHub Search: buscar patrones de claves Stripe en repos publicos
sk_live_ in:file
# Encuentra miles de claves validas en repositorios publicos
```

**Extraccion del historial de git:**
```bash
# Incluso si el secreto fue "borrado" en un commit posterior
git log --all --full-history -- config.service.ts
git show <commit-hash>:src/typescript/src/config.service.ts
# El secreto sigue visible en el historial
```

**Escaneo automatizado:**
```bash
# TruffleHog escanea el historial completo buscando patrones de secretos
trufflehog git file://.
# Detecta: SK_LIVE, AKIA (AWS), ghp_ (GitHub), etc.
```

**Acceso via Docker image:**
```bash
# Si el codigo se incluye en una imagen Docker publica
docker pull empresa/api:latest
docker run empresa/api cat /app/src/config.service.js  # secretos en texto plano
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/config.service.ts` para leer secretos desde variables de entorno y fallar al arranque si faltan:

```typescript
// CODIGO SEGURO
import { Injectable } from '@nestjs/common';

// Leer un secreto obligatorio desde entorno. Falla al arrancar si no esta definido.
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    // Fallar en startup es correcto: mejor no arrancar que operar sin secretos
    throw new Error(`Variable de entorno requerida no esta definida: ${name}`);
  }
  return value;
}

@Injectable()
export class ConfigService {
  // Los secretos se resuelven al instanciar el servicio (al arranque de la app)
  readonly jwtSecret: string = requireEnv('JWT_SECRET');
  readonly dbPassword: string = requireEnv('DB_PASSWORD');
  readonly stripeKey: string = requireEnv('STRIPE_API_KEY');
}
```

### Por que funciona esta mitigacion?

- **Variables de entorno:** los secretos existen solo en el entorno de ejecucion, no en el codigo. No aparecen en `git log`, no van en imagenes Docker, no se comparten con el repositorio.
- **`requireEnv` que falla al arranque:** si falta una variable de entorno critica, la aplicacion no arranca. Esto es el comportamiento correcto: es mejor un error obvio en startup que operar silenciosamente sin autenticacion JWT o con credenciales incorrectas.
- **Separacion de codigo y configuracion:** el codigo define que secreto necesita pero no su valor. El valor se inyecta desde el entorno (Kubernetes Secrets, AWS Secrets Manager, HashiCorp Vault, `.env` local en desarrollo).

---

## Variantes de la misma categoria (Cryptographic Failures via Secrets — mas complejas)

### Variante A: Secretos en archivos .env commiteados al repositorio

```bash
# .gitignore correcto pero .env fue commitado antes de anadirlo al .gitignore
$ git log --all -- .env
commit abc123 Author: dev@empresa.com
    "Add initial config"
    +DATABASE_URL=postgres://admin:S3cr3tP4ss@prod-db.empresa.com/mydb
    +STRIPE_SECRET_KEY=sk_live_abc123xyz
```

El `.env` fue borrado del working directory pero sigue en el historial.

```bash
# Mitigacion: borrar el archivo del historial completo de git
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch .env' \
  --prune-empty --tag-name-filter cat -- --all
# Revocar e invalidar todos los secretos expuestos inmediatamente
# Los secretos en historial se consideran comprometidos aunque se eliminen
```

---

### Variante B: Secretos en variables de entorno de CI/CD expuestos en logs

```yaml
# VULNERABLE — imprimir variables de entorno en CI logs
- name: Debug environment
  run: env  # imprime TODAS las variables de entorno, incluyendo secretos

# O accidentalmente:
- name: Build
  run: npm run build -- --verbose
  env:
    STRIPE_KEY: ${{ secrets.STRIPE_KEY }}
# Si el build falla y imprime argv, STRIPE_KEY puede aparecer en los logs
```

```yaml
# SEGURO — usar secrets de GitHub Actions / GitLab CI correctamente
- name: Build
  run: npm run build
  env:
    STRIPE_KEY: ${{ secrets.STRIPE_KEY }}  # GitHub enmascara el valor en logs
# Nunca imprimir secrets con echo, env, o --verbose que exponga argumentos
```

---

### Variante C: Secretos hardcodeados en imagenes Docker via ARG

```dockerfile
# VULNERABLE — secreto pasado como ARG queda en las capas de la imagen
FROM node:18-alpine
ARG STRIPE_KEY
ENV STRIPE_KEY=$STRIPE_KEY  # persiste en cada capa de la imagen
COPY . .
RUN npm install
```

```bash
# El secreto es visible en los metadatos de la imagen
docker inspect empresa/api:latest | grep -i stripe
# O en el historial de capas:
docker history empresa/api:latest --no-trunc
```

```dockerfile
# SEGURO — nunca pasar secretos como ARG/ENV en tiempo de build
# Los secretos se inyectan en tiempo de ejecucion via el orquestador
FROM node:18-alpine
COPY . .
RUN npm install
CMD ["node", "dist/main.js"]
# Al ejecutar: docker run -e STRIPE_KEY=... empresa/api
# O en Kubernetes: usar secretos de k8s montados como variables de entorno
```

---

## Referencias

- [OWASP A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GitGuardian - State of Secrets Sprawl 2023](https://www.gitguardian.com/state-of-secrets-sprawl)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 19** exige que `src/typescript/src/config.service.ts` contenga:
- `process.env[name]`
- `requireEnv`
- `STRIPE_API_KEY`
- La ausencia de secretos hardcodeados conocidos