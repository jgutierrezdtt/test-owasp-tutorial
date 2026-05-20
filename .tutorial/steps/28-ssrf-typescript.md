# Paso 28 — SSRF via HTTP Client (TypeScript)
**Tecnologia:** TypeScript / NestJS + axios | **OWASP:** A10:2021 - SSRF | **CWE-918**

---

## Que es esta vulnerabilidad?

Esta es la segunda instancia de SSRF en el tutorial, ahora en el contexto de TypeScript/NestJS con la libreria `axios`. Aunque el principio es el mismo que en el step 23, en ecosistemas Node.js hay vectores adicionales: las URLs con schema `file://` en algunas versiones, los redirects automaticos de axios (habilitados por defecto), y el DNS Rebinding que puede evadir validaciones basadas en el hostname si no se resuelve la IP.

En arquitecturas de microservicios, un servicio NestJS que hace peticiones a otros servicios internos es muy comun. Si ese servicio expone un endpoint que permite al usuario controlar la URL destino (para integraciones con APIs externas, webhooks, importacion de datos, thumbnails), se convierte en un vector SSRF. La red interna del microservicio tiene acceso a servicios que no estan expuestos publicamente: bases de datos, caches, servicios de orquestacion (Kubernetes API server en `https://kubernetes.default.svc`).

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/proxy.controller.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
@Controller('proxy')
export class ProxyController {
  @Get('/fetch')
  async fetch(@Query('url') url: string): Promise<string> {
    const response = await axios.get(url);  // cualquier URL, sin restriccion
    return response.data;
  }
}
```

`axios.get(url)` sigue redirects automaticamente por defecto (`maxRedirects: 5`). Esto significa que aunque se valide el host inicial, un redirect a `http://169.254.169.254/` puede bypassear la validacion si no se deshabilitan los redirects.

---

## Como lo explotaria un atacante

**Acceso al Kubernetes API Server (en entornos k8s):**
```
GET /proxy/fetch?url=https://kubernetes.default.svc/api/v1/namespaces
# Con el service account del pod, puede listar namespaces, pods, secrets de k8s
```

**Acceso a GCP Metadata Server:**
```
GET /proxy/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header requerido: Metadata-Flavor: Google
# Pero con SSRF que puede controlar headers, o con versiones antiguas sin validacion
```

**Bypass via Open Redirect:**
```javascript
// El atacante registra una URL en el allowlist que hace redirect a IMDS
// Por ejemplo, si api.github.com devolviera un 301 a 169.254.169.254
// (hipotetico, pero ilustra el vector)

// En la practica: el atacante controla un dominio permitido que hace redirect
// GET /proxy/fetch?url=https://attacker-allowed-domain.com/redirect
// → 301 Location: http://169.254.169.254/latest/meta-data/
// axios sigue el redirect si maxRedirects > 0
```

**DNS Rebinding:**
```
// 1. Registrar ssrf-bypass.attacker.com con TTL muy bajo
// 2. Primera resolucion DNS: ip = 1.2.3.4 (IP valida, publica)
// 3. Servidor valida: 1.2.3.4 no es privada → permitir
// 4. Segunda resolucion DNS (al hacer el get): ip = 169.254.169.254
// 5. La peticion llega al IMDS aunque la validacion paso
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/proxy.controller.ts` para validar la URL contra allowlist y deshabilitar redirects:

```typescript
// CODIGO SEGURO
import { BadRequestException, Controller, Get, Query } from '@nestjs/common';
import axios from 'axios';

// Lista blanca de hostnames permitidos
const ALLOWED_HOSTS = new Set([
  'api.github.com',
  'jsonplaceholder.typicode.com',
  'api.openweathermap.org',
]);

@Controller('proxy')
export class ProxyController {
  @Get('/fetch')
  async fetch(@Query('url') url: string): Promise<string> {
    if (!url) {
      throw new BadRequestException('URL requerida');
    }

    // Parsear y validar la URL antes de hacer la peticion
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new BadRequestException('URL malformada');
    }

    // Solo HTTPS — previene file://, ftp://, gopher://, etc.
    if (parsed.protocol !== 'https:') {
      throw new BadRequestException('Solo se permite HTTPS');
    }

    // Allowlist de hostnames — rechaza IMDS, red interna, localhost
    if (!ALLOWED_HOSTS.has(parsed.hostname)) {
      throw new BadRequestException('Host no permitido');
    }

    // maxRedirects: 0 — no seguir redirects que puedan apuntar a hosts internos
    const response = await axios.get(url, { maxRedirects: 0 });
    return response.data;
  }
}
```

### Por que funciona esta mitigacion?

- **`new URL(url)`:** el constructor URL de Node.js parsea la URL segun RFC 3986. Si la URL es malformada, lanza `TypeError`. Usar `new URL()` en lugar de parsear manualmente con regex evita bypasses de parsing.
- **`ALLOWED_HOSTS`:** solo los hostnames explicitamente permitidos son aceptados. La validacion opera sobre `parsed.hostname` (el hostname real del objeto URL), no sobre el string original que podria contener encoding tricks.
- **`maxRedirects: 0`:** axios no seguira ninguna redireccion HTTP. Si el servidor destino responde con `301/302 Location: http://169.254.169.254/`, axios lanzara un error en lugar de seguir el redirect. Esto elimina el vector de bypass via open redirect.
- **Validacion de protocolo:** `https:` exclusivamente evita protocolos como `file://`, `ftp://`, `gopher://` y `dict://` que pueden leer archivos locales o interactuar con otros servicios.

---

## Variantes de la misma categoria (SSRF en TypeScript — vectores adicionales)

### Variante A: SSRF via fetch en un Worker / Service sin validacion

```typescript
// VULNERABLE — importar datos desde URL remota en un job asynchrono
@Injectable()
export class DataImportService {
  async importFromUrl(dataUrl: string): Promise<void> {
    // Sin validacion: el payload puede ser una URL interna
    const { data } = await axios.get(dataUrl);
    await this.processData(data);
  }
}
```

```typescript
// SEGURO — misma validacion en jobs que en endpoints HTTP
async importFromUrl(dataUrl: string): Promise<void> {
  const parsed = new URL(dataUrl);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new Error('URL de importacion no permitida');
  }
  const { data } = await axios.get(dataUrl, { maxRedirects: 0 });
  await this.processData(data);
}
```

---

### Variante B: SSRF via generacion de PDF con puppeteer/playwright

```typescript
// VULNERABLE — renderizar una URL con Puppeteer (navegador sin restricciones)
@Post('/generate-pdf')
async generatePdf(@Body('url') url: string): Promise<Buffer> {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto(url);  // accede a cualquier URL, incluyendo internas
  return page.pdf();
}
```

Payload: `url=file:///etc/passwd` — Puppeteer lee el archivo local y lo convierte a PDF.

```typescript
// SEGURO — allowlist + bloquear protocolos de archivo en la pagina
async generatePdf(@Body('url') url: string): Promise<Buffer> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
    throw new BadRequestException('URL no permitida para PDF');
  }
  const browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-setuid-sandbox',
           '--disable-dev-shm-usage']
  });
  const page = await browser.newPage();
  // Interceptar y bloquear requests a hosts no permitidos
  await page.setRequestInterception(true);
  page.on('request', req => {
    const u = new URL(req.url());
    if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname)) {
      req.abort();
    } else {
      req.continue();
    }
  });
  await page.goto(url);
  return page.pdf();
}
```

---

### Variante C: SSRF en integraciones con servicios de terceros (webhooks entrantes)

```typescript
// VULNERABLE — reenviar webhook de proveedor externo a URL interna
@Post('/webhook/forward')
async forwardWebhook(
  @Body('destination') destination: string,
  @Body('payload') payload: unknown,
): Promise<void> {
  // Sin validacion: destination puede ser http://internal-service:8080/admin
  await axios.post(destination, payload);
}
```

```typescript
// SEGURO — validar destination con allowlist + solo POST a endpoints declarados
const WEBHOOK_DESTINATIONS = new Set([
  'https://crm.empresa.com/webhooks/incoming',
  'https://slack.com/services/hooks',
]);

@Post('/webhook/forward')
async forwardWebhook(
  @Body('destination') destination: string,
  @Body('payload') payload: unknown,
): Promise<void> {
  if (!WEBHOOK_DESTINATIONS.has(destination)) {
    throw new BadRequestException('Destino de webhook no autorizado');
  }
  await axios.post(destination, payload, { maxRedirects: 0 });
}
```

---

## Referencias

- [OWASP A10:2021 - SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDSv2 - Mitigacion de SSRF en EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 28** exige que `src/typescript/src/proxy.controller.ts` contenga:
- `ALLOWED_HOSTS`
- `new URL(url)`
- `maxRedirects`
- La ausencia de `await axios.get(url);`
