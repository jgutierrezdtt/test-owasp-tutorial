# Paso 2 — Path Traversal
**Tecnologia:** Python / FastAPI | **OWASP:** A01:2021 - Broken Access Control | **CWE-22**

---

## Que es esta vulnerabilidad?

Path Traversal ocurre cuando una aplicacion usa input del usuario para construir rutas de sistema de archivos sin verificar que la ruta resultante permanece dentro del directorio autorizado. El atacante usa secuencias como `../` o su codificacion URL `%2e%2e%2f` para subir en la jerarquia de directorios y acceder a archivos fuera del scope permitido.

El impacto va desde la lectura de archivos de configuracion y credenciales (`/etc/passwd`, `.env`, claves privadas) hasta escritura en rutas arbitrarias cuando el endpoint permite subir archivos. En Windows la secuencia equivalente es `.\..\` y existen variantes con codificacion doble y unicode.

Ejemplos reales: CVE-2021-41773 en Apache HTTP Server (lectura arbitraria de archivos + RCE), CVE-2019-18818 en Strapi CMS, multiples CVEs en plataformas de descarga de documentos empresariales.

---

## Donde ocurre en este codigo?

**Archivo:** `src/python/routes/files.py`

```python
# CODIGO VULNERABLE — estado actual del ejercicio
@router.get("/download")
async def download_file(filename: str):
    path = f"/var/www/public/{filename}"  # ruta construida con input sin verificar
    return FileResponse(path)             # sirve cualquier ruta del sistema
```

El problema esta en la construccion de la ruta. La f-string concatena el directorio base con el nombre recibido sin verificar que el resultado este dentro de `/var/www/public`. `FileResponse` leera el archivo resultante independientemente de donde apunte.

Cuando `filename=../../etc/passwd`, la ruta resulta `/var/www/public/../../etc/passwd`, que el SO resuelve como `/etc/passwd`.

---

## Como lo explotaria un atacante

**Lectura de credenciales del sistema:**
```
GET /download?filename=../../etc/passwd
```
Devuelve los usuarios del sistema con sus home directories y shells.

**Lectura de variables de entorno del proceso:**
```
GET /download?filename=../../../proc/self/environ
```
En Linux, `/proc/self/environ` contiene todas las variables de entorno del proceso servidor, incluyendo claves API, contrasenas de base de datos y tokens JWT.

**Lectura del codigo fuente:**
```
GET /download?filename=../routes/serialize.py
```
El atacante descarga el codigo de la aplicacion para buscar otras vulnerabilidades.

**Bypass de filtros basicos con codificacion URL:**
```
GET /download?filename=..%2F..%2Fetc%2Fpasswd
GET /download?filename=%2e%2e%2f%2e%2e%2fetc%2fpasswd
GET /download?filename=....//....//etc/passwd
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/python/routes/files.py` para resolver la ruta canonica y verificar que esta dentro del directorio autorizado:

```python
# CODIGO SEGURO
import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()

ALLOWED_DIR = os.path.realpath("/var/www/public")

@router.get("/download")
async def download_file(filename: str):
    real_path = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
    if not real_path.startswith(ALLOWED_DIR + os.sep):
        raise HTTPException(status_code=400, detail="Acceso denegado")
    if not os.path.isfile(real_path):
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    return FileResponse(real_path)
```

### Por que funciona esta mitigacion?

- **`os.path.realpath()`:** resuelve toda secuencia `../`, enlaces simbolicos y codificaciones de forma canonica. La ruta `../../etc/passwd` se convierte en `/etc/passwd` antes de la comparacion, revelando que esta fuera del directorio permitido.
- **`startswith(ALLOWED_DIR + os.sep)`:** el `+ os.sep` es critico. Sin el, un directorio `/var/www/public_malicious/file` pasaria la comprobacion `startswith("/var/www/public")` por ser un prefijo de texto valido. El separador `/` garantiza que la ruta es un subdirectorio real.
- **`os.path.isfile()`:** verifica que el path resuelto es un archivo regular, rechazando dispositivos de bloque, FIFOs o directorios.

---

## Variantes de la misma categoria (Broken Access Control — mas complejas)

### Variante A: Zip Slip (Path Traversal en extraccion de archivos)

Un archivo ZIP malicioso puede contener entradas con rutas como `../../etc/cron.d/backdoor`. Si el codigo extrae sin validar, escribe archivos fuera del directorio destino:

```python
# VULNERABLE — extraccion directa sin verificar destino
import zipfile

@router.post("/upload-zip")
async def upload_zip(file: UploadFile):
    with zipfile.ZipFile(file.file) as z:
        z.extractall("/var/uploads/")  # extrae a donde diga el ZIP
```

Un ZIP con la entrada `../../etc/cron.d/backdoor` escribira un script de cron malicioso.

```python
# SEGURO — verificar cada entrada antes de extraer
@router.post("/upload-zip")
async def upload_zip(file: UploadFile):
    dest = os.path.realpath("/var/uploads")
    with zipfile.ZipFile(file.file) as z:
        for member in z.namelist():
            target = os.path.realpath(os.path.join(dest, member))
            if not target.startswith(dest + os.sep):
                raise HTTPException(status_code=400, detail="Zip Slip detectado")
        z.extractall(dest)
```

---

### Variante B: Path Traversal via nombre de archivo con null byte

Algunas validaciones comprueban la extension del archivo pero no sanitizan bytes nulos. En entornos C/PHP, el string se trunca en `\0`:

```python
# VULNERABLE — validacion de extension bypasseable con null byte
@router.get("/download")
async def download_file(filename: str):
    if not filename.endswith(".pdf"):
        raise HTTPException(status_code=400)
    path = f"/var/docs/{filename}"
    return FileResponse(path)
```

Payload: `filename=../../etc/passwd%00.pdf`  
En algunos contextos el string se trunca en `%00` y el archivo servido es `/etc/passwd` aunque la validacion de extension pase.

```python
# SEGURO — sanitizar caracteres de control y resolver ruta canonica
@router.get("/download")
async def download_file(filename: str):
    if '\x00' in filename:
        raise HTTPException(status_code=400)
    real = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
    if not real.startswith(ALLOWED_DIR + os.sep):
        raise HTTPException(status_code=400)
    return FileResponse(real)
```

---

### Variante C: IDOR (Insecure Direct Object Reference) — acceso a recursos ajenos

Path Traversal en el sentido logico: acceder a objetos de otro usuario cambiando un identificador predecible:

```python
# VULNERABLE — el invoice_id del path no se verifica contra el usuario autenticado
@router.get("/invoice/{invoice_id}")
async def get_invoice(invoice_id: int, current_user: User = Depends(get_current_user)):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    return invoice  # devuelve la factura sin importar a quien pertenece
```

Un usuario autenticado puede cambiar `invoice_id=1001` por `invoice_id=1002` y ver facturas ajenas.

```python
# SEGURO — filtrar siempre por el usuario autenticado
@router.get("/invoice/{invoice_id}")
async def get_invoice(invoice_id: int, current_user: User = Depends(get_current_user)):
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.owner_id == current_user.id  # verifica propiedad
    ).first()
    if not invoice:
        raise HTTPException(status_code=404)
    return invoice
```

---

## Referencias

- [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-639: IDOR](https://cwe.mitre.org/data/definitions/639.html)
- [Snyk - Zip Slip vulnerability](https://security.snyk.io/research/zip-slip-vulnerability)
- [CVE-2021-41773 — Apache path traversal + RCE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 02** comprueba que `src/python/routes/files.py` contenga:
- `ALLOWED_DIR`
- `os.path.realpath`
- La verificacion con `startswith`