# Paso 23 — SSRF (Server-Side Request Forgery)
**Tecnologia:** Python / FastAPI | **OWASP:** A10:2021 - SSRF | **CWE-918**

---

## Que es esta vulnerabilidad?

Server-Side Request Forgery (SSRF) ocurre cuando una aplicacion permite que un usuario externo controle el destino de una peticion HTTP que el servidor hace en su nombre. El servidor actua como proxy involuntario entre el atacante y destinos que normalmente son inaccesibles desde internet.

SSRF es especialmente devastadora en entornos cloud (AWS, GCP, Azure) porque el servicio de metadatos de instancia (IMDS) es accesible desde cualquier proceso en la instancia pero no desde internet. Un atacante que explota SSRF puede acceder a `http://169.254.169.254/latest/meta-data/` en AWS y obtener credenciales IAM temporales con los permisos del rol de la instancia EC2, lo que frecuentemente permite acceso completo a S3, RDS, SecretsManager y otros servicios.

En 2019, Capital One sufrió una brecha de 100 millones de registros explotando precisamente SSRF contra el servicio de metadatos de AWS EC2. Esta vulnerabilidad fue la entrada que permitio a la atacante obtener credenciales IAM y luego vaciar buckets de S3.

---

## Donde ocurre en este codigo?

**Archivo:** `src/python/routes/proxy.py`

```python
# CODIGO VULNERABLE — estado actual del ejercicio
@router.get("/fetch")
async def fetch_url(url: str):
    response = requests.get(url, timeout=5)
    return {"status": response.status_code, "content": response.text[:500]}
```

La funcion `requests.get(url)` acepta cualquier URL sin restriccion:
- URLs de la red interna (`http://10.0.0.1:8080/admin`)
- Servicio de metadatos cloud (`http://169.254.169.254/...`)
- Recursos locales (`http://localhost:6379/` para Redis)
- Protocolos no esperados (dependiendo de la version de `requests`)

---

## Como lo explotaria un atacante

**Robo de credenciales IAM en AWS EC2 (el ataque mas critico):**
```
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Respuesta: {"RoleName": "ec2-production-role"}

GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-production-role
# Respuesta: {"AccessKeyId": "ASIA...", "SecretAccessKey": "xxx", "Token": "yyy"}
```

Con esas credenciales, el atacante tiene acceso directo a los servicios AWS del rol.

**Acceso a servicios internos:**
```
GET /fetch?url=http://10.0.0.5:8080/actuator/env   # Spring Boot actuator
GET /fetch?url=http://redis:6379/                    # Redis (responde con error RESP)
GET /fetch?url=http://elasticsearch:9200/_cat/indices  # Elasticsearch
```

**Bypass de SSRF protections via DNS Rebinding:**
```
# 1. Registrar un dominio que resuelve a 169.254.169.254
# 2. El servidor valida: "allowed-domain.attacker.com" esta en el allowlist? NO
# 3. Pero si el allowlist hace lookup del dominio y el DNS rebinda...
# Solucion correcta: resolver el IP y validar la IP, no el hostname
```

**Bypass via redireccion HTTP:**
```
# 1. Servidor permite https://api.github.com
# 2. El atacante controla api.github.com/<path> que hace redirect a 169.254.169.254
# Solucion: deshabilitar redirects automaticos (allow_redirects=False)
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/python/routes/proxy.py` para validar el host contra una allowlist:

```python
# CODIGO SEGURO
import requests
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException

router = APIRouter()

# Lista blanca de hosts permitidos — solo IPs/dominios explicitos
ALLOWED_HOSTS = {
    "api.github.com",
    "api.openweathermap.org",
    "jsonplaceholder.typicode.com",
}

def _validate_ssrf(url: str) -> None:
    """Valida que la URL sea segura antes de hacer la peticion."""
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="URL malformada")

    # Solo HTTPS: previene protocolos como file://, ftp://, gopher://
    if parsed.scheme not in ("https",):
        raise HTTPException(status_code=400, detail="Solo se permite HTTPS")

    # Allowlist de hosts: rechaza IMDS, red interna, localhost
    if parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="Host no permitido")


@router.get("/fetch")
async def fetch_url(url: str):
    _validate_ssrf(url)
    # allow_redirects=False: previene bypasses via redirects a hosts internos
    response = requests.get(url, timeout=5, allow_redirects=False)
    return {"status": response.status_code, "content": response.text[:500]}
```

### Por que funciona esta mitigacion?

- **`ALLOWED_HOSTS` (allowlist):** solo se permiten dominios explicitamente listados. Cualquier otro destino — IMDS, red interna, localhost, IP privada — es rechazado. Una lista negra (bloquear 169.254.x.x) es insuficiente porque hay muchos rangos internos y protocolos alternativos.
- **Validacion de esquema:** al requerir `https:`, se bloquean protocolos como `file://`, `ftp://`, `gopher://`, `dict://` que pueden leer archivos locales o hacer ataques contra otros servicios.
- **`allow_redirects=False`:** si el servidor destino hace un redirect HTTP a una URL interna, `requests` no lo seguira. Previene el bypass via redirect.
- **Validar IP en produccion:** para mayor robustez, despues de resolver el hostname a IP, verificar que la IP no pertenezca a rangos privados (RFC1918: 10.x.x.x, 172.16.x.x, 192.168.x.x) ni a link-local (169.254.x.x).

---

## Variantes de la misma categoria (SSRF — vectores avanzados)

### Variante A: SSRF via webhooks

```python
# VULNERABLE — endpoint de webhook que el usuario configura
@router.post("/webhooks/configure")
async def configure_webhook(url: str):
    # Al dispararse un evento, el servidor hace una peticion POST a esta URL
    # Un atacante puede configurar: url=http://169.254.169.254/latest/meta-data/
    webhook_config.set("url", url)
    return {"message": "Webhook configured"}
```

```python
# SEGURO — validar URL de webhook igual que cualquier SSRF
@router.post("/webhooks/configure")
async def configure_webhook(url: str):
    _validate_ssrf(url)  # misma funcion de validacion
    webhook_config.set("url", url)
    return {"message": "Webhook configured"}
```

---

### Variante B: SSRF en procesamiento de imagenes remoto

```python
# VULNERABLE — descargar imagen desde URL del usuario para procesarla
from PIL import Image
import io

@router.post("/images/process")
async def process_image(image_url: str):
    # Para manipulacion de imagenes, el servidor descarga la URL dada por el usuario
    response = requests.get(image_url, timeout=10)
    img = Image.open(io.BytesIO(response.content))
    # ... procesamiento
    return {"width": img.width, "height": img.height}
```

El atacante pasa `image_url=http://10.0.0.1:8080/sensitive-data`. La respuesta no es una imagen, pero el servidor ya ha hecho la peticion interna y puede que devuelva info del error.

```python
# SEGURO — allowlist + verificar que el content-type sea realmente una imagen
@router.post("/images/process")
async def process_image(image_url: str):
    _validate_ssrf(image_url)
    response = requests.get(image_url, timeout=10, allow_redirects=False)
    content_type = response.headers.get("Content-Type", "")
    if not content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="La URL no apunta a una imagen")
    img = Image.open(io.BytesIO(response.content))
    return {"width": img.width, "height": img.height}
```

---

### Variante C: SSRF via XML con entidades externas (relacion con XXE)

```python
# VULNERABLE — parsear XML con URLs externas resolubles
import xml.etree.ElementTree as ET

@router.post("/parse-xml")
async def parse_xml(body: str):
    # Si body contiene:
    # <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
    # <data>&xxe;</data>
    # El parser resuelve la entidad haciendo una peticion SSRF
    tree = ET.fromstring(body)  # ElementTree no resuelve DTD, pero lxml si
    return {"data": tree.text}
```

La conexion entre XXE y SSRF: las entidades XML externas (`SYSTEM "http://..."`) son un vector de SSRF a nivel de parser XML. La mitigacion en step 06 (deshabilitar DTD processing) previene tanto XXE como este vector SSRF.

---

## Referencias

- [OWASP A10:2021 - SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [Capital One Breach - SSRF via AWS IMDS](https://www.capitalone.com/digital/facts2019/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 23** exige que `src/python/routes/proxy.py` contenga:
- `ALLOWED_HOSTS`
- `_validate_ssrf`
- `urlparse`
