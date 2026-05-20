# Paso 22 — NoSQL Injection
**Tecnologia:** Python / FastAPI + MongoDB | **OWASP:** A03:2021 - Injection | **CWE-943**

---

## Que es esta vulnerabilidad?

NoSQL Injection ocurre en bases de datos que no usan SQL (MongoDB, Cassandra, Redis, CouchDB, Firebase, Elasticsearch) cuando el input del usuario se incorpora directamente a la query sin validacion. En MongoDB, las queries son documentos JSON con operadores especiales como `$ne`, `$gt`, `$where`, `$regex`, `$in`, etc.

El vector mas comun en MongoDB es el **Operator Injection**: cuando el backend acepta un objeto JSON del cliente y lo pasa directamente como query, el atacante puede inyectar operadores MongoDB en lugar de valores escalares. Por ejemplo, en lugar de `{"password": "mi_contrasena"}`, el atacante envia `{"password": {"$ne": ""}}`, que evalua "todos los documentos donde password no sea vacio" — es decir, todos los usuarios.

A diferencia de SQL Injection, NoSQL Injection es menos conocida y muchos desarrolladores asumen erroneamente que MongoDB es "inmune a injection" por no usar SQL. Esto hace que sea frecuentemente ignorada en code reviews y auditorias.

---

## Donde ocurre en este codigo?

**Archivo:** `src/python/routes/products.py`

```python
# CODIGO VULNERABLE — estado actual del ejercicio
@router.post("/login")
async def login(body: dict):
    user = _find_one({"username": body.get("username"), "password": body.get("password")})
    if user:
        return {"token": "access_granted", "role": user.get("role")}
    raise HTTPException(status_code=401, detail="Credenciales invalidas")
```

`body.get("username")` puede devolver un string `"admin"` o un objeto `{"$ne": ""}`.
Si el atacante envia `{"username": "admin", "password": {"$ne": ""}}`, MongoDB evalua la condicion `password != ""`, que es verdadera para cualquier usuario con password no vacio.

---

## Como lo explotaria un atacante

**Bypass de autenticacion con operador $ne:**
```json
POST /login
Content-Type: application/json

{"username": "admin", "password": {"$ne": ""}}
```
MongoDB evalua: `WHERE username = 'admin' AND password != ''`  
Resultado: autentica como admin sin conocer la contrasena.

**Bypass total con $gt para extraer el primer usuario:**
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
Devuelve el primer documento donde username > "" Y password > "" — cualquier usuario.

**Extraccion de datos con $regex:**
```json
{"username": "admin", "password": {"$regex": "^a"}}
```
Si devuelve 200, la contrasena empieza por "a". Iterando caracter a caracter se extrae la contrasena completa (Blind NoSQL Injection).

**En MongoDB con $where (si esta habilitado):**
```json
{"username": "admin", "$where": "this.password.length > 0"}
```
`$where` ejecuta JavaScript en el servidor MongoDB. Con payloads mas elaborados, puede derivar en ejecucion de codigo servidor.

---

## Tu tarea: aplicar la mitigacion

Modifica `src/python/routes/products.py` para validar tipos antes de usar los valores en la query:

```python
# CODIGO SEGURO
from fastapi import APIRouter, HTTPException

router = APIRouter()

@router.post("/login")
async def login(body: dict):
    username = body.get("username")
    password = body.get("password")

    # Validar que username y password sean strings escalares
    # Un operador MongoDB como {"$ne": ""} es un dict, no un str
    if not isinstance(username, str) or not isinstance(password, str):
        raise HTTPException(status_code=400, detail="Tipo de datos invalido")

    # Ahora es seguro: username y password son strings literales,
    # no pueden contener operadores MongoDB
    user = _find_one({"username": username, "password": password})
    if user:
        return {"token": "access_granted", "role": user.get("role")}
    raise HTTPException(status_code=401, detail="Credenciales invalidas")
```

### Por que funciona esta mitigacion?

- **`isinstance(username, str)`:** garantiza que el valor es un string Python, no un dict ni una lista. Un operador MongoDB (`{"$ne": ""}`) es un dict en Python. Si el tipo no es `str`, la peticion se rechaza antes de llegar a la query.
- **Separacion explicita de variables:** en lugar de pasar `body.get("username")` directamente como valor de query, se asigna a una variable tipada. Esto fuerza al desarrollador a pensar en el tipo y permite la validacion.
- **Uso de esquemas Pydantic (mejor practica):** en FastAPI, lo ideal es definir un modelo Pydantic con tipos fijos en lugar de aceptar `dict`:
  ```python
  class LoginBody(BaseModel):
      username: str  # Pydantic rechaza automaticamente dicts/listas aqui
      password: str
  ```

---

## Variantes de la misma categoria (NoSQL / distintas bases de datos)

### Variante A: MongoDB $where con JavaScript (RCE en versiones antiguas)

```javascript
// VULNERABLE — aplicacion Node.js que construye query con $where
app.post('/search', async (req, res) => {
    const { query } = req.body;
    // $where ejecuta JavaScript en el servidor MongoDB
    const results = await db.collection('products').find({
        $where: `this.name.includes('${query}')`  // injection en template literal
    }).toArray();
    res.json(results);
});
```

Payload: `query = "x') || sleep(5000) || ('"`  
Resultado: el servidor MongoDB ejecuta `sleep(5000)` → DoS.  
En MongoDB < 4.4 con motor JS habilitado: posible RCE.

```javascript
// SEGURO — usar operadores nativos de MongoDB, nunca $where con input del usuario
const results = await db.collection('products').find({
    name: { $regex: escapeRegex(query), $options: 'i' }  // operador nativo, no JS
}).toArray();
```

---

### Variante B: Elasticsearch Query Injection

```python
# VULNERABLE — Elasticsearch DSL construido con input del usuario
@router.get("/search")
async def search(q: str):
    query = {
        "query": {
            "query_string": {
                "query": q  # Lucene syntax: q puede contener OR, AND, campos
            }
        }
    }
    # Payload: q = "* OR _exists_:password"
    # Devuelve documentos que tienen el campo password
    return es.search(index="documents", body=query)
```

```python
# SEGURO — usar match query (busqueda de texto, no sintaxis Lucene)
@router.get("/search")
async def search(q: str):
    query = {
        "query": {
            "match": { "content": q }  # q es texto literal
        }
    }
    return es.search(index="documents", body=query)
```

---

### Variante C: Redis Injection via comandos arbitrarios

```python
# VULNERABLE — construir comandos Redis con input del usuario
@router.get("/cache")
async def get_cache(key: str):
    result = redis_client.execute_command(f"GET {key}")
    return {"value": result}
```

Payload: `key = "user:1\r\nSET admin:password hacked\r\n"`  
La inyeccion de `\r\n` separa comandos Redis (protocolo RESP).

```python
# SEGURO — usar los metodos del cliente Redis, no execute_command con concatenacion
@router.get("/cache")
async def get_cache(key: str):
    # redis-py maneja el escape automaticamente
    result = redis_client.get(key)
    return {"value": result}
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
- [OWASP Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [MongoDB Operator Injection](https://www.mongodb.com/docs/manual/core/security-injection/)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 22** exige que `src/python/routes/products.py` contenga:
- `isinstance(username, str)`
- `isinstance(password, str)`
- La ausencia de `{"username": body.get("username"), "password": body.get("password")}`
