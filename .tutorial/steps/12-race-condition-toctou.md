# Paso 12 — Race Condition / TOCTOU
**Tecnologia:** Go | **OWASP:** A01:2021 - Broken Access Control | **CWE-367**

---

## Que es esta vulnerabilidad?

Time-of-Check to Time-of-Use (TOCTOU) es una race condition donde una aplicacion verifica una condicion (check) y luego actua en base a ella (use), pero entre ambas operaciones otro proceso o goroutine puede modificar el estado del sistema, invalidando la verificacion.

El problema fundamental es que la combinacion de dos operaciones atomicas individuales no es, en si misma, atomica. Hay una ventana temporal entre el "check" y el "use" que puede ser aprovechada.

En sistemas de archivos esto es critico: un archivo puede ser creado, movido o reemplazado por un enlace simbolico entre que se verifica su existencia y se crea. En sistemas de alta concurrencia (servidores web), incluso ventanas de microsegundos pueden ser explotadas con ataques de alta frecuencia.

---

## Donde ocurre en este codigo?

**Archivo:** `src/go/handlers/upload.go`

```go
// CODIGO VULNERABLE — estado actual del ejercicio
func UploadHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("name")
    path := filepath.Join(uploadDir, filename)

    // CHECK: verificar si el archivo existe
    if _, err := os.Stat(path); err == nil {
        http.Error(w, "File already exists", http.StatusConflict)
        return
    }

    // ------- VENTANA TOCTOU: otro goroutine puede crear el archivo aqui -------

    // USE: crear el archivo (puede sobrescribir uno creado en la ventana)
    f, _ := os.Create(path)
    defer f.Close()
    io.Copy(f, r.Body)
}
```

La ventana TOCTOU esta entre `os.Stat()` y `os.Create()`. En un servidor web con goroutines concurrentes, dos peticiones simultaneas para el mismo filename pasaran ambas el check de `os.Stat` (el archivo no existe) y ambas llegaran a `os.Create`, donde la segunda sobrescribira el archivo creado por la primera.

Ademas, `filename` no esta validado: un atacante puede enviar `../../../etc/cron.d/backdoor` como nombre de archivo.

---

## Como lo explotaria un atacante

**Path Traversal via nombre de archivo:**
```
POST /upload
name=../../../etc/cron.d/evil-job
[cuerpo: script de cron malicioso]
```

Sobrescribe un archivo de cron del sistema si el proceso tiene permisos suficientes.

**TOCTOU para sobrescribir archivos existentes:**
```bash
# El atacante lanza dos peticiones concurrentes para el mismo archivo
curl -X POST /upload -d "name=config.json" -d @config.json &
curl -X POST /upload -d "name=config.json" -d @malicious.json &
# Una de ellas pasara el check y sobrescribira el archivo legiti
```

**Symlink attack:**
```bash
# Mientras la aplicacion ejecuta os.Stat() y antes de os.Create()
# el atacante crea un symlink que apunta a un archivo sensible
ln -s /etc/passwd /var/uploads/target.txt
# La siguiente os.Create() seguira el symlink y sobrescribira /etc/passwd
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/go/handlers/upload.go` para usar una operacion atomica que elimina la ventana TOCTOU:

```go
// CODIGO SEGURO
package handlers

import (
    "io"
    "net/http"
    "os"
    "path/filepath"
)

const uploadDir = "/var/uploads"

func UploadHandler(w http.ResponseWriter, r *http.Request) {
    // Usar solo el nombre base del archivo (elimina path traversal)
    filename := filepath.Base(r.FormValue("name"))
    if filename == "." || filename == "" {
        http.Error(w, "Invalid filename", http.StatusBadRequest)
        return
    }
    path := filepath.Join(uploadDir, filename)

    // O_CREATE|O_EXCL es atomico: crea el archivo SOLO si no existe.
    // Si ya existe, falla con error. No hay ventana entre check y create.
    f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
    if err != nil {
        if os.IsExist(err) {
            http.Error(w, "File already exists", http.StatusConflict)
        } else {
            http.Error(w, "Internal error", http.StatusInternalServerError)
        }
        return
    }
    defer f.Close()
    io.Copy(f, r.Body)
    w.WriteHeader(http.StatusCreated)
}
```

### Por que funciona esta mitigacion?

- **`O_CREATE|O_EXCL` atomico:** a nivel de kernel, `open(2)` con `O_CREAT|O_EXCL` es atomico. El kernel verifica y crea en una sola operacion indivisible. No hay ventana entre el check y el create. Si el archivo ya existe, `open()` falla con `EEXIST`.
- **`filepath.Base()`:** extrae solo el nombre del archivo de la ruta proporcionada, descartando cualquier componente de directorio. `../../../etc/passwd` se convierte en `passwd`. Previene path traversal.
- **Manejo explicito de errores:** distinguir `os.IsExist` de otros errores permite respuestas HTTP apropiadas sin exponer informacion interna.

---

## Variantes de la misma categoria (Race Conditions — mas complejas)

### Variante A: Double-Spend Race Condition en transferencias

```python
# VULNERABLE — check de saldo y debito no son atomicos
@router.post("/transfer")
async def transfer(amount: int, to_account: str, user=Depends(get_current_user)):
    balance = db.get_balance(user.id)    # CHECK: leer saldo
    if balance < amount:
        raise HTTPException(status_code=400, detail="Saldo insuficiente")
    # VENTANA: otra peticion puede leer el mismo saldo aqui
    db.debit(user.id, amount)            # USE: debitar
    db.credit(to_account, amount)
```

Un atacante envia dos peticiones de transferencia de 100 EUR con saldo de 100 EUR simultaneamente. Ambas pasan el check de saldo, y ambas debitan 100 EUR, dejando la cuenta en -100 EUR.

```python
# SEGURO — transaccion con SELECT FOR UPDATE (bloqueo pesimista)
@router.post("/transfer")
async def transfer(amount: int, to_account: str, user=Depends(get_current_user)):
    async with db.transaction():
        # SELECT FOR UPDATE bloquea la fila hasta que la transaccion termine
        balance = await db.execute(
            "SELECT balance FROM accounts WHERE id = $1 FOR UPDATE",
            user.id
        )
        if balance < amount:
            raise HTTPException(status_code=400)
        await db.execute("UPDATE accounts SET balance = balance - $1 WHERE id = $2", amount, user.id)
        await db.execute("UPDATE accounts SET balance = balance + $1 WHERE id = $2", amount, to_account)
```

---

### Variante B: TOCTOU en verificacion de autorizacion

```go
// VULNERABLE — verificar permisos y luego actuar en operaciones separadas
func DeleteHandler(w http.ResponseWriter, r *http.Request) {
    fileID := r.URL.Query().Get("id")

    // CHECK: verificar que el usuario es propietario
    owner := db.GetFileOwner(fileID)
    if owner != currentUser {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    // VENTANA: entre el check y el borrado, la propiedad puede cambiar
    // (ej: el archivo es transferido a otro usuario)

    // USE: borrar el archivo
    db.DeleteFile(fileID)
}
```

```go
// SEGURO — verificacion y accion en una sola query atomica
func DeleteHandler(w http.ResponseWriter, r *http.Request) {
    fileID := r.URL.Query().Get("id")
    // DELETE WHERE filtra por propiedad atomicamente
    affected := db.Exec(
        "DELETE FROM files WHERE id = $1 AND owner_id = $2",
        fileID, currentUser,
    )
    if affected == 0 {
        http.Error(w, "Not found or forbidden", http.StatusNotFound)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

---

### Variante C: Race Condition en generacion de nombres de archivo temporales

```python
# VULNERABLE — crear archivo temporal con nombre predecible
import os, time

def process_upload(content: bytes) -> str:
    tmpfile = f"/tmp/upload_{int(time.time())}"  # nombre predecible
    if os.path.exists(tmpfile):                  # TOCTOU check
        raise Exception("Temp file exists")
    with open(tmpfile, 'wb') as f:               # TOCTOU use
        f.write(content)
    return tmpfile
```

```python
# SEGURO — usar tempfile del sistema que garantiza atomicidad y nombre unico
import tempfile

def process_upload(content: bytes) -> str:
    # mkstemp crea el archivo atomicamente con nombre unico e impredecible
    fd, tmpfile = tempfile.mkstemp(prefix="upload_", dir="/var/tmp")
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    return tmpfile
```

---

## Referencias

- [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [CWE-362: Concurrent Execution with Shared Resource (Race Condition)](https://cwe.mitre.org/data/definitions/362.html)
- [Linux man page - open(2) con O_EXCL](https://man7.org/linux/man-pages/man2/open.2.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 12** exige que `src/go/handlers/upload.go` contenga:
- `filepath.Base`
- `os.OpenFile` con `O_CREATE|O_EXCL|O_WRONLY`
- La ausencia de `os.Create(path)`