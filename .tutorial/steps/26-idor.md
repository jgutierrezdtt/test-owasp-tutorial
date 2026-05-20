# Paso 26 — IDOR / Broken Object Level Authorization (BOLA)
**Tecnologia:** Go / net/http | **OWASP:** A01:2021 - Broken Access Control | **CWE-639**

---

## Que es esta vulnerabilidad?

Insecure Direct Object Reference (IDOR), tambien llamada Broken Object Level Authorization (BOLA) en el contexto de APIs REST, es la categoria de vulnerabilidad mas reportada en programas de bug bounty desde 2019. Ocurre cuando la aplicacion expone un identificador de recurso (ID de pedido, ID de usuario, ID de documento) y no verifica que el usuario autenticado tiene permiso para acceder a ese recurso especifico.

La vulnerabilidad es conceptualmente sencilla: si el usuario Alice puede acceder a `GET /orders?id=order-001` (su pedido), y el sistema no verifica que `order-001` pertenece a Alice, entonces Alice puede cambiar el ID a `order-002` y acceder al pedido de Bob.

En APIs REST con IDs numericos secuenciales o predecibles (order-1, order-2, ...), un atacante puede iterar automaticamente miles de IDs y descargar todos los recursos del sistema. En APIs con UUIDs aleatorios, la explotacion requiere conocer o adivinar los IDs, pero sigue siendo posible si se combinan con otras vulnerabilidades (como IDOR en endpoints de listado).

---

## Donde ocurre en este codigo?

**Archivo:** `src/go/handlers/orders.go`

```go
// CODIGO VULNERABLE — estado actual del ejercicio
func GetOrder(w http.ResponseWriter, r *http.Request) {
    orderID := r.URL.Query().Get("id")
    order := findOrderByID(orderID)
    if order == nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    // Se devuelve el pedido sin verificar que pertenece al usuario autenticado
    json.NewEncoder(w).Encode(order)
}
```

El sistema tiene pedidos de Alice (`order-001`, `order-003`) y Bob (`order-002`). Alice puede pedir `?id=order-002` y obtiene el pedido de Bob con todos sus datos.

---

## Como lo explotaria un atacante

**Acceso directo a pedidos de otros usuarios:**
```
GET /orders?id=order-001   → Pedido de Alice (atacante = Alice) ✓
GET /orders?id=order-002   → Pedido de Bob   (IDOR: Alice accede a datos de Bob)
GET /orders?id=order-003   → Pedido de Alice (atacante = Alice) ✓
```

**Iteracion masiva automatizada:**
```bash
for i in $(seq 1 9999); do
    curl -s "https://api.empresa.com/orders?id=order-$(printf '%03d' $i)" \
         -H "Authorization: Bearer ${ALICE_TOKEN}" >> dump.json
done
# Descarga los 9999 pedidos del sistema completo
```

**Combinado con enumeracion de IDs:**
```
GET /orders?id=ORD-20240101-0001
GET /orders?id=ORD-20240101-0002
...
# Los IDs basados en fecha y secuencia son facilmente predecibles
```

**IDOR en operaciones de escritura (mas critico):**
```
PUT /orders?id=order-002    {"status": "cancelled"}  # Cancela el pedido de Bob
DELETE /orders?id=order-002                           # Borra el pedido de Bob
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/go/handlers/orders.go` para verificar que el pedido pertenece al usuario autenticado:

```go
// CODIGO SEGURO
package handlers

import (
    "encoding/json"
    "net/http"
)

func GetOrder(w http.ResponseWriter, r *http.Request) {
    orderID := r.URL.Query().Get("id")

    // El ID del usuario autenticado debe venir del middleware de autenticacion,
    // no de un parametro controlable por el cliente.
    // En produccion: extraer del JWT validado por el middleware.
    authenticatedUserID := r.Header.Get("X-User-ID")
    if authenticatedUserID == "" {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    order := findOrderByID(orderID)
    // Verificacion de propiedad: el pedido debe pertenecer al usuario autenticado
    if order == nil || order.UserID != authenticatedUserID {
        // Mismo error para "no existe" y "no es tuyo" — no revelar si el ID existe
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(order)
}
```

### Por que funciona esta mitigacion?

- **Verificacion de propiedad `order.UserID != authenticatedUserID`:** antes de devolver el recurso, se comprueba que el propietario registrado en el objeto coincide con el usuario que hace la peticion. Aunque el cliente manipule el `id`, no puede cambiar el `UserID` almacenado en el servidor.
- **ID autenticado del middleware, no del cliente:** `authenticatedUserID` viene de `X-User-ID`, que a su vez debe ser establecida por un middleware de autenticacion que valida el JWT. Nunca debe ser un parametro de query o body controlable por el cliente.
- **Mismo mensaje de error para "no existe" y "no autorizado":** devolver `404 Not Found` en ambos casos evita que el atacante pueda enumerar IDs validos (si `403 Forbidden` solo aparece para IDs validos, confirma que el ID existe aunque no pertenezca al atacante).
- **En bases de datos:** la query debe incluir el user_id como condicion: `SELECT * FROM orders WHERE id = ? AND user_id = ?`. Esto hace la verificacion atomica y mas eficiente.

---

## Variantes de la misma categoria (Broken Access Control — mas complejas)

### Variante A: IDOR en operaciones de escritura y borrado

```go
// VULNERABLE — borrar un documento sin verificar propiedad
func DeleteDocument(w http.ResponseWriter, r *http.Request) {
    docID := r.URL.Query().Get("id")
    db.DeleteDocumentByID(docID)  // borra cualquier documento
    w.WriteHeader(http.StatusNoContent)
}
```

```go
// SEGURO — verificar propiedad antes de borrar
func DeleteDocument(w http.ResponseWriter, r *http.Request) {
    docID := r.URL.Query().Get("id")
    userID := r.Header.Get("X-User-ID")
    doc := db.GetDocumentByID(docID)
    if doc == nil || doc.OwnerID != userID {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    db.DeleteDocumentByID(docID)
    w.WriteHeader(http.StatusNoContent)
}
```

---

### Variante B: Escalada de privilegios via IDOR en admin endpoints

```go
// VULNERABLE — endpoint admin que verifica rol pero no verifica a que usuario aplica
func AdminGetUser(w http.ResponseWriter, r *http.Request) {
    targetUserID := r.URL.Query().Get("user_id")
    requesterRole := r.Header.Get("X-Role")  // del JWT

    if requesterRole != "admin" {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // Admin puede acceder a datos de cualquier usuario... eso es correcto
    // PERO si un admin de una organizacion puede ver datos de otra organizacion:
    targetUser := db.GetUserByID(targetUserID)  // sin verificar misma org
    json.NewEncoder(w).Encode(targetUser)
}
```

En sistemas multi-tenant, verificar el rol no es suficiente si no se verifica tambien que el recurso pertenece a la misma organizacion del admin.

---

### Variante C: IDOR via referencia indirecta predecible (IDs numericos)

```python
# VULNERABLE — IDs numericos secuenciales facilmente iterables
@app.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: int, user=Depends(get_current_user)):
    invoice = db.get_invoice(invoice_id)  # ID numerico predecible
    if not invoice:
        raise HTTPException(404)
    return invoice  # sin verificar que pertenece al usuario
```

```python
# SEGURO — UUIDs aleatorios + verificacion de propiedad
import uuid

@app.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: str, user=Depends(get_current_user)):
    # Validar que invoice_id es un UUID valido (evita injection)
    try:
        uid = uuid.UUID(invoice_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="ID invalido")

    invoice = db.get_invoice(str(uid))
    if not invoice or invoice.user_id != user.id:  # verificacion de propiedad
        raise HTTPException(status_code=404)
    return invoice
```

---

## Referencias

- [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP IDOR Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP API Top 10 2023 - API1: BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 26** exige que `src/go/handlers/orders.go` contenga:
- `X-User-ID`
- `order.UserID != authenticatedUserID`
