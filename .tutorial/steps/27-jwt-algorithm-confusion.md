# Paso 27 — JWT Algorithm Confusion
**Tecnologia:** Go / golang-jwt | **OWASP:** A07:2021 - Identification and Authentication Failures | **CWE-347**

---

## Que es esta vulnerabilidad?

JWT Algorithm Confusion ocurre cuando el servidor acepta tokens JWT firmados con cualquier algoritmo, incluyendo el algoritmo especial `"none"` que indica "sin firma". El campo `alg` del header JWT es controlado por el cliente — si el servidor simplemente usa el algoritmo que el token declara, un atacante puede crear tokens con `alg=none` y payload arbitrario que el servidor acepta como validos sin ninguna clave.

El segundo vector es la confusion entre algoritmos asimetricos y simetricos: si el servidor usa RSA (`RS256`) para firmar pero tambien acepta HMAC (`HS256`), un atacante puede tomar la clave publica RSA (que es publica por definicion) y usarla como clave secreta HMAC para firmar tokens fraudulentos. El servidor verifica con `HS256` usando la clave publica como secreto, que es exactamente lo que el atacante uso para firmar.

JWT Algorithm Confusion fue CVE-2015-9235 en la libreria `jsonwebtoken` de Node.js y afecto a numerosas aplicaciones. La vulnerabilidad es especialmente critica porque un JWT valido por manipulacion de algoritmo permite autenticacion como cualquier usuario, incluyendo administradores.

---

## Donde ocurre en este codigo?

**Archivo:** `src/go/handlers/jwt.go`

```go
// CODIGO VULNERABLE — estado actual del ejercicio
func ParseToken(tokenString string) (*jwt.MapClaims, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte("secret"), nil  // devuelve la clave sin verificar el algoritmo
    })
    if err != nil || !token.Valid {
        return nil, fmt.Errorf("invalid token")
    }
    claims := token.Claims.(jwt.MapClaims)
    return &claims, nil
}
```

La funcion de lookup devuelve la clave sin verificar qué algoritmo usa el token. Si el header del token dice `"alg": "none"`, la libreria no necesita la clave y acepta el token.

---

## Como lo explotaria un atacante

**Token con alg=none (sin firma):**
```
Header (base64url): {"alg":"none","typ":"JWT"}
Payload (base64url): {"sub":"admin","role":"superuser","exp":9999999999}
Firma: (cadena vacia)

Token completo: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIiLCJleHAiOjk5OTk5OTk5OTl9.
```

```bash
# Crear el token alg=none en bash
header=$(echo -n '{"alg":"none","typ":"JWT"}' | base64url)
payload=$(echo -n '{"sub":"admin","role":"superuser","exp":9999999999}' | base64url)
token="${header}.${payload}."
curl -H "Authorization: Bearer ${token}" https://api.empresa.com/admin
```

**Algorithm Confusion RS256 → HS256:**
```python
# El atacante tiene acceso a la clave publica RSA del servidor (fichero .pem publico)
import jwt

public_key = open('server_public_key.pem').read()
# Usar la clave PUBLICA como secreto HMAC (el servidor hara lo mismo si acepta HS256)
malicious_token = jwt.encode(
    {"sub": "admin", "role": "admin"},
    public_key,
    algorithm="HS256"  # firmado con clave publica como si fuera secreto HMAC
)
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/go/handlers/jwt.go` para validar explicitamente el algoritmo de firma:

```go
// CODIGO SEGURO
package handlers

import (
    "fmt"
    "net/http"
    "os"
    "strings"

    "github.com/golang-jwt/jwt/v5"
)

func ParseToken(tokenString string) (*jwt.MapClaims, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Verificar EXPLICITAMENTE que el algoritmo es HMAC (HS256/HS384/HS512)
        // Si el header dice "none", RSA, ECDSA u otro, se rechaza aqui
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("algoritmo inesperado: %v", token.Header["alg"])
        }
        // El secreto viene de variable de entorno, nunca hardcodeado
        return []byte(os.Getenv("JWT_SECRET")), nil
    })
    if err != nil || !token.Valid {
        return nil, fmt.Errorf("invalid token")
    }
    claims := token.Claims.(jwt.MapClaims)
    return &claims, nil
}

func ValidateJWTHandler(w http.ResponseWriter, r *http.Request) {
    authHeader := r.Header.Get("Authorization")
    if !strings.HasPrefix(authHeader, "Bearer ") {
        http.Error(w, "missing token", http.StatusUnauthorized)
        return
    }
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    claims, err := ParseToken(tokenString)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    fmt.Fprintf(w, `{"valid":true,"sub":"%v"}`, (*claims)["sub"])
}
```

### Por que funciona esta mitigacion?

- **`token.Method.(*jwt.SigningMethodHMAC)` type assertion:** verifica que el algoritmo usado es de la familia HMAC (`HS256`, `HS384`, `HS512`). Si el header dice `"none"`, `"RS256"`, `"ES256"` u otro, el type assertion falla, la funcion devuelve error, y el token es rechazado antes de verificar la firma.
- **El algoritmo se decide en el servidor, no en el token:** el servidor sabe que firma con HS256. Por tanto, solo acepta HS256. El campo `alg` del header JWT es solo informativo para seleccionar la clave correcta, nunca para cambiar la politica de seguridad del servidor.
- **`os.Getenv("JWT_SECRET")`:** la clave secreta no esta hardcodeada en el codigo (ver step 19). Si la clave se rota, solo hay que actualizar la variable de entorno.

---

## Variantes de la misma categoria (Authentication Failures — mas complejas)

### Variante A: JWT sin verificacion de expiracion (exp claim)

```go
// VULNERABLE — no verificar que el token no ha expirado
func ParseTokenNoExpCheck(tokenString string) (*jwt.MapClaims, error) {
    p := jwt.NewParser(jwt.WithoutClaimsValidation())  // deshabilita validacion de claims
    token, err := p.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected method")
        }
        return []byte(os.Getenv("JWT_SECRET")), nil
    })
    ...
}
```

Un token robado sigue siendo valido indefinidamente aunque haya expirado.

```go
// SEGURO — el parser de golang-jwt valida exp, nbf, iat por defecto
// NO usar WithoutClaimsValidation()
// NO usar WithIssuedAt() si no se quiere validar
token, err := jwt.Parse(tokenString, keyFunc)  // valida exp automaticamente
```

---

### Variante B: Session Fixation

```python
# VULNERABLE — no rotar el session ID despues del login
@app.post("/login")
async def login(request: Request, username: str, password: str):
    if verify_credentials(username, password):
        # Reutiliza el session ID existente (que el atacante puede conocer)
        request.session["user"] = username  # session ID no cambia
        return {"message": "Logged in"}
```

Ataque: el atacante fija un session ID conocido enviandolo a la victima. Cuando la victima hace login, el servidor asocia ese session ID conocido a la sesion autenticada.

```python
# SEGURO — regenerar el session ID despues de autenticacion exitosa
@app.post("/login")
async def login(request: Request, username: str, password: str):
    if verify_credentials(username, password):
        request.session.clear()    # eliminar la sesion anonima existente
        request.session.regenerate_id()  # nuevo ID de sesion
        request.session["user"] = username
        return {"message": "Logged in"}
```

---

### Variante C: Brute Force en endpoints de autenticacion sin rate limiting

```go
// VULNERABLE — login sin proteccion contra fuerza bruta
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")
    if checkPassword(username, password) {
        // generar token
    } else {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
    }
    // Sin contador de intentos, sin lockout, sin CAPTCHA
}
```

```go
// SEGURO — rate limiting por IP y por usuario
var loginAttempts = make(map[string]int)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
    ip := r.RemoteAddr
    username := r.FormValue("username")
    key := fmt.Sprintf("%s:%s", ip, username)

    if loginAttempts[key] >= 5 {
        http.Error(w, "too many attempts", http.StatusTooManyRequests)
        return
    }
    if !checkPassword(username, r.FormValue("password")) {
        loginAttempts[key]++
        time.AfterFunc(15*time.Minute, func() { delete(loginAttempts, key) })
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }
    delete(loginAttempts, key)  // reset on success
    // ... generar token
}
```

---

## Referencias

- [OWASP A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CVE-2015-9235 - JWT None Algorithm Attack](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235)
- [Auth0 - Critical Vulnerabilities in JWT Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 27** exige que `src/go/handlers/jwt.go` contenga:
- `jwt.SigningMethodHMAC`
- `os.Getenv("JWT_SECRET")`
- La ausencia de `return []byte("secret"), nil`
