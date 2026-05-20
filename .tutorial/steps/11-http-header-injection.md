# Paso 11 — HTTP Header Injection
**Tecnologia:** Go | **OWASP:** A03:2021 - Injection | **CWE-113**

---

## Que es esta vulnerabilidad?

HTTP Header Injection (tambien llamada Response Splitting) ocurre cuando una aplicacion escribe en un header HTTP un valor controlado por el usuario sin eliminar los caracteres de control `\r` (CR) y `\n` (LF). En el protocolo HTTP, la secuencia `\r\n` separa los headers de la respuesta. Inyectando esta secuencia, un atacante puede:

- Anadir headers arbitrarios a la respuesta (ej: `Set-Cookie` fraudulento)
- Dividir la respuesta HTTP en dos y controlar el cuerpo de la segunda
- Envenenar caches HTTP intermedias (cache poisoning)
- Forzar descargas de archivos maliciosos con `Content-Disposition`

El header mas vulnerable es `Location` en redirecciones, porque acepta URLs que pueden contener caracteres codificados que al decodificar incluyen `%0d%0a` (\r\n).

---

## Donde ocurre en este codigo?

**Archivo:** `src/go/handlers/headers.go`

```go
// CODIGO VULNERABLE — estado actual del ejercicio
func RedirectHandler(w http.ResponseWriter, r *http.Request) {
    next := r.URL.Query().Get("next")  // input del usuario
    w.Header().Set("Location", next)  // escribe next directamente en el header
    w.WriteHeader(http.StatusFound)
}
```

Al escribir `next` directamente en el header `Location`, si `next` contiene `\r\n`, el servidor emite dos headers donde deberia haber uno. El cliente HTTP o el navegador puede interpretar lo que viene despues de `\r\n` como un header adicional de la respuesta.

---

## Como lo explotaria un atacante

**Inyeccion de Set-Cookie fraudulento:**
```
GET /redirect?next=/home%0d%0aSet-Cookie:+session=attacker_session%3B+Path%3D%2F
```

La respuesta HTTP generada seria:
```
HTTP/1.1 302 Found
Location: /home
Set-Cookie: session=attacker_session; Path=/
```

El navegador de la victima sobrescribe su cookie de sesion con la del atacante (session fixation).

**Cache Poisoning via response splitting:**
```
GET /redirect?next=%0d%0aHTTP/1.1+200+OK%0d%0aContent-Type:+text/html%0d%0a%0d%0a<script>alert(1)</script>
```

Un proxy intermedio puede cachear la segunda "respuesta" manufacturada y servir el XSS a usuarios posteriores.

**Inyeccion de Content-Type para forzar descarga:**
```
GET /redirect?next=/file%0d%0aContent-Disposition:+attachment%3B+filename%3Dmalware.exe
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/go/handlers/headers.go` para sanitizar el valor del header y usar allowlist de destinos:

```go
// CODIGO SEGURO
package handlers

import (
    "net/http"
    "strings"
)

var allowedRedirects = map[string]bool{
    "/home":      true,
    "/dashboard": true,
    "/profile":   true,
}

// sanitizeHeaderValue elimina caracteres de control del valor de un header
func sanitizeHeaderValue(value string) string {
    value = strings.ReplaceAll(value, "\r", "")
    value = strings.ReplaceAll(value, "\n", "")
    return value
}

func RedirectHandler(w http.ResponseWriter, r *http.Request) {
    next := r.URL.Query().Get("next")
    sanitized := sanitizeHeaderValue(next)

    // Allowlist: solo redirigir a rutas internas conocidas
    if !allowedRedirects[sanitized] {
        sanitized = "/home"
    }

    w.Header().Set("Location", sanitized)
    w.WriteHeader(http.StatusFound)
}
```

### Por que funciona esta mitigacion?

- **`sanitizeHeaderValue`:** elimina `\r` y `\n` del valor antes de escribirlo en el header. Sin estos caracteres, es imposible inyectar headers adicionales o dividir la respuesta.
- **Allowlist de destinos:** aunque la sanitizacion sea suficiente para prevenir header injection, la allowlist garantiza ademas que no se puede hacer open redirect. Defense in depth.
- **Destino seguro por defecto:** si `sanitized` no esta en la allowlist, la redireccion va a `/home`. El atacante no recibe error descriptivo.

---

## Variantes de la misma categoria (Injection en headers y protocolos — mas complejas)

### Variante A: HTTP Request Smuggling (CL.TE / TE.CL)

HTTP Request Smuggling ocurre cuando un proxy frontend y el servidor backend interpretan de forma diferente donde termina una peticion HTTP, permitiendo al atacante "contrabandear" una peticion dentro de otra.

```
# ATAQUE CL.TE: frontend usa Content-Length, backend usa Transfer-Encoding
POST / HTTP/1.1
Host: empresa.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: empresa.com
```

El frontend envia la peticion completa como un POST. El backend, usando Transfer-Encoding, procesa el `0\r\n\r\n` como fin del cuerpo, y trata `GET /admin HTTP/1.1` como el inicio de la siguiente peticion del atacante.

**Mitigacion:** normalizar todos los headers en el proxy, rechazar peticiones con ambos headers `Content-Length` y `Transfer-Encoding`, o usar HTTP/2 que no tiene este problema.

---

### Variante B: Host Header Injection (Password Reset Poisoning)

```go
// VULNERABLE — usar el header Host para construir URLs en emails
func PasswordResetHandler(w http.ResponseWriter, r *http.Request) {
    host := r.Host  // controlado por el cliente
    token := generateResetToken()
    resetURL := fmt.Sprintf("https://%s/reset?token=%s", host, token)
    sendResetEmail(email, resetURL)  // el link del email apunta al host del atacante
}
```

El atacante modifica el header `Host: evil.com` en la peticion de reset. El email enviado a la victima contiene el link `https://evil.com/reset?token=TOKEN`. Cuando la victima hace clic, envia el token al servidor del atacante.

```go
// SEGURO — usar una URL base configurada, nunca el header Host
var baseURL = os.Getenv("APP_BASE_URL")  // "https://app.empresa.com"

func PasswordResetHandler(w http.ResponseWriter, r *http.Request) {
    token := generateResetToken()
    resetURL := fmt.Sprintf("%s/reset?token=%s", baseURL, token)
    sendResetEmail(email, resetURL)
}
```

---

### Variante C: Content-Type Sniffing via header injection

```go
// VULNERABLE — Content-Type del archivo derivado del input del usuario
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
    mimeType := r.URL.Query().Get("type")  // controlado por el usuario
    w.Header().Set("Content-Type", mimeType)  // inyeccion posible
    w.Write(fileContent)
}
```

El atacante puede inyectar `Content-Type: text/html\r\n` y convertir una descarga de archivo en una pagina HTML renderizable, posibilitando XSS.

```go
// SEGURO — detectar MIME del contenido real, nunca del parametro
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
    mimeType := http.DetectContentType(fileContent)  // basado en los bytes reales
    w.Header().Set("Content-Type", mimeType)
    w.Header().Set("X-Content-Type-Options", "nosniff")  // previene sniffing en IE
    w.Write(fileContent)
}
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-113: HTTP Response Splitting](https://cwe.mitre.org/data/definitions/113.html)
- [PortSwigger - HTTP request smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger - Host header injection](https://portswigger.net/web-security/host-header)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 11** exige que `src/go/handlers/headers.go` contenga:
- `sanitizeHeaderValue`
- `allowedRedirects`
- El uso del valor saneado en `Location`