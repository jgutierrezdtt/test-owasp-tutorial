# Paso 15 — Clickjacking
**Tecnologia:** Go | **OWASP:** A05:2021 - Security Misconfiguration | **CWE-1021**

---

## Que es esta vulnerabilidad?

Clickjacking (tambien llamado UI redressing) es un ataque donde un sitio malicioso incrusta la aplicacion victima en un `<iframe>` invisible o semitransparente, superpuesto sobre un elemento atractivo de la pagina del atacante. El usuario cree hacer clic en algo inofensivo ("Ganar un iPhone") pero en realidad su clic actua sobre la aplicacion real subyacente ("Confirmar transferencia bancaria", "Autorizar acceso OAuth", "Eliminar cuenta").

El ataque funciona porque sin proteccion anti-framing, cualquier pagina puede incrustar cualquier URL en un iframe. El atacante controla el CSS para hacer el iframe transparente (`opacity: 0`) y alinear el boton objetivo exactamente con el elemento falso que la victima ve.

La mitigacion principal son las cabeceras HTTP `X-Frame-Options` y `Content-Security-Policy: frame-ancestors`, que instruyen al navegador a rechazar el renderizado de la pagina dentro de un iframe de otro origen.

---

## Donde ocurre en este codigo?

**Archivo:** `src/go/handlers/middleware.go`

```go
// CODIGO VULNERABLE — estado actual del ejercicio
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Sin ninguna cabecera de seguridad:
        // - Sin X-Frame-Options: la aplicacion puede ser incrustada en iframes
        // - Sin X-Content-Type-Options: el navegador puede adivinar MIME types
        // - Sin Permissions-Policy: la pagina puede acceder a camara, microfono, etc.
        next.ServeHTTP(w, r)
    })
}
```

Sin `X-Frame-Options` o `Content-Security-Policy: frame-ancestors`, cualquier pagina externa puede incrustar esta aplicacion en un iframe y ejecutar un ataque de clickjacking.

---

## Como lo explotaria un atacante

**Pagina de ataque en evil.com:**
```html
<!DOCTYPE html>
<html>
<head>
<style>
  /* El iframe es invisible pero ocupa toda la pantalla */
  iframe {
    position: absolute;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
    opacity: 0;           /* invisible */
    z-index: 10;          /* encima de todo */
    pointer-events: all;  /* captura los clics */
  }
  /* El boton falso visible se posiciona exactamente sobre el boton real del iframe */
  #fake-button {
    position: absolute;
    top: 300px;
    left: 200px;
    z-index: 5;
    background: green;
    color: white;
    padding: 20px;
  }
</style>
</head>
<body>
  <div id="fake-button">Haz clic aqui para ganar un iPhone!</div>
  <!-- El iframe invisible esta encima del boton falso, alineado con "Confirmar" -->
  <iframe src="https://app.empresa.com/transfer?amount=1000&to=attacker"></iframe>
</body>
</html>
```

La victima hace clic en "Ganar un iPhone" pero en realidad confirma una transferencia de 1.000 EUR.

**Clickjacking en flujo OAuth:**
El atacante puede incrustar la pagina de autorizacion OAuth y forzar al usuario a autorizar una aplicacion maliciosa sin saberlo.

---

## Tu tarea: aplicar la mitigacion

Modifica `src/go/handlers/middleware.go` para anadir las cabeceras de seguridad necesarias:

```go
// CODIGO SEGURO
package handlers

import "net/http"

func SecurityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Prevenir clickjacking: rechazar iframe desde otros origenes
        w.Header().Set("X-Frame-Options", "DENY")

        // Alternativa moderna: CSP frame-ancestors (mas flexible)
        // w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")

        // Prevenir MIME sniffing: el navegador no adivina el Content-Type
        w.Header().Set("X-Content-Type-Options", "nosniff")

        // Limitar acceso a funcionalidades del navegador
        w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

        // Forzar HTTPS (HSTS)
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

        // Politica de referrer
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

        next.ServeHTTP(w, r)
    })
}
```

### Por que funciona esta mitigacion?

- **`X-Frame-Options: DENY`:** instruccion al navegador de rechazar cualquier intento de cargar esta pagina en un `<frame>`, `<iframe>`, `<embed>` u `<object>`. `DENY` es mas seguro que `SAMEORIGIN` (que permite iframes del mismo dominio).
- **`X-Content-Type-Options: nosniff`:** previene que el navegador interprete archivos con MIME types diferentes al declarado (evita XSS via subida de archivos con extension `.jpg` pero contenido HTML).
- **`Permissions-Policy`:** restringe el acceso a APIs sensibles del navegador como camara, microfono y geolocation, reduciendo el impacto de ataques XSS.
- **`Strict-Transport-Security`:** fuerza conexiones HTTPS para futuras visitas, previniendo downgrade attacks y MITM.

---

## Variantes de la misma categoria (Security Misconfiguration / UI Attacks — mas complejas)

### Variante A: Double Framing para bypass de X-Frame-Options SAMEORIGIN

`X-Frame-Options: SAMEORIGIN` tiene una vulnerabilidad conocida: si se usa doble framing donde el frame intermedio es del mismo origen, algunos navegadores antiguos permiten el anidamiento.

```html
<!-- evil.com incrustar a empresa.com via un intermediario del mismo origen -->
<iframe src="https://empresa.com/page-that-iframes-app">
  <!-- empresa.com/page-that-iframes-app contiene: -->
  <!-- <iframe src="https://empresa.com/transfer"></iframe> -->
</iframe>
```

Solucion: usar `Content-Security-Policy: frame-ancestors 'none'` en lugar de (o ademas de) `X-Frame-Options`, porque CSP especifica la cadena completa de ancestors, no solo el padre directo.

```
# SEGURO — CSP frame-ancestors impide toda cadena de anidamiento
Content-Security-Policy: frame-ancestors 'none'
```

---

### Variante B: Likejacking en redes sociales

Variante de clickjacking especifica para botones de "Me gusta" o "Compartir" en redes sociales:

```html
<!-- El atacante superpone un iframe de Facebook Like sobre contenido atractivo -->
<style>
  iframe { opacity: 0.001; position: absolute; top: 100px; left: 250px; }
</style>
<p>Haz clic para ver el video exclusivo:</p>
<button>VER VIDEO</button>
<iframe src="https://www.facebook.com/plugins/like.php?href=http%3A%2F%2Fevil.com%2F">
</iframe>
```

Cada clic en "VER VIDEO" en realidad da "Me gusta" al contenido del atacante en Facebook.

Mitigacion: los proveedores de botones sociales deben implementar `X-Frame-Options` o CSP en sus endpoints de plugins. Los desarrolladores de aplicaciones deben anadir las cabeceras en todos sus endpoints.

---

### Variante C: Cursor Spoofing via CSS

Variante que no requiere iframe: el atacante usa CSS para mostrar un cursor falso que apunta a un lugar diferente de donde el usuario cree que esta haciendo clic:

```css
/* ATAQUE: cursor falso que apunta 200px a la izquierda del cursor real */
body {
    cursor: none;  /* ocultar cursor real */
}
body::after {
    content: url('cursor-image.png');
    position: fixed;
    pointer-events: none;
    /* La imagen del cursor falso aparece desplazada del cursor real */
    transform: translate(-200px, 0px);
}
```

Mitigacion en el servidor: `Content-Security-Policy: style-src 'self'` impide CSS externo. `Permissions-Policy` puede restringir CSS custom cursors en navegadores que implementen la directiva.

---

## Referencias

- [OWASP A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-1021: Improper Restriction of Rendered UI Layers](https://cwe.mitre.org/data/definitions/1021.html)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [Mozilla MDN - X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 15** exige que `src/go/handlers/middleware.go` contenga:
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Permissions-Policy`