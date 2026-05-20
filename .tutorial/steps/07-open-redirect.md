# Paso 7 — Open Redirect
**Tecnologia:** Java / Spring Boot | **OWASP:** A01:2021 - Broken Access Control | **CWE-601**

---

## Que es esta vulnerabilidad?

Open Redirect ocurre cuando una aplicacion redirige al usuario a una URL controlada por el atacante, usando como destino un parametro de la peticion sin validarlo. La pagina origen (tu dominio de confianza) actua como relay hacia un sitio malicioso.

Esto es especialmente peligroso en flujos de login: el patron `GET /login?next=<url>` es legitimo para redirigir al usuario a la pagina que intentaba visitar despues de autenticarse. Si no se valida `next`, un atacante puede construir un enlace aparentemente legitimo de `empresa.com` que lleva a `phishing.com`.

El atacante combina Open Redirect con ingenieria social: el usuario ve `empresa.com` en la URL del email de phishing, hace clic confiando en el dominio conocido, se autentica, y es redirigido al sitio del atacante que puede robar credenciales o tokens.

---

## Donde ocurre en este codigo?

**Archivo:** `src/java/src/main/java/com/example/api/controller/RedirectController.java`

```java
// CODIGO VULNERABLE — estado actual del ejercicio
@GetMapping("/login")
public String login(@RequestParam(defaultValue = "/dashboard") String next) {
    return "redirect:" + next;  // next controlado por el usuario, sin validacion
}
```

El valor de `next` se usa directamente como destino de la redireccion. Spring MVC interpreta el prefijo `redirect:` y emite una respuesta `302 Found` con `Location: <valor_de_next>`. No importa que `next` sea un dominio externo: el servidor lo acepta sin restriccion.

---

## Como lo explotaria un atacante

**Phishing via login redirect:**
```
GET /auth/login?next=https://evil.com/fake-login HTTP/1.1
Host: empresa.com
```

El servidor responde:
```
HTTP/1.1 302 Found
Location: https://evil.com/fake-login
```

El atacante envia a la victima el enlace `https://empresa.com/auth/login?next=https://evil.com/fake-login` por email. La victima ve el dominio `empresa.com` y confia. Despues del login es redirigida a la pagina falsa del atacante.

**Robo de token OAuth via redirect malicioso:**
```
GET /auth/login?next=https://evil.com
```

Si el token JWT o el codigo OAuth se pasa como fragmento o query param al destino, el atacante lo recibe directamente.

**Bypass via URL encoding:**
```
GET /auth/login?next=https%3A%2F%2Fevil.com
GET /auth/login?next=%2F%2Fevil.com   (protocol-relative URL)
```

---

## Tu tarea: aplicar la mitigacion

Modifica `RedirectController.java` para validar el destino contra una lista de rutas permitidas:

```java
// CODIGO SEGURO
@Controller
@RequestMapping("/auth")
public class RedirectController {

    private static final List<String> ALLOWED_REDIRECTS = List.of(
        "/dashboard",
        "/profile",
        "/settings",
        "/orders"
    );

    @GetMapping("/login")
    public String login(@RequestParam(defaultValue = "/dashboard") String next) {
        // Solo redirigir a rutas internas de la allowlist
        if (!ALLOWED_REDIRECTS.contains(next)) {
            return "redirect:/dashboard";  // destino seguro por defecto
        }
        return "redirect:" + next;
    }
}
```

### Por que funciona esta mitigacion?

- **Allowlist de rutas internas:** solo se permiten rutas relativas predefinidas. Un atacante no puede incluir `https://evil.com` porque no esta en la lista.
- **Solo rutas relativas (sin `://`):** incluso si la allowlist no se aplica correctamente, una URL relativa como `/dashboard` siempre apunta al mismo dominio servidor. No puede ser un dominio externo.
- **Destino seguro por defecto:** si `next` no esta en la allowlist, en lugar de mostrar un error se redirige al dashboard. Esto evita exponer el mecanismo de validacion al atacante.

---

## Variantes de la misma categoria (Broken Access Control / Redirect — mas complejas)

### Variante A: Open Redirect via URL Fragment

Algunas implementaciones solo validan el path y olvidan el fragment:

```python
# VULNERABLE — validacion incompleta que ignora el fragment
def is_safe_redirect(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.netloc == '' or parsed.netloc == 'empresa.com'
    # No valida: https://empresa.com@evil.com o http://evil.com#empresa.com
```

Bypass via credenciales en URL: `https://empresa.com@evil.com` — el navegador envia la peticion a `evil.com` con `empresa.com` como credencial de usuario.

Bypass via fragment: la URL `https://empresa.com/login?next=//evil.com%23` puede hacer que la validacion vea `empresa.com` como host pero el navegador resuelva `evil.com` como destino real.

```python
# SEGURO — allowlist explicita y rechazo de URLs con netloc externo
ALLOWED_PATHS = {"/dashboard", "/profile", "/settings"}

def is_safe_redirect(url: str) -> bool:
    parsed = urlparse(url)
    # Rechazar cualquier URL con dominio externo
    if parsed.netloc and parsed.netloc != 'empresa.com':
        return False
    # Solo permitir rutas de la allowlist
    return parsed.path in ALLOWED_PATHS
```

---

### Variante B: Subdomain Takeover + Open Redirect

```java
// VULNERABLE — valida solo el dominio base pero acepta subdominios arbitrarios
private boolean isSafeUrl(String url) {
    return url.endsWith(".empresa.com") || url.equals("empresa.com");
}
```

Si el atacante registra un subdominio abandonado como `old-blog.empresa.com` (subdomain takeover), la URL `https://old-blog.empresa.com/phishing` pasaria la validacion.

```java
// SEGURO — set de dominios completos permitidos
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "empresa.com",
    "app.empresa.com",
    "admin.empresa.com"
);

private boolean isSafeUrl(String url) {
    try {
        URI uri = new URI(url);
        return ALLOWED_HOSTS.contains(uri.getHost());
    } catch (URISyntaxException e) {
        return false;
    }
}
```

---

### Variante C: Redireccion en flujo OAuth (OAuth redirect_uri manipulation)

```java
// VULNERABLE — redirect_uri en OAuth sin validacion estricta
@GetMapping("/oauth/authorize")
public ResponseEntity<?> authorize(
        @RequestParam String client_id,
        @RequestParam String redirect_uri,
        @RequestParam String state) {
    // Solo valida que empiece con el dominio registrado
    if (!redirect_uri.startsWith("https://app.cliente.com")) {
        return ResponseEntity.badRequest().build();
    }
    // Procede con la autorizacion
    String code = generateAuthCode(client_id, state);
    return ResponseEntity.status(302).header("Location", redirect_uri + "?code=" + code).build();
}
```

Bypass: `redirect_uri=https://app.cliente.com.evil.com/callback` empieza por el dominio correcto pero el host real es `app.cliente.com.evil.com`.

```java
// SEGURO — comparacion exacta de redirect_uri contra los registrados en DB
@GetMapping("/oauth/authorize")
public ResponseEntity<?> authorize(...) {
    OAuthClient client = clientRepository.findById(client_id);
    // Comparacion exacta: la redirect_uri debe ser exactamente la registrada
    if (!client.getRegisteredRedirectUris().contains(redirect_uri)) {
        return ResponseEntity.badRequest().build();
    }
    // ...
}
```

---

## Referencias

- [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-601: Open Redirect](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Open Redirect Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [PortSwigger - Open redirection](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 07** exige que `RedirectController.java` contenga:
- `ALLOWED_REDIRECTS`
- La comprobacion `contains(next)`