# Paso 10 — Cross-Site Request Forgery (CSRF)
**Tecnologia:** Java / Spring Boot | **OWASP:** A01:2021 - Broken Access Control | **CWE-352**

---

## Que es esta vulnerabilidad?

CSRF (Cross-Site Request Forgery) es un ataque donde un sitio malicioso fuerza al navegador de la victima a ejecutar peticiones autenticadas contra una aplicacion en la que el usuario ya tiene sesion activa. El servidor no puede distinguir una peticion legitima del usuario de una forzada por el atacante, porque ambas llegan con las mismas cookies de sesion.

El mecanismo de ataque es el siguiente: el navegador incluye automaticamente las cookies del dominio destino en cualquier peticion hacia ese dominio, independientemente del origen de la pagina que inicia la peticion. Si un sitio en `evil.com` hace un formulario con `action="https://banco.com/transferencia"`, el navegador enviara las cookies del usuario en `banco.com`.

CSRF afecta principalmente a aplicaciones que usan cookies para autenticacion (en oposicion a tokens Bearer en el header `Authorization`). Es especialmente grave en acciones de alto impacto: cambio de email, cambio de contrasena, transferencias bancarias, borrado de datos.

---

## Donde ocurre en este codigo?

**Archivo:** `src/java/src/main/java/com/example/api/controller/SecurityConfig.java`

```java
// CODIGO VULNERABLE — estado actual del ejercicio
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable())  // proteccion CSRF completamente deshabilitada
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}
```

Con `csrf.disable()`, Spring Security no requiere ni verifica tokens CSRF en ningun endpoint. Cualquier peticion con metodos POST, PUT, DELETE sera aceptada si llega con una cookie de sesion valida, sin importar el origen.

---

## Como lo explotaria un atacante

**Escenario:** el usuario esta autenticado en `app.empresa.com`. El atacante crea esta pagina en `evil.com`:

```html
<!-- evil.com/csrf-attack.html -->
<html>
<body>
  <!-- Formulario invisible que se envia automaticamente al cargar la pagina -->
  <form id="attack" action="https://app.empresa.com/api/user/email" method="POST">
    <input type="hidden" name="newEmail" value="attacker@evil.com">
  </form>
  <script>document.getElementById('attack').submit();</script>
</body>
</html>
```

Cuando la victima visita `evil.com/csrf-attack.html`, su navegador envia automaticamente la peticion POST a `app.empresa.com` con las cookies de sesion activas. El email del usuario queda cambiado al del atacante, que puede entonces hacer un reset de contrasena y tomar la cuenta.

**Ataque via img tag (peticiones GET):**
```html
<img src="https://app.empresa.com/api/user/delete-account">
```

---

## Tu tarea: aplicar la mitigacion

Modifica `SecurityConfig.java` para habilitar CSRF con `CookieCsrfTokenRepository`:

```java
// CODIGO SEGURO
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CSRF habilitado con token en cookie accesible al frontend del mismo origen
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
```

### Por que funciona esta mitigacion?

- **`CookieCsrfTokenRepository`:** Spring escribe el token CSRF en una cookie `XSRF-TOKEN`. El frontend JavaScript del mismo origen puede leerla y enviarla en el header `X-XSRF-TOKEN` con cada peticion.
- **`withHttpOnlyFalse()`:** permite que JavaScript lea la cookie `XSRF-TOKEN`. Sin esto, el frontend no podria leer el token para incluirlo en las peticiones. La cookie de sesion principal sigue siendo `HttpOnly`.
- **Proteccion Double Submit Cookie:** el servidor verifica que el valor en el header `X-XSRF-TOKEN` coincida con el token de la sesion. Un atacante en `evil.com` no puede leer la cookie `XSRF-TOKEN` del usuario (bloqueado por Same-Origin Policy) y por tanto no puede incluir el header correcto.

---

## Variantes de la misma categoria (CSRF / Broken Access Control — mas complejas)

### Variante A: CSRF con Content-Type JSON (SameSite bypass)

Algunas APIs solo aceptan peticiones `Content-Type: application/json`, asumiendo que el navegador no puede enviar ese tipo desde un formulario externo. Esto es incorrecto en contextos modernos:

```javascript
// VULNERABLE — asumir que JSON content-type previene CSRF
// El servidor acepta la peticion si el Content-Type es application/json
// Un atacante puede enviarla via fetch desde evil.com:
fetch('https://app.empresa.com/api/transfer', {
    method: 'POST',
    credentials: 'include',   // envia cookies
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: 9999, to: 'attacker' })
});
// El preflight CORS puede fallar, pero con una CORS misconfiguration, pasa.
```

```java
// SEGURO — combinar CSRF token + verificacion de Origin header
// Verificar que Origin o Referer corresponde al dominio propio
@Component
public class OriginVerificationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String origin = req.getHeader("Origin");
        if (origin != null && !origin.equals("https://app.empresa.com")) {
            res.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        chain.doFilter(req, res);
    }
}
```

---

### Variante B: Login CSRF (forzar sesion del atacante en el navegador de la victima)

```java
// VULNERABLE — endpoint de login sin proteccion CSRF
// Un atacante puede forzar al navegador de la victima a iniciar sesion
// con las credenciales del atacante
@PostMapping("/login")
public ResponseEntity<?> login(@RequestParam String username, @RequestParam String password) {
    // autenticar y crear sesion
}
```

Payload: la victima visita `evil.com` que tiene un formulario que hace submit automatico a `/login` con credenciales del atacante. La victima queda logada como el atacante sin saberlo. Todo lo que la victima hace (subir documentos, realizar compras) queda en la cuenta del atacante.

```java
// SEGURO — CSRF token tambien en el formulario de login (aunque el usuario no este autenticado)
// Spring Security aplica CSRF por defecto a todos los metodos POST, incluyendo /login
// Solo debe deshabilitarse si se usa autenticacion stateless con JWT en header
```

---

### Variante C: CSRF bypass via SameSite=None en cookies de terceros

```
# VULNERABLE — configurar cookies de sesion con SameSite=None sin Secure
Set-Cookie: JSESSIONID=abc123; SameSite=None
```

`SameSite=None` permite que la cookie se envie en peticiones cross-site. Sin `Secure`, ademas viaja por HTTP.

```
# SEGURO — usar SameSite=Strict o SameSite=Lax con el token CSRF como defensa en profundidad
Set-Cookie: JSESSIONID=abc123; HttpOnly; Secure; SameSite=Strict
```

Con `SameSite=Strict`, el navegador no envia la cookie en peticiones cross-site, eliminando CSRF sin necesidad de token. Sin embargo, CSRF token sigue siendo recomendado como defensa en profundidad ante bugs de implementacion `SameSite`.

---

## Referencias

- [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-352: CSRF](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Spring Security - CSRF](https://docs.spring.io/spring-security/reference/features/exploits/csrf.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 10** exige que `SecurityConfig.java` contenga:
- `CookieCsrfTokenRepository`
- `EnableWebSecurity`
- La ausencia de `csrf.disable()`