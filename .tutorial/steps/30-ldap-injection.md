# Paso 30 — LDAP Injection
**Tecnologia:** TypeScript / NestJS | **OWASP:** A03:2021 - Injection | **CWE-90**

---

## Que es esta vulnerabilidad?

LDAP Injection ocurre cuando input del usuario se incorpora sin escapar a un filtro LDAP (Lightweight Directory Access Protocol). LDAP es el protocolo estandar para directorios de usuarios en entornos corporativos: Active Directory de Microsoft, OpenLDAP, Oracle Directory Server. Las aplicaciones empresariales lo usan para autenticacion y autorizacion (SSO, LDAP bind).

Los filtros LDAP tienen metacaracteres especiales: `(`, `)`, `*`, `\`, y el byte nulo `\x00`. El filtro tipico de autenticacion es `(&(uid=USUARIO)(userPassword=CONTRASENA))`, que significa "uid es USUARIO Y userPassword es CONTRASENA". Si `USUARIO` contiene `)(&`, el filtro se convierte en `(&(uid=admin)(&)(userPassword=x))`. El subfilro `(&)` siempre es verdadero, haciendo que el AND principal pase aunque la contrasena sea incorrecta.

LDAP Injection es menos conocida que SQL Injection pero su impacto es comparable: en entornos donde Active Directory controla acceso a sistemas criticos, un bypass de autenticacion LDAP puede dar acceso a correo corporativo, VPN, servidores de desarrollo y datos de negocio.

---

## Donde ocurre en este codigo?

**Archivo:** `src/typescript/src/ldap.service.ts`

```typescript
// CODIGO VULNERABLE — estado actual del ejercicio
async authenticate(username: string, password: string): Promise<boolean> {
    const filter = `(&(uid=${username})(userPassword=${password}))`;
    const results = this.search(filter);
    return results.length > 0;
}
```

Con `username = "admin"` y `password = "pass"`, el filtro es correcto:
```
(&(uid=admin)(userPassword=pass))
```

Con `username = "admin)(&"` y `password = "x"`, el filtro es:
```
(&(uid=admin)(&)(userPassword=x))
```
El `(&)` es un filtro AND vacio que siempre es verdadero, ignorando la condicion `userPassword=x`.

---

## Como lo explotaria un atacante

**Bypass de autenticacion con payload en username:**
```json
POST /auth/ldap
{"username": "admin)(&", "password": "cualquier_cosa"}
```

El filtro resultante: `(&(uid=admin)(&)(userPassword=cualquier_cosa))`  
El primer AND evalua: `(uid=admin) AND (&)` — como `(&)` siempre es true, la condicion pasa.

**Bypass con wildcard en password:**
```json
{"username": "admin", "password": "*"}
```
El filtro: `(&(uid=admin)(userPassword=*))` — `*` en LDAP significa "tiene algun valor". Cualquier usuario con password no nulo pasa.

**Enumeracion de usuarios con wildcard:**
```json
{"username": "a*", "password": "x))(|(uid=*"}
```
El filtro: `(&(uid=a*)(userPassword=x))(|(uid=*))`  
La parte `(|(uid=*))` devuelve todos los usuarios, ignorando el resto del filtro.

**Extraccion de atributos con injection:**
```json
{"username": "admin)(|(description=*", "password": "x))(&(uid=*"}
```
Permite extraer atributos del directorio paso a paso (Blind LDAP Injection).

---

## Tu tarea: aplicar la mitigacion

Modifica `src/typescript/src/ldap.service.ts` para escapar los metacaracteres de LDAP:

```typescript
// CODIGO SEGURO
import { Injectable } from '@nestjs/common';

@Injectable()
export class LdapService {
  private readonly directory = [
    { uid: 'alice', userPassword: 'pass1', cn: 'Alice Smith', role: 'user' },
    { uid: 'admin', userPassword: 'adminpass', cn: 'Admin User', role: 'admin' },
  ];

  // Escapar los 5 metacaracteres especiales de filtros LDAP (RFC 4515)
  private escapeLdapFilter(value: string): string {
    return value
      .replace(/\\/g, '\\5C')   // \ → \5C  (debe ser primero para no escapar los otros escapes)
      .replace(/\*/g, '\\2A')   // * → \2A
      .replace(/\(/g, '\\28')   // ( → \28
      .replace(/\)/g, '\\29')   // ) → \29
      .replace(/\x00/g, '\\00'); // NUL → \00
  }

  private search(filter: string): Array<Record<string, string>> {
    const matchUid = filter.match(/\(uid=([^)]*)\)/);
    const matchPass = filter.match(/\(userPassword=([^)]*)\)/);
    if (!matchUid || !matchPass) return [];
    return this.directory.filter(
      e => e.uid === matchUid[1] && e.userPassword === matchPass[1],
    );
  }

  async authenticate(username: string, password: string): Promise<boolean> {
    // Escapar ANTES de interpoler en el filtro
    const safeUser = this.escapeLdapFilter(username);
    const safePass = this.escapeLdapFilter(password);
    const filter = `(&(uid=${safeUser})(userPassword=${safePass}))`;
    const results = this.search(filter);
    return results.length > 0;
  }
}
```

### Por que funciona esta mitigacion?

- **`escapeLdapFilter` segun RFC 4515:** los caracteres especiales de filtros LDAP se representan con su escape `\XX` hexadecimal. `(` → `\28`, `)` → `\29`, `*` → `\2A`, `\` → `\5C`. El servidor LDAP descodifica estos escapes antes de evaluar el filtro, pero no los interpreta como metacaracteres.
- **El orden importa:** `\` debe escaparse primero (`\5C`) para no escapar dos veces los escapes que se generan a continuacion.
- **Escapar TODOS los valores, no solo los "sospechosos":** cualquier campo del usuario que entre en el filtro debe escaparse, incluyendo los que vienen de la base de datos (para prevenir Second-Order LDAP Injection).
- **Alternativa: LDAP Bind en lugar de filter de busqueda:** en lugar de construir un filtro con la contrasena, autenticar directamente con LDAP Bind (`ldapClient.bind(dn, password)`). LDAP Bind no usa filtros de busqueda, eliminando el vector de injection para la verificacion de contrasena.

---

## Variantes de la misma categoria (Injection en directorios y servicios de identidad)

### Variante A: LDAP Injection en busquedas de usuario (no solo autenticacion)

```typescript
// VULNERABLE — buscar usuarios por nombre en Active Directory
async findUsers(searchTerm: string): Promise<string[]> {
    const filter = `(&(objectClass=user)(cn=*${searchTerm}*))`;
    // Si searchTerm = "*)(objectClass=* el filtro revela la estructura del directorio
    return this.ldapClient.search(filter);
}
```

```typescript
// SEGURO — escapar en busquedas tambien
async findUsers(searchTerm: string): Promise<string[]> {
    const safe = this.escapeLdapFilter(searchTerm);
    const filter = `(&(objectClass=user)(cn=*${safe}*))`;
    return this.ldapClient.search(filter);
}
```

---

### Variante B: XPath Injection (similar concepto, diferente tecnologia)

```typescript
// VULNERABLE — consulta XPath con input del usuario sin escapar
// XPath se usa en APIs SOAP/XML, servicios de directorio XML, selectores de documentos
async findUser(username: string, password: string): Promise<boolean> {
    const xpath = `//user[name/text()='${username}' and password/text()='${password}']`;
    // Payload: username = "' or '1'='1"
    // XPath: //user[name/text()='' or '1'='1' and password/text()='x']
    const result = this.xmlDoc.evaluate(xpath, ...);
    return result.iterateNext() !== null;
}
```

```typescript
// SEGURO — parametrizar la consulta XPath (XPath variables)
async findUser(username: string, password: string): Promise<boolean> {
    // Algunas librerias XPath soportan variables: $username en el query
    const xpath = `//user[name/text()=$username and password/text()=$password]`;
    const result = this.xmlDoc.evaluate(xpath, this.xmlDoc, {
        lookupVariable: (name) => name === 'username' ? username : password
    }, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
    return result.singleNodeValue !== null;
}
```

---

### Variante C: SAML Injection — manipulacion de assertions XML

```xml
<!-- VULNERABLE — assertion SAML construida con string concatenation -->
<!-- Si username contiene </NameID><NameID>admin -->
<!-- La assertion XML resultante tiene un NameID extra que algunos parsers aceptan -->
<samlp:Response>
  <Assertion>
    <Subject>
      <NameID>usuario_normal</NameID><NameID>admin</NameID>  <!-- injection -->
    </Subject>
  </Assertion>
</samlp:Response>
```

```typescript
// SEGURO — usar librerias SAML establecidas que manejan la construccion XML
// nunca concatenar strings para generar XML/SAML
import { SamlStrategy } from '@node-saml/passport-saml';
// saml-lib construye las assertions con encoding correcto
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-90: LDAP Injection](https://cwe.mitre.org/data/definitions/90.html)
- [RFC 4515 - Lightweight Directory Access Protocol: String Representation of Search Filters](https://www.rfc-editor.org/rfc/rfc4515)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 30** exige que `src/typescript/src/ldap.service.ts` contenga:
- `escapeLdapFilter`
- `\\28`
- La ausencia de `` `(&(uid=${username}) ``
