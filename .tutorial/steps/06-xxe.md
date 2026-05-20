# Paso 6 — XXE (XML External Entity)
**Tecnologia:** Java / Spring Boot | **OWASP:** A05:2021 - Security Misconfiguration | **CWE-611**

---

## Que es esta vulnerabilidad?

XML External Entity (XXE) ocurre cuando un parser XML procesa documentos que incluyen referencias a entidades externas. La especificacion XML permite que un documento defina entidades que apuntan a URLs o archivos del sistema de archivos. Si el parser las procesa sin restricciones, el atacante puede leer archivos locales del servidor, realizar peticiones internas (SSRF) o incluso causar denegacion de servicio (Billion Laughs attack).

El problema es que `DocumentBuilderFactory` en Java acepta DTDs y entidades externas por defecto. Esto era un comportamiento legitimo en 1998, pero en el contexto de APIs web modernas representa una superficie de ataque critica. El parser no tiene forma de saber si el XML viene de una fuente confiable o de un atacante.

XXE fue la base de CVE-2019-0232 (Apache Tomcat CGI), CVE-2018-1000840 (varias librerias Java) y del famoso bypass de autenticacion SAML donde las firmas XML podian ser manipuladas para incluir entidades externas.

---

## Donde ocurre en este codigo?

**Archivo:** `src/java/src/main/java/com/example/api/controller/XmlController.java`

```java
// CODIGO VULNERABLE — estado actual del ejercicio
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// Sin ninguna configuracion de seguridad: acepta DTDs y entidades externas por defecto
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xml)));
```

Con la configuracion por defecto, `DocumentBuilderFactory` procesa:
- Declaraciones `DOCTYPE` y sus DTDs asociadas
- Entidades generales externas (`SYSTEM` y `PUBLIC`)
- Entidades de parametro externas
- Includes via XInclude

Todo ello puede apuntar a rutas del sistema de archivos local o URLs internas.

---

## Como lo explotaria un atacante

**Lectura de archivos locales:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request>
  <name>&xxe;</name>
</request>
```
El servidor devuelve el contenido de `/etc/passwd` en el campo `name` de la respuesta.

**SSRF — acceso a servicios internos:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<request><data>&xxe;</data></request>
```
En entornos AWS, esta URL devuelve las credenciales IAM temporales de la instancia EC2.

**Billion Laughs (DoS):**
```xml
<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "12345678901234567890">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY bomb "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<data>&bomb;</data>
```
La expansion exponencial de entidades agota la memoria del servidor.

---

## Tu tarea: aplicar la mitigacion

Modifica `XmlController.java` para deshabilitar completamente el procesamiento de entidades externas:

```java
// CODIGO SEGURO
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Deshabilitar DOCTYPE completamente (opcion mas segura)
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Por si acaso: deshabilitar entidades externas generales y de parametro
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Deshabilitar carga de DTD externas y XInclude
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xml)));
```

### Por que funciona esta mitigacion?

- **`disallow-doctype-decl`:** rechaza cualquier documento que contenga una declaracion `DOCTYPE`. Es la proteccion mas contundente: si no hay DOCTYPE, no puede haber entidades externas. Lanza `SAXParseException` al encontrar `<!DOCTYPE`.
- **`external-general-entities: false`:** impide que el parser resuelva entidades `SYSTEM` o `PUBLIC` que apunten a recursos externos.
- **`external-parameter-entities: false`:** impide entidades de parametro externas (`<!ENTITY % name SYSTEM "url">`).
- **`setXIncludeAware(false)`:** deshabilita XInclude, otro vector para incluir archivos externos en XML.

---

## Variantes de la misma categoria (Security Misconfiguration en parsers — mas complejas)

### Variante A: XXE en carga de SVG

Los archivos SVG son XML. Si la aplicacion acepta uploads de SVG y los parsea o los renderiza en el servidor:

```python
# VULNERABLE — el SVG es XML y puede contener entidades externas
from lxml import etree

@router.post("/render-svg")
async def render_svg(file: UploadFile):
    content = await file.read()
    tree = etree.parse(io.BytesIO(content))  # lxml procesa entidades por defecto
    return {"elements": len(tree.getroot())}
```

Payload SVG:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

```python
# SEGURO — lxml con resolve_entities=False
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
tree = etree.parse(io.BytesIO(content), parser)
```

---

### Variante B: XXE en importacion de Excel/LibreOffice (OOXML)

Los archivos `.xlsx`, `.docx` y `.odt` son ZIPs de XML. Algunos parsers de Office procesan entidades externas en los XML internos:

```java
// VULNERABLE — Apache POI con configuracion por defecto en versiones antiguas
Workbook wb = WorkbookFactory.create(inputStream);
```

Un archivo `.xlsx` malicioso puede contener en `xl/sharedStrings.xml`:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<sst><si><t>&xxe;</t></si></sst>
```

```java
// SEGURO — usar version actualizada de Apache POI (>= 5.2.0) y verificar el tipo antes
if (!isValidExcelFile(inputStream)) {
    throw new SecurityException("Formato de archivo no permitido");
}
// Apache POI >= 5.2.0 tiene proteccion XXE por defecto
Workbook wb = WorkbookFactory.create(inputStream);
```

---

### Variante C: XXE en SAML Authentication Bypass

```java
// VULNERABLE — parser SAML sin proteccion XXE
// Un atacante puede modificar la firma XML de un SAML assertion
// e inyectar entidades externas para exfiltrar datos o bypassear la firma
SAMLResponse response = samlParser.parse(xmlString);  // parser sin hardening
if (response.isValid()) {
    // autenticar usuario
}
```

En ataques reales de bypass SAML, la entidad externa en un campo firmado puede hacer que la firma verifique sobre un valor diferente al que el servidor procesa. Esto fue explotado en Google Workspace, GitHub Enterprise y otros proveedores SSO.

```java
// SEGURO — usar libreria SAML con XXE protection documentada
// OpenSAML >= 3.x o Spring Security SAML con SAMLBootstrap
SAMLBootstrap.bootstrap();  // configura parsers seguros para todos los contextos SAML
```

---

## Referencias

- [OWASP A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [CWE-611: XXE](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger - XML external entity injection](https://portswigger.net/web-security/xxe)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 06** exige que `XmlController.java` contenga:
- `disallow-doctype-decl`
- `external-general-entities`
- `setXIncludeAware(false)`