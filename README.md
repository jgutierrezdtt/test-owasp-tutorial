# Paso 3 — Server-Side Template Injection (SSTI)
**Tecnologia:** Python / FastAPI | **OWASP:** A03:2021 - Injection | **CWE-1336**

---

## Que es esta vulnerabilidad?

Server-Side Template Injection ocurre cuando input del usuario se interpola directamente dentro de la sintaxis del motor de templates, en lugar de pasarse como variable de contexto. El motor evalua el input como codigo de template, lo que en motores como Jinja2, Mako o Freemarker puede derivar en ejecucion arbitraria de codigo Python o Java en el servidor.

El patron vulnerable es confundir "renderizar datos con un template" con "renderizar un template construido con datos". En el primer caso el template es fijo y los datos son variables; en el segundo, el template lo controla el atacante.

SSTI es especialmente grave porque los motores de templates tienen acceso a la introspeccion de objetos del lenguaje host. En Jinja2 es posible navegar el grafo de objetos de Python para llegar a modulos del sistema operativo desde una expresion aparentemente inofensiva como `{{ ''.__class__.__mro__ }}`.

---

## Donde ocurre en este codigo?

**Archivo:** `src/python/routes/render.py`

```python
# CODIGO VULNERABLE — estado actual del ejercicio
from jinja2 import Template

@router.get("/greet")
async def greet(name: str):
    template = Template(f"Hola {name}!")  # el input del usuario ES el template
    return {"message": template.render()}  # Jinja2 evalua {name} como sintaxis
```

La diferencia critica: el template no es fijo. Se construye con una f-string interpolando `name` directamente. Si `name` contiene `{{ 7*7 }}`, Jinja2 evalua la expresion y devuelve `Hola 49!`. Si contiene expresiones de introspection, llega a RCE.

---

## Como lo explotaria un atacante

**Deteccion — confirmar que es vulnerable:**
```
GET /greet?name={{7*7}}
```
Respuesta: `Hola 49!` confirma que el motor evalua expresiones.

**Lectura del sistema de archivos:**
```
GET /greet?name={{lipsum.__globals__.os.popen('cat+/etc/passwd').read()}}
```

**RCE completo via subclases de Python:**
```
GET /greet?name={{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}
```
El indice `396` varia segun la version de Python; el atacante lo enumera iterando `__subclasses__()`.

**RCE via config en aplicaciones Flask/Jinja2:**
```
GET /greet?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

---

## Tu tarea: aplicar la mitigacion

Modifica `src/python/routes/render.py` para usar un template fijo y pasar el input como variable de contexto:

```python
# CODIGO SEGURO
from jinja2 import Environment, select_autoescape
from fastapi import APIRouter

router = APIRouter()

# El template es una constante definida por el desarrollador, nunca por el usuario
GREETING_TEMPLATE = "Hola {{ name }}!"

env = Environment(autoescape=select_autoescape(["html", "xml"]))

@router.get("/greet")
async def greet(name: str):
    template = env.from_string(GREETING_TEMPLATE)
    return {"message": template.render(name=name)}  # name es un dato, no sintaxis
```

### Por que funciona esta mitigacion?

- **Template fijo (`GREETING_TEMPLATE`):** Jinja2 solo procesa los delimitadores `{{ }}` que estan en el template. El valor de `name` se pasa como contexto de renderizado, no como sintaxis. Si `name` vale `{{ 7*7 }}`, aparece literalmente en la salida, no evaluado.
- **`select_autoescape`:** activa el escapado automatico de caracteres HTML/XML, previniendo XSS si la salida se inyecta en una pagina web.
- **`env.from_string(GREETING_TEMPLATE)` en lugar de `Template(f"...")`:** `Template()` parseara el string resultante de la f-string (con el input interpolado), mientras que `from_string()` sobre una constante siempre parsea el mismo template seguro.

---

## Variantes de la misma categoria (Injection via Templates — mas complejas)

### Variante A: SSTI con allowlist de templates (sandbox escape)

Incluso si se intenta usar el sandbox de Jinja2, existen tecnicas de escape documentadas. La solucion correcta es no aceptar templates del usuario en ningun caso:

```python
# VULNERABLE — sandbox de Jinja2 bypasseable
from jinja2.sandbox import SandboxedEnvironment

@router.get("/render")
async def render_custom(user_template: str):
    env = SandboxedEnvironment()
    return env.from_string(user_template).render()  # acepta template del usuario
```

Payload de escape del sandbox:
```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
En versiones vulnerables del sandbox, es posible llegar a `subprocess.Popen` a traves de la jerarquia de clases.

```python
# SEGURO — allowlist de templates, nunca templates dinamicos
ALLOWED_TEMPLATES = {
    "welcome": "Bienvenido, {{ name }}!",
    "farewell": "Hasta luego, {{ name }}.",
}

@router.get("/render")
async def render_custom(template_id: str, name: str):
    tpl_str = ALLOWED_TEMPLATES.get(template_id)
    if not tpl_str:
        raise HTTPException(status_code=400, detail="Template no permitido")
    return env.from_string(tpl_str).render(name=name)
```

---

### Variante B: Expression Language Injection en Thymeleaf (Java/Spring Boot)

```java
// VULNERABLE — input del usuario como fragmento de template Thymeleaf
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    return "greeting :: " + name;  // name puede contener expresiones SpEL
}
```

Payload: `name=__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x`  
Thymeleaf evalua expresiones Spring Expression Language (SpEL) en los fragmentos, produciendo RCE. Esta fue la base de CVE-2018-1273.

```java
// SEGURO — nombre de fragmento fijo, input como variable del modelo
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", name);  // name es dato, no sintaxis de template
    return "greeting";                  // nombre de view fijo y controlado
}
```

---

### Variante C: SSTI en Mako Templates (Python)

```python
# VULNERABLE — Mako permite codigo Python embebido con <% %>
from mako.template import Template

@router.get("/page")
async def render_page(content: str):
    t = Template(content)  # content controlado por el usuario
    return t.render()
```

Payload: `content=<%import os%>${os.popen('id').read()}`  
Mako permite bloques de codigo Python arbitrario con `<% ... %>` y expresiones con `${}`.

```python
# SEGURO — template fijo, content como variable de sustitucion simple
from mako.template import Template

PAGE_TEMPLATE = Template("<p>Contenido: ${content | h}</p>")

@router.get("/page")
async def render_page(content: str):
    return PAGE_TEMPLATE.render(content=content)  # content es un dato escapado
```

---

## Referencias

- [OWASP A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-1336: Improper Neutralization in Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [PortSwigger - Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [CVE-2018-1273 — Spring Data REST SSTI via SpEL](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1273)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 03** exige que `src/python/routes/render.py` contenga:
- `GREETING_TEMPLATE`
- `select_autoescape`
- `from_string`