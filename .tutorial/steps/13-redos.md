# Paso 13 — ReDoS (Regular Expression Denial of Service)
**Tecnologia:** Go | **OWASP:** A06:2021 - Vulnerable and Outdated Components / DoS | **CWE-1333**

---

## Que es esta vulnerabilidad?

ReDoS (Regular Expression Denial of Service) ocurre cuando un motor de expresiones regulares tarda un tiempo exponencial o cuadratico en evaluar un input especialmente diseñado contra ciertos patrones. Esto se debe al "backtracking catastrofico": el motor intenta todas las combinaciones posibles de matching antes de concluir que el input no coincide.

El problema surge cuando el patron tiene:
1. Cuantificadores anidados: `(a+)+`, `(a|aa)+`, `(a+b)+`
2. Alternaciones con prefijos comunes: `(cat|catch|ca)+`
3. Grupos que se solapan entre si

Con un input como `aaaaaaaaaaaaaaaaaaaaX` (muchas `a` seguidas de una letra que fuerza el fallo), el motor explora 2^n combinaciones para n caracteres, bloqueando el thread o proceso durante segundos o minutos con un solo request.

---

## Donde ocurre en este codigo?

**Archivo:** `src/go/handlers/search.go`

```go
// CODIGO VULNERABLE — estado actual del ejercicio
var emailPattern = regexp.MustCompile(`^(([a-zA-Z]+)+)@example\.com$`)

func SearchHandler(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("q")
    if emailPattern.MatchString(input) {
        w.Write([]byte("valid"))
    }
}
```

El patron `(([a-zA-Z]+)+)` es vulnerable porque:
- El grupo externo `(...)+` puede matchear una o mas veces
- El grupo interno `[a-zA-Z]+` tambien puede matchear una o mas veces
- Ambos grupos pueden repartirse los mismos caracteres de infinitas formas

Con input `aaaaaaaaaaaaaaaaaaaaX`, el motor intenta todas las formas de dividir las `a` entre los dos grupos antes de fallar en la `X`. El tiempo crece exponencialmente con la longitud del input.

**Nota Go:** el paquete `regexp` de Go usa una implementacion NFA que evita el backtracking catastrofico. Sin embargo, el patron vulnerable aqui sirve como ejemplo del problema que es critico en otros lenguajes (Python `re`, JavaScript, Java, Ruby, PHP) y en dependencias de terceros.

---

## Como lo explotaria un atacante

**Input que provoca backtracking catastrofico (en motores con backtracking):**
```
GET /search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX
```

En Python con el mismo patron:
```python
import re, time
pattern = re.compile(r'^(([a-zA-Z]+)+)@example\.com$')
start = time.time()
pattern.match('a' * 30 + 'X')  # tarda >30 segundos con 30 caracteres
print(time.time() - start)
```

**Numero de intentos necesario para DoS:**
- 20 caracteres: ~1 segundo
- 25 caracteres: ~30 segundos
- 30 caracteres: >10 minutos
- Con 3 peticiones concurrentes, el servidor queda inutilizable

**Bibliotecas vulnerables frecuentes:**
- `validator.js` (npm): tuvo multiples CVEs de ReDoS en validaciones de email/URL
- `moment.js`: CVE-2022-24785 (ReDoS en parsing de fechas)
- `express-fileupload`: CVE-2020-7699

---

## Tu tarea: aplicar la mitigacion

Modifica `src/go/handlers/search.go` para usar un patron sin backtracking catastrofico y limitar la longitud del input:

```go
// CODIGO SEGURO
package handlers

import (
    "net/http"
    "regexp"
)

const maxInputLength = 254  // longitud maxima de email segun RFC 5321

// Patron lineal: sin cuantificadores anidados, sin alternaciones con prefijo comun
// [a-zA-Z0-9._%+\-]+ matchea una vez por caracter, sin posibilidad de repartir
var safeEmailPattern = regexp.MustCompile(
    `^[a-zA-Z0-9._%+\-]+@example\.com$`,
)

func SearchHandler(w http.ResponseWriter, r *http.Request) {
    input := r.URL.Query().Get("q")

    // Limitar longitud antes de evaluar la regex
    if len(input) > maxInputLength {
        http.Error(w, "Input too long", http.StatusBadRequest)
        return
    }

    if safeEmailPattern.MatchString(input) {
        w.Write([]byte("valid"))
    } else {
        w.Write([]byte("invalid"))
    }
}
```

### Por que funciona esta mitigacion?

- **Patron lineal `[a-zA-Z0-9._%+\-]+`:** cada posicion del input solo puede ser matcheada de una forma. No hay forma de "repartir" los caracteres entre grupos anidados. El motor evalua cada caracter exactamente una vez: complejidad O(n).
- **Limite de longitud:** incluso con un patron potencialmente lento, limitar el input a 254 caracteres pone un techo al tiempo de evaluacion. Es la primera linea de defensa ante cualquier patron desconocido.
- **Sin cuantificadores anidados:** la regla es: nunca `(X+)+`, nunca `(X|Y)+` donde X e Y comparten prefijos, nunca grupos que se solapan.

---

## Variantes de la misma categoria (DoS via logica vulnerable — mas complejas)

### Variante A: ReDoS en validacion de URL (JavaScript/Node.js)

```javascript
// VULNERABLE — patron con backtracking catastrofico en validacion de URL
const URL_PATTERN = /^(https?:\/\/)?(([a-zA-Z\d]([a-zA-Z\d-]*[a-zA-Z\d])*)\.)+[a-zA-Z]{2,}$/;

app.get('/validate', (req, res) => {
    const url = req.query.url;
    // Con input como 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.'
    // el motor tarda exponencialmente
    res.json({ valid: URL_PATTERN.test(url) });
});
```

```javascript
// SEGURO — usar la clase URL nativa del runtime (sin backtracking)
app.get('/validate', (req, res) => {
    const rawUrl = req.query.url;
    if (rawUrl.length > 2048) {
        return res.status(400).json({ error: 'URL too long' });
    }
    try {
        const parsed = new URL(rawUrl);  // parser nativo, no regex
        const valid = ['http:', 'https:'].includes(parsed.protocol);
        res.json({ valid });
    } catch {
        res.json({ valid: false });
    }
});
```

---

### Variante B: Catastrophic Backtracking en validacion de fechas (Python)

```python
# VULNERABLE — validacion de fecha con alternacion que causa backtracking
DATE_PATTERN = re.compile(
    r'^(\d{4})[-/.](\d{1,2}|0[1-9]|1[0-2])[-/.](\d{1,2}|0[1-9]|[12]\d|3[01])$'
)
```

Este patron tiene alternaciones `(\d{1,2}|0[1-9]|1[0-2])` con prefijos comunes (todos pueden empezar por un digito). Con input `1999-99-99999999999X`, el backtracking es cuadratico.

```python
# SEGURO — patron sin alternaciones solapadas + longitud fija
DATE_PATTERN = re.compile(r'^\d{4}[-/.]\d{2}[-/.]\d{2}$')

def validate_date(date_str: str) -> bool:
    if len(date_str) > 10:
        return False
    if not DATE_PATTERN.match(date_str):
        return False
    # Validacion logica post-regex (mes 1-12, dia 1-31)
    parts = re.split(r'[-/.]', date_str)
    month, day = int(parts[1]), int(parts[2])
    return 1 <= month <= 12 and 1 <= day <= 31
```

---

### Variante C: Amplification via compresion (zip bomb) — DoS de otro tipo

```python
# VULNERABLE — descomprimir sin limitar el taman~o del output
import zipfile

@router.post("/extract")
async def extract(file: UploadFile):
    with zipfile.ZipFile(file.file) as z:
        total = sum(info.file_size for info in z.infolist())
        z.extractall("/tmp/output")  # puede descomprimir GBs desde pocos KB
```

Un zip bomb como `42.zip` (42 KB) se expande a 4.5 PB de datos anidados.

```python
# SEGURO — limitar taman~o total antes de extraer
MAX_UNCOMPRESSED = 100 * 1024 * 1024  # 100 MB

@router.post("/extract")
async def extract(file: UploadFile):
    with zipfile.ZipFile(file.file) as z:
        total = sum(info.file_size for info in z.infolist())
        if total > MAX_UNCOMPRESSED:
            raise HTTPException(status_code=400, detail="Archivo demasiado grande")
        z.extractall("/tmp/output")
```

---

## Referencias

- [OWASP CWE-1333: ReDoS](https://cwe.mitre.org/data/definitions/1333.html)
- [PortSwigger - ReDoS](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings)
- [OWASP ReDoS article](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [CVE-2022-24785 — ReDoS en moment.js](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24785)

---

## Lo que valida el workflow automaticamente

El workflow **Validate Step 13** exige que `src/go/handlers/search.go` contenga:
- `safeEmailPattern`
- El limite de longitud del input
- La desaparicion del patron vulnerable