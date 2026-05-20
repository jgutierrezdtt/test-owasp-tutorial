#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUTORIAL_DIR="$ROOT_DIR/.tutorial"
README_FILE="$ROOT_DIR/README.md"
STATE_FILE="$TUTORIAL_DIR/state.env"
MARKER_FILE="$ROOT_DIR/.tutorial-started"
TOTAL_STEPS=30

CURRENT_STEP=1
COMPLETED=0

step_file() {
  case "$1" in
    0|00) echo "$TUTORIAL_DIR/steps/00-introduccion.md" ;;
    1|01) echo "$TUTORIAL_DIR/steps/01-command-injection.md" ;;
    2|02) echo "$TUTORIAL_DIR/steps/02-path-traversal.md" ;;
    3|03) echo "$TUTORIAL_DIR/steps/03-ssti.md" ;;
    4|04) echo "$TUTORIAL_DIR/steps/04-insecure-deserialization.md" ;;
    5|05) echo "$TUTORIAL_DIR/steps/05-cors-misconfiguration.md" ;;
    6|06) echo "$TUTORIAL_DIR/steps/06-xxe.md" ;;
    7|07) echo "$TUTORIAL_DIR/steps/07-open-redirect.md" ;;
    8|08) echo "$TUTORIAL_DIR/steps/08-insecure-randomness.md" ;;
    9|09) echo "$TUTORIAL_DIR/steps/09-log-injection.md" ;;
    10) echo "$TUTORIAL_DIR/steps/10-csrf.md" ;;
    11) echo "$TUTORIAL_DIR/steps/11-http-header-injection.md" ;;
    12) echo "$TUTORIAL_DIR/steps/12-race-condition-toctou.md" ;;
    13) echo "$TUTORIAL_DIR/steps/13-redos.md" ;;
    14) echo "$TUTORIAL_DIR/steps/14-timing-attack.md" ;;
    15) echo "$TUTORIAL_DIR/steps/15-clickjacking.md" ;;
    16) echo "$TUTORIAL_DIR/steps/16-prototype-pollution.md" ;;
    17) echo "$TUTORIAL_DIR/steps/17-regex-injection.md" ;;
    18) echo "$TUTORIAL_DIR/steps/18-sensitive-data-in-logs.md" ;;
    19) echo "$TUTORIAL_DIR/steps/19-hardcoded-secrets.md" ;;
    20) echo "$TUTORIAL_DIR/steps/20-insecure-file-upload.md" ;;
    21) echo "$TUTORIAL_DIR/steps/21-sql-injection.md" ;;
    22) echo "$TUTORIAL_DIR/steps/22-nosql-injection.md" ;;
    23) echo "$TUTORIAL_DIR/steps/23-ssrf.md" ;;
    24) echo "$TUTORIAL_DIR/steps/24-xss-reflected.md" ;;
    25) echo "$TUTORIAL_DIR/steps/25-xss-stored.md" ;;
    26) echo "$TUTORIAL_DIR/steps/26-idor.md" ;;
    27) echo "$TUTORIAL_DIR/steps/27-jwt-algorithm-confusion.md" ;;
    28) echo "$TUTORIAL_DIR/steps/28-ssrf-typescript.md" ;;
    29) echo "$TUTORIAL_DIR/steps/29-mass-assignment.md" ;;
    30) echo "$TUTORIAL_DIR/steps/30-ldap-injection.md" ;;
    done|99) echo "$TUTORIAL_DIR/steps/99-tutorial-completado.md" ;;
    *)
      echo "Paso desconocido: $1" >&2
      return 1
      ;;
  esac
}

render_step() {
  cp "$(step_file "$1")" "$README_FILE"
}

save_state() {
  mkdir -p "$TUTORIAL_DIR"
  cat > "$STATE_FILE" <<EOF
CURRENT_STEP=$1
COMPLETED=$2
TOTAL_STEPS=$TOTAL_STEPS
EOF
}

load_state() {
  if [[ -f "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
  fi
}

non_comment_stream() {
  local file="$1"
  grep -Ev '^[[:space:]]*(#|//|/\*|\*|\*/|$)' "$file" || true
}

require_non_comment() {
  local file="$ROOT_DIR/$1"
  local marker="$2"
  if [[ ! -f "$file" ]]; then
    echo "Falta archivo requerido: $1" >&2
    return 1
  fi
  if ! non_comment_stream "$file" | grep -Fq -- "$marker"; then
    echo "No aparece el marcador requerido en $1: $marker" >&2
    return 1
  fi
}

forbid_non_comment() {
  local file="$ROOT_DIR/$1"
  local marker="$2"
  if [[ ! -f "$file" ]]; then
    echo "Falta archivo requerido: $1" >&2
    return 1
  fi
  if non_comment_stream "$file" | grep -Fq -- "$marker"; then
    echo "Sigue apareciendo un patron inseguro en $1: $marker" >&2
    return 1
  fi
}

validate_01() {
  require_non_comment src/python/routes/commands.py 'VALID_HOSTNAME'
  require_non_comment src/python/routes/commands.py '["ping", "-c", "1", host]'
  forbid_non_comment src/python/routes/commands.py 'shell=True'
}

validate_02() {
  require_non_comment src/python/routes/files.py 'ALLOWED_DIR'
  require_non_comment src/python/routes/files.py 'os.path.realpath'
  require_non_comment src/python/routes/files.py 'startswith(ALLOWED_DIR + os.sep)'
  require_non_comment src/python/routes/files.py 'raise HTTPException'
  forbid_non_comment src/python/routes/files.py 'f"/var/www/public/{filename}"'
}

validate_03() {
  require_non_comment src/python/routes/render.py 'GREETING_TEMPLATE'
  require_non_comment src/python/routes/render.py 'select_autoescape'
  require_non_comment src/python/routes/render.py 'from_string'
  require_non_comment src/python/routes/render.py 'Environment('
  forbid_non_comment src/python/routes/render.py 'Template(f"Hola {name}!")'
}

validate_04() {
  require_non_comment src/python/routes/serialize.py 'json.loads'
  require_non_comment src/python/routes/serialize.py 'UserPreferences'
  require_non_comment src/python/routes/serialize.py 'field_validator'
  forbid_non_comment src/python/routes/serialize.py 'pickle.loads'
}

validate_05() {
  require_non_comment src/python/routes/cors.py 'ALLOWED_ORIGINS'
  require_non_comment src/python/routes/cors.py 'allow_origins=ALLOWED_ORIGINS'
  require_non_comment src/python/routes/cors.py 'os.environ.get'
  forbid_non_comment src/python/routes/cors.py 'allow_origins=["*"]'
}

validate_06() {
  require_non_comment src/java/src/main/java/com/example/api/controller/XmlController.java 'disallow-doctype-decl'
  require_non_comment src/java/src/main/java/com/example/api/controller/XmlController.java 'external-general-entities'
  require_non_comment src/java/src/main/java/com/example/api/controller/XmlController.java 'setXIncludeAware(false)'
  require_non_comment src/java/src/main/java/com/example/api/controller/XmlController.java 'factory.setFeature'
}

validate_07() {
  require_non_comment src/java/src/main/java/com/example/api/controller/RedirectController.java 'ALLOWED_REDIRECTS'
  require_non_comment src/java/src/main/java/com/example/api/controller/RedirectController.java 'contains(next)'
  require_non_comment src/java/src/main/java/com/example/api/controller/RedirectController.java 'ResponseEntity.badRequest()'
  forbid_non_comment src/java/src/main/java/com/example/api/controller/RedirectController.java '"redirect:" + next'
}

validate_08() {
  require_non_comment src/java/src/main/java/com/example/api/controller/TokenController.java 'SecureRandom'
  require_non_comment src/java/src/main/java/com/example/api/controller/TokenController.java 'nextBytes'
  require_non_comment src/java/src/main/java/com/example/api/controller/TokenController.java 'Base64.getUrlEncoder()'
  forbid_non_comment src/java/src/main/java/com/example/api/controller/TokenController.java 'new Random()'
}

validate_09() {
  require_non_comment src/java/src/main/java/com/example/api/controller/AuthController.java 'sanitizeForLog'
  require_non_comment src/java/src/main/java/com/example/api/controller/AuthController.java 'replaceAll'
  forbid_non_comment src/java/src/main/java/com/example/api/controller/AuthController.java 'log.info("Login attempt for user: " + username)'
}

validate_10() {
  require_non_comment src/java/src/main/java/com/example/api/controller/SecurityConfig.java 'CookieCsrfTokenRepository'
  require_non_comment src/java/src/main/java/com/example/api/controller/SecurityConfig.java 'EnableWebSecurity'
  forbid_non_comment src/java/src/main/java/com/example/api/controller/SecurityConfig.java 'csrf.disable()'
}

validate_11() {
  require_non_comment src/go/handlers/headers.go 'sanitizeHeaderValue'
  require_non_comment src/go/handlers/headers.go 'allowedRedirects'
  require_non_comment src/go/handlers/headers.go 'w.Header().Set("Location", safe)'
  require_non_comment src/go/handlers/headers.go 'strings.ContainsAny'
  forbid_non_comment src/go/handlers/headers.go 'w.Header().Set("Location", next)'
}

validate_12() {
  require_non_comment src/go/handlers/upload.go 'filepath.Base'
  require_non_comment src/go/handlers/upload.go 'os.OpenFile'
  require_non_comment src/go/handlers/upload.go 'os.O_CREATE|os.O_EXCL|os.O_WRONLY'
  forbid_non_comment src/go/handlers/upload.go 'os.Create(path)'
}

validate_13() {
  require_non_comment src/go/handlers/search.go 'safeEmailPattern'
  require_non_comment src/go/handlers/search.go 'len(input) > 200'
  require_non_comment src/go/handlers/search.go 'regexp.MustCompile'
  forbid_non_comment src/go/handlers/search.go '(([a-zA-Z]+)+)'
  forbid_non_comment src/go/handlers/search.go 'var emailPattern'
}

validate_14() {
  require_non_comment src/go/handlers/auth.go 'subtle.ConstantTimeCompare'
  require_non_comment src/go/handlers/auth.go 'os.Getenv("API_KEY")'
  forbid_non_comment src/go/handlers/auth.go 'provided == expected'
}

validate_15() {
  require_non_comment src/go/handlers/middleware.go 'X-Frame-Options'
  require_non_comment src/go/handlers/middleware.go 'X-Content-Type-Options'
  require_non_comment src/go/handlers/middleware.go 'Permissions-Policy'
  require_non_comment src/go/handlers/middleware.go 'Content-Security-Policy'
  require_non_comment src/go/handlers/middleware.go 'Strict-Transport-Security'
}

validate_16() {
  require_non_comment src/typescript/src/merge.controller.ts 'plainToInstance'
  require_non_comment src/typescript/src/merge.controller.ts 'validateSync'
  require_non_comment src/typescript/src/merge.controller.ts 'Object.create(null)'
  forbid_non_comment src/typescript/src/merge.controller.ts 'Object.assign(prefs, body)'
}

validate_17() {
  require_non_comment src/typescript/src/search.controller.ts 'escapeRegExp'
  require_non_comment src/typescript/src/search.controller.ts 'q.length > 100'
  require_non_comment src/typescript/src/search.controller.ts "new RegExp(escapeRegExp(q), 'i')"
  forbid_non_comment src/typescript/src/search.controller.ts "new RegExp(q, 'i')"
}

validate_18() {
  require_non_comment src/typescript/src/logs.service.ts 'SENSITIVE_FIELDS'
  require_non_comment src/typescript/src/logs.service.ts '[REDACTED]'
  require_non_comment src/typescript/src/logs.service.ts 'this.redact(body)'
  forbid_non_comment src/typescript/src/logs.service.ts 'JSON.stringify(body)'
}

validate_19() {
  require_non_comment src/typescript/src/config.service.ts 'process.env[name]'
  require_non_comment src/typescript/src/config.service.ts 'requireEnv'
  require_non_comment src/typescript/src/config.service.ts 'STRIPE_API_KEY'
  forbid_non_comment src/typescript/src/config.service.ts 'super-secret-key'
  forbid_non_comment src/typescript/src/config.service.ts 'admin1234'
  forbid_non_comment src/typescript/src/config.service.ts 'sk_live_'
}

validate_20() {
  require_non_comment src/typescript/src/upload.controller.ts 'ALLOWED_MIME_TYPES'
  require_non_comment src/typescript/src/upload.controller.ts 'ALLOWED_EXTENSIONS'
  require_non_comment src/typescript/src/upload.controller.ts 'randomUUID'
  require_non_comment src/typescript/src/upload.controller.ts 'fileSize'
  forbid_non_comment src/typescript/src/upload.controller.ts 'return { filename: file.originalname }'
}

validate_21() {
  require_non_comment src/python/routes/users.py '"SELECT id, username, email FROM users WHERE username = ?"'
  require_non_comment src/python/routes/users.py '(username,)'
  forbid_non_comment src/python/routes/users.py 'f"SELECT'
}

validate_22() {
  require_non_comment src/python/routes/products.py 'isinstance(username, str)'
  require_non_comment src/python/routes/products.py 'isinstance(password, str)'
  forbid_non_comment src/python/routes/products.py '"username": body.get("username"), "password": body.get("password")'
}

validate_23() {
  require_non_comment src/python/routes/proxy.py 'ALLOWED_HOSTS'
  require_non_comment src/python/routes/proxy.py '_validate_ssrf'
  require_non_comment src/python/routes/proxy.py 'urlparse'
  forbid_non_comment src/python/routes/proxy.py 'requests.get(url, timeout=5)'
}

validate_24() {
  require_non_comment src/java/src/main/java/com/example/api/controller/SearchController.java 'import org.springframework.web.util.HtmlUtils'
  require_non_comment src/java/src/main/java/com/example/api/controller/SearchController.java 'HtmlUtils.htmlEscape(q)'
  require_non_comment src/java/src/main/java/com/example/api/controller/SearchController.java 'String safeQ'
  forbid_non_comment src/java/src/main/java/com/example/api/controller/SearchController.java '+ q + "</h2></body></html>"'
}

validate_25() {
  require_non_comment src/java/src/main/java/com/example/api/controller/CommentsController.java 'import org.springframework.web.util.HtmlUtils'
  require_non_comment src/java/src/main/java/com/example/api/controller/CommentsController.java 'HtmlUtils.htmlEscape(c)'
  require_non_comment src/java/src/main/java/com/example/api/controller/CommentsController.java '.append(HtmlUtils.htmlEscape(c)).append("</li>")'
  forbid_non_comment src/java/src/main/java/com/example/api/controller/CommentsController.java '.append(c).append("</li>")'
}

validate_26() {
  require_non_comment src/go/handlers/orders.go 'r.Header.Get("X-User-ID")'
  require_non_comment src/go/handlers/orders.go 'authenticatedUserID'
  require_non_comment src/go/handlers/orders.go 'order.UserID != authenticatedUserID'
  require_non_comment src/go/handlers/orders.go 'http.StatusForbidden'
}

validate_27() {
  require_non_comment src/go/handlers/jwt.go 'jwt.SigningMethodHMAC'
  require_non_comment src/go/handlers/jwt.go 'os.Getenv("JWT_SECRET")'
  require_non_comment src/go/handlers/jwt.go '"unexpected signing method"'
  forbid_non_comment src/go/handlers/jwt.go 'return []byte("secret"), nil'
}

validate_28() {
  require_non_comment src/typescript/src/proxy.controller.ts 'ALLOWED_HOSTS'
  require_non_comment src/typescript/src/proxy.controller.ts 'new URL(url)'
  require_non_comment src/typescript/src/proxy.controller.ts 'maxRedirects'
  forbid_non_comment src/typescript/src/proxy.controller.ts 'await axios.get(url);'
}

validate_29() {
  require_non_comment src/typescript/src/profile.controller.ts 'UpdateProfileDto'
  require_non_comment src/typescript/src/profile.controller.ts 'instanceToPlain'
  require_non_comment src/typescript/src/profile.controller.ts '@Body() dto: UpdateProfileDto'
  forbid_non_comment src/typescript/src/profile.controller.ts '@Body() body: any'
  forbid_non_comment src/typescript/src/profile.controller.ts 'Object.assign(this.users[userId], body)'
}

validate_30() {
  require_non_comment src/typescript/src/ldap.service.ts 'escapeLdapFilter'
  require_non_comment src/typescript/src/ldap.service.ts '\\28'
  require_non_comment src/typescript/src/ldap.service.ts 'safeUser'
  require_non_comment src/typescript/src/ldap.service.ts 'safePass'
  forbid_non_comment src/typescript/src/ldap.service.ts '`(&(uid=${username})'
}

# Ejecuta el validator del paso indicado sin modificar el estado del tutorial.
# Sale con codigo 1 si el codigo no cumple los requisitos; con 0 si los cumple.
check_only() {
  local requested="$1"
  local numeric="${requested#0}"
  if [[ -z "$numeric" ]]; then numeric=0; fi

  if [[ ! -f "$MARKER_FILE" ]]; then
    echo 'Tutorial no iniciado; comprobacion omitida.'
    return 0
  fi

  local validator
  validator=$(printf 'validate_%02d' "$numeric")
  "$validator"
  echo "Paso $requested: codigo correcto."
}

validate_step() {
  local requested="$1"
  local numeric="${requested#0}"

  if [[ -z "$numeric" ]]; then
    numeric=0
  fi

  if [[ ! -f "$MARKER_FILE" ]]; then
    echo 'Tutorial no iniciado; se omite validacion.'
    return 0
  fi

  load_state

  if [[ "$COMPLETED" == "1" ]]; then
    echo 'Tutorial ya completado.'
    return 0
  fi

  # Siempre validar el codigo cuando el tutorial esta iniciado,
  # independientemente del paso actual.
  local validator
  validator=$(printf 'validate_%02d' "$numeric")
  "$validator"

  # Solo avanzar estado si es el paso que toca.
  if [[ "$CURRENT_STEP" != "$numeric" ]]; then
    echo "Paso actual: $CURRENT_STEP. Codigo del paso $requested correcto pero no se avanza estado."
    return 0
  fi

  if (( numeric >= TOTAL_STEPS )); then
    render_step done
    save_state "$numeric" 1
    echo "Paso $requested validado. Tutorial completado."
    return 0
  fi

  local next_step=$((numeric + 1))
  render_step "$(printf '%02d' "$next_step")"
  save_state "$next_step" 0
  echo "Paso $requested validado. Se habilita el paso $(printf '%02d' "$next_step")."
}

start_tutorial() {
  render_step 01
  touch "$MARKER_FILE"
  save_state 1 0
  echo 'Tutorial iniciado en el paso 01.'
}

reset_tutorial() {
  rm -f "$MARKER_FILE" "$STATE_FILE"
  render_step 00
  echo 'Tutorial reiniciado al paso 0.'
}

main() {
  local command="${1:-}"
  case "$command" in
    start)
      start_tutorial
      ;;
    reset)
      reset_tutorial
      ;;
    validate-step)
      if [[ $# -lt 2 ]]; then
        echo 'Uso: tutorial.sh validate-step <numero>' >&2
        exit 1
      fi
      validate_step "$2"
      ;;
    check-only)
      if [[ $# -lt 2 ]]; then
        echo 'Uso: tutorial.sh check-only <numero>' >&2
        exit 1
      fi
      check_only "$2"
      ;;
    *)
      echo 'Uso: tutorial.sh {start|reset|validate-step <numero>|check-only <numero>}' >&2
      exit 1
      ;;
  esac
}

main "$@"