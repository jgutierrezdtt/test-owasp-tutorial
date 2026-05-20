# Secure Coding Checklist — Multi-Stack

## Frente 1: Inyeccion de comandos y recursos del sistema

- [ ] Ninguna llamada a subprocess/exec usa shell=True con input del usuario
- [ ] Todas las rutas de archivo se normalizan con realpath y verifican prefix permitido
- [ ] Ningun template se construye interpolando input del usuario directamente
- [ ] Ningun endpoint deserializa con pickle/Java ObjectInputStream input del usuario

## Frente 2: Configuracion de seguridad del servidor

- [ ] CORS tiene lista de origenes especifica, sin wildcard con credentials
- [ ] XML parsing tiene DTDs y external entities deshabilitados
- [ ] Los redirects validan destino contra una allowlist
- [ ] Los tokens de seguridad usan SecureRandom / secrets.token_bytes, no Random
- [ ] Los logs sanitizan saltos de linea y no incluyen contrasenas ni tokens
- [ ] CSRF protection esta habilitada en todos los endpoints con estado

## Frente 3: Seguridad en Go y sistemas de bajo nivel

- [ ] Los valores de cabeceras HTTP se sanitizan antes de escribirlos
- [ ] Las operaciones sobre archivos usan flags atomicos (O_EXCL) donde corresponda
- [ ] Los regex aplicados a input del usuario no tienen backtracking catastrofico
- [ ] Las comparaciones de tokens usan constant-time compare
- [ ] Las cabeceras anti-clickjacking (X-Frame-Options) estan configuradas

## Frente 4: Seguridad en Node.js / TypeScript

- [ ] Ninguna actualizacion de objeto mezcla input del usuario sin validar (prototype pollution)
- [ ] Los RegExp construidos con input del usuario escapan metacaracteres
- [ ] Los logs filtran campos sensibles (password, token, secret, creditCard)
- [ ] Ningun secreto (JWT_SECRET, DB_PASSWORD, API_KEY) esta hardcodeado en el codigo
- [ ] Las subidas de archivo validan MIME type, extension y usan nombre generado
