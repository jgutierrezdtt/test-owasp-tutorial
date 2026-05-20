# OWASP Multi-Stack Secure Coding — Tutorial interactivo

Tutorial de secure coding con **30 pasos** sobre las vulnerabilidades mas frecuentes del OWASP Top 10, en cuatro tecnologias reales: Python/FastAPI, Java/Spring Boot, Go/net-http y TypeScript/NestJS.

## Como empezar

1. Haz clic en **Use this template** → **Create a new repository** (en tu cuenta personal).
2. En tu repositorio nuevo, ve a la pestana **Actions** y ejecuta el workflow **Start Tutorial**.
3. Lee el paso actual en `README.md`, corrige el archivo indicado y haz push.
4. GitHub Actions valida el cambio y avanza automaticamente al siguiente paso.

> No hagas un fork: usa **Use this template** para que los workflows de Actions queden activos desde el principio.

## Los 30 pasos

| Paso | Vulnerabilidad | Stack |
| ---: | -------------- | ----- |
| 1 | Command Injection | Python / FastAPI |
| 2 | Path Traversal | Python / FastAPI |
| 3 | Server-Side Template Injection (SSTI) | Python / FastAPI |
| 4 | Insecure Deserialization | Python / FastAPI |
| 5 | CORS Misconfiguration | Python / FastAPI |
| 6 | XXE (XML External Entity) | Java / Spring Boot |
| 7 | Open Redirect | Java / Spring Boot |
| 8 | Insecure Randomness | Java / Spring Boot |
| 9 | Log Injection | Java / Spring Boot |
| 10 | CSRF | Java / Spring Boot |
| 11 | HTTP Header Injection | Go / net-http |
| 12 | Race Condition / TOCTOU | Go / net-http |
| 13 | ReDoS | Go / net-http |
| 14 | Timing Attack | Go / net-http |
| 15 | Clickjacking | Go / net-http |
| 16 | Prototype Pollution | TypeScript / NestJS |
| 17 | Regex Injection | TypeScript / NestJS |
| 18 | Sensitive Data in Logs | TypeScript / NestJS |
| 19 | Hardcoded Secrets | TypeScript / NestJS |
| 20 | Insecure File Upload | TypeScript / NestJS |
| 21 | SQL Injection | Python / FastAPI |
| 22 | NoSQL Injection | Python / FastAPI |
| 23 | SSRF | Python / FastAPI |
| 24 | XSS Reflejado | Java / Spring Boot |
| 25 | XSS Almacenado | Java / Spring Boot |
| 26 | IDOR / BOLA | Go / net-http |
| 27 | JWT Algorithm Confusion | Go / net-http |
| 28 | SSRF | TypeScript / NestJS |
| 29 | Mass Assignment | TypeScript / NestJS |
| 30 | LDAP Injection | TypeScript / NestJS |

## Estructura del repositorio

```
src/
  python/     # Fuentes vulnerables Python/FastAPI
  java/       # Fuentes vulnerables Java/Spring Boot
  go/         # Fuentes vulnerables Go/net-http
  typescript/ # Fuentes vulnerables TypeScript/NestJS
.tutorial/
  steps/      # Instrucciones de cada paso (markdown)
  config.yml  # Configuracion del tutorial
scripts/
  tutorial.sh # Motor del tutorial (bash)
.github/
  workflows/  # 30 workflows de validacion + start + reset
```
