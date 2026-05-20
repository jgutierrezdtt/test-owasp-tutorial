# Paso 0. Introduccion al tutorial OWASP Multi-Stack Secure Coding

Bienvenido al tutorial multitecnologia de secure coding.

## Que vas a practicar

Este repositorio funciona como template de formacion. El codigo fuente empieza en estado vulnerable y cada paso te pide aplicar una mitigacion concreta en un archivo real. Cuando haces push, GitHub Actions valida el cambio y reemplaza este README por el siguiente paso.

Los 20 pasos cubren:

| Paso | Tema |
| ---- | ---- |
| 1 | Command Injection en Python/FastAPI |
| 2 | Path Traversal en Python/FastAPI |
| 3 | SSTI en Python/FastAPI |
| 4 | Insecure Deserialization en Python/FastAPI |
| 5 | CORS misconfiguration en Python/FastAPI |
| 6 | XXE en Java/Spring Boot |
| 7 | Open Redirect en Java/Spring Boot |
| 8 | Insecure Randomness en Java/Spring Boot |
| 9 | Log Injection en Java/Spring Boot |
| 10 | CSRF en Java/Spring Boot |
| 11 | HTTP Header Injection en Go |
| 12 | Race Condition TOCTOU en Go |
| 13 | ReDoS en Go |
| 14 | Timing Attack en Go |
| 15 | Clickjacking en Go |
| 16 | Prototype Pollution en TypeScript/NestJS |
| 17 | Regex Injection en TypeScript/NestJS |
| 18 | Sensitive Data in Logs en TypeScript/NestJS |
| 19 | Hardcoded Secrets en TypeScript/NestJS |
| 20 | Insecure File Upload en TypeScript/NestJS |

## Como funciona

1. Haz un fork del repositorio.
2. Ejecuta el workflow `Start Tutorial` en la pestaña Actions de tu fork.
3. Lee el paso actual en `README.md`.
4. Corrige el archivo indicado.
5. Haz push y deja que el workflow del paso valide el cambio.

## Archivos de instrucciones

Los pasos se guardan en `.tutorial/steps/` y GitHub Actions copia el paso actual a `README.md`.
