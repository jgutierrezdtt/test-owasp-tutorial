# src/python/routes/proxy.py
# PASO 23: SSRF — validar host contra allowlist antes de hacer requests externos

import requests
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException

router = APIRouter()

# VULNERABLE (punto de inicio del ejercicio):
# @router.get("/fetch")
# async def fetch_url(url: str):
#     response = requests.get(url, timeout=5)
#     return {"status": response.status_code, "content": response.text[:500]}
#
# Vectores de ataque:
# 1. Cloud metadata: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
#    Devuelve credenciales IAM de AWS en instancias EC2.
# 2. Servicios internos: ?url=http://10.0.0.1:8080/admin
#    Acceso a servicios internos no expuestos publicamente.
# 3. Escaneo de puertos: ?url=http://192.168.1.1:22
#    El tiempo de respuesta revela si el puerto esta abierto.
# 4. Protocolo file: ?url=file:///etc/passwd (si la libreria lo soporta)

@router.get("/fetch")
async def fetch_url(url: str):
    response = requests.get(url, timeout=5)
    return {"status": response.status_code, "content": response.text[:500]}
