# src/python/routes/proxy.py
# PASO 23: SSRF — validar host contra allowlist antes de hacer requests externos

import requests
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException

router = APIRouter()

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def _validate_ssrf(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Esquema no permitido")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="Host no permitido")

@router.get("/fetch")
async def fetch_url(url: str):
    _validate_ssrf(url)
    response = requests.get(url, timeout=5, allow_redirects=False)
    return {"status": response.status_code, "content": response.text[:500]}
