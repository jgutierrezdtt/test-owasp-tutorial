# src/python/routes/files.py
# PASO 2: Path Traversal — normalizar ruta real y verificar que esta dentro del directorio permitido

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()

ALLOWED_DIR = "/var/www/public"

@router.get("/download")
async def download_file(filename: str):
    real = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
    if not real.startswith(ALLOWED_DIR + os.sep):
        raise HTTPException(status_code=400, detail="Acceso denegado")
    return FileResponse(real)
