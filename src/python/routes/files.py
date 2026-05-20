# src/python/routes/files.py
# PASO 2: Path Traversal — normalizar ruta real y verificar que esta dentro del directorio permitido

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

# VULNERABLE (punto de inicio del ejercicio):
# @router.get("/download")
# async def download_file(filename: str):
#     path = f"/var/www/public/{filename}"
#     return FileResponse(path)
#
# Un atacante puede enviar: filename=../../etc/passwd
# El servidor devuelve el archivo de credenciales del sistema.


@router.get("/download")
async def download_file(filename: str):
    path = f"/var/www/public/{filename}"
    return FileResponse(path)
