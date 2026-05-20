# src/python/routes/commands.py
# PASO 1: Command Injection — subprocess sin shell=True y validacion de hostname

import subprocess

from fastapi import APIRouter

router = APIRouter()

# VULNERABLE (punto de inicio del ejercicio):
# @router.get("/ping")
# async def ping_host(host: str):
#     result = subprocess.run(
#         f"ping -c 1 {host}", shell=True, capture_output=True, text=True
#     )
#     return {"output": result.stdout}
#
# Un atacante puede enviar: host=8.8.8.8; cat /etc/passwd
# El shell interpreta el punto y coma como separador de comandos.

@router.get("/ping")
async def ping_host(host: str):
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return {"output": result.stdout}
