# src/python/routes/commands.py
# PASO 1: Command Injection — subprocess sin shell=True y validacion de hostname

import re
import subprocess

from fastapi import APIRouter, HTTPException

router = APIRouter()

VALID_HOSTNAME = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]{1,63}$"
)

@router.get("/ping")
async def ping_host(host: str):
    if not VALID_HOSTNAME.match(host):
        raise HTTPException(status_code=400, detail="Hostname invalido")
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True
    )
    return {"output": result.stdout}
