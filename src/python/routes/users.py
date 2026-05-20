# src/python/routes/users.py
# PASO 21: SQL Injection — consultas parametrizadas con sqlite3

import sqlite3

from fastapi import APIRouter

router = APIRouter()

# VULNERABLE (punto de inicio del ejercicio):
# @router.get("/users")
# async def get_user(username: str):
#     conn = sqlite3.connect(":memory:")
#     cursor = conn.execute(
#         f"SELECT id, username, email FROM users WHERE username = '{username}'"
#     )
#     rows = cursor.fetchall()
#     conn.close()
#     return {"users": rows}
#
# Un atacante puede enviar: username=' OR '1'='1
# La query se convierte en: SELECT ... WHERE username = '' OR '1'='1'
# Devuelve todas las filas de la tabla.
# Con UNION SELECT puede extraer datos de otras tablas.

@router.get("/users")
async def get_user(username: str):
    conn = sqlite3.connect(":memory:")
    cursor = conn.execute(
        f"SELECT id, username, email FROM users WHERE username = '{username}'"
    )
    rows = cursor.fetchall()
    conn.close()
    return {"users": rows}
