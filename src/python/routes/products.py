# src/python/routes/products.py
# PASO 22: NoSQL Injection — validacion de tipos antes de queries a MongoDB

from fastapi import APIRouter, HTTPException

router = APIRouter()

# Simulacion de coleccion MongoDB en memoria para el ejercicio
_db_users = [
    {"username": "alice", "password": "secret1", "role": "user"},
    {"username": "admin", "password": "adminpass", "role": "admin"},
]

def _find_one(query: dict):
    """Simula mongodb find_one evaluando operadores $ne, $gt, $regex, etc."""
    for doc in _db_users:
        match = True
        for key, val in query.items():
            if isinstance(val, dict):
                # Operadores MongoDB: {"$ne": ""} pasa si el valor no es vacio
                if "$ne" in val:
                    if doc.get(key) == val["$ne"]:
                        match = False
                        break
                elif "$gt" in val:
                    if not (doc.get(key, "") > val["$gt"]):
                        match = False
                        break
            else:
                if doc.get(key) != val:
                    match = False
                    break
        if match:
            return doc
    return None


# VULNERABLE (punto de inicio del ejercicio):
# @router.post("/login")
# async def login(body: dict):
#     user = _find_one({"username": body.get("username"), "password": body.get("password")})
#     if user:
#         return {"token": "access_granted", "role": user.get("role")}
#     raise HTTPException(status_code=401, detail="Credenciales invalidas")
#
# Un atacante puede enviar: {"username": "admin", "password": {"$ne": ""}}
# _find_one recibe {"username": "admin", "password": {"$ne": ""}}
# La evaluacion pasa porque el password del admin NO es "" (cualquier password sirve).
# Bypass de autenticacion sin conocer la contrasena.

@router.post("/login")
async def login(body: dict):
    user = _find_one({"username": body.get("username"), "password": body.get("password")})
    if user:
        return {"token": "access_granted", "role": user.get("role")}
    raise HTTPException(status_code=401, detail="Credenciales invalidas")
