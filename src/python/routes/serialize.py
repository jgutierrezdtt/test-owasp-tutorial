# src/python/routes/serialize.py
# PASO 4: Insecure Deserialization — usar JSON con schema validado en lugar de pickle

import base64
import pickle

from fastapi import APIRouter

router = APIRouter()


# VULNERABLE (punto de inicio del ejercicio):
# import pickle, base64
#
# @router.post("/load-prefs")
# async def load_prefs(data: str):
#     prefs = pickle.loads(base64.b64decode(data))
#     return prefs
#
# Un atacante puede enviar un payload pickle serializado que ejecute codigo arbitrario
# al deserializarse. Ejemplo: pickle.dumps(os.system("id")) encode en base64.

@router.post("/load-prefs")
async def load_prefs(data: str):
    prefs = pickle.loads(base64.b64decode(data))
    return prefs
