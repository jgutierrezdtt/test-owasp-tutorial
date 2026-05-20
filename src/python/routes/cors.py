# src/python/routes/cors.py
# PASO 5: CORS misconfiguration — origen especifico desde variable de entorno,
#         sin wildcard cuando allow_credentials=True

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# VULNERABLE (punto de inicio del ejercicio):
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,  # combinacion prohibida: credentials + wildcard
#     allow_methods=["*"],
#     allow_headers=["*"],
# )
#
# allow_origins=["*"] con allow_credentials=True permite que cualquier sitio
# malicioso haga peticiones autenticadas en nombre del usuario.
# Los navegadores modernos bloquean esto, pero algunas configuraciones proxy no.

def configure_cors(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
