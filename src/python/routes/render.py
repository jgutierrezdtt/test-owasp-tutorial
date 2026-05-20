# src/python/routes/render.py
# PASO 3: Server-Side Template Injection (SSTI) — template fijo con autoescaping habilitado

from fastapi import APIRouter
from jinja2 import Template

router = APIRouter()

# VULNERABLE (punto de inicio del ejercicio):
# from jinja2 import Template
#
# @router.get("/greet")
# async def greet(name: str):
#     template = Template(f"Hola {name}!")
#     return {"message": template.render()}
#
# Un atacante puede enviar: name={{ 7*7 }} y obtenera "Hola 49!"
# Con: name={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
# el atacante ejecuta comandos arbitrarios en el servidor.

from jinja2 import Environment, select_autoescape

env = Environment(autoescape=select_autoescape(["html", "xml"]))
GREETING_TEMPLATE = env.from_string("Hola {{ name }}!")

@router.get("/greet")
async def greet(name: str):
    return {"message": GREETING_TEMPLATE.render(name=name)}
