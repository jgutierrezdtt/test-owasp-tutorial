# src/python/routes/serialize.py
# PASO 4: Insecure Deserialization — usar JSON con schema validado en lugar de pickle

import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

router = APIRouter()


class UserPreferences(BaseModel):
    theme: str = "light"
    language: str = "es"

    @field_validator("theme")
    @classmethod
    def validate_theme(cls, v: str) -> str:
        if v not in ("light", "dark"):
            raise ValueError("Tema invalido")
        return v


@router.post("/load-prefs")
async def load_prefs(data: str):
    try:
        raw = json.loads(data)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="JSON invalido")
    prefs = UserPreferences(**raw)
    return prefs.model_dump()
