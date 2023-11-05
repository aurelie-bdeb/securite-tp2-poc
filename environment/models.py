from pydantic import BaseModel


class InformationsConfidentiels(BaseModel):
    codes_nuclaire: str = "1234"


class ModelErreurUnauthorized(BaseModel):
    detail: str
