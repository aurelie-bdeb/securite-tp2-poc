from pydantic import BaseModel


class ComparisonResponse(BaseModel):
    valide: bool = False
