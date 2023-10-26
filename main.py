import hmac

from fastapi import FastAPI
from starlette.responses import RedirectResponse

from models import ComparisonResponse
from very_unsafe_compare import very_unsafe_compare

app = FastAPI(
    title="Attaque temporel",
    version="1.0.0",
    description="Preuve de concept d'un API vulnerable à une attaque temporel"
)

API_KEY = "58c32806ef12e036b2df5f9b74ef6da144080b3b"


@app.get("/secure", name="Comparaison sécuritaire", response_model=ComparisonResponse)
async def secure(key: str):
    """
    Compare **sécuritairement** une clé à une autre sur le serveur
    """
    return {"valide": hmac.compare_digest(key, API_KEY)}


@app.get("/insecure", name="Comparaison dangereuse", response_model=ComparisonResponse)
async def insecure(key: str):
    """
    Compare **dangereusement** (par défaut) une clé à une autre sur le serveur
    """
    return {"valide": key == API_KEY}


@app.get("/tres-insecure", name="Comparaison très dangereuse", response_model=ComparisonResponse)
async def tres_insecure(key: str, delay: int = 20):
    """
    Compare de manière **artificiellement très dangereuse** (avec un ralentissement artificiel)
    une clé à une autre sur le serveur
    """
    return {"valide": very_unsafe_compare(key, API_KEY, delay/1000)}


@app.get("/", response_class=RedirectResponse, include_in_schema=False)
async def root():
    """
    Redirige vers la documentation
    """
    return RedirectResponse("/docs")
