from typing import Annotated

from fastapi import FastAPI, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.responses import RedirectResponse, FileResponse, HTMLResponse

import bd

app = FastAPI(
    title="Attaque temporel",
    version="1.0.0",
    description="Preuve de concept d'un API vulnerable à une attaque temporel"
)
basic_scheme = HTTPBasic(auto_error=False)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request, _exc):
    return FileResponse("pages/erreur.html", status_code=422)


@app.get("/secure", name="Comparaison sécuritaire", response_class=HTMLResponse, responses={401: {"model": str}})
async def secure(
        identification: Annotated[HTTPBasicCredentials, Depends(basic_scheme)]
) -> FileResponse:
    """
    Compare **sécuritairement** une clé à une autre sur le serveur
    """

    if identification is None or not bd.verifier_mot_de_passe_secure(identification.username, identification.password):
        return FileResponse(
            "pages/mauvais_mdp.html",
            401,
            {"WWW-Authenticate": "Basic"}
        )
    return FileResponse("pages/codes.html")


@app.get("/vulnerable", name="Comparaison vulnérable", response_class=HTMLResponse, responses={401: {"model": str}})
async def vulnerable(
        identification: Annotated[HTTPBasicCredentials, Depends(basic_scheme)]
) -> FileResponse:
    """
    Compare **dangereusement** (par défaut) une clé à une autre sur le serveur
    """
    if identification is None or not bd.verifier_mot_de_passe(identification.username, identification.password):
        return FileResponse(
            "pages/mauvais_mdp.html",
            401,
            {"WWW-Authenticate": "Basic"}
        )
    return FileResponse("pages/codes.html")


@app.get("/deconnecter", name="Déconnecter",
         response_class=HTMLResponse, status_code=401, responses={302: {}, 422: {"model": str}}
         )
async def deconnecter(rediriger_url: str, rediriger: bool = False):
    """
    Montre une page qui déconnecte l'utilisateur
    """
    if not rediriger:
        return FileResponse(
            "pages/deconnexion.html",
            401,
            {"Refresh": f"0;url=/deconnecter?rediriger=true&rediriger_url={rediriger_url}"}
        )
    else:
        return RedirectResponse(rediriger_url, 302)


@app.get("/", response_class=RedirectResponse, include_in_schema=False)
async def root():
    """
    Redirige vers la documentation
    """
    return RedirectResponse("/docs")
