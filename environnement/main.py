import random
from typing import Annotated

from fastapi import FastAPI, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.params import Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.requests import Request
from starlette.responses import RedirectResponse, FileResponse, HTMLResponse

import bd

app = FastAPI(
    title="Attaque temporel",
    version="1.0.0",
    description="Preuve de concept d'un API vulnerable à une attaque temporel"
)
basic_scheme = HTTPBasic(auto_error=False)


@app.middleware("http")
async def deactiver_cache(request: Request, call_next):
    """
    Middleware qui intercepte les réponses et s'assure que les navigateurs ne la cacheron pas
    :param request: La requête interceptée
    :param call_next: La prochaine fonction dans la chaine d'éxécution
    :return: La réponse à retourner au client
    """
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request, _exc):
    """
    Handler pour les exceptions de validations pour afficher une page HTML à la place d'une réponse JSON moche
    :param _request: La requête qui a échoué
    :param _exc: L'erreur qui s'est produite
    :return: Une page d'erreur
    :rtype: FileResponse
    """
    return FileResponse("pages/erreur.html", status_code=422)


@app.get("/secure", name="Validation sécuritaire", response_class=HTMLResponse, responses={401: {"model": str}})
async def secure(
        identification: Annotated[HTTPBasicCredentials, Depends(basic_scheme)]
) -> FileResponse:
    """
    Vérifie de façon sécuritaire les informations de l'usager avant d'afficher la page authentifiée
    """
    if identification is None or not bd.verifier_mot_de_passe(
            identification.username,
            identification.password,
            True
    ):
        return FileResponse(
            "pages/mauvais_mdp.html",
            401,
            {"WWW-Authenticate": "Basic realm=" + str(random.random())}
        )
    return FileResponse("pages/codes.html")


@app.get("/vulnerable", name="Validation vulnérable", response_class=HTMLResponse, responses={401: {"model": str}})
async def vulnerable(
        identification: Annotated[HTTPBasicCredentials, Depends(basic_scheme)]
) -> FileResponse:
    """
    Vérifie de façon vulnérable aux attaques temporelles les informations de l'usager avant
        d'afficher la page authentifiée
    """
    if identification is None or not bd.verifier_mot_de_passe(identification.username, identification.password):
        return FileResponse(
            "pages/mauvais_mdp.html",
            401,
            {"WWW-Authenticate": "Basic realm=" + str(random.random())}
        )
    return FileResponse("pages/codes.html")


@app.get("/deconnecter", name="Déconnecter",
         response_class=HTMLResponse, status_code=401, responses={422: {"model": str}}
         )
async def deconnecter(_rediriger_url: str = Query(None, alias="rediriger_url")):
    """
    Affiche une page qui, sur Chrome, déconnecte l'usager. On affiche une page 401 pour faire oublier les informations,
        et ensuite la page qu'on affiche utilise du JavaScript pour rediriger l'usager sur la page initiale
    """
    return FileResponse(
        "pages/deconnexion.html",
        401
    )


@app.get("/", response_class=RedirectResponse, include_in_schema=False)
async def root():
    """
    Redirige vers la documentation
    """
    return RedirectResponse("/docs")
