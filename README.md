# Example d'attaque temporelle
## Application vulnerable
Le dossier ``environnement/`` contient un serveur FastAPI (``main.py``) ainsi qu'un utilitaire en ligne de commande (``bd.py``) pour modifier la liste d'utilisateurs.

Le serveur contient deux manières de se connecter, ``/secure`` (résistant aux attaques temporelles) et ``/vulnerable`` (vulnérable aux attaques temporelles).

## Attaque
Le dossier ``attaque/`` contient un utilitaire en ligne de commande (``main.py``) permettant de lister tous les utilisateurs grâce à une attaque temporelle.
