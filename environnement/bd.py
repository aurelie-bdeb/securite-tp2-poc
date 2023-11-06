#!/usr/bin/env python3
import argparse
import os
import sqlite3
from getpass import getpass
from hashlib import pbkdf2_hmac
from sqlite3 import IntegrityError
from typing import Optional

PBKDF2_ITERATIONS = 600_000
PBKDF2_ALGORITHME = "sha256"
LONGUEUR_SALT = 32
SALT_VIDE = os.urandom(LONGUEUR_SALT)

bd = sqlite3.connect("bd.sqlite3", isolation_level=None)
curseur = bd.cursor()

# Création de la table si elle n'existe pas déja
curseur.execute("""
CREATE TABLE IF NOT EXISTS usagers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT UNIQUE NOT NULL,
    hash BLOB NOT NULL,
    salt BLOB NOT NULL
);
""")


def verifier_mot_de_passe(nom: str, mot_de_passe: str, securitaire=False) -> bool:
    """
    Vérifie une combinaison nom d'usager/mot de passe, vulnérable aux attaques temporelles
    :param nom: Nom d'usager à vérifier
    :type nom: str
    :param mot_de_passe: Mot de passe à vérifier
    :type mot_de_passe: str
    :param securitaire: Valide la combinaison nom d'usager/mot de passe en utilisant
        un algorithme résistant aux attaques temporelles  
    :type securitaire: bool
    :return: Si la combinaison nom d'usager/mot de passe est valide
    :rtype: bool
    """
    usager = curseur.execute("""
    SELECT hash, salt FROM usagers
    WHERE nom = ?;
    """, [nom]).fetchone()

    if usager is None:
        if securitaire:
            pbkdf2_hmac(
                PBKDF2_ALGORITHME, 
                mot_de_passe.encode("utf8"),
                SALT_VIDE,
                PBKDF2_ITERATIONS
            )
        return False
    else:
        [hash_correct, salt] = usager
        hash_test = pbkdf2_hmac(
            PBKDF2_ALGORITHME, 
            mot_de_passe.encode("utf8"), 
            salt, 
            PBKDF2_ITERATIONS
        )
        if hash_correct != hash_test:
            return False

    return True


def cmd_creer_usager(nom: str, mot_de_passe: Optional[str]) -> None:
    """
    Commande administrative pour créer un nouvel usager
    :param nom: Nom de l'usager à créer
    :type nom: str
    :param mot_de_passe: Mot de passe de l'usager à créer
    :type mot_de_passe: str
    :raises: ValueError
    :return: None
    :rtype: None
    """
    if mot_de_passe is None:
        mot_de_passe = getpass("Mot de passe: ")

    salt = os.urandom(LONGUEUR_SALT)
    mdp_hash = pbkdf2_hmac(
        PBKDF2_ALGORITHME,
        mot_de_passe.encode("utf8"),
        salt,
        PBKDF2_ITERATIONS
    )
    try:
        curseur.execute("""
        INSERT INTO usagers(nom, hash, salt)
        VALUES (?, ?, ?);
        """, [nom, mdp_hash, salt])
    except IntegrityError:
        print(f"Usager {nom} existe déja")
        return

    print(f"Usager {nom} créé")


def cmd_supprimer_usager(nom: str) -> None:
    """
    Commande administrative pour supprimer un usager
    :param nom: Nom de l'usager à supprimer
    :type nom: str
    :raises: ValueError
    :return: None
    :rtype: None
    """
    changements = curseur.execute("""
    DELETE FROM usagers
    WHERE nom == ?;
    """, [nom]).rowcount
    if changements == 0:
        print(f"Usager {nom} n'existe pas")
        return

    print(f"Usager {nom} supprimé")


def cmd_changer_mot_de_passe(nom: str, mot_de_passe: Optional[str]) -> None:
    """
    Commande administrative pour changer le mot de passe d'un usager
    :param nom: Le nom de l'usager du mot de passe à changer
    :type nom: str
    :param mot_de_passe: Le nouveau mot de passe de cet usager
    :type nom: str
    :raises: ValueError
    :return: None
    :rtype: None
    """
    if mot_de_passe is None:
        mot_de_passe = getpass("Mot de passe: ")

    salt = os.urandom(LONGUEUR_SALT)
    mdp_hash = pbkdf2_hmac(
        PBKDF2_ALGORITHME,
        mot_de_passe.encode("utf8"),
        salt,
        PBKDF2_ITERATIONS
    )
    changement = curseur.execute("""
    UPDATE usagers
    SET hash = ?, salt = ?
    WHERE nom = ?;
    """, [mdp_hash, salt, nom]).rowcount

    if changement == 0:
        print(f"Usager {nom} n'existe pas")
        return

    print(f"Mot de passe réinitialisé pour {nom}")


def cmd_afficher_usagers() -> None:
    """
    Affiche tous les usagers dans la base de données
    :return: None
    :rtype: None
    """
    nombre_usagers = 0
    usagers = curseur.execute("""SELECT nom FROM usagers;""")
    for usager in usagers:
        print(usager[0])
        nombre_usagers += 1
    print("==============")
    print(f"{nombre_usagers} usagers.")


def creer_parser() -> argparse.ArgumentParser:
    """
    Crée un :class:`argparse.ArgumentParser` pour parse les commandes administratives
    :return: Le :class:`argparse.ArgumentParser`
    :rtype: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        description='Utilitaire de control de base de données',
        epilog='Alex Karkouche, Aurélie Marineau & Félix Leprohon')
    parser.set_defaults(func=lambda _: parser.print_help())
    subparser = parser.add_subparsers(metavar="sous-commande")

    sub = subparser.add_parser("creer_usager", help='Créer un nouvel usager')
    sub.add_argument("nom", help="Nom d'usager")
    sub.add_argument("mot_de_passe", help="Mot de passe, omettre pour demander", nargs="?")
    sub.set_defaults(func=lambda x: cmd_creer_usager(x.nom, x.mot_de_passe))

    sub = subparser.add_parser("supprimer_usager", help="Supprimer un usager")
    sub.add_argument("nom", help="Nom d'usager")
    sub.set_defaults(func=lambda x: cmd_supprimer_usager(x.nom))

    sub = subparser.add_parser("changer_mot_de_passe", help="Réinitialiser le mot de passe d'un usager")
    sub.add_argument("nom", help="Nom d'usager")
    sub.add_argument("mot_de_passe", help="Mot de passe, omettre pour demander", nargs="?")
    sub.set_defaults(func=lambda x: cmd_changer_mot_de_passe(x.nom, x.mot_de_passe))

    sub = subparser.add_parser("afficher_usagers", help="Lister tous les usagers du système")
    sub.set_defaults(func=lambda x: cmd_afficher_usagers())

    return parser


if __name__ == '__main__':
    args = creer_parser().parse_args()
    args.func(args)
