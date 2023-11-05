#!/usr/bin/env python3
import argparse
import os
import sqlite3
from getpass import getpass
from hashlib import pbkdf2_hmac
from typing import Optional

bd = sqlite3.connect("bd.sqlite3", isolation_level=None)
curseur = bd.cursor()

curseur.execute("""
CREATE TABLE IF NOT EXISTS usagers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT UNIQUE NOT NULL,
    hash BLOB NOT NULL,
    salt BLOB NOT NULL
);
""")

PBKDF2_ITERATIONS = 300_000
PBKDF2_ALGORITHME = "blake2b"
LONGUEUR_SALT = 32


def usager_existe(nom: str) -> bool:
    return curseur.execute("SELECT 1 FROM usagers WHERE nom = ?", [nom]).fetchone() is not None


def verifier_mot_de_passe(nom: str, mot_de_passe: str) -> bool:
    usager = curseur.execute("""
    SELECT hash, salt FROM usagers
    WHERE nom = ?
    """, [nom]).fetchone()

    if usager is None:
        return False

    [hash_correct, salt] = usager
    hash_test = pbkdf2_hmac(PBKDF2_ALGORITHME, mot_de_passe.encode("utf8"), salt, PBKDF2_ITERATIONS)
    if hash_correct != hash_test:
        return False

    return True


def verifier_mot_de_passe_secure(nom: str, mot_de_passe: str) -> bool:
    usager = curseur.execute("""
    SELECT hash, salt FROM usagers
    WHERE nom = ?
    """, [nom]).fetchone()

    if usager is None:
        pbkdf2_hmac(PBKDF2_ALGORITHME, mot_de_passe.encode("utf8"), os.urandom(LONGUEUR_SALT), PBKDF2_ITERATIONS)
        return False
    else:
        [hash_correct, salt] = usager
        hash_test = pbkdf2_hmac(PBKDF2_ALGORITHME, mot_de_passe.encode("utf8"), salt, PBKDF2_ITERATIONS)
        if hash_correct != hash_test:
            return False

    return True


def cmd_creer_usager(nom: str, mot_de_passe: Optional[str]):
    if usager_existe(nom):
        raise ValueError("Usager existe déja")

    if mot_de_passe is None:
        mot_de_passe = getpass("Mot de passe: ")

    salt = os.urandom(LONGUEUR_SALT)
    mdp_hash = pbkdf2_hmac(PBKDF2_ALGORITHME, mot_de_passe.encode("utf8"), salt, PBKDF2_ITERATIONS)
    curseur.execute("""
    INSERT INTO usagers(nom, hash, salt)
    VALUES (?, ?, ?)
    """, [nom, mdp_hash, salt])

    print(f"Usager {nom} créé")


def cmd_supprimer_usager(nom: str):
    if not usager_existe(nom):
        raise ValueError("Usager n'existe pas")

    curseur.execute("""
    DELETE FROM usagers
    WHERE nom == ?
    """, [nom])

    print(f"Usager {nom} supprimé")


def cmd_changer_mot_de_passe(nom: str, mot_de_passe: Optional[str]):
    if not usager_existe(nom):
        raise ValueError("Usager n'existe pas")

    if mot_de_passe is None:
        mot_de_passe = getpass("Mot de passe: ")

    salt = os.urandom(LONGUEUR_SALT)
    mdp_hash = pbkdf2_hmac(PBKDF2_ALGORITHME, mot_de_passe.encode("utf8"), salt, PBKDF2_ITERATIONS)
    curseur.execute("""
    UPDATE usagers
    SET hash = ?, salt = ?
    WHERE nom = ?
    """, [mdp_hash, salt, nom])

    print(f"Mot de passe réinitialisé pour {nom}")


def creer_parser():
    parser = argparse.ArgumentParser(
        description='Utilitaire de control de base de données',
        epilog='Alex Karkouche, Aurélie Marineau & Félix Leprohon')
    parser.set_defaults(func=lambda _: parser.print_help())
    subparser = parser.add_subparsers(metavar="sous-commande")

    sub = subparser.add_parser("creer_usager", help='Créer un nouveau usager')
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

    return parser


if __name__ == '__main__':
    args = creer_parser().parse_args()
    args.func(args)
