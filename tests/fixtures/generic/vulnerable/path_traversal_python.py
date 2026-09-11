# Fixture vulnérable : path traversal Python — fichier ouvert avec entrée utilisateur
from flask import request

def download_file():
    filename = request.args.get("file")
    with open(filename, "r") as f:
        return f.read()


# Multi-ligne : open sur plusieurs lignes
def download_file_multiline():
    filename = request.args.get("file")
    with open(
        filename,
        "r"
    ) as f:
        return f.read()
