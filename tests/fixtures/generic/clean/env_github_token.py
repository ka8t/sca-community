# Fixture clean : token GitHub via variable d'environnement
import os
import requests

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

headers = {"Authorization": f"token {GITHUB_TOKEN}"}
response = requests.get("https://api.github.com/user", headers=headers)
