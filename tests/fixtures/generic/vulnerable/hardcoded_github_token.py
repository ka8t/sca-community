# Fixture vulnérable : token GitHub Personal Access Token hardcodé
import requests

GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

headers = {"Authorization": f"token {GITHUB_TOKEN}"}
response = requests.get("https://api.github.com/user", headers=headers)
