# Fixture clean : cookie Python avec httponly et secure
from flask import Flask, make_response

app = Flask(__name__)

@app.route("/login")
def login():
    resp = make_response("logged in")
    resp.set_cookie("session_id", "abc123", httponly=True, secure=True, samesite="Lax")
    return resp
