# Intentionally vulnerable demo app — DO NOT deploy this anywhere.
#
# A small, synthetic Flask app assembled to exercise several of the
# rules shipped in SCA Community Edition. Run the scanner on this
# directory to see real findings without needing your own codebase:
#
#   ./run_audit.py examples/demo-app --quick
from flask import Flask, request, Markup
import random

app = Flask(__name__)


@app.route("/users")
def users():
    # SQL injection: user input reaches a query unescaped (taint_sqli)
    name = request.args.get("name")
    db.execute(f"SELECT * FROM users WHERE name = '{name}'")


@app.route("/hello")
def hello():
    # Reflected XSS: user input reaches the response unescaped (taint_xss)
    name = request.args.get("name")
    return Markup(f"<h1>Hello {name}</h1>")


@app.route("/file")
def get_file():
    # Path traversal: user input controls which file is read (taint_path_traversal)
    path = request.args.get("path")
    return open(path).read()


def generate_session_token():
    # Predictable token: random.randint() is not cryptographically
    # secure (weak_random_python) — use secrets.token_hex() instead.
    return random.randint(100000, 999999)
