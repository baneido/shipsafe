# Intentionally vulnerable Python sample used by ShipSafe integration tests.
# DO NOT copy any of this into real code.
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "super-secret-prod-password"


@app.route("/users")
def get_user(cursor):
    user_id = request.args.get("id")
    # SQL injection via f-string
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return "ok"


@app.route("/admin/users", methods=["POST"])
def create_admin_user():
    # Sensitive route without authentication decorator
    return "created"


@app.route("/calc")
def calc():
    # Remote code execution via eval on user input
    return str(eval(request.args.get("expr")))


def load_settings(stream):
    # Unsafe YAML deserialization
    return yaml.load(stream)


def ping(host):
    # Command injection via shell interpolation
    subprocess.run(f"ping -c 1 {host}", shell=True)
