# Test cases for rules/sast/python.yml (semgrep --test format).
import os
import subprocess
import yaml
from flask import Flask, request

app = Flask(__name__)

# --- ai-py-hardcoded-credentials ---

# ruleid: ai-py-hardcoded-credentials
db_password = "hunter2-prod"
# ruleid: ai-py-hardcoded-credentials
API_KEY = "sk-proj-abcdef123456"
# ok: ai-py-hardcoded-credentials
password = ""
# ok: ai-py-hardcoded-credentials
api_key = os.environ.get("API_KEY")
# ok: ai-py-hardcoded-credentials
username = "admin"


# --- ai-py-sql-injection-concat ---

def get_user(cursor, user_id, name):
    # ruleid: ai-py-sql-injection-concat
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    # ruleid: ai-py-sql-injection-concat
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: ai-py-sql-injection-concat
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: ai-py-sql-injection-concat
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ok: ai-py-sql-injection-concat
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    # ok: ai-py-sql-injection-concat
    cursor.execute("SELECT * FROM users")


# --- ai-py-flask-sensitive-route-no-auth ---

def login_required(f):
    return f


# ruleid: ai-py-flask-sensitive-route-no-auth
@app.route("/admin/users", methods=["GET"])
def list_admin_users():
    return "users"


# ok: ai-py-flask-sensitive-route-no-auth
@app.route("/admin/settings", methods=["POST"])
@login_required
def update_settings():
    return "ok"


# ok: ai-py-flask-sensitive-route-no-auth
@app.route("/health", methods=["GET"])
def health():
    return "ok"


# --- ai-py-unsafe-yaml-load ---

def load_config(stream):
    # ruleid: ai-py-unsafe-yaml-load
    cfg = yaml.load(stream)
    # ok: ai-py-unsafe-yaml-load
    safe_cfg = yaml.safe_load(stream)
    # ok: ai-py-unsafe-yaml-load
    loader_cfg = yaml.load(stream, Loader=yaml.SafeLoader)
    return cfg, safe_cfg, loader_cfg


# --- ai-py-eval-on-input ---

def calculator():
    # ruleid: ai-py-eval-on-input
    result = eval(input("enter expression: "))
    return result


@app.route("/calc")
def calc():
    # ruleid: ai-py-eval-on-input
    return str(eval(request.args.get("expr")))


def safe_calc(expr):
    import ast
    # ok: ai-py-eval-on-input
    return ast.literal_eval(expr)


# --- ai-py-subprocess-shell-format ---

def ping(host):
    # ruleid: ai-py-subprocess-shell-format
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ruleid: ai-py-subprocess-shell-format
    os.system("ping -c 1 " + host)
    # ok: ai-py-subprocess-shell-format
    subprocess.run(["ping", "-c", "1", host])
