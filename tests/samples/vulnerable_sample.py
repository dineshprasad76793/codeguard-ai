# VULNERABLE SAMPLE — real taint chains. Expected: confirmed/potential
# findings with data flow, appropriately high severity.

import sqlite3
import subprocess
import pickle
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db")

@app.route("/find")
def find_user():
    name = request.args.get("name")                       # source
    q = "SELECT * FROM users WHERE name = '" + name + "'"  # concatenation
    return db.execute(q).fetchall()                        # sink


@app.route("/ping")
def ping():
    host = request.args.get("host")
    output = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return output.stdout


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)                       # unsafe deserialization
    return str(obj)


ADMIN_TOKEN = "sk-live-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"


@app.route("/read")
def read_file():
    path = "/var/data/" + request.args.get("name")
    with open(path) as f:                                  # traversal-capable open
        return f.read()
