import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "appsec-assurance")
SCRIPTS = os.path.join(SKILL, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import build_fixture  # noqa: E402


def make_fixture() -> str:
    d = tempfile.mkdtemp(prefix="appsec-fixture-")
    return build_fixture.build(d)


SECRETS = [build_fixture.FAKE_AWS_KEY, build_fixture.FAKE_GH_TOKEN, build_fixture.FAKE_DB_PW,
           "supersecret123", "hunter2hunter2", "hardcoded-jwt-secret-value", "s3cr3t-flask-k3y"]


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def read_json(path: str):
    import json
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
