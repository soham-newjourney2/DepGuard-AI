"""Token-shaped values are assembled at run time so the repo never holds secret-looking strings."""
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import real, wait_job

from app.config import ROOT
from app.main import create_app
from app.risks import Inputs, secrets

AWS = "AKIA" + "Q" * 4 + "7RTZ3XWVN2BM"
GH = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5"
NPM = "np" + "m_" + "Zx8Cv7Bn6Ml5Kj4Hg3Fd2Sa1Qw0ErTyUiOp"
SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"
PASSWORD = "s3cr3tPassw0rd99"
LITERAL = "Q2xxRk9tZ0h1N3pYd2E"
ENVVAL = "Zk29xTq81LmPw7"
RAW = [AWS, GH, NPM, SLACK, PASSWORD, LITERAL, ENVVAL]


def build(root: Path) -> None:
    files = {
        ".env": f"DATABASE_URL=postgres://localhost/app\nAPI_TOKEN={ENVVAL}\nSECRET_KEY=changeme\n",
        "scripts/release.sh": f"export GH_TOKEN={GH}\n",
        ".npmrc": f"//registry.npmjs.org/:_authToken={NPM}\n",
        "src/config.js": f"module.exports = {{ region: 'eu-west-1', key: '{AWS}' }};\n",
        "src/db.py": f'URL = "https://admin:{PASSWORD}@db.internal/app"\n'
                     f'api_key = "{LITERAL}"\npassword = request.form["password"]\n',
        "deploy/id_rsa": f"{PEM}\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n",
        "test/fake.js": f"const t = '{SLACK}';\n",
        "docs/aws.md": "Example: " + "AKIA" + "IOSFODNN7EXAMPLE\n",
        "node_modules/x/index.js": f"const k = '{AWS}';\n",
        "big.txt": "a" * (secrets.MAX_BYTES + 10) + AWS,
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    (root / "blob.bin").write_bytes(b"\0\1\2" + AWS.encode())


@pytest.fixture
def found(tmp_path):
    build(tmp_path)
    return {r["location"]["file"] + ":" + r["evidence"][1].split(": ")[1]: r
            for r in secrets.check(Inputs(tmp_path, "npm", None, [], "upload"))}


def test_each_pattern_fires(found):
    assert set(found) == {
        ".env:env_secret", ".npmrc:npmrc_auth", "scripts/release.sh:github_token",
        "src/config.js:aws_access_key_id",
        "src/db.py:url_credentials", "src/db.py:hardcoded_secret", "deploy/id_rsa:private_key",
        "test/fake.js:slack_token", "docs/aws.md:aws_access_key_id"}
    r = found["src/config.js:aws_access_key_id"]
    assert r["kind"] == "secret" and r["severity"] == "high" and r["confidence"] == "high"
    assert r["location"] == {"file": "src/config.js", "line": 1}
    assert r["package"] is None and r["title"] == "AWS access key id in src/config.js"


def test_values_are_masked_everywhere(found):
    blob = json.dumps(list(found.values()))
    for raw in RAW:
        assert raw not in blob
    assert "AKIA… (20 chars, value not shown)" in found["src/config.js:aws_access_key_id"][
        "evidence"][0]
    assert "key body not shown" in found["deploy/id_rsa:private_key"]["evidence"][0]


def test_placeholders_skips_and_low_confidence(found):
    assert "changeme" not in json.dumps(found)
    assert found["test/fake.js:slack_token"]["confidence"] == "low"
    aws_doc = found["docs/aws.md:aws_access_key_id"]
    assert aws_doc["confidence"] == "low" and "documented example" in aws_doc["evidence"][2]
    assert not any(k.startswith(("node_modules", "big.txt", "blob.bin")) for k in found)


def test_sample_looking_values_are_low_confidence(tmp_path):
    (tmp_path / "a.js").write_text("const SECRET = 'demo-only-secret';\n", encoding="utf-8")
    [r] = secrets.check(Inputs(tmp_path, "npm", None, [], "upload"))
    assert r["confidence"] == "low" and "placeholder" in r["evidence"][2]


def test_public_github_repo_says_rotate_now(tmp_path):
    build(tmp_path)
    r = secrets.check(Inputs(tmp_path, "npm", None, [], "github"))[0]
    assert r["recommendation"].startswith("This repository is public")


def test_file_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "MAX_FILES", 3)
    for i in range(10):
        (tmp_path / f"f{i}.env").write_text(f"API_TOKEN={GH}\n", encoding="utf-8")
    assert len(secrets.check(Inputs(tmp_path, "npm", None, [], "upload"))) == 3


def test_raw_value_never_lands_outside_extracted_source(settings):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in ("package.json", "package-lock.json"):
            zf.writestr(name, (real(ROOT / "samples" / "clean-demo") / name).read_text("utf-8"))
        zf.writestr("src/config.js", f"const key = '{AWS}';\nconst tok = '{GH}';\n")
    with TestClient(create_app(settings)) as c:
        job_id = c.post("/api/jobs", files={"file": ("p.zip", buf.getvalue())}).json()["job_id"]
        job = wait_job(c, job_id)
        api_blob = json.dumps([c.get(f"/api/jobs/{job_id}/risks").json(), job,
                               c.get(f"/api/jobs/{job_id}/report").json()])
        job_dir = c.app.state.store.job_dir(job_id)
        leaked = [p for p in job_dir.rglob("*") if p.is_file() and "src" not in
                  p.relative_to(job_dir).parts
                  and any(r.encode() in p.read_bytes() for r in (AWS, GH))]
    assert job["status"] == "ready" and job["summary"]["risk_counts"]["by_kind"]["secret"] == 2
    assert leaked == []
    assert AWS not in api_blob and GH not in api_blob
