import re
import shutil

import pytest
from fastapi.testclient import TestClient
from helpers import wait_job

from app.config import ROOT, Settings
from app.main import create_app
from app.report.sbom import method, purl


@pytest.fixture(scope="module")
def bom(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sbom")
    shutil.copytree(ROOT / "samples" / "vuln-demo", tmp / "samples" / "vuln-demo")
    s = Settings(_env_file=None, data_dir=tmp / "data", frontend_dir=tmp / "none",
                 samples_dir=tmp / "samples", scanner="fixture", verify_mode="mock")
    with TestClient(create_app(s), raise_server_exceptions=False) as c:
        job_id = wait_job(c, c.post("/api/jobs/demo/vuln-demo").json()["job_id"])["id"]
        doc = c.get(f"/api/jobs/{job_id}/sbom").json()
        dl = c.get(f"/api/jobs/{job_id}/sbom", params={"download": True})
        yield doc, dl, c.get(f"/api/jobs/{job_id}/sbom").json()


def test_cyclonedx_envelope(bom):
    doc, dl, again = bom
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", doc["serialNumber"])
    assert doc["serialNumber"] == again["serialNumber"], "stable per job"
    assert doc["metadata"]["component"] == {"type": "application", "bom-ref": "root",
                                            "name": "vuln-demo", "version": "1.0.0"}
    assert dl.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert ".cdx.json" in dl.headers["content-disposition"]


def test_components_and_dependency_refs(bom):
    doc, _, _ = bom
    refs = {c["bom-ref"] for c in doc["components"]}
    assert len(refs) == len(doc["components"]) == 95
    assert "pkg:npm/qs@6.7.0" in refs and "pkg:npm/qs@6.5.5" in refs
    for d in doc["dependencies"]:
        assert d["ref"] in refs | {"root"}
        assert set(d["dependsOn"]) <= refs
    root = next(d for d in doc["dependencies"] if d["ref"] == "root")
    assert set(root["dependsOn"]) == {"pkg:npm/express@4.17.1", "pkg:npm/request@2.88.2",
                                      "pkg:npm/mkdirp@0.5.1"}
    mini = next(c for c in doc["components"] if c["name"] == "minimist")
    assert mini["scope"] == "excluded"


def test_vulnerabilities(bom):
    doc, _, _ = bom
    refs = {c["bom-ref"] for c in doc["components"]}
    vulns = doc["vulnerabilities"]
    assert len(vulns) == 22
    for v in vulns:
        assert v["affects"][0]["ref"] in refs
        assert v["ratings"][0]["severity"] in {"critical", "high", "medium", "low", "unknown"}
        assert v["source"]["url"].startswith("https://osv.dev/vulnerability/")
    qs = next(v for v in vulns if v["id"] == "GHSA-hrpp-h998-j3pp"
              and v["affects"][0]["ref"] == "pkg:npm/qs@6.7.0")
    assert qs["ratings"][0]["method"] == "CVSSv31" and qs["ratings"][0]["score"] == 7.5
    assert {"id": "CVE-2022-24999", "source": {"name": "NVD"}} in qs["references"]
    assert "6.7.3" in qs["recommendation"]


def test_purl_and_method():
    assert purl("@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    assert purl("qs", "6.7.0") == "pkg:npm/qs@6.7.0"
    assert method({"source": "CVSS_V3", "vector": "CVSS:3.0/AV:N"}) == "CVSSv3"
    assert method({"source": "CVSS_V4", "vector": "CVSS:4.0/AV:N"}) == "CVSSv4"
    assert method({"source": "database_specific"}) == "other"


def test_vulnerabilities_carry_exploit_properties(bom):
    doc, _, _ = bom
    v = next(v for v in doc["vulnerabilities"] if v["id"] == "GHSA-hrpp-h998-j3pp")
    props = {p["name"]: p["value"] for p in v["properties"]}
    assert props["depguard:exploit_status"] == "scored" and props["depguard:kev"] == "false"
    assert 0 < float(props["depguard:epss"]) <= 1
    assert 0.95 <= float(props["depguard:epss_percentile"]) <= 1
