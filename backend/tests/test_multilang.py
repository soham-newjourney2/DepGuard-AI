from app.reachability import assess, index_sources
from app.report.sbom import purl


def write(root, files: dict[str, str]):
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body, encoding="utf-8")


def finding(name: str, eco: str, paths=None) -> dict:
    return {"package": {"name": name, "version": "1.0.0", "ecosystem": eco},
            "paths": paths or [["root", f"{name}@1.0.0"]]}


def test_python_imports_with_distribution_aliases(tmp_path):
    write(tmp_path, {
        "app/main.py": "import os, yaml as y\nfrom fastapi import FastAPI\nfrom . import local\n",
        "app/util.py": "from bs4 import BeautifulSoup\nimport dateutil.parser\n",
        "tests/test_api.py": "import requests\n",
        ".venv/lib/site.py": "import django\n"})
    idx = index_sources(tmp_path, "PyPI")
    assert idx.files == 3
    assert assess(finding("PyYAML", "PyPI"), idx)["label"] == "Strong evidence"
    assert assess(finding("beautifulsoup4", "PyPI"), idx)["label"] == "Strong evidence"
    assert assess(finding("python-dateutil", "PyPI"), idx)["label"] == "Strong evidence"
    assert assess(finding("FastAPI", "PyPI"), idx)["evidence"][0]["file"] == "app/main.py"
    assert assess(finding("requests", "PyPI"), idx)["label"] == "Not observed", "test-only"
    assert assess(finding("django", "PyPI"), idx)["label"] == "Not observed", "venv skipped"
    starlette = finding("starlette", "PyPI", [["root", "fastapi@0.95.0", "starlette@0.26.1"]])
    assert assess(starlette, idx)["label"] == "Possible"


def test_python_dynamic_import_is_unknown(tmp_path):
    write(tmp_path, {"m.py": "import importlib\nmod = importlib.import_module(name)\n"})
    assert assess(finding("yaml", "PyPI"), index_sources(tmp_path, "PyPI"))["label"] == "Unknown"


def test_go_import_blocks_match_module_prefix(tmp_path):
    write(tmp_path, {
        "main.go": 'package main\n\nimport (\n\t"fmt"\n\tg "github.com/gin-gonic/gin/binding"\n)\n',
        "x_test.go": 'import "golang.org/x/net/html"\n'})
    idx = index_sources(tmp_path, "Go")
    assert assess(finding("github.com/gin-gonic/gin", "Go"), idx)["label"] == "Strong evidence"
    assert assess(finding("golang.org/x/net", "Go"), idx)["label"] == "Not observed"


def test_rust_and_ruby(tmp_path):
    write(tmp_path, {"src/main.rs": "use serde_json::Value;\nuse crate::x;\n",
                     "lib/app.rb": "require 'active_support/core_ext'\nrequire \"nokogiri\"\n"})
    rs = index_sources(tmp_path, "crates.io")
    assert assess(finding("serde-json", "crates.io"), rs)["label"] == "Strong evidence"
    rb = index_sources(tmp_path, "RubyGems")
    assert assess(finding("nokogiri", "RubyGems"), rb)["label"] == "Strong evidence"
    assert assess(finding("activesupport", "RubyGems"), rb)["label"] == "Strong evidence"


def test_unsupported_language_is_unknown(tmp_path):
    write(tmp_path, {"src/A.php": "use GuzzleHttp\\Client;\n"})
    idx = index_sources(tmp_path, "Packagist")
    assert idx.files == 0
    assert assess(finding("guzzlehttp/guzzle", "Packagist"), idx)["label"] == "Unknown"


def test_purls_per_ecosystem():
    assert purl("@babel/core", "7.0.0") == "pkg:npm/%40babel/core@7.0.0"
    assert purl("Django_Rest", "3.0", "PyPI") == "pkg:pypi/django-rest@3.0"
    assert purl("github.com/gin-gonic/gin", "1.9.0", "Go") == \
        "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
    assert purl("guzzlehttp/psr7", "2.1.0", "Packagist") == "pkg:composer/guzzlehttp/psr7@2.1.0"
    assert purl("junit:junit", "4.12", "Maven") == "pkg:maven/junit/junit@4.12"
    assert purl("serde", "1.0.0", "crates.io") == "pkg:cargo/serde@1.0.0"
    assert purl("rails", "6.1.0", "RubyGems") == "pkg:gem/rails@6.1.0"
    assert purl("Newtonsoft.Json", "12.0.1", "NuGet") == "pkg:nuget/Newtonsoft.Json@12.0.1"
