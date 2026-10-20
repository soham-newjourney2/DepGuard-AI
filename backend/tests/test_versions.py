import pytest

from app import versions
from app.scanner.base import Package
from app.scanner.normalize import ranges_for


@pytest.mark.parametrize("eco,a,b", [
    ("npm", "1.2.3", "1.10.0"),
    ("npm", "2.0.0-rc.1", "2.0.0"),
    ("Go", "v1.2.3", "v1.10.0"),
    ("crates.io", "0.9.9", "0.10.0"),
    ("PyPI", "2.0rc1", "2.0"),
    ("PyPI", "1.0.post1", "1.1"),
    ("PyPI", "1.9", "1.10"),
    ("RubyGems", "1.2.3.beta", "1.2.3"),
    ("Maven", "1.9", "1.10"),
    ("NuGet", "4.5", "4.10.1"),
])
def test_ordering_per_ecosystem(eco, a, b):
    assert versions.compare(eco, a, b) == -1
    assert versions.compare(eco, b, a) == 1
    assert versions.compare(eco, a, a) == 0


def test_unparseable_versions_still_compare():
    assert versions.compare("PyPI", "1.0", "weird-1.2") in (-1, 1)
    assert versions.key("npm", "") < versions.key("npm", "0.0.1")


def test_same_name_normalisation():
    assert versions.same_name("PyPI", "Django_REST-framework", "django-rest-framework")
    assert versions.same_name("NuGet", "Newtonsoft.Json", "newtonsoft.json")
    assert not versions.same_name("npm", "Lodash", "lodash")


def test_package_key_namespaces_non_npm():
    assert Package("qs", "6.7.0").key == "qs@6.7.0"
    assert Package("django", "3.2.0", "PyPI").key == "PyPI:django@3.2.0"
    assert Package("django", "3.2.0", "PyPI") != Package("django", "3.2.0", "npm")


def test_ecosystem_ranges_and_listed_versions():
    rec = {"affected": [
        {"package": {"ecosystem": "PyPI", "name": "Django"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0"}, {"fixed": "3.2.19"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "django"}, "versions": ["2.2.1"]},
    ]}
    def hit(version, eco="PyPI"):
        return any(r["contains"] for r in ranges_for(rec, "django", version, eco)[0])
    assert hit("3.2.4") and hit("2.2.1")
    assert not hit("3.2.19") and not hit("3.2.4", "npm")
    assert "3.2.19" in ranges_for(rec, "django", "3.2.4", "PyPI")[1]
