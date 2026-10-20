import json

import pytest

from app.remediation.patch import apply, bump_spec, detect_indent, section_of, unified

BASE = {"name": "app", "version": "1.0.0", "dependencies": {"express": "4.17.1", "qs": "^6.7.0"},
        "devDependencies": {"mkdirp": "~0.5.1"}}


@pytest.mark.parametrize("indent", ["  ", "    ", "\t"])
def test_indent_preserved(indent):
    text = json.dumps(BASE, indent=indent) + "\n"
    out = apply(text, [{"op": "set", "section": "dependencies", "name": "express",
                        "value": "4.20.0"}])
    assert detect_indent(out) == indent
    assert json.loads(out)["dependencies"]["express"] == "4.20.0"
    assert list(json.loads(out)) == list(BASE), "key order kept"
    assert out.endswith("}\n")


def test_crlf_bom_and_missing_newline():
    text = "﻿" + json.dumps(BASE, indent=2).replace("\n", "\r\n")
    out = apply(text, [{"op": "set", "section": "dependencies", "name": "qs", "value": "^6.7.3"}])
    assert out.startswith("﻿") and "\r\n" in out and "\n" not in out.replace("\r\n", "")
    assert not out.endswith("\n")


def test_nested_override_and_existing_string_override():
    text = json.dumps({**BASE, "overrides": {"express": "4.17.1"}}, indent=2) + "\n"
    out = json.loads(apply(text, [
        {"op": "override", "path": ["express", "qs"], "value": "6.7.3"},
        {"op": "override", "path": ["request", "form-data"], "value": "2.5.6"},
    ]))
    assert out["overrides"] == {"express": {".": "4.17.1", "qs": "6.7.3"},
                                "request": {"form-data": "2.5.6"}}


def test_unified_diff_format():
    before = json.dumps(BASE, indent=2) + "\n"
    after = apply(before, [{"op": "set", "section": "dependencies", "name": "express",
                            "value": "4.20.0"}])
    diff = unified(before, after)
    lines = diff.splitlines()
    assert lines[0] == "--- a/package.json" and lines[1] == "+++ b/package.json"
    assert lines[2].startswith("@@ -") and lines[2].endswith(" @@")
    assert '-    "express": "4.17.1",' in lines and '+    "express": "4.20.0",' in lines
    assert all(line[:1] in " +-@" for line in lines)
    assert unified(before, before) == ""


def test_unknown_edit_rejected():
    with pytest.raises(ValueError):
        apply(json.dumps(BASE), [{"op": "delete"}])


@pytest.mark.parametrize("old,new", [("^6.7.0", "^6.7.3"), ("~1.19.0", "~6.7.3"),
                                     ("6.7.0", "6.7.3"), (">=6", "^6.7.3"), ("*", "^6.7.3"),
                                     ("", "^6.7.3")])
def test_bump_spec_keeps_style(old, new):
    assert bump_spec(old, "6.7.3") == new


def test_section_of():
    assert section_of(BASE, "mkdirp") == "devDependencies"
    assert section_of(BASE, "nope") is None
