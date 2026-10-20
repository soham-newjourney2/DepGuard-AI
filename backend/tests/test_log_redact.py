from app.security import REDACTED
from app.verify.runner import LINE_CAP, LOG_CAP, StageLog


def test_lines_redacted_before_storage_and_emit():
    emitted = []
    log = StageLog("resolve", emitted.append)
    log.add("npm ERR! //registry.npmjs.org/:_authToken=npm_" + "q" * 36)
    log.add("using token ghp_" + "r" * 36)
    assert "q" * 36 not in log.text() and "r" * 36 not in log.text()
    assert log.text().count(REDACTED) == 2
    assert all("q" * 36 not in e["data"]["text"] for e in emitted)
    assert emitted[0] == {"type": "log", "data": {"stage": "resolve",
                                                  "text": emitted[0]["data"]["text"]}}


def test_log_capped_keeping_tail():
    log = StageLog("test", lambda e: None)
    for i in range(6000):
        log.add(f"line {i:05d} " + "x" * 60)
    text = log.text()
    assert log.truncated and text.startswith("[earlier output truncated]")
    assert len(text.encode()) <= LOG_CAP + 100
    assert text.rstrip().endswith("line 05999 " + "x" * 60)
    assert "line 00000" not in text


def test_single_line_capped():
    log = StageLog("test", lambda e: None)
    log.add("y" * (LINE_CAP * 3))
    assert len(log.text()) == LINE_CAP
