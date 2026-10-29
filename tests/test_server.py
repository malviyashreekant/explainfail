import json
import threading
import urllib.error
import urllib.request

import pytest

from explainfail.rules import load_rules
from explainfail.server import Settings, make_server, requires_token


@pytest.fixture
def start():
    servers = []

    def _start(token=None):
        srv = make_server("127.0.0.1", 0, Settings(rules=load_rules(), token=token))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield _start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def call(url, payload=None, token=None, method=None, raw=None):
    data = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data is not None else "GET"))
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.headers.get("Content-Type"), resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type"), exc.read().decode()


def test_health(start):
    status, _, body = call(start() + "/health")
    assert status == 200 and json.loads(body)["status"] == "ok"


def test_analyze_returns_a_json_report(start):
    log = "Traceback (most recent call last):\n  File 'x'\nModuleNotFoundError: No module named 'pandas'\n"
    status, ctype, body = call(start() + "/analyze", {"log": log, "job": "etl", "exit_code": 1})
    data = json.loads(body)
    assert status == 200 and ctype.startswith("application/json")
    assert data["job"] == "etl" and data["findings"][0]["rule_id"] == "py-module-not-found"


def test_analyze_redacts_secrets(start):
    _, _, body = call(start() + "/analyze", {"log": "password=hunter22 failed\nPermission denied\n"})
    assert "hunter22" not in body


def test_text_format(start):
    status, ctype, body = call(start() + "/analyze", {"log": "Killed\n", "format": "text"})
    assert status == 200 and ctype.startswith("text/plain") and "MOST LIKELY CAUSE" in body


def test_token_is_enforced(start):
    base = start(token="s3cret")
    assert call(base + "/analyze", {"log": "x"})[0] == 401
    assert call(base + "/analyze", {"log": "x"}, token="wrong")[0] == 401
    assert call(base + "/analyze", {"log": "x"}, token="s3cret")[0] == 200
    assert call(base + "/health")[0] == 200  # health stays open for load balancers


@pytest.mark.parametrize(
    "payload,raw",
    [
        ({"job": "no log"}, None),
        ({"log": 5}, None),
        ({"log": "x", "exit_code": "1"}, None),
        ({"log": "x", "exit_code": True}, None),
        ({"log": "x", "format": "xml"}, None),
        (None, b"not json"),
        (None, b"[1, 2]"),
    ],
)
def test_bad_requests_are_400(start, payload, raw):
    assert call(start() + "/analyze", payload, raw=raw)[0] == 400


def test_empty_body_and_unknown_paths(start):
    base = start()
    assert call(base + "/analyze", raw=b"")[0] == 400
    assert call(base + "/nope")[0] == 404
    assert call(base + "/nope", {"log": "x"})[0] == 404


def test_oversized_body_is_rejected(start, monkeypatch):
    monkeypatch.setattr("explainfail.server.MAX_BODY_BYTES", 100)
    assert call(start() + "/analyze", {"log": "x" * 500})[0] == 413


def test_requires_token_only_for_non_local_hosts():
    assert not requires_token("127.0.0.1") and not requires_token("localhost")
    assert requires_token("0.0.0.0") and requires_token("10.1.2.3")
