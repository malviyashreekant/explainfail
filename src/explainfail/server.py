"""A tiny HTTP service so any scheduler or script can POST a log and get an explanation back.

    POST /analyze   {"log": "...", "job": "nightly_etl", "exit_code": 1, "format": "json"}
    GET  /health

Standard library only. Binds to localhost by default and refuses to listen on other
addresses without a token.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, List, Optional

from . import __version__
from .core import analyze
from .llm import LLMConfig
from .outputs import render
from .rules import Rule

MAX_BODY_BYTES = 10 * 1024 * 1024
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


@dataclass
class Settings:
    rules: List[Rule]
    ai: Optional[LLMConfig] = None
    redact_secrets: bool = True
    redact_ips: bool = False
    tail_lines: int = 40
    max_findings: int = 3
    token: Optional[str] = None


def requires_token(host: str) -> bool:
    return host not in LOOPBACK_HOSTS


def make_server(host: str, port: int, settings: Settings) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "explainfail"
        sys_version = ""

        def _send(self, code: int, body: str, ctype: str = "application/json") -> None:
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _error(self, code: int, message: str) -> None:
            self._send(code, json.dumps({"error": message}))

        def _authorized(self) -> bool:
            if not settings.token:
                return True
            header = self.headers.get("Authorization", "")
            supplied = header[7:] if header.lower().startswith("bearer ") else ""
            return hmac.compare_digest(supplied.encode("utf-8"), settings.token.encode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, json.dumps({"status": "ok", "version": __version__}))
            else:
                self._error(404, "not found")

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/analyze":
                return self._error(404, "not found")
            if not self._authorized():
                return self._error(401, "missing or invalid bearer token")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._error(400, "invalid Content-Length")
            if length <= 0:
                return self._error(400, "request body is required")
            if length > MAX_BODY_BYTES:
                return self._error(413, f"body too large (max {MAX_BODY_BYTES} bytes)")
            try:
                data: Any = json.loads(self.rfile.read(length))
            except ValueError:
                return self._error(400, "body must be valid JSON")
            if not isinstance(data, dict) or not isinstance(data.get("log"), str):
                return self._error(400, "'log' (a string) is required")

            exit_code = data.get("exit_code")
            if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
                return self._error(400, "'exit_code' must be an integer")
            fmt = data.get("format", "json")
            if fmt not in ("json", "text", "markdown"):
                return self._error(400, "'format' must be json, text or markdown")

            try:
                report = analyze(
                    data["log"],
                    job=str(data.get("job") or "unknown")[:200],
                    exit_code=exit_code,
                    rules=settings.rules,
                    ai=settings.ai,
                    redact_secrets=settings.redact_secrets,
                    redact_ips=settings.redact_ips,
                    tail_lines=settings.tail_lines,
                    max_findings=settings.max_findings,
                )
            except Exception:  # noqa: BLE001
                return self._error(500, "analysis failed")
            if fmt == "json":
                self._send(200, render(report, "json"))
            else:
                self._send(200, render(report, fmt), "text/plain")

    return ThreadingHTTPServer((host, port), Handler)
