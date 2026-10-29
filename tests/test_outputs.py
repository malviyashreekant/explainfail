import io
import json
import urllib.error

import pytest

from explainfail import analyze, outputs
from explainfail.models import Finding, Report
from explainfail.outputs import OutputError


@pytest.fixture
def report():
    return analyze("ModuleNotFoundError: No module named 'pandas'\n", job="nightly_etl", exit_code=1)


def test_text_report_has_the_key_sections(report):
    text = outputs.render_text(report)
    for needle in ("JOB: nightly_etl", "EXIT CODE: 1", "MOST LIKELY CAUSE", "What happened:", "How to fix:", "Evidence:"):
        assert needle in text


def test_markdown_and_json(report):
    md = outputs.render_markdown(report)
    assert md.startswith("### Job failed: `nightly_etl` (exit code 1)")
    assert "**How to fix:**" in md
    data = json.loads(outputs.render_json(report))
    assert data["findings"][0]["rule_id"] == "py-module-not-found"
    assert outputs.render(report, "json") == outputs.render_json(report)
    assert outputs.render(report, "md") == md


def test_clean_run_text():
    text = outputs.render_text(analyze("fine", exit_code=0))
    assert "NO ERRORS FOUND" in text and "MOST LIKELY" not in text


def test_ai_sections_and_errors_are_shown(report):
    report.ai_explanation, report.ai_provider = "Do the thing.", "anthropic/m"
    assert "AI EXPLANATION (anthropic/m)" in outputs.render_text(report)
    report.ai_explanation, report.ai_error = None, "unreachable"
    text = outputs.render_text(report)
    assert "AI explanation unavailable: unreachable" in text and "rule-based result" in text


def test_slack_text_escapes_markup():
    r = Report(
        job="a<b>&c",
        status="failed",
        summary="s",
        findings=[Finding("x", "T", "explain <b>", "fix", matched_line="<script>&")],
    )
    text = outputs.render_slack(r)
    assert "<b>" not in text and "<script>" not in text
    assert "a&lt;b&gt;&amp;c" in text and "&lt;script&gt;&amp;" in text


def test_teams_payload_shape(report):
    payload = outputs.teams_payload(report)
    attachment = payload["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert attachment["content"]["type"] == "AdaptiveCard"
    assert any("How to fix" in b["text"] for b in attachment["content"]["body"])


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_post_json_sends_json(monkeypatch, report):
    seen = {}

    def fake_urlopen(req, timeout):
        seen.update(url=req.full_url, data=req.data, ctype=req.get_header("Content-type"))
        return _FakeResponse(b"ok")

    monkeypatch.setattr(outputs.urllib.request, "urlopen", fake_urlopen)
    outputs.send_slack("https://hooks.slack.com/services/T/B/X", report)
    assert seen["ctype"] == "application/json"
    assert "nightly_etl" in json.loads(seen["data"])["text"]
    outputs.send_webhook("http://localhost:9000/hook", report)
    assert json.loads(seen["data"])["job"] == "nightly_etl"


def test_webhook_errors_never_leak_the_url(monkeypatch, report):
    secret_url = "https://hooks.slack.com/services/T000/B000/SECRETSECRET"

    def http_error(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, io.BytesIO())

    monkeypatch.setattr(outputs.urllib.request, "urlopen", http_error)
    with pytest.raises(OutputError) as exc:
        outputs.send_slack(secret_url, report)
    assert "HTTP 500" in str(exc.value) and "SECRETSECRET" not in str(exc.value)

    def down(req, timeout):
        raise urllib.error.URLError("dns failure")

    monkeypatch.setattr(outputs.urllib.request, "urlopen", down)
    with pytest.raises(OutputError) as exc:
        outputs.send_teams(secret_url, report)
    assert "SECRETSECRET" not in str(exc.value)


def test_url_scheme_rules(report):
    with pytest.raises(OutputError):
        outputs.send_slack("http://insecure.example/hook", report)  # Slack/Teams need https
    with pytest.raises(OutputError):
        outputs.send_webhook("file:///etc/passwd", report)
    with pytest.raises(OutputError):
        outputs.send_webhook("not a url", report)


class FakeSMTP:
    instances = []
    tls_available = True

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.calls = host, port, []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return FakeSMTP.tls_available

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg):
        self.calls.append(("send", msg))


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.instances.clear()
    FakeSMTP.tls_available = True
    monkeypatch.setattr(outputs.smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


def test_email_uses_starttls_then_logs_in_and_sends(smtp, report):
    outputs.send_email(report, ["ops@example.com", "dev@example.com"], "smtp.example.com", 587, "u", "p", "alerts@example.com")
    calls = smtp.instances[0].calls
    assert calls.index("starttls") < calls.index(("login", "u", "p"))
    msg = calls[-1][1]
    assert msg["Subject"].startswith("[explainfail] nightly_etl:")
    assert msg["To"] == "ops@example.com, dev@example.com" and msg["From"] == "alerts@example.com"
    assert "MOST LIKELY CAUSE" in msg.get_content()


def test_email_refuses_to_send_credentials_without_tls(smtp, report):
    smtp.tls_available = False
    with pytest.raises(OutputError, match="without TLS"):
        outputs.send_email(report, ["a@b.com"], "smtp.example.com", 25, "u", "p")
    assert not any(isinstance(c, tuple) and c[0] == "send" for c in smtp.instances[0].calls)


def test_email_without_login_works_on_plain_relay(smtp, report):
    smtp.tls_available = False
    outputs.send_email(report, ["a@b.com"], "relay.internal", 25)
    assert smtp.instances[0].calls[-1][0] == "send"


def test_email_needs_recipients(report):
    with pytest.raises(OutputError, match="recipients"):
        outputs.send_email(report, [], "smtp.example.com")


def test_email_subject_cannot_inject_headers(smtp):
    r = Report(job="evil\r\nBcc: x@y.z", status="failed", summary="s\nmore")
    outputs.send_email(r, ["a@b.com"], "relay.internal", 25)
    msg = smtp.instances[0].calls[-1][1]
    assert "\n" not in msg["Subject"] and msg["Bcc"] is None
