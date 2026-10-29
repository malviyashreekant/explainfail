"""Turn a Report into text, Markdown, JSON, a Slack/Teams message, a webhook call or an email."""

from __future__ import annotations

import json
import smtplib
import ssl
import textwrap
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Any, Dict, Optional, Sequence
from urllib.parse import urlparse

from .models import Report


class OutputError(Exception):
    """Raised when a report cannot be delivered. Messages never contain webhook URLs."""


# ----------------------------------------------------------------------------- rendering
def _wrap(text: str, indent: str, width: int = 96) -> str:
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


def _status_label(report: Report) -> str:
    return report.status.replace("_", " ").upper()


def render_text(report: Report) -> str:
    head = f"JOB: {report.job}   STATUS: {_status_label(report)}"
    if report.exit_code is not None:
        head += f"   EXIT CODE: {report.exit_code}"
    out = ["=" * 78, head, "=" * 78, "", f"SUMMARY: {report.summary}"]
    for i, f in enumerate(report.findings):
        label = "MOST LIKELY CAUSE" if i == 0 else f"ALSO POSSIBLE ({i + 1})"
        out += ["", f"{label}: {f.title}   [severity: {f.severity}]"]
        out += ["  What happened:", _wrap(f.explanation, "    ")]
        out += ["  How to fix:", _wrap(f.fix, "    ")]
        if f.notify:
            out.append(f"  Who to tell: {f.notify}")
        if f.matched_line:
            out.append(f"  Evidence: {f.matched_line[:200]}")
    if report.ai_explanation:
        out += ["", f"AI EXPLANATION ({report.ai_provider or 'ai'}):", report.ai_explanation]
    elif report.ai_error:
        out += ["", f"AI explanation unavailable: {report.ai_error}", "(The rule-based result above still applies.)"]
    if report.redactions:
        out += ["", f"({report.redactions} secret-looking value(s) were redacted.)"]
    return "\n".join(out)


def render_markdown(report: Report) -> str:
    title = f"### {'Job failed' if report.status == 'failed' else 'No errors found'}: `{report.job}`"
    if report.exit_code is not None:
        title += f" (exit code {report.exit_code})"
    out = [title, "", f"**Summary:** {report.summary}"]
    for i, f in enumerate(report.findings):
        label = "Most likely cause" if i == 0 else "Also possible"
        out += [
            "",
            f"**{label}:** {f.title} _(severity: {f.severity})_",
            "",
            f"- **What happened:** {f.explanation}",
            f"- **How to fix:** {f.fix}",
        ]
        if f.notify:
            out.append(f"- **Who to tell:** {f.notify}")
        if f.matched_line:
            out.append(f"- **Evidence:** `{f.matched_line[:200]}`")
    if report.ai_explanation:
        out += ["", f"**AI explanation** ({report.ai_provider or 'ai'}):", "", report.ai_explanation]
    elif report.ai_error:
        out += ["", f"_AI explanation unavailable: {report.ai_error}_"]
    return "\n".join(out)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render(report: Report, fmt: str = "text") -> str:
    if fmt == "json":
        return render_json(report)
    if fmt in ("markdown", "md"):
        return render_markdown(report)
    return render_text(report)


def _slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_slack(report: Report) -> str:
    esc = _slack_escape
    head = f":rotating_light: *Job failed: {esc(report.job)}*"
    if report.exit_code is not None:
        head += f" (exit code {report.exit_code})"
    lines = [head, f"*Summary:* {esc(report.summary)}"]
    if report.findings:
        f = report.findings[0]
        lines += [f"*What happened:* {esc(f.explanation)}", f"*How to fix:* {esc(f.fix)}"]
        meta = f"*Severity:* {f.severity}"
        if f.notify:
            meta += f"  |  *Who to tell:* {esc(f.notify)}"
        lines.append(meta)
        if f.matched_line:
            lines.append(f"*Evidence:* `{esc(f.matched_line[:200])}`")
    if report.ai_explanation:
        lines += ["*AI explanation:*", esc(report.ai_explanation[:2500])]
    return "\n".join(lines)


def teams_payload(report: Report) -> Dict[str, Any]:
    body = [
        {"type": "TextBlock", "text": f"Job failed: {report.job}", "weight": "Bolder", "size": "Medium", "wrap": True},
        {"type": "TextBlock", "text": f"Summary: {report.summary}", "wrap": True},
    ]
    if report.findings:
        f = report.findings[0]
        body += [
            {"type": "TextBlock", "text": f"What happened: {f.explanation}", "wrap": True},
            {"type": "TextBlock", "text": f"How to fix: {f.fix}", "wrap": True},
            {
                "type": "TextBlock",
                "text": f"Severity: {f.severity}" + (f" | Who to tell: {f.notify}" if f.notify else ""),
                "isSubtle": True,
                "wrap": True,
            },
        ]
    if report.ai_explanation:
        body.append({"type": "TextBlock", "text": "AI explanation: " + report.ai_explanation[:2500], "wrap": True})
    card = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    return {
        "type": "message",
        "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}
        ],
    }


# ------------------------------------------------------------------------------ delivery
def _check_url(url: str, require_https: bool) -> None:
    parsed = urlparse(url)
    allowed = ("https",) if require_https else ("http", "https")
    if parsed.scheme not in allowed or not parsed.netloc:
        raise OutputError("webhook URL must start with " + " or ".join(f"{s}://" for s in allowed))


def _post_json(url: str, payload: Dict[str, Any], timeout: float = 15.0, require_https: bool = False) -> None:
    _check_url(url, require_https)
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "explainfail"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked)
            resp.read(65536)
    except urllib.error.HTTPError as exc:
        raise OutputError(f"webhook returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise OutputError(f"could not reach webhook: {getattr(exc, 'reason', exc)}") from exc


def send_slack(url: str, report: Report) -> None:
    _post_json(url, {"text": render_slack(report)}, require_https=True)


def send_teams(url: str, report: Report) -> None:
    _post_json(url, teams_payload(report), require_https=True)


def send_webhook(url: str, report: Report) -> None:
    _post_json(url, report.to_dict())


def send_email(
    report: Report,
    to: Sequence[str],
    host: str,
    port: int = 587,
    user: Optional[str] = None,
    password: Optional[str] = None,
    sender: Optional[str] = None,
    timeout: float = 20.0,
) -> None:
    if not to:
        raise OutputError("no email recipients given")
    subject = " ".join(f"[explainfail] {report.job}: {report.summary}".split())[:200]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender or user or "explainfail@localhost"
    msg["To"] = ", ".join(to)
    msg.set_content(render_text(report))
    ctx = ssl.create_default_context()
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        with server:
            secure = port == 465
            if not secure:
                server.ehlo()
                if server.has_extn("starttls"):
                    server.starttls(context=ctx)
                    server.ehlo()
                    secure = True
            if user:
                if not secure:
                    raise OutputError("refusing to send SMTP credentials without TLS")
                server.login(user, password or "")
            server.send_message(msg)
    except OutputError:
        raise
    except (smtplib.SMTPException, OSError) as exc:
        raise OutputError(f"email failed: {exc}") from exc
