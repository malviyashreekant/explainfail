"""Command line interface: analyze, run, serve, rules."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections import deque
from typing import Deque, List, Optional, Sequence, Tuple

from . import __version__
from .core import analyze
from .llm import PROVIDERS, LLMConfig, LLMError
from .models import Report
from .outputs import (
    OutputError,
    render,
    send_email,
    send_slack,
    send_teams,
    send_webhook,
)
from .rules import RuleError, load_rules, load_rules_file, match_rule
from .server import Settings, make_server, requires_token

_READ_HEAD = 1_000_000
_READ_TAIL = 4_000_000
_RUN_MAX_LINES = 200_000


class CliError(Exception):
    pass


# ---------------------------------------------------------------------------- arguments
def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rules", action="append", default=[], metavar="PATH",
                   help="extra rules file or folder (repeatable; also EXPLAINFAIL_RULES)")
    p.add_argument("--ai", choices=PROVIDERS, metavar="PROVIDER",
                   help=f"optional AI explanation: {', '.join(PROVIDERS)} (also EXPLAINFAIL_PROVIDER)")
    p.add_argument("--model", help="AI model name (also EXPLAINFAIL_MODEL)")
    p.add_argument("--base-url", help="AI endpoint for openai-compatible/ollama (also EXPLAINFAIL_BASE_URL)")
    p.add_argument("--no-redact", dest="redact_secrets", action="store_false",
                   help="do NOT remove secrets from the output or from text sent to an AI")
    p.add_argument("--redact-ips", action="store_true", help="also hide IPv4 addresses")
    p.add_argument("--tail", type=int, default=40, metavar="N", help="lines of log end to keep (default 40)")
    p.add_argument("--max-findings", type=int, default=3, metavar="N", help="max causes to show (default 3)")


def _add_delivery(p: argparse.ArgumentParser) -> None:
    p.add_argument("--job", help="job name shown in the report")
    p.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    p.add_argument("--out", metavar="FILE", help="also write the report to this file")
    p.add_argument("--slack", metavar="URL", help="Slack webhook (prefer EXPLAINFAIL_SLACK_WEBHOOK)")
    p.add_argument("--teams", metavar="URL", help="Teams workflow webhook (prefer EXPLAINFAIL_TEAMS_WEBHOOK)")
    p.add_argument("--webhook", metavar="URL", help="POST the JSON report here (EXPLAINFAIL_WEBHOOK)")
    p.add_argument("--email-to", metavar="ADDRS", help="comma-separated recipients (EXPLAINFAIL_EMAIL_TO)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="explainfail",
        description="Explain failed jobs and scripts in plain English. Rules first, AI optional.",
    )
    parser.add_argument("--version", action="version", version=f"explainfail {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="explain a log file (or stdin)")
    a.add_argument("logfile", nargs="?", default="-", help="log file, or - for stdin (default)")
    a.add_argument("--exit-code", type=int, help="the job's exit code, if you know it")
    _add_delivery(a)
    _add_common(a)
    a.set_defaults(func=_cmd_analyze)

    r = sub.add_parser("run", help="run a command; if it fails, explain why (keeps its exit code)")
    r.add_argument("--always", action="store_true", help="also analyze when the command succeeds")
    _add_delivery(r)
    _add_common(r)
    r.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    r.set_defaults(func=_cmd_run)

    s = sub.add_parser("serve", help="run an HTTP service: POST /analyze")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--token", help="require this bearer token (prefer EXPLAINFAIL_TOKEN)")
    _add_common(s)
    s.set_defaults(func=_cmd_serve)

    ru = sub.add_parser("rules", help="list or validate rules")
    rsub = ru.add_subparsers(dest="rules_cmd", required=True)
    rl = rsub.add_parser("list", help="list all active rules")
    rl.add_argument("--rules", action="append", default=[], metavar="PATH")
    rl.set_defaults(func=_cmd_rules_list)
    rc = rsub.add_parser("check", help="validate rules files and check their examples")
    rc.add_argument("files", nargs="+")
    rc.set_defaults(func=_cmd_rules_check)
    return parser


# -------------------------------------------------------------------------------- input
def _read_input(path: str) -> Tuple[str, str]:
    if path == "-":
        return sys.stdin.buffer.read().decode("utf-8", errors="replace"), "stdin"
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size <= _READ_HEAD + _READ_TAIL:
                data = fh.read()
            else:
                head = fh.read(_READ_HEAD)
                fh.seek(size - _READ_TAIL)
                data = head + b"\n...[explainfail: middle of log truncated]...\n" + fh.read()
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc.strerror or exc}") from exc
    return data.decode("utf-8", errors="replace"), os.path.basename(path)


# ----------------------------------------------------------------------------- delivery
def _warn(message: str) -> None:
    print(f"explainfail: warning: {message}", file=sys.stderr)


def _deliver(report: Report, args: argparse.Namespace, stream) -> None:
    text = render(report, args.format)
    print(text, file=stream)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            _warn(f"could not write {args.out}: {exc.strerror or exc}")

    env = os.environ.get
    targets = [
        ("Slack", args.slack or env("EXPLAINFAIL_SLACK_WEBHOOK"), send_slack),
        ("Teams", args.teams or env("EXPLAINFAIL_TEAMS_WEBHOOK"), send_teams),
        ("webhook", args.webhook or env("EXPLAINFAIL_WEBHOOK"), send_webhook),
    ]
    for name, url, sender in targets:
        if url:
            try:
                sender(url, report)
            except OutputError as exc:
                _warn(f"{name} delivery failed: {exc}")

    recipients = [a.strip() for a in (args.email_to or env("EXPLAINFAIL_EMAIL_TO") or "").split(",") if a.strip()]
    if recipients:
        host = env("EXPLAINFAIL_SMTP_HOST")
        if not host:
            _warn("email requested but EXPLAINFAIL_SMTP_HOST is not set")
            return
        try:
            send_email(
                report,
                recipients,
                host=host,
                port=int(env("EXPLAINFAIL_SMTP_PORT", "587")),
                user=env("EXPLAINFAIL_SMTP_USER"),
                password=env("EXPLAINFAIL_SMTP_PASSWORD"),
                sender=env("EXPLAINFAIL_EMAIL_FROM"),
            )
        except (OutputError, ValueError) as exc:
            _warn(f"email delivery failed: {exc}")


def _analyze_kwargs(args: argparse.Namespace, ai: Optional[LLMConfig]) -> dict:
    return dict(
        rules=load_rules(args.rules),
        ai=ai,
        redact_secrets=args.redact_secrets,
        redact_ips=args.redact_ips,
        tail_lines=args.tail,
        max_findings=args.max_findings,
    )


# ---------------------------------------------------------------------------- commands
def _cmd_analyze(args: argparse.Namespace) -> int:
    ai = LLMConfig.from_env(args.ai, args.model, args.base_url)
    text, default_job = _read_input(args.logfile)
    report = analyze(
        text, job=args.job or default_job, exit_code=args.exit_code, **_analyze_kwargs(args, ai)
    )
    _deliver(report, args, sys.stdout)
    return 0


def _write_out(raw: bytes) -> None:
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        buf.write(raw)
        buf.flush()
    else:
        sys.stdout.write(raw.decode("utf-8", errors="replace"))
        sys.stdout.flush()


def _execute(cmd: List[str], lines: Deque[str]) -> int:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        msg = f"explainfail: {cmd[0]}: command not found"
        print(msg, file=sys.stderr)
        lines.append(msg + "\n")
        return 127
    except PermissionError:
        msg = f"explainfail: {cmd[0]}: Permission denied"
        print(msg, file=sys.stderr)
        lines.append(msg + "\n")
        return 126
    except OSError as exc:
        msg = f"explainfail: cannot start {cmd[0]}: {exc.strerror or exc}"
        print(msg, file=sys.stderr)
        lines.append(msg + "\n")
        return 126
    try:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            _write_out(raw)
            lines.append(raw.decode("utf-8", errors="replace"))
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()
        return 130
    rc = proc.returncode
    return 128 - rc if rc < 0 else rc  # killed by signal N -> 128+N, like a shell


def _cmd_run(args: argparse.Namespace) -> int:
    cmd = list(args.command or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise CliError("nothing to run. Usage: explainfail run [options] -- COMMAND [ARGS...]")
    lines: Deque[str] = deque(maxlen=_RUN_MAX_LINES)
    rc = _execute(cmd, lines)
    if rc != 0 or args.always:
        try:  # explainfail must never change the job's own exit code
            ai = LLMConfig.from_env(args.ai, args.model, args.base_url)
            report = analyze(
                "".join(lines),
                job=args.job or os.path.basename(cmd[0]),
                exit_code=rc,
                **_analyze_kwargs(args, ai),
            )
            print("", file=sys.stderr)
            _deliver(report, args, sys.stderr)
        except Exception as exc:  # noqa: BLE001
            _warn(f"could not analyze the failure: {exc}")
    return rc


def _cmd_serve(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("EXPLAINFAIL_TOKEN")
    if requires_token(args.host) and not token:
        raise CliError(
            "refusing to listen on a non-local address without a token. "
            "Set EXPLAINFAIL_TOKEN (or --token), or bind to 127.0.0.1."
        )
    settings = Settings(
        rules=load_rules(args.rules),
        ai=LLMConfig.from_env(args.ai, args.model, args.base_url),
        redact_secrets=args.redact_secrets,
        redact_ips=args.redact_ips,
        tail_lines=args.tail,
        max_findings=args.max_findings,
        token=token,
    )
    server = make_server(args.host, args.port, settings)
    host, port = server.server_address[:2]
    print(
        f"explainfail {__version__} listening on http://{host}:{port} (POST /analyze, GET /health)",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _cmd_rules_list(args: argparse.Namespace) -> int:
    rules = sorted(load_rules(args.rules), key=lambda r: (r.category, r.id))
    width = max((len(r.id) for r in rules), default=10)
    for r in rules:
        origin = "builtin" if r.source == "builtin" else "custom "
        print(f"{r.id:<{width}}  {r.category:<10} {r.severity:<8} {origin}  {r.title}")
    print(f"\n{len(rules)} rules")
    return 0


def _cmd_rules_check(args: argparse.Namespace) -> int:
    problems = 0
    for path in args.files:
        try:
            rules = load_rules_file(path)
        except RuleError as exc:
            print(f"FAIL {exc}")
            problems += 1
            continue
        file_problems = 0
        for rule in rules:
            for example in rule.examples:
                if match_rule(rule, example, None) is None:
                    print(f"FAIL {path}: rule '{rule.id}': example does not match: {example!r}")
                    file_problems += 1
        problems += file_problems
        if not file_problems:
            print(f"OK   {path}: {len(rules)} rule(s)")
    return 1 if problems else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CliError, RuleError, LLMError, OutputError) as exc:
        print(f"explainfail: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
