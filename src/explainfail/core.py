"""The analysis pipeline: parse -> match rules -> redact -> (optionally) ask an AI."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence, Union

from . import llm
from .models import Finding, ParsedLog, Report
from .parser import parse
from .redact import redact
from .rules import Rule, load_rules, match_rules

_HEAD_CHARS = 1_000_000
_TAIL_CHARS = 4_000_000
_TRUNC_NOTE = "\n...[explainfail: middle of log truncated]...\n"


def _cap(text: str) -> str:
    if len(text) <= _HEAD_CHARS + _TAIL_CHARS:
        return text
    return text[:_HEAD_CHARS] + _TRUNC_NOTE + text[-_TAIL_CHARS:]


def _fallback_finding(parsed: ParsedLog, exit_code: Optional[int]) -> Finding:
    if parsed.traceback:
        exc_line = parsed.traceback.strip().splitlines()[-1].strip()
        exc_type = exc_line.split(":", 1)[0].split(".")[-1] or "exception"
        return Finding(
            rule_id="fallback.python-exception",
            title=f"Unhandled Python error ({exc_type})",
            explanation=(
                "The script crashed with an error that explainfail has no specific rule for. "
                "The last line of the traceback is the actual error; the lines above it show "
                "where in the code it happened (the most recent call is last)."
            ),
            fix=(
                "Read the last line of the traceback, then open the last file and line listed "
                "above it: that is where it failed. Search for the exact error message, check "
                "what was different about this run's input, and consider enabling AI mode for "
                "a plain-English explanation."
            ),
            severity="medium",
            category="python",
            matched_line=exc_line,
            priority=0,
        )
    if exit_code not in (None, 0):
        title = f"Job failed with exit code {exit_code} (no known pattern matched)"
    else:
        title = "Possible problem found in the log (no known pattern matched)"
    first = parsed.first_error
    if first:
        what = "explainfail has no specific rule for this failure. The first error-looking line is shown as evidence."
    else:
        what = (
            "explainfail has no specific rule for this failure and the log has no obvious error "
            "message. The job may have been stopped from outside or may have failed silently."
        )
    return Finding(
        rule_id="fallback.unknown",
        title=title,
        explanation=what,
        fix=(
            "Start at the first error in the log, not the last one, because later errors are "
            "usually side effects of the first. Then check what changed since the last "
            "successful run (code, input data, credentials, servers, upstream jobs). Enable AI "
            "mode for a plain-English explanation, or add a rule so this error is recognised "
            "next time."
        ),
        severity="medium",
        category="general",
        matched_line=first,
        priority=0,
    )


def _scrub(report: Report, redact_ips: bool) -> int:
    total = 0

    def r(text: str) -> str:
        nonlocal total
        out, n = redact(text, redact_ips)
        total += n
        return out

    report.job = r(report.job)
    for f in report.findings:
        f.title = r(f.title)
        f.explanation = r(f.explanation)
        f.fix = r(f.fix)
        f.matched_line = r(f.matched_line)
    p = report.parsed
    p.traceback = r(p.traceback)
    p.first_error = r(p.first_error)
    p.tail = r(p.tail)
    p.error_lines = [r(line) for line in p.error_lines]
    return total


def analyze(
    log_text: str,
    *,
    job: str = "unknown",
    exit_code: Optional[int] = None,
    rules: Optional[Sequence[Rule]] = None,
    rule_paths: Sequence[Union[str, Path]] = (),
    ai: Optional[llm.LLMConfig] = None,
    redact_secrets: bool = True,
    redact_ips: bool = False,
    tail_lines: int = 40,
    max_findings: int = 3,
) -> Report:
    """Explain a failed run.

    Works with no AI at all. If ``ai`` is given, the (redacted) evidence is also sent to that
    model for a plain-English explanation; if the AI call fails, the rule-based result is
    still returned and the problem is recorded in ``report.ai_error``.
    """
    text = _cap(log_text or "")
    parsed = parse(text, exit_code=exit_code, tail_lines=tail_lines)
    active_rules = list(rules) if rules is not None else load_rules(rule_paths)
    findings = match_rules(active_rules, text, parsed.exit_code)[: max(1, max_findings)]

    code = parsed.exit_code
    failed = (
        (code not in (None, 0))
        or bool(findings)
        or bool(parsed.traceback)
        or (code is None and bool(parsed.first_error))
    )
    if failed and not findings:
        findings = [_fallback_finding(parsed, code)]
    if not failed:
        findings = []

    report = Report(
        job=job,
        status="failed" if failed else "no_errors_found",
        summary="",
        exit_code=code,
        findings=findings,
        parsed=parsed,
    )
    if redact_secrets:
        report.redactions = _scrub(report, redact_ips)
    report.summary = findings[0].title if findings else "No errors found in the log"

    if ai is not None and report.status == "failed":
        try:
            report.ai_explanation = llm.explain_with_ai(report, ai)
            report.ai_provider = f"{ai.provider}/{ai.model}"
        except Exception as exc:  # never let the AI layer break the rule-based result
            report.ai_error = str(exc) or type(exc).__name__
    return report
