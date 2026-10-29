import json
from pathlib import Path

import pytest

from explainfail import analyze
from explainfail.llm import LLMConfig, LLMError

SAMPLES = Path(__file__).resolve().parent.parent / "examples" / "sample_logs"


def _sample(name):
    return (SAMPLES / f"{name}.log").read_text(encoding="utf-8")


def test_missing_module_sample():
    r = analyze(_sample("python_missing_module"), job="nightly_etl")
    assert r.status == "failed"
    assert r.exit_code == 1
    assert r.findings[0].rule_id == "py-module-not-found"
    assert r.summary == "Python package is not installed"


def test_oom_sample_without_any_exit_code():
    r = analyze(_sample("oom_killed"))
    assert r.findings[0].rule_id == "oom-killed"


def test_db_login_sample():
    r = analyze(_sample("db_login_failed"))
    assert r.findings[0].rule_id == "db-auth"
    assert r.findings[0].notify == "DBA / job owner"


def test_secrets_never_appear_anywhere_in_the_report():
    r = analyze(_sample("python_missing_module"))
    blob = json.dumps(r.to_dict())
    assert "hunter2" not in blob and "Sup3rS3cret" not in blob
    assert r.redactions >= 2


def test_redaction_can_be_turned_off():
    r = analyze(_sample("python_missing_module"), redact_secrets=False)
    assert "Sup3rS3cret" in json.dumps(r.to_dict())
    assert r.redactions == 0


def test_unknown_python_exception_gets_a_helpful_fallback():
    r = analyze(_sample("unknown_python_error"))
    f = r.findings[0]
    assert f.rule_id == "fallback.python-exception"
    assert "ArithmeticError" in f.title
    assert f.matched_line.startswith("ArithmeticError")


def test_unknown_failure_with_exit_code():
    r = analyze("something odd happened\n", exit_code=2)
    assert r.status == "failed"
    assert r.findings[0].rule_id == "fallback.unknown"
    assert "exit code 2" in r.summary


def test_clean_run_reports_no_errors():
    r = analyze("all good\nfinished\n", exit_code=0)
    assert r.status == "no_errors_found"
    assert r.findings == []
    assert r.summary == "No errors found in the log"


def test_empty_log_does_not_crash():
    assert analyze("").status == "no_errors_found"
    assert analyze("", exit_code=1).status == "failed"


def test_max_findings_limit():
    log = "Connection refused\nPermission denied\nNo such file or directory\nTimeoutError\n"
    assert len(analyze(log, max_findings=2).findings) == 2


def test_huge_log_is_capped_and_still_finds_the_end():
    filler = ("x" * 100 + "\n") * 52_000  # about 5.2 MB
    r = analyze(filler + "ModuleNotFoundError: No module named 'foo'\n")
    assert r.findings[0].rule_id == "py-module-not-found"
    assert r.parsed.total_lines < 52_000


def _ai():
    return LLMConfig(provider="anthropic", model="test-model", api_key="k")


def test_ai_explanation_is_added_and_prompt_is_redacted(monkeypatch):
    seen = {}

    def fake_complete(config, system, user):
        seen["system"], seen["user"] = system, user
        return "Plain English answer"

    monkeypatch.setattr("explainfail.llm.complete", fake_complete)
    r = analyze(_sample("python_missing_module"), ai=_ai())
    assert r.ai_explanation == "Plain English answer"
    assert r.ai_provider == "anthropic/test-model"
    assert "hunter2" not in seen["user"] and "Sup3rS3cret" not in seen["user"]
    assert seen["user"].startswith("<log_data>") and "untrusted" in seen["system"]


def test_ai_failure_degrades_gracefully(monkeypatch):
    def boom(config, system, user):
        raise LLMError("provider unreachable")

    monkeypatch.setattr("explainfail.llm.complete", boom)
    r = analyze(_sample("oom_killed"), ai=_ai())
    assert r.ai_explanation is None
    assert r.ai_error == "provider unreachable"
    assert r.findings[0].rule_id == "oom-killed"  # the rule-based answer is intact


def test_ai_is_not_called_for_clean_runs(monkeypatch):
    monkeypatch.setattr("explainfail.llm.complete", lambda *a: pytest.fail("should not be called"))
    assert analyze("all good", exit_code=0, ai=_ai()).ai_explanation is None
