import io
import json
import sys
from pathlib import Path

import pytest

from explainfail.cli import main

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "examples" / "sample_logs"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (
        "EXPLAINFAIL_PROVIDER", "EXPLAINFAIL_MODEL", "EXPLAINFAIL_API_KEY", "ANTHROPIC_API_KEY",
        "EXPLAINFAIL_SLACK_WEBHOOK", "EXPLAINFAIL_TEAMS_WEBHOOK", "EXPLAINFAIL_WEBHOOK",
        "EXPLAINFAIL_EMAIL_TO", "EXPLAINFAIL_TOKEN", "EXPLAINFAIL_RULES",
    ):  # fmt: skip
        monkeypatch.delenv(name, raising=False)


def py(code):
    return [sys.executable, "-c", code]


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("explainfail ")


def test_analyze_a_file(capsys):
    assert main(["analyze", str(SAMPLES / "python_missing_module.log")]) == 0
    out = capsys.readouterr().out
    assert "JOB: python_missing_module.log" in out
    assert "Python package is not installed" in out
    assert "Sup3rS3cret" not in out


def test_analyze_reads_stdin_by_default(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"Killed\n")))
    assert main(["analyze", "--job", "from_pipe"]) == 0
    out = capsys.readouterr().out
    assert "JOB: from_pipe" in out and "out of memory" in out


def test_analyze_json_and_out_file(tmp_path, capsys):
    target = tmp_path / "report.json"
    code = main(["analyze", "--format", "json", "--out", str(target), str(SAMPLES / "oom_killed.log")])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["rule_id"] == "oom-killed"
    assert json.loads(target.read_text(encoding="utf-8")) == data


def test_analyze_with_explicit_exit_code(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"job log with no error text\n")))
    assert main(["analyze", "--exit-code", "143", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["exit_code"] == 143
    assert data["findings"][0]["rule_id"] == "exit-143-terminated"


def test_analyze_missing_file(capsys):
    assert main(["analyze", "/no/such/file.log"]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_analyze_custom_rules(tmp_path, capsys):
    rules = tmp_path / "r.yaml"
    rules.write_text(
        "- {id: mine, title: My own rule, match: 'Killed', explain: e, fix: f}\n", encoding="utf-8"
    )
    main(["analyze", "--rules", str(rules), str(SAMPLES / "oom_killed.log")])
    assert "My own rule" in capsys.readouterr().out


def test_analyze_bad_ai_setup_is_a_clean_error(capsys):
    assert main(["analyze", "--ai", "anthropic", str(SAMPLES / "oom_killed.log")]) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_analyze_can_deliver_to_a_webhook(monkeypatch, capsys):
    sent = {}
    monkeypatch.setattr("explainfail.cli.send_slack", lambda url, rep: sent.update(url=url, job=rep.job))
    main(["analyze", "--slack", "https://hooks.slack.com/x", "--job", "j", str(SAMPLES / "oom_killed.log")])
    assert sent == {"url": "https://hooks.slack.com/x", "job": "j"}


def test_delivery_failure_is_only_a_warning(monkeypatch, capsys):
    from explainfail.outputs import OutputError

    def fail(url, rep):
        raise OutputError("webhook returned HTTP 500")

    monkeypatch.setattr("explainfail.cli.send_teams", fail)
    code = main(["analyze", "--teams", "https://x.example/h", str(SAMPLES / "oom_killed.log")])
    captured = capsys.readouterr()
    assert code == 0 and "warning: Teams delivery failed" in captured.err
    assert "Process was killed" in captured.out


# --------------------------------------------------------------------------- run
def test_run_passes_through_output_and_exit_code(capsys):
    code = main(["run", "--job", "t", "--"] + py("import sys; print('hello'); sys.stderr.write('Killed\\n'); sys.exit(137)"))
    captured = capsys.readouterr()
    assert code == 137
    assert "hello" in captured.out
    assert "Process was killed" in captured.err  # explanation goes to stderr, not stdout
    assert "Process was killed" not in captured.out


def test_run_success_is_silent_and_returns_zero(capsys):
    assert main(["run", "--"] + py("print('fine')")) == 0
    captured = capsys.readouterr()
    assert "fine" in captured.out and captured.err == ""


def test_run_always_analyzes_even_on_success(capsys):
    assert main(["run", "--always", "--"] + py("print('fine')")) == 0
    assert "NO ERRORS FOUND" in capsys.readouterr().err


def test_run_explains_a_python_crash(capsys):
    assert main(["run", "--"] + py("raise ValueError('boom')")) == 1
    err = capsys.readouterr().err
    assert "Unhandled Python error (ValueError)" in err


def test_run_command_not_found(capsys):
    assert main(["run", "--", "definitely-not-a-real-command-xyz"]) == 127
    assert "command not found" in capsys.readouterr().err


def test_run_without_a_command(capsys):
    assert main(["run"]) == 2
    assert "nothing to run" in capsys.readouterr().err


def test_run_never_changes_the_job_exit_code_when_ai_is_misconfigured(capsys):
    code = main(["run", "--ai", "anthropic", "--"] + py("import sys; sys.exit(3)"))
    assert code == 3
    assert "warning: could not analyze the failure" in capsys.readouterr().err


def test_run_exit_code_for_signal_kill(capsys):
    code = main(["run", "--"] + py("import os, signal; os.kill(os.getpid(), signal.SIGKILL)"))
    assert code == 137


def test_run_handles_non_utf8_output(capsys, monkeypatch):
    passed_through = []
    monkeypatch.setattr("explainfail.cli._write_out", passed_through.append)
    code = main(["run", "--"] + py("import sys; sys.stdout.buffer.write(b'caf\\xe9\\n'); sys.exit(1)"))
    assert code == 1  # must not crash on bytes that are not valid UTF-8
    assert passed_through == [b"caf\xe9\n"]  # and the job's output is passed through untouched


# ------------------------------------------------------------------- rules & serve
def test_rules_list(capsys):
    assert main(["rules", "list"]) == 0
    out = capsys.readouterr().out
    assert "py-module-not-found" in out and "rules" in out.splitlines()[-1]


def test_rules_check_ok_and_failing(tmp_path, capsys):
    good = tmp_path / "good.yaml"
    good.write_text("- {id: g1, title: G, match: foo, explain: e, fix: f, examples: ['a foo b']}\n", encoding="utf-8")
    assert main(["rules", "check", str(good)]) == 0
    assert "OK" in capsys.readouterr().out

    bad_example = tmp_path / "bad.yaml"
    bad_example.write_text("- {id: b1, title: B, match: foo, explain: e, fix: f, examples: ['nothing here']}\n", encoding="utf-8")
    assert main(["rules", "check", str(bad_example)]) == 1
    assert "example does not match" in capsys.readouterr().out

    broken = tmp_path / "broken.yaml"
    broken.write_text("- {id: x}\n", encoding="utf-8")
    assert main(["rules", "check", str(broken)]) == 1


def test_shipped_example_rules_are_valid(capsys):
    assert main(["rules", "check", str(ROOT / "examples" / "custom_rules.yaml")]) == 0


def test_serve_refuses_public_bind_without_token(capsys):
    assert main(["serve", "--host", "0.0.0.0"]) == 2
    assert "token" in capsys.readouterr().err
