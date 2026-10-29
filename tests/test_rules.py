import textwrap
import time

import pytest

from explainfail.rules import (
    RuleError,
    build_rule,
    load_builtin_rules,
    load_rules,
    match_rule,
    match_rules,
)

BUILTIN = list(load_builtin_rules())


def test_builtin_rules_load_and_ids_are_unique():
    assert len(BUILTIN) >= 50
    ids = [r.id for r in BUILTIN]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", BUILTIN, ids=lambda r: r.id)
def test_every_builtin_rule_is_complete_and_its_examples_match(rule):
    assert rule.title and rule.explain and rule.fix
    if rule.patterns:
        assert rule.examples, f"{rule.id} needs at least one example"
        for example in rule.examples:
            assert match_rule(rule, example) is not None, f"{rule.id} does not match {example!r}"
    else:
        assert rule.exit_codes
        for code in rule.exit_codes:
            assert match_rule(rule, "", code) is not None


@pytest.mark.parametrize(
    "text",
    [
        ("x" * 2000 + "\n") * 200,  # very long single tokens
        ("word " * 400 + "\n") * 200,  # many short tokens
        ("a/b.c-d+e " * 200 + "\n") * 200,  # path-like tokens
    ],
    ids=["long-tokens", "many-words", "path-like"],
)
def test_no_builtin_rule_has_catastrophic_backtracking(text):
    start = time.perf_counter()
    for rule in BUILTIN:
        match_rule(rule, text)
    assert time.perf_counter() - start < 3.0, "a built-in rule is too slow on large logs"


def test_cmd_not_found_still_captures_paths_and_quoted_names():
    f = match_rules(BUILTIN, "bash: ./run.sh: command not found")[0]
    assert "./run.sh" in f.explanation
    f = match_rules(BUILTIN, "'sqlplus' is not recognized as an internal or external command")[0]
    assert "sqlplus" in f.explanation


def test_specific_rule_ranks_above_generic():
    log = "cp: cannot create file: Permission denied\nModuleNotFoundError: No module named 'x'\n"
    findings = match_rules(BUILTIN, log)
    assert findings[0].rule_id == "py-module-not-found"
    assert "permission-denied" in [f.rule_id for f in findings]


def test_exit_code_only_rule_fires():
    findings = match_rules(BUILTIN, "", exit_code=143)
    assert [f.rule_id for f in findings] == ["exit-143-terminated"]


def test_exit_code_137_matches_oom_without_any_log_text():
    assert match_rules(BUILTIN, "nothing useful", exit_code=137)[0].rule_id == "oom-killed"


def test_named_groups_are_filled_in():
    f = match_rules(BUILTIN, "ModuleNotFoundError: No module named 'requests'")[0]
    assert "requests" in f.explanation and "{module}" not in f.explanation


def test_missing_group_and_unknown_braces():
    rule = build_rule(
        {
            "id": "t1",
            "title": "T",
            "explain": "got {a} / {b} / {zzz}",
            "fix": "f",
            "match": "(?P<a>foo)|(?P<b>bar)",
        }
    )
    f = match_rules([rule], "foo")[0]
    assert f.explanation == "got foo / (see log) / {zzz}"


def test_crlf_rule_beats_generic_command_not_found():
    log = "script.sh: line 2: $'\\r': command not found\n"
    assert match_rules(BUILTIN, log)[0].rule_id == "shell-crlf"


def test_matched_line_and_first_match_wins():
    log = "line one\nConnection refused here\nConnection refused again\n"
    f = match_rules(BUILTIN, log)[0]
    assert f.matched_line == "Connection refused here"


def _write(tmp_path, body, name="mine.yaml"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def test_user_rule_overrides_builtin_id_and_ranks_first(tmp_path):
    path = _write(
        tmp_path,
        """\
        rules:
          - id: py-module-not-found
            title: Ask platform team to rebuild the image
            severity: low
            priority: 1
            match: 'No module named'
            explain: Our image is missing a package.
            fix: Open a ticket with the platform team.
        """,
    )
    rules = load_rules([path])
    assert sum(r.id == "py-module-not-found" for r in rules) == 1
    findings = match_rules(rules, "ModuleNotFoundError: No module named 'x'")
    assert findings[0].title == "Ask platform team to rebuild the image"


def test_custom_rule_outranks_builtin_even_with_low_priority(tmp_path):
    path = _write(
        tmp_path,
        """\
        - id: acme-down
          title: ACME is down
          priority: 1
          match: 'acme\\.example'
          explain: e
          fix: f
        """,
    )
    findings = match_rules(load_rules([path]), "Connection refused to acme.example")
    assert findings[0].rule_id == "acme-down"


def test_rules_directory_is_loaded(tmp_path):
    _write(tmp_path, "- {id: a1, title: A, match: aaa, explain: e, fix: f}\n", "a.yaml")
    _write(tmp_path, "- {id: b1, title: B, match: bbb, explain: e, fix: f}\n", "b.yml")
    ids = {r.id for r in load_rules([tmp_path])}
    assert {"a1", "b1"} <= ids


def test_env_var_rules(tmp_path, monkeypatch):
    p = _write(tmp_path, "- {id: env1, title: E, match: zzz, explain: e, fix: f}\n")
    monkeypatch.setenv("EXPLAINFAIL_RULES", str(p))
    assert "env1" in {r.id for r in load_rules()}


@pytest.mark.parametrize(
    "bad,message",
    [
        ({"title": "T", "explain": "e", "fix": "f", "match": "x"}, "'id' is required"),
        ({"id": "Bad ID", "title": "T", "explain": "e", "fix": "f", "match": "x"}, "'id' is required"),
        ({"id": "a", "explain": "e", "fix": "f", "match": "x"}, "'title'"),
        ({"id": "a", "title": "T", "fix": "f", "match": "x"}, "'explain'"),
        ({"id": "a", "title": "T", "explain": "e", "match": "x"}, "'fix'"),
        ({"id": "a", "title": "T", "explain": "e", "fix": "f"}, "needs 'match'"),
        ({"id": "a", "title": "T", "explain": "e", "fix": "f", "match": "("}, "invalid regex"),
        ({"id": "a", "title": "T", "explain": "e", "fix": "f", "match": "x", "severity": "meh"}, "severity"),
        ({"id": "a", "title": "T", "explain": "e", "fix": "f", "match": "x", "colour": "red"}, "unknown field"),
        ({"id": "a", "title": "T", "explain": "e", "fix": "f", "exit_codes": [999]}, "exit_codes"),
        ({"id": "a", "title": "T", "explain": "e", "fix": "f", "match": "x", "priority": "high"}, "priority"),
    ],
)
def test_invalid_rules_are_rejected_with_a_clear_message(bad, message):
    with pytest.raises(RuleError, match=message):
        build_rule(bad, "test.yaml")


def test_invalid_yaml_and_wrong_shape(tmp_path):
    with pytest.raises(RuleError, match="invalid YAML"):
        load_rules([_write(tmp_path, "rules: [unclosed\n")])
    with pytest.raises(RuleError, match="expected a list"):
        load_rules([_write(tmp_path, "rules: 5\n", "x.yaml")])
    with pytest.raises(RuleError, match="not found"):
        load_rules([tmp_path / "missing.yaml"])
