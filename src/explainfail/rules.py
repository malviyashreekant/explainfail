"""Rule engine: patterns and exit codes -> a plain-English diagnosis, defined in YAML.

Rules are data, not code. Anyone can add one by editing a YAML file; see CONTRIBUTING.md.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import yaml

from .models import Finding
from .parser import strip_ansi

SEVERITIES = ("low", "medium", "high", "critical")
_ALLOWED_FIELDS = {
    "id", "title", "category", "severity", "priority", "match", "exit_codes",
    "explain", "fix", "notify", "examples",
}  # fmt: skip
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_MAX_LINE = 1000  # characters of each log line that rules look at (keeps matching fast on huge lines)
_MAX_GROUP = 200


class RuleError(ValueError):
    """A rule file is invalid. The message says which file and which rule."""


@dataclass
class Rule:
    id: str
    title: str
    explain: str
    fix: str
    patterns: List[re.Pattern[str]] = field(default_factory=list)
    exit_codes: List[int] = field(default_factory=list)
    severity: str = "medium"
    category: str = "general"
    priority: int = 50
    notify: str = ""
    examples: List[str] = field(default_factory=list)
    source: str = "custom"  # "builtin", or the path of the file the rule came from


# --------------------------------------------------------------------------- building rules


def _text(data: Dict[str, Any], key: str, where: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleError(f"{where}: '{key}' is required and must be text")
    return value.strip()


def build_rule(data: Any, source: str = "custom") -> Rule:
    """Validate one rule mapping and turn it into a Rule. Raises RuleError with a clear message."""
    if not isinstance(data, dict):
        raise RuleError(f"{source}: each rule must be a mapping, got {type(data).__name__}")
    rid = data.get("id")
    if not isinstance(rid, str) or not _ID_RE.match(rid):
        raise RuleError(f"{source}: rule {rid!r}: 'id' is required (lowercase letters, digits, '-' or '_')")
    where = f"{source}: rule '{rid}'"
    unknown = sorted(set(data) - _ALLOWED_FIELDS)
    if unknown:
        allowed = ", ".join(sorted(_ALLOWED_FIELDS))
        raise RuleError(f"{where}: unknown field(s) {', '.join(unknown)} (allowed: {allowed})")
    title = _text(data, "title", where)
    explain = _text(data, "explain", where)
    fix_raw = data.get("fix")
    if isinstance(fix_raw, list):
        fix_raw = "\n".join(str(item) for item in fix_raw)
    if not isinstance(fix_raw, str) or not fix_raw.strip():
        raise RuleError(f"{where}: 'fix' is required and must be text")

    severity = str(data.get("severity", "medium")).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}, got {severity!r}")
    priority = data.get("priority", 50)
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise RuleError(f"{where}: priority must be a whole number, got {priority!r}")

    exit_codes = data.get("exit_codes", []) or []
    if not isinstance(exit_codes, list) or not all(
        isinstance(c, int) and not isinstance(c, bool) and 1 <= c <= 255 for c in exit_codes
    ):
        raise RuleError(f"{where}: exit_codes must be a list of exit codes between 1 and 255")

    raw_match = data.get("match")
    if raw_match is None:
        raw_match = []
    if isinstance(raw_match, str):
        raw_match = [raw_match]
    if not isinstance(raw_match, list) or not all(isinstance(p, str) and p for p in raw_match):
        raise RuleError(f"{where}: 'match' must be a regex or a list of regexes")
    if not raw_match and not exit_codes:
        raise RuleError(f"{where}: needs 'match' (a regex) or 'exit_codes'")
    patterns = []
    for raw in raw_match:
        try:
            patterns.append(re.compile(raw))
        except re.error as exc:
            raise RuleError(f"{where}: invalid regex {raw!r}: {exc}") from exc

    examples = data.get("examples", []) or []
    if not isinstance(examples, list) or not all(isinstance(e, str) for e in examples):
        raise RuleError(f"{where}: examples must be a list of sample log lines")

    return Rule(
        id=rid, title=title, explain=explain, fix=fix_raw.strip(), patterns=patterns,
        exit_codes=list(exit_codes), severity=severity, category=str(data.get("category", "general")),
        priority=priority, notify=str(data.get("notify", "") or ""), examples=list(examples), source=source,
    )  # fmt: skip


def _rules_from_yaml(text: str, source: str) -> List[Rule]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"{source}: invalid YAML: {exc}") from exc
    if data is None:
        return []
    if isinstance(data, dict) and "rules" in data:
        data = data["rules"]
    if not isinstance(data, list):
        raise RuleError(f"{source}: expected a list of rules (either a top-level list or a 'rules:' list)")
    rules = [build_rule(item, source) for item in data]
    seen = set()
    for r in rules:
        if r.id in seen:
            raise RuleError(f"{source}: duplicate rule id '{r.id}'")
        seen.add(r.id)
    return rules


def load_rules_file(path: Union[str, Path]) -> List[Rule]:
    p = Path(path)
    if not p.is_file():
        raise RuleError(f"{p}: rules file not found")
    return _rules_from_yaml(p.read_text(encoding="utf-8"), str(p))


@lru_cache(maxsize=1)
def _builtin_cached() -> Tuple[Rule, ...]:
    text = resources.files("explainfail").joinpath("rules/builtin.yaml").read_text(encoding="utf-8")
    return tuple(_rules_from_yaml(text, "builtin"))


def load_builtin_rules() -> List[Rule]:
    return list(_builtin_cached())


def _expand(path: Union[str, Path]) -> List[Path]:
    p = Path(path).expanduser()
    if p.is_dir():
        return sorted([*p.glob("*.yaml"), *p.glob("*.yml")])
    if p.is_file():
        return [p]
    raise RuleError(f"{p}: rules file or folder not found")


def load_rules(paths: Optional[Iterable[Union[str, Path]]] = None) -> List[Rule]:
    """Built-in rules plus your own.

    Your own come from the EXPLAINFAIL_RULES environment variable (files or folders, separated by
    the OS path separator) and from ``paths``. A rule with the same id as a built-in replaces it.
    """
    wanted: List[Union[str, Path]] = [p for p in os.environ.get("EXPLAINFAIL_RULES", "").split(os.pathsep) if p.strip()]
    wanted += list(paths or [])
    by_id: Dict[str, Rule] = {r.id: r for r in _builtin_cached()}
    for entry in wanted:
        for file in _expand(entry):
            for rule in load_rules_file(file):
                by_id[rule.id] = rule
    return list(by_id.values())


# --------------------------------------------------------------------------- matching


def _fill(template: str, groups: Dict[str, Optional[str]]) -> str:
    """Replace {name} with the regex group of that name. Unmatched group -> '(see log)'; unknown {x} kept."""

    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name not in groups:
            return m.group(0)
        value = groups[name]
        return value.strip()[:_MAX_GROUP] if value else "(see log)"

    return re.sub(r"\{(\w+)\}", sub, template)


def _match(rule: Rule, lines: Sequence[str], exit_code: Optional[int]) -> Optional[Tuple[Finding, int]]:
    groups: Dict[str, Optional[str]] = {}
    matched_line, line_no = "", -1
    for i, line in enumerate(lines):
        hit = None
        probe = line[:_MAX_LINE]
        for pattern in rule.patterns:
            hit = pattern.search(probe)
            if hit:
                break
        if hit:
            groups, matched_line, line_no = hit.groupdict(), line.strip()[:300], i
            break
    if line_no < 0:
        if exit_code is None or exit_code not in rule.exit_codes:
            return None
        matched_line, line_no = f"exit code {exit_code}", 10**9  # exit-code-only evidence sorts last
    finding = Finding(
        rule_id=rule.id,
        title=_fill(rule.title, groups),
        explanation=_fill(rule.explain, groups),
        fix=_fill(rule.fix, groups),
        severity=rule.severity,
        category=rule.category,
        notify=rule.notify,
        matched_line=matched_line,
        priority=rule.priority,
    )
    return finding, line_no


def match_rule(rule: Rule, text: str, exit_code: Optional[int] = None) -> Optional[Finding]:
    """Apply one rule to a log. Returns its Finding, or None if it does not apply."""
    hit = _match(rule, strip_ansi(text or "").splitlines(), exit_code)
    return hit[0] if hit else None


def match_rules(rules: Sequence[Rule], text: str, exit_code: Optional[int] = None) -> List[Finding]:
    """Every rule that applies, best first.

    Your own (non-built-in) rules always come first. After that: higher priority first, and for
    equal priority the one whose evidence appears earliest in the log (the first error is usually
    the root cause; later ones are side effects).
    """
    lines = strip_ansi(text or "").splitlines()
    scored = []
    for order, rule in enumerate(rules):
        hit = _match(rule, lines, exit_code)
        if hit:
            finding, line_no = hit
            scored.append(((rule.source == "builtin", -rule.priority, line_no, order), finding))
    scored.sort(key=lambda item: item[0])
    return [finding for _key, finding in scored]


__all__ = [
    "Rule", "RuleError", "build_rule", "load_builtin_rules", "load_rules", "load_rules_file",
    "match_rule", "match_rules",
]  # fmt: skip
