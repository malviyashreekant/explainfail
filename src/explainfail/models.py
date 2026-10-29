from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """One diagnosed cause, produced by a rule (or by the built-in fallback)."""

    rule_id: str
    title: str
    explanation: str
    fix: str
    severity: str = "medium"
    category: str = "general"
    notify: str = ""
    matched_line: str = ""
    priority: int = 50


@dataclass
class ParsedLog:
    """Structured facts pulled out of a raw log."""

    total_lines: int = 0
    exit_code: Optional[int] = None
    traceback: str = ""
    error_lines: List[str] = field(default_factory=list)
    first_error: str = ""
    tail: str = ""


@dataclass
class Report:
    """The result of analysing one failed run."""

    job: str
    status: str  # "failed" or "no_errors_found"
    summary: str
    exit_code: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)
    parsed: ParsedLog = field(default_factory=ParsedLog)
    ai_explanation: Optional[str] = None
    ai_provider: Optional[str] = None
    ai_error: Optional[str] = None
    redactions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
