"""Pull the interesting facts out of a raw log: exit code, traceback, error lines, tail."""

from __future__ import annotations

import re
from typing import List, Optional, Sequence

from .models import ParsedLog

MAX_ERROR_LINES = 40  # first 20 + last 20 when there are more

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

_EXIT_CODE_PATTERNS = [
    re.compile(r"\bexit(?:ed)?\s*(?:with\s*)?(?:code|status|value)\s*[:=]?\s*(\d{1,4})\b", re.IGNORECASE),
    re.compile(r"\breturn(?:ed)?\s*(?:code|value)\s*[:=]?\s*(\d{1,4})\b", re.IGNORECASE),
    re.compile(r"\brc\s*[:=]\s*(\d{1,4})\b", re.IGNORECASE),
]

_TRACEBACK_START = "Traceback (most recent call last):"
# "ValueError: boom", "psycopg2.OperationalError: ...", "KeyboardInterrupt" -- but not "INFO done"
_EXCEPTION_LINE = re.compile(r"^(?:[A-Za-z_]\w*\.)*[A-Z]\w*[a-z]\w*(?::|\s*$)")

_ERROR_LINE = re.compile(
    r"\b(?:\w*errors?|\w*exceptions?|fatal|critical|severe|traceback|failed|failure|denied|refused|"
    r"not found|cannot|can't|unable to|timed out|timeout|killed|aborted)\b",
    re.IGNORECASE,
)
_NOT_AN_ERROR = re.compile(r"\b(?:0 errors?|no errors?|errors?\s*[:=]\s*0|without errors?)\b", re.IGNORECASE)


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def detect_exit_code(text: str) -> Optional[int]:
    """The last plausible (0-255) exit code mentioned in the log, or None."""
    best_pos, best_code = -1, None
    for pattern in _EXIT_CODE_PATTERNS:
        for m in pattern.finditer(text):
            code = int(m.group(1))
            if 0 <= code <= 255 and m.start() >= best_pos:
                best_pos, best_code = m.start(), code
    return best_code


def extract_traceback(lines: Sequence[str]) -> str:
    """The last Python traceback in the log (including its final exception line), or ''."""
    start = None
    for i in range(len(lines) - 1, -1, -1):
        if _TRACEBACK_START in lines[i]:
            start = i
            break
    if start is None:
        return ""
    prefix = lines[start][: lines[start].index(_TRACEBACK_START)]  # e.g. "[etl] " or a timestamp
    end = start + 1
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if prefix and not line.startswith(prefix):
            break
        rest = line[len(prefix):]
        if not rest.strip() or rest[0] in " \t":
            end = j + 1  # a stack frame or its source line
            continue
        if _EXCEPTION_LINE.match(rest):
            end = j + 1  # the exception itself, which ends the traceback
        break
    return "\n".join(lines[start:end])


def find_error_lines(lines: Sequence[str]) -> List[str]:
    """Lines that look like errors: stripped, de-duplicated, in order, capped to a manageable size."""
    seen = set()
    found: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped in seen:
            continue
        if _ERROR_LINE.search(stripped) and not _NOT_AN_ERROR.search(stripped):
            seen.add(stripped)
            found.append(stripped[:400])
    if len(found) > MAX_ERROR_LINES:
        half = MAX_ERROR_LINES // 2
        found = found[:half] + found[-half:]
    return found


def parse(text: str, exit_code: Optional[int] = None, tail_lines: int = 40) -> ParsedLog:
    text = strip_ansi(text or "")
    lines = text.splitlines()
    errors = find_error_lines(lines)
    trimmed = list(lines)
    while trimmed and not trimmed[-1].strip():
        trimmed.pop()
    tail = trimmed[-tail_lines:] if tail_lines > 0 else []
    return ParsedLog(
        total_lines=len(lines),
        exit_code=exit_code if exit_code is not None else detect_exit_code(text),
        traceback=extract_traceback(lines),
        error_lines=errors,
        first_error=errors[0] if errors else "",
        tail="\n".join(tail),
    )
