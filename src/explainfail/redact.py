"""Secret redaction.

Applied to every report by default, so passwords, tokens and keys are removed before anything is
printed, posted to a chat webhook, or sent to an AI model. Error text itself is left alone: the
patterns only fire on things that look like credentials, not on words such as "password" or
"credentials" appearing inside an error message.
"""

from __future__ import annotations

import re
from typing import Callable, List, Tuple

PLACEHOLDER = "***"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.DOTALL,
)
_URL_CREDENTIALS = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
_BEARER = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE)
_PROVIDER_TOKENS = re.compile(
    r"\b(?:"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}"  # AWS access key id
    r"|eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}"  # JSON web token
    r"|gh[pousr]_[A-Za-z0-9]{30,}"  # GitHub
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"  # Slack
    r"|sk-[A-Za-z0-9_-]{20,}"  # OpenAI / Anthropic style
    r"|AIza[0-9A-Za-z_-]{30,}"  # Google API key
    r")\b"
)
# name = value, where the name is (or ends/starts with a - _ . part that is) a secret-ish word.
# The word must stand alone: "NoCredentialsError: ..." and "ExpiredToken when ..." do not match.
_KEY_VALUE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"((?:[A-Za-z0-9]+[_.-])*"
    r"(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"authorization|credentials?)"
    r"(?:[_.-][A-Za-z0-9]+)*)"
    r"(?![A-Za-z0-9])"
    r"([\"']?\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")


def _sub(pattern: re.Pattern[str], repl: Callable[[re.Match[str]], str], text: str) -> Tuple[str, int]:
    count = 0

    def wrapper(m: re.Match[str]) -> str:
        nonlocal count
        new = repl(m)
        if new != m.group(0):
            count += 1
        return new

    return pattern.sub(wrapper, text), count


def redact(text: str, redact_ips: bool = False) -> Tuple[str, int]:
    """Return ``(clean_text, number_of_values_hidden)``."""
    if not text:
        return text, 0
    steps: List[Tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = [
        (_PRIVATE_KEY, lambda m: "<private-key>"),
        (_URL_CREDENTIALS, lambda m: f"{m.group(1)}{m.group(2)}:{PLACEHOLDER}@"),
        (_BEARER, lambda m: f"{m.group(1)} {PLACEHOLDER}"),
        (_PROVIDER_TOKENS, lambda m: PLACEHOLDER),
        (
            _KEY_VALUE,
            lambda m: m.group(0) if m.group(3) == PLACEHOLDER else f"{m.group(1)}{m.group(2)}{PLACEHOLDER}",
        ),
        (_EMAIL, lambda m: "<email>"),
    ]
    if redact_ips:
        steps.append((_IPV4, lambda m: "<ip>"))
    total = 0
    for pattern, repl in steps:
        text, n = _sub(pattern, repl, text)
        total += n
    return text, total
