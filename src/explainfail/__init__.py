"""explainfail: plain-English explanations for failed jobs, scripts and pipelines."""

__version__ = "0.1.0"

from .core import analyze  # noqa: E402
from .models import Finding, ParsedLog, Report  # noqa: E402

__all__ = ["analyze", "Finding", "ParsedLog", "Report", "__version__"]
