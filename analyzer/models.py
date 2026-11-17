"""Shared data model for findings produced by the scanners."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SOURCE_SECURITY = "security"
SOURCE_QUALITY = "quality"

SEVERITIES = ("HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass
class Finding:
    """A single security vulnerability or code quality warning."""

    source: str  # "security" (Bandit) or "quality" (AST)
    rule_id: str
    title: str
    severity: str
    confidence: str
    line: int
    category: str
    description: str
    remediation: str
    code_snippet: str = ""
    cwe: str = ""
    more_info: str = ""
    end_line: int | None = None
    finding_id: str = ""
    ai_explanation: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def snippet_from_source(
    lines: list[str], start: int, end: int | None = None, max_lines: int = 8
) -> str:
    """Return the source text for ``start..end`` (1-based, inclusive), capped in length."""
    if not lines or start < 1 or start > len(lines):
        return ""
    last = end if end and end >= start else start
    last = min(last, start + max_lines - 1, len(lines))
    return "\n".join(lines[start - 1 : last])
