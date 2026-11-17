"""Orchestrates validation, Bandit scanning and AST analysis."""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, ast_analyzer
from .bandit_scanner import BanditError, bandit_available, bandit_version, scan_source
from .models import SEVERITIES, SEVERITY_RANK, SOURCE_QUALITY, SOURCE_SECURITY, Finding

ALLOWED_EXTENSIONS = {".py"}
DEFAULT_MAX_UPLOAD_KB = 512


class ValidationError(ValueError):
    """The submitted file or source is not acceptable for analysis."""


def get_max_upload_bytes() -> int:
    try:
        kb = int(os.environ.get("MAX_UPLOAD_KB", DEFAULT_MAX_UPLOAD_KB))
    except ValueError:
        kb = DEFAULT_MAX_UPLOAD_KB
    return max(1, kb) * 1024


def validate_source(code: str) -> str:
    """Validate pasted/decoded source text and normalise line endings."""
    if not code or not code.strip():
        raise ValidationError("No source code was provided.")
    if "\x00" in code:
        raise ValidationError("The input contains null bytes and does not look like Python source.")
    limit = get_max_upload_bytes()
    if len(code.encode("utf-8")) > limit:
        raise ValidationError(f"Source is too large (limit: {limit // 1024} KB).")
    return code.replace("\r\n", "\n").replace("\r", "\n")


def validate_upload(filename: str, data: bytes) -> str:
    """Validate an uploaded file (extension, size, encoding) and return its text."""
    name = Path(filename or "").name
    if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValidationError("Only .py files are supported.")
    if not data:
        raise ValidationError("The uploaded file is empty.")
    limit = get_max_upload_bytes()
    if len(data) > limit:
        raise ValidationError(f"The file is too large ({len(data) // 1024} KB; limit: {limit // 1024} KB).")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("The file must be UTF-8 encoded text.") from exc
    return validate_source(text)


def compute_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate statistics computed from the actual findings."""
    by_severity = Counter(f["severity"] for f in findings)
    by_source = Counter(f["source"] for f in findings)
    by_category = Counter(f["category"] for f in findings)
    return {
        "total": len(findings),
        "security": by_source.get(SOURCE_SECURITY, 0),
        "quality": by_source.get(SOURCE_QUALITY, 0),
        "by_severity": {sev: by_severity.get(sev, 0) for sev in SEVERITIES},
        "by_category": dict(sorted(by_category.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


def _sort_key(finding: Finding) -> tuple[int, int, int]:
    source_rank = 0 if finding.source == SOURCE_SECURITY else 1
    return (SEVERITY_RANK.get(finding.severity, 9), source_rank, finding.line)


def analyze_code(
    code: str,
    filename: str = "pasted_code.py",
    run_bandit: bool = True,
    bandit_timeout: int | None = None,
) -> dict[str, Any]:
    """Analyse Python source and return a JSON-serialisable result dictionary.

    The code is only parsed and statically scanned - it is never executed.
    """
    code = validate_source(code)
    filename = Path(filename or "").name or "pasted_code.py"
    lines = code.splitlines()
    warnings: list[str] = []

    try:
        quality = ast_analyzer.analyze_source(code, lines)
    except SyntaxError as exc:
        raise ValidationError(f"Python syntax error on line {exc.lineno}: {exc.msg}") from exc
    except (RecursionError, MemoryError, ValueError) as exc:
        raise ValidationError(f"The source could not be parsed safely: {exc}") from exc

    security: list[Finding] = []
    bandit_info: dict[str, Any] = {"ran": False, "version": None}
    if run_bandit:
        if not bandit_available():
            warnings.append("Bandit is not installed - security analysis was skipped. Run: pip install bandit")
        else:
            try:
                security = scan_source(code, bandit_timeout)
                bandit_info = {"ran": True, "version": bandit_version()}
            except BanditError as exc:
                warnings.append(f"Bandit scan failed - security results are unavailable: {exc}")

    ordered = sorted([*security, *quality], key=_sort_key)
    findings: list[dict[str, Any]] = []
    for index, finding in enumerate(ordered, start=1):
        finding.finding_id = f"F{index:03d}"
        findings.append(finding.to_dict())

    return {
        "tool": "CodeSentinel AI",
        "version": __version__,
        "filename": filename,
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "lines": len(lines),
        "bytes": len(code.encode("utf-8")),
        "scanners": {"bandit": bandit_info, "ast": {"ran": True}},
        "summary": compute_summary(findings),
        "findings": findings,
        "warnings": warnings,
        "ai": {"enabled": False},
    }
