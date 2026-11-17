"""Security scanning through Bandit.

Bandit is executed in a separate process with a timeout. The submitted source is
written to a temporary file and analysed statically - it is never imported or run.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .models import SOURCE_SECURITY, Finding, snippet_from_source

DEFAULT_TIMEOUT = 30


class BanditError(RuntimeError):
    """Raised when Bandit cannot be run or its output cannot be understood."""


# --------------------------------------------------------------------------- #
# Static knowledge keyed by Bandit test id (the scanner supplies the detections;
# this table only adds a category and a remediation hint for each real result).
# --------------------------------------------------------------------------- #
_CATEGORY_BY_TEST: dict[str, str] = {}


def _register(category: str, *test_ids: str) -> None:
    for test_id in test_ids:
        _CATEGORY_BY_TEST[test_id] = category


_register("Hardcoded Credentials", "B105", "B106", "B107")
_register("Code Injection", "B102", "B307")
_register(
    "Command Injection",
    "B404", "B602", "B603", "B604", "B605", "B606", "B607",
)
_register(
    "Weak Cryptography",
    "B303", "B304", "B305", "B311", "B324", "B413", "B502", "B503", "B504", "B505",
)
_register("Unsafe File Operations", "B103", "B108", "B306")
_register(
    "Insecure Deserialization",
    "B301", "B302", "B401", "B402", "B403", "B506", "B614",
)
_register("SQL Injection", "B608")
_register("TLS/SSL Misconfiguration", "B501")
_register("Network Exposure", "B104")
_register("Debug Configuration", "B201", "B202")
_register("Error Handling", "B110", "B112")
_register("Assertion Misuse", "B101")
_register("Cross-Site Scripting", "B701", "B702", "B703")
_register("Network Resilience", "B113")
_register("Unsafe URL Handling", "B310")

_REMEDIATION_BY_TEST: dict[str, str] = {
    "B101": "Do not rely on assert for validation or access control - it is stripped when Python runs with -O. Raise an explicit exception instead.",
    "B102": "Avoid exec(). Use explicit logic, a dispatch table, or a sandboxed, purpose-built parser.",
    "B103": "Use restrictive permissions (for example 0o600 for files, 0o750 for directories). Never make files world-writable.",
    "B104": "Bind to 127.0.0.1 unless external access is required, and then restrict it with a firewall or reverse proxy.",
    "B105": "Remove the secret from source control, rotate it, and load it from environment variables or a secrets manager.",
    "B106": "Do not pass literal passwords as arguments. Read the credential from the environment or a secrets manager.",
    "B107": "Remove the default password from the function signature and require the caller to supply it from a secure source.",
    "B108": "Create temporary files with tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead of fixed paths in /tmp.",
    "B110": "Catch specific exceptions and log or handle them. Silent try/except/pass hides failures and attacks.",
    "B112": "Catch specific exceptions and log them instead of silently continuing the loop.",
    "B113": "Always pass a timeout to requests calls so a slow server cannot hang the application.",
    "B201": "Never run Flask with debug=True in production. Read the setting from configuration and default it to off.",
    "B301": "Do not unpickle untrusted data. Use a safe format such as JSON, or sign and verify payloads before loading.",
    "B302": "Do not unmarshal untrusted data. Use JSON or another data-only format.",
    "B303": "Replace MD5/SHA-1 with SHA-256 or stronger. Use a password hashing function (bcrypt, scrypt, argon2, PBKDF2) for passwords.",
    "B304": "Replace weak ciphers with AES-GCM or ChaCha20-Poly1305 from the cryptography package.",
    "B305": "Avoid ECB and other insecure cipher modes. Use an authenticated mode such as GCM.",
    "B306": "tempfile.mktemp() is race-prone. Use tempfile.mkstemp() or NamedTemporaryFile() instead.",
    "B307": "Never eval() untrusted input. Use ast.literal_eval() for literals, or parse the input explicitly.",
    "B310": "Validate URL schemes against an allow-list (https) before calling urlopen so file:// and custom schemes are rejected.",
    "B311": "random is not cryptographically secure. Use the secrets module for tokens, passwords and keys.",
    "B324": "Use SHA-256 or stronger, and a dedicated password hash (PBKDF2, scrypt, argon2) for credentials.",
    "B401": "Avoid telnet - it sends data in clear text. Use SSH.",
    "B402": "Avoid FTP - it sends data in clear text. Use SFTP or FTPS.",
    "B403": "Only import pickle if you never load untrusted data. Prefer JSON.",
    "B404": "Make sure subprocess is only called with fixed, trusted arguments and shell=False.",
    "B413": "pycrypto is unmaintained. Migrate to the cryptography package.",
    "B501": "Keep TLS certificate verification enabled. If you use a private CA, point verify= at the CA bundle.",
    "B502": "Disable SSLv2/SSLv3/TLS 1.0. Use ssl.create_default_context() with modern defaults.",
    "B503": "Use ssl.create_default_context() instead of hand-picked legacy protocol versions.",
    "B504": "Use ssl.create_default_context() instead of ssl.wrap_socket() with no explicit version.",
    "B505": "Use at least 2048-bit RSA (or 256-bit elliptic curve) keys.",
    "B506": "Use yaml.safe_load() so YAML documents cannot instantiate arbitrary Python objects.",
    "B602": "Avoid shell=True. Pass an argument list (subprocess.run([...])) and validate or allow-list any user-controlled value.",
    "B603": "Make sure the arguments passed to subprocess come from trusted sources and shell=False is kept.",
    "B604": "Avoid shell=True for any callable that spawns a command. Pass an argument list instead.",
    "B605": "Avoid os.system()/os.popen() with dynamic strings. Use subprocess.run([...]) with an argument list.",
    "B606": "Avoid starting processes without a shell only when arguments are untrusted. Validate arguments strictly.",
    "B607": "Use the absolute path of the executable rather than a partial path that depends on PATH.",
    "B608": "Use parameterised queries (cursor.execute(sql, params)) instead of building SQL with string formatting.",
    "B701": "Enable autoescape in Jinja2 (autoescape=True or select_autoescape()) to prevent XSS.",
    "B702": "Use a template engine with output escaping enabled, such as Jinja2 with autoescape.",
    "B703": "Do not mark user-controlled content as safe in Django. Let the template engine escape it.",
    "B614": "Do not load untrusted models/tensors with pickle-based loaders. Use safe formats such as safetensors.",
}


def bandit_available() -> bool:
    """True when the bandit package can be imported by this interpreter."""
    return importlib.util.find_spec("bandit") is not None


def bandit_version() -> str:
    try:
        return importlib.metadata.version("bandit")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _timeout_seconds(timeout: int | None) -> int:
    if timeout is not None:
        return timeout
    try:
        return int(os.environ.get("BANDIT_TIMEOUT", DEFAULT_TIMEOUT))
    except ValueError:
        return DEFAULT_TIMEOUT


def _run_bandit(code: str, timeout: int) -> dict[str, Any]:
    """Write ``code`` to a temp file, run Bandit on it and return the parsed JSON."""
    with tempfile.TemporaryDirectory(prefix="codesentinel_") as tmp_dir:
        target = Path(tmp_dir) / "target.py"
        target.write_text(code, encoding="utf-8")

        command = [
            sys.executable, "-m", "bandit",
            "-f", "json",
            "-q",
            "--exit-zero",
            str(target),
        ]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                cwd=tmp_dir,
                env=env,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BanditError(f"Bandit timed out after {timeout}s") from exc
        except OSError as exc:
            raise BanditError(f"Could not start Bandit: {exc}") from exc

    stdout = proc.stdout.strip()
    if not stdout:
        detail = proc.stderr.strip()[:300] or f"exit code {proc.returncode}"
        raise BanditError(f"Bandit produced no output ({detail})")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        detail = proc.stderr.strip()[:300]
        raise BanditError(f"Bandit returned invalid JSON. {detail}") from exc


def _humanise(test_name: str) -> str:
    return test_name.replace("_", " ").strip().capitalize()


def parse_results(raw: dict[str, Any], source_lines: list[str]) -> list[Finding]:
    """Convert Bandit's JSON report into Finding objects."""
    errors = raw.get("errors") or []
    results = raw.get("results") or []
    if errors and not results:
        reasons = "; ".join(str(e.get("reason", e)) for e in errors)[:300]
        raise BanditError(f"Bandit could not analyse the file: {reasons}")

    findings: list[Finding] = []
    for item in results:
        test_id = str(item.get("test_id", "B000"))
        severity = str(item.get("issue_severity", "LOW")).upper()
        confidence = str(item.get("issue_confidence", "LOW")).upper()
        if severity not in ("HIGH", "MEDIUM", "LOW"):
            severity = "LOW"
        if confidence not in ("HIGH", "MEDIUM", "LOW"):
            confidence = "LOW"

        line = int(item.get("line_number") or 1)
        line_range = item.get("line_range") or [line]
        end_line = max(int(n) for n in line_range) if line_range else line

        cwe_info = item.get("issue_cwe") or {}
        cwe = f"CWE-{cwe_info['id']}" if cwe_info.get("id") else ""

        remediation = _REMEDIATION_BY_TEST.get(
            test_id,
            "Review the Bandit documentation for this check and replace the flagged construct with a safer alternative.",
        )
        findings.append(
            Finding(
                source=SOURCE_SECURITY,
                rule_id=test_id,
                title=f"{test_id}: {_humanise(str(item.get('test_name', 'security issue')))}",
                severity=severity,
                confidence=confidence,
                line=line,
                end_line=end_line,
                category=_CATEGORY_BY_TEST.get(test_id, "Other Security"),
                description=str(item.get("issue_text", "")).strip(),
                remediation=remediation,
                code_snippet=snippet_from_source(source_lines, line, end_line),
                cwe=cwe,
                more_info=str(item.get("more_info", "")),
            )
        )
    return findings


def scan_source(code: str, timeout: int | None = None) -> list[Finding]:
    """Run Bandit on ``code`` and return its findings. Raises BanditError on failure."""
    if not bandit_available():
        raise BanditError("Bandit is not installed (pip install bandit)")
    raw = _run_bandit(code, _timeout_seconds(timeout))
    return parse_results(raw, code.splitlines())
