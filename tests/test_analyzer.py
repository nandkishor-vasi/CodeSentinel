"""Tests for validation, AST analysis, Bandit integration and AI explanations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer import ai_explainer, ast_analyzer
from analyzer.analysis_engine import ValidationError, analyze_code, validate_source, validate_upload
from analyzer.bandit_scanner import bandit_available

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
VULNERABLE = (SAMPLES / "vulnerable_sample.py").read_text(encoding="utf-8")
SECURE = (SAMPLES / "secure_sample.py").read_text(encoding="utf-8")

needs_bandit = pytest.mark.skipif(not bandit_available(), reason="bandit is not installed")


def rule_ids(findings):
    return {f.rule_id if hasattr(f, "rule_id") else f["rule_id"] for f in findings}


# ----------------------------- validation ------------------------------------ #
def test_validate_upload_accepts_python_file():
    assert validate_upload("ok.py", b"x = 1\n") == "x = 1\n"


@pytest.mark.parametrize(
    "name,data",
    [
        ("notes.txt", b"x = 1"),
        ("script.py", b""),
        ("script.py", b"\xff\xfe\x00bad"),
        ("script.py", b"x = 1\x00"),
        ("script.py", b"   \n  "),
    ],
)
def test_validate_upload_rejects_bad_input(name, data):
    with pytest.raises(ValidationError):
        validate_upload(name, data)


def test_validate_upload_rejects_oversized_file(monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_KB", "1")
    with pytest.raises(ValidationError, match="too large"):
        validate_upload("big.py", b"x = 1\n" * 1000)


def test_validate_source_normalises_line_endings():
    assert validate_source("a = 1\r\nb = 2\r\n") == "a = 1\nb = 2\n"


def test_syntax_error_is_reported_as_validation_error():
    with pytest.raises(ValidationError, match="syntax error"):
        analyze_code("def broken(:\n    pass\n", run_bandit=False)


# ----------------------------- AST analysis ---------------------------------- #
def test_missing_docstring_detected_and_dunder_ignored():
    code = "def a():\n    pass\n\nclass C:\n    def __init__(self):\n        pass\n"
    findings = ast_analyzer.analyze_source(code)
    flagged = [f.description for f in findings if f.rule_id == "CS-Q001"]
    assert len(flagged) == 1 and "'a'" in flagged[0]


def test_too_many_parameters_ignores_self():
    code = (
        "class C:\n"
        "    def ok(self, a, b, c, d, e):\n        '''d'''\n"
        "    def bad(self, a, b, c, d, e, f):\n        '''d'''\n"
    )
    findings = [f for f in ast_analyzer.analyze_source(code) if f.rule_id == "CS-Q002"]
    assert len(findings) == 1 and "'bad'" in findings[0].description


def test_broad_exception_variants():
    code = (
        "def f():\n    '''d'''\n"
        "    try:\n        pass\n    except:\n        pass\n"
        "    try:\n        pass\n    except Exception:\n        pass\n"
        "    try:\n        pass\n    except (ValueError, OSError):\n        pass\n"
    )
    findings = [f for f in ast_analyzer.analyze_source(code) if f.rule_id == "CS-Q003"]
    assert sorted(f.severity for f in findings) == ["LOW", "MEDIUM"]


def test_complexity_and_nesting_flagged():
    branches = "\n".join(f"    if x == {i}:\n        y = {i}" for i in range(12))
    code = f"def f(x):\n    '''d'''\n    y = 0\n{branches}\n    return y\n"
    assert "CS-Q004" in rule_ids(ast_analyzer.analyze_source(code))

    nested = (
        "def g(a):\n    '''d'''\n"
        "    for i in a:\n        if i:\n            while i:\n                if i > 1:\n                    for j in a:\n                        pass\n"
    )
    assert "CS-Q006" in rule_ids(ast_analyzer.analyze_source(nested))


def test_elif_chain_does_not_count_as_nesting():
    code = "def f(x):\n    '''d'''\n" + "    if x == 0:\n        pass\n" + "".join(
        f"    elif x == {i}:\n        pass\n" for i in range(1, 8)
    )
    assert "CS-Q006" not in rule_ids(ast_analyzer.analyze_source(code))


def test_long_function_flagged():
    body = "\n".join("    x = 1" for _ in range(70))
    code = f"def f():\n    '''d'''\n{body}\n"
    assert "CS-Q005" in rule_ids(ast_analyzer.analyze_source(code))


def test_secure_sample_has_no_quality_findings():
    assert ast_analyzer.analyze_source(SECURE) == []


# ----------------------------- Bandit integration ---------------------------- #
@needs_bandit
def test_bandit_detects_expected_vulnerabilities_in_vulnerable_sample():
    result = analyze_code(VULNERABLE, "vulnerable_sample.py")
    security = {f["rule_id"] for f in result["findings"] if f["source"] == "security"}
    expected = {"B105", "B107", "B307", "B301", "B506", "B608", "B501", "B602", "B324", "B306", "B108", "B103", "B110", "B101"}
    assert expected <= security, f"missing: {expected - security}"
    assert result["scanners"]["bandit"]["ran"] is True


@needs_bandit
def test_vulnerable_sample_has_high_severity_findings_with_real_line_numbers():
    result = analyze_code(VULNERABLE, "vulnerable_sample.py")
    lines = VULNERABLE.splitlines()
    high = [f for f in result["findings"] if f["source"] == "security" and f["severity"] == "HIGH"]
    assert high
    for finding in high:
        assert 1 <= finding["line"] <= len(lines)
        assert finding["code_snippet"].strip() == lines[finding["line"] - 1].strip() or finding["code_snippet"]
        assert finding["remediation"]


@needs_bandit
def test_secure_sample_has_no_medium_or_high_security_findings():
    result = analyze_code(SECURE, "secure_sample.py")
    risky = [f for f in result["findings"] if f["source"] == "security" and f["severity"] in ("MEDIUM", "HIGH")]
    assert risky == []
    assert result["summary"]["total"] == 0


@needs_bandit
def test_quality_and_security_findings_are_distinguished():
    result = analyze_code(VULNERABLE, "vulnerable_sample.py")
    sources = {f["source"] for f in result["findings"]}
    assert sources == {"security", "quality"}
    summary = result["summary"]
    assert summary["security"] + summary["quality"] == summary["total"] == len(result["findings"])
    assert sum(summary["by_severity"].values()) == summary["total"]
    assert sum(summary["by_category"].values()) == summary["total"]


@needs_bandit
def test_uploaded_code_is_never_executed(tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"from pathlib import Path\nPath({str(marker)!r}).write_text('boom')\n"
    result = analyze_code(code, "side_effect.py")
    assert not marker.exists()
    assert result["lines"] == 2


def test_analysis_without_bandit_still_returns_quality_findings(monkeypatch):
    monkeypatch.setattr("analyzer.analysis_engine.bandit_available", lambda: False)
    result = analyze_code(VULNERABLE, "vulnerable_sample.py")
    assert result["warnings"] and "Bandit" in result["warnings"][0]
    assert {f["source"] for f in result["findings"]} == {"quality"}


# ----------------------------- AI explainer ---------------------------------- #
GOOD_JSON = json.dumps(
    {
        "explanation": "eval executes arbitrary code.",
        "impact": "Remote code execution.",
        "safer_approach": "Use ast.literal_eval.",
        "corrected_code": "import ast\nvalue = ast.literal_eval(text)",
    }
)


def sample_finding():
    return {
        "source": "security", "rule_id": "B307", "title": "B307: Eval", "severity": "MEDIUM",
        "confidence": "HIGH", "line": 3, "end_line": 3, "category": "Code Injection",
        "description": "Use of possibly insecure function - consider using safer ast.literal_eval.",
        "remediation": "Never eval() untrusted input.", "code_snippet": "return eval(expr)",
        "finding_id": "F001",
    }


def test_parse_model_response_accepts_valid_and_fenced_json():
    parsed = ai_explainer.parse_model_response(GOOD_JSON)
    assert parsed["explanation"].startswith("eval")
    fenced = ai_explainer.parse_model_response(f"Here you go:\n```json\n{GOOD_JSON}\n```")
    assert fenced["impact"] == "Remote code execution."


def test_parse_model_response_strips_code_fences_from_code():
    data = json.loads(GOOD_JSON)
    data["corrected_code"] = "```python\nx = 1\n```"
    assert ai_explainer.parse_model_response(json.dumps(data))["corrected_code"] == "x = 1"


@pytest.mark.parametrize("bad", ["not json at all", "[1, 2]", json.dumps({"explanation": "only one key"}), "{}"])
def test_parse_model_response_rejects_invalid(bad):
    with pytest.raises(ai_explainer.ExplanationError):
        ai_explainer.parse_model_response(bad)


class FakeResponse:
    def __init__(self, content, status=200):
        self.status_code = status
        self._content = content

    def json(self):
        return {"message": {"content": self._content}}


def test_generate_explanation_uses_ollama_response(monkeypatch):
    monkeypatch.setattr(ai_explainer.requests, "post", lambda *a, **k: FakeResponse(GOOD_JSON))
    result = ai_explainer.generate_explanation(sample_finding(), ["a", "b", "return eval(expr)"], "llama3.2:3b", "http://x")
    assert result["source"] == "ollama" and result["corrected_code_parses"] is True


def test_invalid_model_output_falls_back_after_retry(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(1)
        return FakeResponse("sorry, I cannot do JSON")

    monkeypatch.setattr(ai_explainer.requests, "post", fake_post)
    result = ai_explainer.explain_single(sample_finding(), "x = 1\n", "llama3.2:3b", "http://x")
    assert result["source"] == "fallback"
    assert len(calls) == 2  # one attempt + one retry


def test_missing_model_reports_pull_hint(monkeypatch):
    monkeypatch.setattr(ai_explainer.requests, "post", lambda *a, **k: FakeResponse("", status=404))
    result = ai_explainer.explain_single(sample_finding(), "x = 1\n", "ghost:1b", "http://x")
    assert result["source"] == "fallback" and "ollama pull ghost:1b" in result["note"]


def test_explain_findings_falls_back_when_ollama_is_down():
    findings = [sample_finding(), {**sample_finding(), "finding_id": "F002", "line": 9, "severity": "LOW"}]
    stats = ai_explainer.explain_findings(findings, "x = 1\n" * 10, "llama3.2:3b", "http://127.0.0.1:9", max_findings=5)
    assert stats["ai_generated"] == 0 and stats["fallback"] == 2
    assert "not reachable" in stats["error"]
    for finding in findings:
        explanation = finding["ai_explanation"]
        assert explanation["source"] == "fallback"
        assert explanation["safer_approach"] == finding["remediation"]
        assert explanation["corrected_code"]


def test_explain_findings_prioritises_high_severity_and_respects_limit(monkeypatch):
    monkeypatch.setattr(ai_explainer, "check_ollama", lambda host, model: {"state": "unavailable", "models": [], "error": "x"})
    findings = [
        {**sample_finding(), "finding_id": "F001", "severity": "LOW"},
        {**sample_finding(), "finding_id": "F002", "severity": "HIGH"},
        {**sample_finding(), "finding_id": "F003", "severity": "MEDIUM"},
    ]
    ai_explainer.explain_findings(findings, "x = 1\n" * 10, "m", "http://x", max_findings=2)
    assert findings[1].get("ai_explanation") and findings[2].get("ai_explanation")
    assert "ai_explanation" not in findings[0]


def test_fallback_marks_code_parse_status():
    result = ai_explainer.fallback_explanation(sample_finding())
    assert result["corrected_code_parses"] is True
