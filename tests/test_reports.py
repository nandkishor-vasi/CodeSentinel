"""Tests for JSON and Markdown report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.analysis_engine import analyze_code
from analyzer.ai_explainer import fallback_explanation
from analyzer.bandit_scanner import bandit_available
from analyzer.report_generator import _fence, generate_json_report, generate_markdown_report

SAMPLE = (Path(__file__).resolve().parent.parent / "samples" / "vulnerable_sample.py").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def result():
    return analyze_code(SAMPLE, "vulnerable_sample.py", run_bandit=bandit_available())


def test_json_report_is_complete_and_round_trips(result):
    data = json.loads(generate_json_report(result))
    assert data["filename"] == "vulnerable_sample.py"
    assert data["summary"]["total"] == len(data["findings"]) > 0
    assert {"rule_id", "severity", "confidence", "line", "description", "remediation"} <= set(data["findings"][0])


def test_markdown_report_has_sections_and_every_finding(result):
    markdown = generate_markdown_report(result)
    assert markdown.startswith("# CodeSentinel AI - Analysis Report")
    assert "## Summary" in markdown
    assert "## Security vulnerabilities (Bandit)" in markdown
    assert "## Code quality warnings (AST)" in markdown
    for finding in result["findings"]:
        assert finding["title"] in markdown
        assert f"(line {finding['line']})" in markdown


@pytest.mark.skipif(not bandit_available(), reason="bandit is not installed")
def test_markdown_report_contains_security_details(result):
    markdown = generate_markdown_report(result)
    assert "B602" in markdown and "Remediation" in markdown and "CWE-" in markdown


def test_markdown_includes_ai_explanation_when_present():
    local = analyze_code(SAMPLE, "vulnerable_sample.py", run_bandit=False)
    local["findings"][0]["ai_explanation"] = fallback_explanation(local["findings"][0])
    markdown = generate_markdown_report(local)
    assert "**Impact:**" in markdown and "**Safer approach:**" in markdown


def test_empty_result_report_renders():
    clean = analyze_code('def f():\n    """Doc."""\n    return 1\n', "clean.py", run_bandit=False)
    markdown = generate_markdown_report(clean)
    assert "0 findings" in markdown and "_No findings._" in markdown


def test_fence_handles_backticks_in_content():
    block = _fence("print('```')", "python")
    assert block.startswith("````python") and block.endswith("````")
