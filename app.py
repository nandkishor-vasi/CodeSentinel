"""CodeSentinel AI - AI-powered code review and security scanner (Streamlit dashboard)."""

from __future__ import annotations

import inspect
import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from analyzer import __version__  # noqa: E402
from analyzer.ai_explainer import (  # noqa: E402
    check_ollama,
    explain_findings,
    explain_single,
    get_default_host,
    get_default_model,
)
from analyzer.analysis_engine import (  # noqa: E402
    ValidationError,
    analyze_code,
    get_max_upload_bytes,
    validate_source,
    validate_upload,
)
from analyzer.bandit_scanner import bandit_available, bandit_version  # noqa: E402
from analyzer.models import SEVERITIES, SOURCE_SECURITY  # noqa: E402
from analyzer.report_generator import generate_json_report, generate_markdown_report  # noqa: E402

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"
SEV_COLORS = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#38bdf8"}
SEV_ICONS = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🔵"}
TYPE_COLORS = {"Security": "#ef4444", "Quality": "#a78bfa"}

st.set_page_config(page_title="CodeSentinel AI", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; max-width: 1300px;}
    .cs-hero {padding: 1.2rem 1.5rem; border-radius: 14px; margin-bottom: 1rem;
        background: linear-gradient(120deg, #0f1b33 0%, #12253f 55%, #0e3a4a 100%);
        border: 1px solid #1f3a5f;}
    .cs-hero h1 {margin: 0; font-size: 1.9rem; letter-spacing: .2px;}
    .cs-hero p {margin: .25rem 0 0; color: #9fb3cf;}
    .cs-card {background: #121a2b; border: 1px solid #1f2b45; border-radius: 12px;
        padding: .9rem 1rem; text-align: left;}
    .cs-card .label {color: #8ea2c2; font-size: .78rem; text-transform: uppercase; letter-spacing: .08em;}
    .cs-card .value {font-size: 1.9rem; font-weight: 700; line-height: 1.2;}
    .cs-badge {display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .75rem;
        font-weight: 600; margin-right: 6px; border: 1px solid transparent;}
    .cs-badge.security {background: #3b1620; color: #fca5a5; border-color: #7f1d1d;}
    .cs-badge.quality {background: #2a2250; color: #c4b5fd; border-color: #4c3b9a;}
    .cs-badge.neutral {background: #1a2438; color: #b6c4dd; border-color: #2a3a5a;}
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------- #
# Small compatibility helpers (Streamlit API changed across versions)
# --------------------------------------------------------------------------- #
def _stretch(fn) -> dict:
    """Keyword arguments that make a widget fill the container on any Streamlit version."""
    if "width" in inspect.signature(fn).parameters:
        return {"width": "stretch"}
    return {"use_container_width": True}


def show_code(code: str, line_numbers: bool = True) -> None:
    try:
        st.code(code, language="python", line_numbers=line_numbers)
    except TypeError:
        st.code(code, language="python")


def metric_card(label: str, value: object, color: str = "#e6edf7") -> str:
    return f'<div class="cs-card"><div class="label">{label}</div><div class="value" style="color:{color}">{value}</div></div>'


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
@st.cache_data(ttl=15, show_spinner=False)
def cached_ollama_status(host: str, model: str) -> dict:
    return check_ollama(host, model)


def render_sidebar() -> dict:
    st.sidebar.markdown("## 🛡️ CodeSentinel AI")
    st.sidebar.caption(f"v{__version__} · static analysis only")

    st.sidebar.markdown("### Scanners")
    if bandit_available():
        st.sidebar.success(f"Bandit {bandit_version()} ready")
    else:
        st.sidebar.error("Bandit not installed - run `pip install bandit`")
    st.sidebar.success("AST quality analyzer ready")

    st.sidebar.markdown("### AI explanations")
    ai_enabled = st.sidebar.toggle("Use Ollama for explanations", value=True)
    host = st.sidebar.text_input("Ollama host", value=get_default_host())
    model = st.sidebar.text_input("Model", value=get_default_model())
    max_explain = st.sidebar.slider(
        "Findings to explain per scan", 1, 25, 5,
        help="Highest severity first. Local models are slow on CPU - you can also explain single findings on demand.",
    )

    if ai_enabled:
        status = cached_ollama_status(host, model)
        if status["state"] == "ready":
            st.sidebar.success(f"Ollama ready · {model}")
        elif status["state"] == "model_missing":
            st.sidebar.warning(f"Model not installed. Run `ollama pull {model}`")
            if status["models"]:
                st.sidebar.caption("Installed: " + ", ".join(status["models"]))
        else:
            st.sidebar.info("Ollama not reachable - built-in fallback explanations will be used.")
        if st.sidebar.button("Refresh status"):
            cached_ollama_status.clear()
            st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.caption(f"Max file size: {get_max_upload_bytes() // 1024} KB · `.py` files only")
    st.sidebar.caption("Uploaded code is parsed and scanned, never executed.")
    return {"ai_enabled": ai_enabled, "host": host, "model": model, "max_explain": max_explain}


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
def run_analysis(code: str, filename: str, settings: dict) -> None:
    try:
        with st.status("Analysing code...", expanded=True) as status:
            st.write("Running Bandit and the AST analyzer...")
            result = analyze_code(code, filename)
            if settings["ai_enabled"] and result["findings"]:
                st.write(f"Generating explanations with `{settings['model']}`...")
                bar = st.progress(0.0)
                result["ai"] = explain_findings(
                    result["findings"],
                    code,
                    model=settings["model"],
                    host=settings["host"],
                    max_findings=settings["max_explain"],
                    progress_cb=lambda done, total: bar.progress(done / total),
                )
            status.update(label="Analysis complete", state="complete", expanded=False)
    except ValidationError as exc:
        st.error(str(exc))
        return
    st.session_state["result"] = result
    st.session_state["code"] = code
    st.session_state["open_ids"] = set()


# --------------------------------------------------------------------------- #
# Input section
# --------------------------------------------------------------------------- #
def code_preview(code: str) -> None:
    with st.expander(f"Submitted code ({len(code.splitlines())} lines)", expanded=True):
        show_code(code)


def render_input(settings: dict) -> None:
    tab_upload, tab_paste, tab_sample = st.tabs(["📁 Upload file", "📝 Paste code", "🧪 Sample files"])

    with tab_upload:
        uploaded = st.file_uploader("Upload a Python file", type=["py"], help="Only .py files up to the size limit.")
        if uploaded is not None:
            try:
                code = validate_upload(uploaded.name, uploaded.getvalue())
            except ValidationError as exc:
                st.error(str(exc))
            else:
                code_preview(code)
                if st.button("Analyze uploaded file", type="primary", key="btn_upload"):
                    run_analysis(code, uploaded.name, settings)

    with tab_paste:
        pasted = st.text_area("Paste Python source", height=280, placeholder="def example():\n    ...")
        if pasted.strip():
            try:
                code = validate_source(pasted)
            except ValidationError as exc:
                st.error(str(exc))
            else:
                if st.button("Analyze pasted code", type="primary", key="btn_paste"):
                    run_analysis(code, "pasted_code.py", settings)

    with tab_sample:
        samples = sorted(SAMPLES_DIR.glob("*.py"))
        if not samples:
            st.info("No sample files found in the samples/ folder.")
        else:
            choice = st.selectbox("Choose a sample", samples, format_func=lambda p: p.name)
            code = choice.read_text(encoding="utf-8")
            code_preview(code)
            if st.button("Analyze sample", type="primary", key="btn_sample"):
                run_analysis(code, choice.name, settings)


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #
def style_fig(fig, height: int = 330):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=50, b=10),
        height=height,
    )
    return fig


def findings_frame(findings: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "ID": f["finding_id"],
                "Type": "Security" if f["source"] == SOURCE_SECURITY else "Quality",
                "Severity": f["severity"],
                "Confidence": f["confidence"],
                "Line": f["line"],
                "Rule": f["rule_id"],
                "Category": f["category"],
                "Description": f["description"],
            }
            for f in findings
        ]
    )


def render_charts(df: pd.DataFrame, summary: dict) -> None:
    c1, c2, c3 = st.columns(3)

    sev_df = pd.DataFrame({"Severity": list(SEVERITIES), "Count": [summary["by_severity"][s] for s in SEVERITIES]})
    fig = px.bar(sev_df, x="Severity", y="Count", color="Severity", color_discrete_map=SEV_COLORS, text="Count",
                 title="Severity distribution", category_orders={"Severity": list(SEVERITIES)})
    fig.update_layout(showlegend=False)
    c1.plotly_chart(style_fig(fig), **_stretch(c1.plotly_chart))

    type_df = df.groupby("Type").size().reset_index(name="Count")
    fig = px.pie(type_df, names="Type", values="Count", hole=0.55, color="Type",
                 color_discrete_map=TYPE_COLORS, title="Security vs quality")
    c2.plotly_chart(style_fig(fig), **_stretch(c2.plotly_chart))

    cat_df = df.groupby(["Category", "Type"]).size().reset_index(name="Count")
    order = df["Category"].value_counts().index.tolist()[::-1]
    fig = px.bar(cat_df, x="Count", y="Category", color="Type", orientation="h",
                 color_discrete_map=TYPE_COLORS, title="Findings by category",
                 category_orders={"Category": order})
    fig.update_layout(legend=dict(orientation="h", y=-0.15))
    c3.plotly_chart(style_fig(fig), **_stretch(c3.plotly_chart))


def render_ai_block(finding: dict, code: str, settings: dict) -> None:
    ai = finding.get("ai_explanation")
    if ai:
        origin = f"Ollama · {ai['model']}" if ai["source"] == "ollama" else "Built-in guidance (no LLM)"
        st.markdown(f"**🤖 AI explanation** — _{origin}_")
        st.markdown(ai["explanation"])
        st.markdown(f"**Impact:** {ai['impact']}")
        st.markdown(f"**Safer approach:** {ai['safer_approach']}")
        if ai.get("corrected_code"):
            show_code(ai["corrected_code"], line_numbers=False)
        notes = [ai.get("note", "")]
        if ai.get("source") == "ollama" and ai.get("corrected_code_parses") is False:
            notes.append("The suggested snippet is not standalone valid Python - treat it as pseudo-code and review it.")
        st.caption(" ".join(n for n in notes if n))
    else:
        label = "Explain with AI" if settings["ai_enabled"] else "Show built-in explanation"
        if st.button(label, key=f"ai_{finding['finding_id']}"):
            with st.spinner("Generating explanation..."):
                finding["ai_explanation"] = explain_single(
                    finding, code, settings["model"], settings["host"], use_llm=settings["ai_enabled"]
                )
            st.session_state.setdefault("open_ids", set()).add(finding["finding_id"])
            st.rerun()


def render_finding(finding: dict, code: str, settings: dict) -> None:
    kind = "security" if finding["source"] == SOURCE_SECURITY else "quality"
    label = f"{SEV_ICONS[finding['severity']]} {finding['severity']} · line {finding['line']} · {finding['title']}"
    expanded = finding["finding_id"] in st.session_state.get("open_ids", set())
    with st.expander(label, expanded=expanded):
        badges = (
            f'<span class="cs-badge {kind}">{kind.upper()}</span>'
            f'<span class="cs-badge neutral">Confidence: {finding["confidence"]}</span>'
            f'<span class="cs-badge neutral">{finding["category"]}</span>'
            f'<span class="cs-badge neutral">{finding["finding_id"]}</span>'
        )
        if finding.get("cwe"):
            badges += f'<span class="cs-badge neutral">{finding["cwe"]}</span>'
        st.markdown(badges, unsafe_allow_html=True)
        st.markdown(finding["description"])
        if finding.get("code_snippet"):
            show_code(finding["code_snippet"], line_numbers=False)
        st.markdown(f"**🛠️ Remediation:** {finding['remediation']}")
        if finding.get("more_info"):
            st.caption(f"Reference: {finding['more_info']}")
        st.divider()
        render_ai_block(finding, code, settings)


def render_dashboard(result: dict, code: str, settings: dict) -> None:
    summary = result["summary"]
    st.markdown("---")
    st.subheader(f"Results · {result['filename']}")
    st.caption(
        f"{result['lines']} lines · analysed {result['analyzed_at']} UTC · sha256 {result['sha256'][:12]}… · "
        f"Bandit: {'v' + result['scanners']['bandit']['version'] if result['scanners']['bandit']['ran'] else 'not run'}"
    )
    for warning in result.get("warnings", []):
        st.warning(warning)
    ai = result.get("ai", {})
    if ai.get("enabled") and ai.get("error"):
        st.info(ai["error"])
    elif ai.get("enabled"):
        st.caption(f"AI: {ai['ai_generated']} explanation(s) by {ai['model']}, {ai['fallback']} built-in.")

    cards = st.columns(6)
    values = [
        ("Total findings", summary["total"], "#e6edf7"),
        ("High", summary["by_severity"]["HIGH"], SEV_COLORS["HIGH"]),
        ("Medium", summary["by_severity"]["MEDIUM"], SEV_COLORS["MEDIUM"]),
        ("Low", summary["by_severity"]["LOW"], SEV_COLORS["LOW"]),
        ("Security", summary["security"], TYPE_COLORS["Security"]),
        ("Quality", summary["quality"], TYPE_COLORS["Quality"]),
    ]
    for col, (label, value, color) in zip(cards, values):
        col.markdown(metric_card(label, value, color), unsafe_allow_html=True)

    findings = result["findings"]
    if not findings:
        st.success("No security vulnerabilities or code quality issues were detected by the enabled scanners.")
        tab_source, tab_export = st.tabs(["Source", "Export"])
        with tab_source:
            show_code(code)
        with tab_export:
            render_export(result)
        return

    df = findings_frame(findings)
    st.write("")
    render_charts(df, summary)

    tab_findings, tab_table, tab_source, tab_export = st.tabs(["🔎 Findings", "📋 Table", "💻 Source", "⬇️ Export"])

    with tab_findings:
        f1, f2, f3, f4 = st.columns([1, 1, 1.4, 1.6])
        types = f1.multiselect("Type", ["Security", "Quality"], default=["Security", "Quality"])
        sevs = f2.multiselect("Severity", list(SEVERITIES), default=list(SEVERITIES))
        cats = f3.multiselect("Category", sorted(df["Category"].unique()), default=sorted(df["Category"].unique()))
        query = f4.text_input("Search", placeholder="rule id, keyword...").strip().lower()

        shown = [
            f for f in findings
            if ("Security" if f["source"] == SOURCE_SECURITY else "Quality") in types
            and f["severity"] in sevs
            and f["category"] in cats
            and (not query or query in f"{f['rule_id']} {f['title']} {f['description']}".lower())
        ]
        st.caption(f"Showing {len(shown)} of {len(findings)} findings")
        for finding in shown:
            render_finding(finding, code, settings)

    with tab_table:
        st.dataframe(df, hide_index=True, **_stretch(st.dataframe))

    with tab_source:
        flagged = df.groupby("Line")["Rule"].apply(lambda s: ", ".join(sorted(set(s)))).reset_index()
        st.caption("Flagged lines: " + "; ".join(f"{r.Line}: {r.Rule}" for r in flagged.itertuples()))
        show_code(code)

    with tab_export:
        render_export(result)


def render_export(result: dict) -> None:
    stem = Path(result["filename"]).stem
    json_report = generate_json_report(result)
    md_report = generate_markdown_report(result)
    col1, col2 = st.columns(2)
    col1.download_button(
        "⬇️ Download JSON report", json_report, file_name=f"codesentinel_{stem}.json",
        mime="application/json", **_stretch(col1.download_button),
    )
    col2.download_button(
        "⬇️ Download Markdown report", md_report, file_name=f"codesentinel_{stem}.md",
        mime="text/markdown", **_stretch(col2.download_button),
    )
    with st.expander("Preview Markdown report"):
        st.markdown(md_report)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    settings = render_sidebar()
    st.markdown(
        '<div class="cs-hero"><h1>🛡️ CodeSentinel AI</h1>'
        "<p>AI-powered code review &amp; security scanner for Python — Bandit + AST analysis, explained by a local LLM.</p></div>",
        unsafe_allow_html=True,
    )
    render_input(settings)
    if "result" in st.session_state:
        render_dashboard(st.session_state["result"], st.session_state["code"], settings)
    else:
        st.info("Upload a file, paste code, or pick a sample, then run the analysis to see the dashboard.")
    st.caption("CodeSentinel AI is a static analysis aid. Review all findings and AI-suggested fixes before applying them.")


main()
