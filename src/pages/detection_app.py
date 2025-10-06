from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from io import StringIO
import csv

import streamlit as st
from dotenv import load_dotenv
import pandas as pd

# Ensure src on path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Load .env
load_dotenv(dotenv_path=PROJECT_ROOT / ".env", override=False)

st.set_page_config(page_title="CAMA Detection", layout="wide")

st.title("CAMA Detection")
st.caption("Detect threats, vulnerabilities, and compliance gaps from ingested audit logs.")

# Helpers

def _find_latest_run_dir() -> Optional[Path]:
    cache_root = PROJECT_ROOT / ".cache"
    runs = [p for p in cache_root.glob("run_*") if p.is_dir()]
    if not runs:
        return None
    return sorted(runs, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def _load_json_files(run_dir: Path) -> List[Tuple[str, List[Dict[str, Any]]]]:
    pairs: List[Tuple[str, List[Dict[str, Any]]]] = []
    for p in sorted(run_dir.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, list):
                pairs.append((p.name, data))
        except Exception:
            continue
    return pairs


def _summarize_for_agent(pairs: List[Tuple[str, List[Dict[str, Any]]]]) -> Tuple[str, Dict[str, Any]]:
    provider = "Unknown"
    actions: List[str] = []
    users: set[str] = set()
    services: set[str] = set()
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None

    blocks: List[str] = []
    for fname, entries in pairs:
        if fname.startswith("gcp_"):
            provider = "GCP"
        elif fname.startswith("aws_"):
            provider = "AWS"
        a = fname.replace("gcp_", "").replace("aws_", "").replace(".json", "")
        actions.append(a)
        count = len(entries)
        # sample a few entries to extract hints
        for e in entries[:50]:
            try:
                if isinstance(e, dict):
                    pp = e.get("protoPayload", {})
                    user = (pp.get("authenticationInfo", {}) or {}).get("principalEmail")
                    if user:
                        users.add(str(user))
                    svc = pp.get("serviceName") or e.get("EventSource")
                    if svc:
                        services.add(str(svc))
                    ts = e.get("timestamp") or e.get("receiveTimestamp") or pp.get("timestamp") or e.get("EventTime")
                    if isinstance(ts, str):
                        first_ts = first_ts or ts
                        last_ts = ts
            except Exception:
                pass
        blocks.append(f"- File: {fname} | records={count}")

    summary_lines = [
        f"Provider: {provider}",
        f"Files: {len(pairs)}",
        f"Actions: {', '.join(actions[:100])}",
        f"Users: {', '.join(list(users)[:100])}",
        f"Services: {', '.join(list(services)[:100])}",
        f"Time Range (approx): {first_ts} -> {last_ts}",
        "Details:",
        *blocks,
    ]
    return "\n".join(summary_lines), {"provider": provider, "actions": actions}


def _extract_section(text: str, start_tag: str, end_tag: str) -> str:
    s = text.find(start_tag)
    e = text.find(end_tag)
    if s == -1 or e == -1 or e <= s:
        return ""
    return text[s + len(start_tag) : e].strip()


def _to_df(csv_text: str) -> pd.DataFrame:
    if not csv_text or not csv_text.strip():
        return pd.DataFrame()

    expected_cols = [
        "id",
        "title",
        "severity",
        "cvss_v3_base_score",
        "provider",
        "services",
        "actions",
        "resources",
        "users",
        "time_window",
        "evidence",
        "compliance_controls",
        "remediation",
    ]

    # Normalize lines: replace tabs with commas, ensure balanced quotes, drop empties
    lines = [ln for ln in csv_text.splitlines() if ln.strip()]
    if not lines:
        return pd.DataFrame(columns=expected_cols)

    # Drop header if present
    first_lower = lines[0].lower().replace(" ", "")
    if first_lower.startswith(",".join(expected_cols)) or first_lower.startswith("id,title"):
        lines = lines[1:]

    rows: List[List[str]] = []
    for raw in lines:
        line = raw.replace("\t", ",").strip()
        # Fix common quoting issues
        if line.count('"') % 2 != 0:
            line = line + '"'
        try:
            parsed = next(csv.reader([line], delimiter=",", quotechar='"', skipinitialspace=True))
        except Exception:
            # Last resort: split on comma without respecting quotes
            parsed = [p.strip().strip('"') for p in line.split(",")]
        # Pad or trim to expected length
        if len(parsed) < len(expected_cols):
            parsed += [""] * (len(expected_cols) - len(parsed))
        elif len(parsed) > len(expected_cols):
            # Merge overflow columns into the last column (typically remediation)
            head, tail = parsed[: len(expected_cols) - 1], parsed[len(expected_cols) - 1 :]
            parsed = head + [", ".join(tail)]
        rows.append(parsed)

    df = pd.DataFrame(rows, columns=expected_cols)
    return df


# Determine run directory
selected_path: Optional[Path] = None
if "run_dir" in st.session_state and st.session_state.get("run_dir"):
    p = Path(str(st.session_state["run_dir"]))
    if p.exists() and p.is_dir():
        selected_path = p
if not selected_path:
    latest = _find_latest_run_dir()
    if latest:
        selected_path = latest

if not selected_path:
    st.error("No run directory found. Please run ingestion first.")
    st.stop()

st.success(f"Using run directory: {selected_path}")

pairs = _load_json_files(selected_path)
if not pairs:
    st.warning("No JSON files found in run directory.")
    st.stop()

# Agent setup
from cama.agents.detection_agent import DetectionAgents
try:
    detection_agent = DetectionAgents().threat_detection_agent()
except Exception as e:
    st.error(f"Failed to initialize detection agent: {e}")
    st.stop()

# Build instructions (LLM-only, no web search)
summary_text, ctx = _summarize_for_agent(pairs)
provider = ctx.get("provider", "Unknown")

instructions = f"""
You are a senior cloud security analyst. Based only on the following audit log summary and your internal knowledge, perform a deep detection, vulnerability analysis, and compliance check. Be provider-agnostic (GCP/AWS), but tailor compliance notes to the detected provider.

STRICT OUTPUT FORMAT WITH TAGS (no extra prose outside tags):
<<<FINDINGS_CSV>>>
CSV with columns: id,title,severity,cvss_v3_base_score,provider,services,actions,resources,users,time_window,evidence,compliance_controls,remediation
- services/actions/resources/users: pipe-separated if multiple (e.g., s1|s2)
- compliance_controls: semicolon-separated tuples standard:control_id (e.g., CIS:1.1;NIST 800-53:AU-6)
- remediation: pipe-separated action steps
<<<END_FINDINGS_CSV>>>

<<<DAILY_CSV>>>
CSV summarizing normal day-to-day activities for the time window with columns: time_bucket,action,service,count,top_users
- time_bucket in ISO date or ISO date hour
- top_users: pipe-separated usernames
<<<END_DAILY_CSV>>>

<<<THREAT_REPORT>>>
A detailed natural-language threat report (well-structured with headings and bullet lists). Include: overview, notable threats, vulnerabilities, suspected misconfigurations, impact, and remediation recommendations.
<<<END_THREAT_REPORT>>>

<<<DAILY_REPORT>>>
A clear daily activity report in natural language for stakeholders, summarizing key actions and routine tasks.
<<<END_DAILY_REPORT>>>

Context:
{summary_text}
"""

from crewai import Crew, Task, Process

detect_task = Task(
    description=instructions,
    expected_output=(
        "All four tagged sections present and well-formed: FINDINGS_CSV, DAILY_CSV, THREAT_REPORT, DAILY_REPORT"
    ),
    agent=detection_agent,
)
crew = Crew(agents=[detection_agent], tasks=[detect_task], process=Process.sequential, verbose=True)

# Run with progress
progress = st.progress(0, text="Preparing detection...")
progress.progress(20, text="Building detection prompts...")

try:
    with st.spinner("Running detection agent (this may take a while)..."):
        out = crew.kickoff()
    result_str = None
    for attr in ("output", "raw"):
        if hasattr(out, attr):
            result_str = getattr(out, attr)
            break
    if not result_str:
        result_str = str(out)
    progress.progress(60, text="Parsing model output...")
except Exception as e:
    st.error(f"Detection failed: {e}")
    st.stop()

# Extract sections
findings_csv = _extract_section(result_str, "<<<FINDINGS_CSV>>>", "<<<END_FINDINGS_CSV>>>")
daily_csv = _extract_section(result_str, "<<<DAILY_CSV>>>", "<<<END_DAILY_CSV>>>")
threat_md = _extract_section(result_str, "<<<THREAT_REPORT>>>", "<<<END_THREAT_REPORT>>>")
daily_md = _extract_section(result_str, "<<<DAILY_REPORT>>>", "<<<END_DAILY_REPORT>>>")

# Parse tables
findings_df = _to_df(findings_csv)
daily_df = _to_df(daily_csv)

if findings_df.empty:
    st.warning("No findings parsed from the model output.")
if daily_df.empty:
    st.info("No daily summary table parsed; continuing with narrative reports.")

progress.progress(80, text="Rendering results...")

# Display structured results using tables
st.subheader("Findings")
if not findings_df.empty:
    st.dataframe(findings_df, width="stretch")
else:
    st.write("<no structured findings>")

st.markdown("---")
st.subheader("Daily Activity Summary")
if not daily_df.empty:
    st.dataframe(daily_df, width="stretch")
else:
    st.write("<no structured daily activity>")

st.markdown("---")
st.subheader("Threat Report (Preview)")
st.write(threat_md or "<no threat report>")

st.markdown("---")
st.subheader("Daily Report (Preview)")
st.write(daily_md or "<no daily report>")

# Build Markdown reports instead of PDFs

def _df_to_markdown_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "\n_No data_\n"
    headers = list(df.columns)
    lines = [
        "| " + " | ".join(str(h) for h in headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for _, row in df.astype(str).iterrows():
        lines.append("| " + " | ".join(row.values.tolist()) + " |")
    return "\n".join(lines) + "\n"

meta_block = (
    f"Provider: {provider}\n\n"
    f"Run directory: {selected_path}\n\n"
    f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
)

threat_report_md = (
    "# CAMA Threat, Vulnerability, and Compliance Report\n\n"
    + meta_block
    + "## Findings\n\n"
    + _df_to_markdown_table(findings_df)
    + "\n## Narrative\n\n"
    + (threat_md or "_No threat narrative provided._")
    + "\n"
)

daily_report_md = (
    "# CAMA Daily Activity Report\n\n"
    + meta_block
    + "## Daily Activity Summary\n\n"
    + _df_to_markdown_table(daily_df)
    + "\n## Narrative\n\n"
    + (daily_md or "_No daily narrative provided._")
    + "\n"
)

progress.progress(100, text="Detection completed.")

# Save and download buttons for Markdown
threat_path = selected_path / "threat_report.md"
daily_path = selected_path / "daily_report.md"
try:
    threat_path.write_text(threat_report_md, encoding="utf-8")
    daily_path.write_text(daily_report_md, encoding="utf-8")
except Exception:
    pass

st.markdown("---")
st.subheader("Downloads")
st.download_button("Download Threat Report (MD)", data=threat_report_md, file_name="threat_report.md", mime="text/markdown")
st.download_button("Download Daily Report (MD)", data=daily_report_md, file_name="daily_report.md", mime="text/markdown")

# Optional navigation
col_a, col_b = st.columns(2)
with col_a:
    if st.button("Back to Analysis"):
        try:
            st.switch_page("pages/analysis_app.py")
        except Exception:
            pass
