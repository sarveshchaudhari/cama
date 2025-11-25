from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone, date
import csv
import re
import importlib.util
import importlib

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

# ------------------ Helpers ------------------

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
        for e in entries[:50]:  # sample a few
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


def _to_df(csv_text: str, expected_cols: Optional[List[str]] = None) -> pd.DataFrame:
    if not csv_text or not csv_text.strip():
        return pd.DataFrame(columns=expected_cols or [])

    lines = [ln for ln in csv_text.splitlines() if ln.strip()]
    if not lines:
        return pd.DataFrame(columns=expected_cols or [])

    # Drop header if present
    header = lines[0]
    if expected_cols:
        first_lower = header.lower().replace(" ", "")
        if first_lower.startswith(",".join(expected_cols).lower().replace(" ", "")) or first_lower.startswith("id,title"):
            lines = lines[1:]

    rows: List[List[str]] = []
    for raw in lines:
        line = raw.replace("\t", ",").strip()
        if line.count('"') % 2 != 0:
            line = line + '"'
        try:
            parsed = next(csv.reader([line], delimiter=",", quotechar='"', skipinitialspace=True))
        except Exception:
            parsed = [p.strip().strip('"') for p in line.split(",")]
        if expected_cols:
            if len(parsed) < len(expected_cols):
                parsed += [""] * (len(expected_cols) - len(parsed))
            elif len(parsed) > len(expected_cols):
                head, tail = parsed[: len(expected_cols) - 1], parsed[len(expected_cols) - 1 :]
                parsed = head + [", ".join(tail)]
        rows.append(parsed)

    df = pd.DataFrame(rows, columns=expected_cols if expected_cols else None)
    for c in df.columns:
        try:
            df[c] = df[c].astype(str).str.strip()
        except Exception:
            pass
    return df


def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def _compute_cvss_base(vector: str) -> Optional[float]:
    if not vector or not isinstance(vector, str):
        return None
    v = vector.strip()
    if not v.startswith("CVSS:3.") and re.match(r"^[A-Z]{2}:[A-Z]", v):
        v = "CVSS:3.1/" + v
    # Try cvss
    try:
        if _has_module("cvss"):
            mod = importlib.import_module("cvss")
            CVSS3 = getattr(mod, "CVSS3", None)
            if CVSS3 is not None:
                obj = CVSS3(v)
                if hasattr(obj, "base_score"):
                    return float(obj.base_score)  # type: ignore
                scores = getattr(obj, "scores", None)
                if callable(scores):
                    return float(obj.scores()[0])
    except Exception:
        pass
    # Try cvsslib
    try:
        if _has_module("cvsslib"):
            mod2 = importlib.import_module("cvsslib")
            calc = getattr(mod2, "calculate_cvss_from_vector", None)
            if callable(calc):
                score = calc(v)[0]
                return float(score)
    except Exception:
        pass
    return None

# ------------------ Load data ------------------

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

# ------------------ Agent ------------------
from cama.agents.detection_agent import DetectionAgents
try:
    detection_agent = DetectionAgents().threat_detection_agent()
except Exception as e:
    st.error(f"Failed to initialize detection agent: {e}")
    st.stop()

summary_text, ctx = _summarize_for_agent(pairs)
provider = ctx.get("provider", "Unknown")

# System-like instructions enforcing strict schemas and no CVSS scores
SYSTEM_PROMPT = """
You are a senior cloud security analyst. Return ONLY the tagged sections. No text outside tags.

1) Three CSVs with EXACT schemas:
<<<THREATS_CSV_SCHEMA>>>
Columns: id,title,severity,cvss_v31_vector,provider,services,actions,resources,users,time_window,evidence,kill_chain_phase,compliance_controls,remediation
- id: deterministic (e.g., T-001)
- severity: Critical|High|Medium|Low
- cvss_v31_vector: full CVSS:3.1 vector (no scores)
- services/actions/resources/users: pipe-separated
- compliance_controls: semicolon-separated framework:control_id
- remediation: pipe-separated steps
<<<END_THREATS_CSV_SCHEMA>>>

<<<VULNS_CSV_SCHEMA>>>
Columns: id,cve_id,title,severity,cvss_v31_vector,provider,services,resources,users,time_window,evidence,affected_versions,remediation
- cve_id: CVE id or N/A
<<<END_VULNS_CSV_SCHEMA>>>

<<<COMPLIANCE_CSV_SCHEMA>>>
Columns: id,framework,control_id,title,severity,provider,services,resources,evidence,gap_description,remediation
<<<END_COMPLIANCE_CSV>>>

2) One daily CSV with EXACT schema:
<<<DAILY_CSV_SCHEMA>>>
Columns: time_bucket,action,service,count,top_users
<<<END_DAILY_CSV>>>

3) Two narrative reports in natural language:
<<<THREAT_REPORT>>>
A detailed narrative covering threats, vulnerabilities, misconfigurations, impact, and remediation.
<<<END_THREAT_REPORT>>>
<<<DAILY_REPORT>>>
A clear daily activity narrative for stakeholders.
<<<END_DAILY_REPORT>>>

Rules:
- Do NOT output CVSS scores, only vectors. The application will compute scores.
- Tailor wording to inferred provider (AWS/GCP).
- If no concrete vulnerabilities are found, DO NOT return V-000. Instead, output at least three hardening recommendation rows in VULNERABILITIES_CSV (ids like V-REC-001..003), with cve_id=N/A and practical remediation/suggestions to improve security and robustness.
- Each CSV must contain at least one data row.
- Respond in this exact order and nothing else:
  <<<THREATS_CSV>>> ... <<<END_THREATS_CSV>>>
  <<<VULNERABILITIES_CSV>>> ... <<<END_VULNERABILITIES_CSV>>>
  <<<COMPLIANCE_CSV>>> ... <<<END_COMPLIANCE_CSV>>>
  <<<DAILY_CSV>>> ... <<<END_DAILY_CSV>>>
  <<<THREAT_REPORT>>> ... <<<END_THREAT_REPORT>>>
  <<<DAILY_REPORT>>> ... <<<END_DAILY_REPORT>>>
"""

instructions = f"""
{SYSTEM_PROMPT}

Context:
{summary_text}
"""

from crewai import Crew, Task, Process

detect_task = Task(
    description=instructions,
    expected_output=(
        "All four tagged sections present and well-formed: THREATS_CSV, VULNERABILITIES_CSV, COMPLIANCE_CSV, DAILY_CSV"
    ),
    agent=detection_agent,
)
crew = Crew(agents=[detection_agent], tasks=[detect_task], process=Process.sequential, verbose=True)

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

# ------------------ Parse sections ------------------

def _section(name: str) -> str:
    return _extract_section(result_str, f"<<<{name}>>>", f"<<<END_{name}>>>")

threats_csv = _section("THREATS_CSV")
vulns_csv = _section("VULNERABILITIES_CSV")
compliance_csv = _section("COMPLIANCE_CSV")
daily_csv = _section("DAILY_CSV")
# Parse narrative sections
threat_md = _section("THREAT_REPORT")
daily_md = _section("DAILY_REPORT")

THREATS_COLS = [
    "id","title","severity","cvss_v31_vector","provider","services","actions","resources","users","time_window","evidence","kill_chain_phase","compliance_controls","remediation",
]
VULNS_COLS = [
    "id","cve_id","title","severity","cvss_v31_vector","provider","services","resources","users","time_window","evidence","affected_versions","remediation",
]
COMPLIANCE_COLS = [
    "id","framework","control_id","title","severity","provider","services","resources","evidence","gap_description","remediation",
]
DAILY_COLS = ["time_bucket","action","service","count","top_users"]

# Parse tables
threats_df = _to_df(threats_csv, THREATS_COLS)
vulns_df = _to_df(vulns_csv, VULNS_COLS)
compliance_df = _to_df(compliance_csv, COMPLIANCE_COLS)
daily_df = _to_df(daily_csv, DAILY_COLS)

# Compute accurate CVSS base scores from vectors
for df in (threats_df, vulns_df):
    if not df.empty and "cvss_v31_vector" in df.columns:
        df["cvss_v31_base_score"] = [
            _compute_cvss_base(v) for v in df["cvss_v31_vector"].astype(str).tolist()
        ]

# Provider-aware default vulnerability recommendations if none detected
def _default_vuln_recommendations(provider: str) -> pd.DataFrame:
    prov = (provider or "").upper()
    svc_iam = "iam.googleapis.com" if prov == "GCP" else "iam.amazonaws.com"
    svc_storage = "storage.googleapis.com" if prov == "GCP" else "s3.amazonaws.com"
    svc_logging = "logging.googleapis.com" if prov == "GCP" else "cloudtrail.amazonaws.com"
    rows = [
        [
            "V-REC-001",
            "N/A",
            "Enforce MFA for privileged accounts",
            "High",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            provider,
            svc_iam,
            "N/A",
            "N/A",
            "N/A",
            "Control gap: privileged identities without enforced MFA",
            "N/A",
            "Enable MFA for owners|Require strong factors|Monitor MFA enrollment",
        ],
        [
            "V-REC-002",
            "N/A",
            "Reduce overly broad IAM permissions",
            "High",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            provider,
            svc_iam,
            "N/A",
            "N/A",
            "N/A",
            "Control gap: wildcard actions or project-wide roles in use",
            "N/A",
            "Adopt least privilege|Refactor custom roles|Review access regularly",
        ],
        [
            "V-REC-003",
            "N/A",
            "Harden storage and logging retention",
            "Medium",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            provider,
            f"{svc_storage}|{svc_logging}",
            "N/A",
            "N/A",
            "N/A",
            "Control gap: missing versioning/retention and audit log protections",
            "N/A",
            "Enable bucket versioning|Configure retention locks|Restrict public access|Enforce log immutability",
        ],
    ]
    df = pd.DataFrame(rows, columns=VULNS_COLS)
    df["cvss_v31_base_score"] = [
        _compute_cvss_base(v) for v in df["cvss_v31_vector"].astype(str).tolist()
    ]
    return df

# Drop placeholder vulnerability row if present (e.g., V-000)
if not vulns_df.empty and "id" in vulns_df.columns:
    vulns_df = vulns_df[vulns_df["id"].str.upper() != "V-000"]

# If still empty, add default recommendations
if vulns_df.empty:
    vulns_df = _default_vuln_recommendations(provider)

# Inform user if CVSS computation libraries are missing
if (not threats_df.empty or not vulns_df.empty) and not (_has_module("cvss") or _has_module("cvsslib")):
    st.warning("CVSS libraries not installed. Add 'cvss' or 'cvsslib' to dependencies to compute base scores.")

if threats_df.empty and vulns_df.empty and compliance_df.empty:
    st.warning("No structured detections parsed from the model output.")
if daily_df.empty:
    st.info("No daily summary table parsed.")

progress.progress(80, text="Rendering results...")

# ------------------ Tables ------------------

st.subheader("Threat Detections")
if not threats_df.empty:
    st.dataframe(threats_df, width='stretch')
else:
    st.info("No structured threat detections.")

st.markdown("---")
st.subheader("Vulnerabilities")
if not vulns_df.empty:
    st.dataframe(vulns_df, width='stretch')
else:
    st.info("No structured vulnerabilities.")

st.markdown("---")
st.subheader("Compliance Gaps")
if not compliance_df.empty:
    st.dataframe(compliance_df, width='stretch')
else:
    st.info("No structured compliance gaps.")

st.markdown("---")
st.subheader("Daily Activity Summary")
if not daily_df.empty:
    st.dataframe(daily_df, width='stretch')
else:
    st.info("No structured daily activity.")

# ------------------ Narrative Previews ------------------

st.markdown("---")
st.subheader("Threat Report (Preview)")
st.write(threat_md or "<no threat report>")

st.markdown("---")
st.subheader("Daily Report (Preview)")
st.write(daily_md or "<no daily report>")

# ------------------ Vertical Timeline ------------------

st.markdown("---")
st.subheader("Activity Timeline")

# Simple, readable tables without timeframe selection
if not daily_df.empty:
    # Aggregate by service and action
    tmp = daily_df.copy()
    tmp["count_num"] = pd.to_numeric(tmp["count"], errors="coerce").fillna(0)
    agg = (
        tmp.groupby(["service", "action"], dropna=False)
        .agg(
            total_count=("count_num", "sum"),
            users=("top_users", lambda s: "|".join(sorted(set(u.strip() for v in s.astype(str) for u in v.split("|") if u.strip())))),
        )
        .reset_index()
        .sort_values(["service", "action"])
    )

    st.caption("Activity summary by service and action (entire dataset)")
    st.dataframe(agg, width='stretch')

    st.caption("Raw activity timeline (as provided)")
    # Keep the original DAILY_CSV rows for transparency
    st.dataframe(daily_df.sort_values(by=["service", "action"]).reset_index(drop=True), width='stretch')
else:
    st.info("No daily activity available.")

# ------------------ Markdown Reports ------------------

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
    + "## Threat Detections\n\n"
    + _df_to_markdown_table(threats_df)
    + "\n## Vulnerabilities\n\n"
    + _df_to_markdown_table(vulns_df)
    + "\n## Compliance Gaps\n\n"
    + _df_to_markdown_table(compliance_df)
    + "\n## Narrative\n\n"
    + (threat_md or "_No threat narrative provided._")
    + "\n"
)

# Daily report now includes narrative
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

# Save & download
threat_path = selected_path / "threat_report.md"
daily_path = selected_path / "daily_report.md"
try:
    threat_path.write_text(threat_report_md, encoding="utf-8")
    daily_path.write_text(daily_report_md, encoding="utf-8")
except Exception:
    pass

st.markdown("---")
st.subheader("Downloads")
st.download_button("Download Threat/Compliance Report (MD)", data=threat_report_md, file_name="threat_report.md", mime="text/markdown")
st.download_button("Download Daily Report (MD)", data=daily_report_md, file_name="daily_report.md", mime="text/markdown")

# Optional navigation
col_a, col_b = st.columns(2)
with col_a:
    if st.button("Back to Analysis"):
        try:
            st.switch_page("pages/analysis_app.py")
        except Exception:
            pass
