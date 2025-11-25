from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timedelta, timezone
import math
import re
import shutil

import streamlit as st
from dotenv import load_dotenv

# Ensure the project's src is on sys.path so we can import our package
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Load .env if present
load_dotenv(dotenv_path=PROJECT_ROOT / ".env", override=False)

# Lazy imports of our modules (after sys.path adjustment)
from cama.lib.gcp_handler import fetch_and_format_gcp_logs  # noqa: F401  # referenced in notes
from cama.lib.aws_handler import fetch_and_format_aws_logs  # noqa: F401  # referenced in notes
from cama.agents.ingestion_agent import IngestionAgents  # noqa: F401
from cama.agents.analysis_agent import AnalysisAgents  # noqa: F401
from cama.crew import CamaCrew

st.set_page_config(page_title="CAMA Ingestion + Analysis (Agentic)", layout="wide")

# Exit and clear cache utilities

def _clear_cache_dir() -> None:
    cache_root = PROJECT_ROOT / ".cache"
    if cache_root.exists() and cache_root.is_dir():
        for child in cache_root.iterdir():
            try:
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
            except Exception:
                pass

def _clear_cache_only() -> None:
    _clear_cache_dir()
    try:
        st.toast("Memory cleared")
    except Exception:
        pass
    st.success(".cache cleared.")

# Sidebar configuration
st.sidebar.header("Configuration")
# Exit button in sidebar
st.sidebar.markdown("---")
if st.sidebar.button("Clear Cache"):
    _clear_cache_only()

provider = st.sidebar.selectbox("Cloud Provider", ["GCP", "AWS"])

# API Key config
st.sidebar.markdown("---")

gemini_key = st.sidebar.text_input(
    "GOOGLE_API_KEY (Gemini)", value=os.getenv("GOOGLE_API_KEY", ""), type="password"
)

st.sidebar.markdown("---")

# Provider-specific configuration comes BEFORE timeframe so we can adapt UI
aws_source_mode = "API"
aws_dir_input: Optional[str] = None
if provider == "GCP":
    st.subheader("GCP Credentials")
    st.write("Paste your Service Account JSON. It will be used only in-memory for this session.")
    gcp_json_default = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
    gcp_json = st.text_area("Service Account JSON", value=gcp_json_default, height=200)
else:
    st.subheader("AWS Source")
    aws_source_mode = st.radio("How do you want to ingest AWS CloudTrail logs?", ["Local Directory", "API"], index=0)
    if aws_source_mode == "Local Directory":
        default_dir = str((PROJECT_ROOT / "Resources" / "CloudTrail").resolve())
        aws_dir_input = st.text_input("CloudTrail directory path", value=os.getenv("AWS_CLOUDTRAIL_DIR", default_dir))
        st.caption("Provide a folder containing CloudTrail .json files (non-recursive). No AWS credentials needed.")
    else:
        st.subheader("AWS Credentials")
        aws_key = st.text_input("AWS_ACCESS_KEY_ID", value=os.getenv("AWS_ACCESS_KEY_ID", ""))
        aws_secret = st.text_input("AWS_SECRET_ACCESS_KEY", value=os.getenv("AWS_SECRET_ACCESS_KEY", ""), type="password")
        aws_region = st.text_input("AWS_DEFAULT_REGION", value=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))

# Timeframe selection (hide when AWS Local Directory)
show_timeframe = not (provider == "AWS" and aws_source_mode == "Local Directory")
if show_timeframe:
    timeframe_mode = st.sidebar.radio("Timeframe Mode", ["Days", "Custom Range"], index=0)
    if timeframe_mode == "Days":
        days = st.sidebar.slider("Days to fetch", min_value=1, max_value=30, value=1)
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(days=days)
        end_dt = now
    else:
        now = datetime.now(timezone.utc)
        min_dt = now - timedelta(days=30)
        default_start = now - timedelta(days=1)
        start_dt, end_dt = st.sidebar.slider(
            "Select time range",
            min_value=min_dt,
            max_value=now,
            value=(default_start, now),
            format="YYYY-MM-DD HH:mm",
        )
        delta_days = max(1, math.ceil((end_dt - start_dt).total_seconds() / 86400))
        days = int(delta_days)
else:
    # Local directory mode ignores timeframe entirely
    now = datetime.now(timezone.utc)
    start_dt = now - timedelta(days=1)
    end_dt = now
    days = 1

# Helper to run the crew and return the run_dir

def _run_ingestion_then_analysis(provider: str, days: int, start_dt: datetime, end_dt: datetime) -> Optional[str]:
    if not gemini_key:
        st.error("Please set your GOOGLE_API_KEY for Gemini.")
        return None
    os.environ["GOOGLE_API_KEY"] = gemini_key

    # Set runtime environment variables from UI for this session
    if provider == "GCP":
        if not gcp_json:
            st.error("Please provide the GCP Service Account JSON.")
            return None
        os.environ["GOOGLE_APPLICATION_CREDENTIALS_JSON"] = gcp_json
    else:
        if aws_source_mode == "Local Directory":
            if not aws_dir_input:
                st.error("Please provide the CloudTrail directory path.")
                return None
            p = Path(aws_dir_input).expanduser()
            if not p.exists() or not p.is_dir():
                st.error("CloudTrail directory not found or not a directory.")
                return None
            os.environ["AWS_CLOUDTRAIL_DIR"] = str(p.resolve())
            # Ensure we don't accidentally force API mode due to leftover envs
            os.environ.pop("AWS_ACCESS_KEY_ID", None)
            os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        else:
            if not (aws_key and aws_secret and aws_region):
                st.error("Please provide AWS key, secret, and region.")
                return None
            os.environ["AWS_ACCESS_KEY_ID"] = aws_key
            os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret
            os.environ["AWS_DEFAULT_REGION"] = aws_region
            os.environ.pop("AWS_CLOUDTRAIL_DIR", None)

    try:
        crew = CamaCrew().build(
            provider=provider,
            days=days,
            start_iso=start_dt.isoformat(),
            end_iso=end_dt.isoformat(),
        )
        with st.spinner("Running ingestion and analysis agents..."):
            result = crew.kickoff()
    except Exception as e:
        st.error(f"Agentic pipeline failed: {e}")
        return None

    # Try to locate the run directory from the result
    run_dir: Optional[str] = None
    for attr in ("tasks_output", "output", "raw"):
        if hasattr(result, attr):
            val = getattr(result, attr)
            if isinstance(val, list) and val:
                first = val[0]
                for subattr in ("output", "raw"):
                    if hasattr(first, subattr):
                        run_dir = getattr(first, subattr)
                        break
                if run_dir:
                    break
            elif isinstance(val, str):
                run_dir = val
                break
    if not run_dir:
        s = str(result)
        m = re.search(r"(\\.cache|/\.cache)[\\/](run_[^\s'\"]+)", s)
        if m:
            run_dir = str((PROJECT_ROOT / ".cache" / m.group(2)).resolve())

    if not run_dir:
        cache_root = PROJECT_ROOT / ".cache"
        candidates = [p for p in cache_root.glob("run_*") if p.is_dir()]
        if candidates:
            run_dir = str(sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0].resolve())

    return run_dir

# Content area for previews
col1, col2 = st.columns(2)
with col1:
    st.markdown("### Notes")
    st.markdown("- The output is written under the project-root `.cache/` folder in a unique `run_*` subdirectory.")
    st.markdown("- Files are grouped by activity (`methodName` for GCP, `eventName` for AWS). One JSON per activity.")
    st.markdown("- This app uses a CrewAI pipeline with 2 agents: Ingestion then Analysis (Gemini 2.5 Flash Lite).")

with col2:
    if "run_dir" in st.session_state and st.session_state.get("run_dir"):
        out_dir = st.session_state["run_dir"]
        st.success(f"Latest run directory: {out_dir}")
        out_path = Path(out_dir)
        if out_path.exists() and out_path.is_dir():
            files: List[Path] = sorted([p for p in out_path.iterdir() if p.is_file() and p.suffix == ".json"])
            if files:
                st.info(f"Found {len(files)} JSON file(s) in {out_dir}")
                for p in files[:10]:  # preview up to 10
                    st.write(f"- {p.name}")

# Fixed footer button styles
st.markdown(
    """
    <style>
    .fixed-footer {position: fixed; left: 0; right: 0; bottom: 0; background: white; padding: 12px 16px; border-top: 1px solid #ddd; z-index: 9999;}
    .fixed-footer .stButton>button {width: 240px; height: 42px; font-weight: 600;}
    </style>
    """,
    unsafe_allow_html=True,
)

# Footer container with the action button
with st.container():
    st.markdown('<div class="fixed-footer">', unsafe_allow_html=True)
    btn_col1, btn_col2 = st.columns([1, 3])
    with btn_col1:
        start = st.button("Start Analysis", type="primary")
    st.markdown('</div>', unsafe_allow_html=True)

if start:
    run_dir = _run_ingestion_then_analysis(provider, days, start_dt, end_dt)
    if run_dir:
        st.session_state["run_dir"] = run_dir
        st.success(f"Ingestion complete. Output directory: {run_dir}")
        try:
            st.switch_page("pages/analysis_app.py")
        except Exception:
            st.warning("Navigation issue detected.")
            if st.button("Continue to Analysis"):
                st.switch_page("pages/analysis_app.py")
