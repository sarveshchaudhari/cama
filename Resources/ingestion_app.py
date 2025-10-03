from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List
from datetime import datetime, timedelta, timezone
import math

import streamlit as st
from dotenv import load_dotenv

# Ensure the project's src is on sys.path so we can import our package
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Load .env if present
load_dotenv(dotenv_path=PROJECT_ROOT / ".env", override=False)

# Lazy imports of our modules (after sys.path adjustment)
from cama.lib.gcp_handler import fetch_and_format_gcp_logs
from cama.lib.aws_handler import fetch_and_format_aws_logs
from cama.agents.ingestion_agent import IngestionAgents

try:
    from crewai import Crew, Task, Process
except Exception:
    Crew = None  # type: ignore
    Task = None  # type: ignore
    Process = None  # type: ignore

st.set_page_config(page_title="CAMA Ingestion Test UI", layout="wide")
st.title("CAMA Ingestion Test UI")
st.caption("Use this UI to verify that log ingestion, grouping, and file output to .cache/ works as expected.")

# Sidebar configuration
st.sidebar.header("Configuration")
provider = st.sidebar.selectbox("Cloud Provider", ["GCP", "AWS"])

# Timeframe selection (Days vs Custom Range)
timeframe_mode = st.sidebar.radio("Timeframe Mode", ["Days", "Custom Range"], index=0)
if timeframe_mode == "Days":
    days = st.sidebar.slider("Days to fetch", min_value=1, max_value=30, value=1)
    # Derive start/end for display
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
    # Compute days window for handlers/tools (rounded up, min 1)
    delta_days = max(1, math.ceil((end_dt - start_dt).total_seconds() / 86400))
    days = int(delta_days)

use_agent = st.sidebar.checkbox("Use Ingestion Agent (LLM)", value=False)

st.sidebar.markdown("---")
if use_agent:
    gemini_key = st.sidebar.text_input("GOOGLE_API_KEY (Gemini)", value=os.getenv("GOOGLE_API_KEY", ""), type="password")
else:
    gemini_key = os.getenv("GOOGLE_API_KEY", "")

st.sidebar.markdown("---")

if provider == "GCP":
    st.subheader("GCP Credentials")
    st.write("Paste your Service Account JSON. It will be used only in-memory for this session.")
    gcp_json_default = os.getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON", "")
    gcp_json = st.text_area("Service Account JSON", value=gcp_json_default, height=200)
else:
    st.subheader("AWS Credentials")
    aws_key = st.text_input("AWS_ACCESS_KEY_ID", value=os.getenv("AWS_ACCESS_KEY_ID", ""))
    aws_secret = st.text_input("AWS_SECRET_ACCESS_KEY", value=os.getenv("AWS_SECRET_ACCESS_KEY", ""), type="password")
    aws_region = st.text_input("AWS_DEFAULT_REGION", value=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))

col1, col2 = st.columns(2)

with col1:
    if st.button("Run Ingestion"):
        try:
            # Set runtime environment variables from UI for this session
            if provider == "GCP":
                if not gcp_json:
                    st.error("Please provide the GCP Service Account JSON.")
                    st.stop()
                os.environ["GOOGLE_APPLICATION_CREDENTIALS_JSON"] = gcp_json
            else:
                if not (aws_key and aws_secret and aws_region):
                    st.error("Please provide AWS key, secret, and region.")
                    st.stop()
                os.environ["AWS_ACCESS_KEY_ID"] = aws_key
                os.environ["AWS_SECRET_ACCESS_KEY"] = aws_secret
                os.environ["AWS_DEFAULT_REGION"] = aws_region

            if use_agent:
                if not gemini_key:
                    st.error("Please set your GOOGLE_API_KEY for Gemini to use the agent.")
                    st.stop()
                os.environ["GOOGLE_API_KEY"] = gemini_key

                if Crew is None or Task is None or Process is None:
                    st.error("'crewai' is not installed or could not be imported. Please install it to use the agent mode.")
                    st.stop()

                # Build the ingestion agent with Gemini
                ingestion_agent = IngestionAgents().log_ingestion_agent()

                # Create a simple task that instructs the agent to use the correct tool
                task_text = (
                    f"Provider: {provider}. Days: {days}. "
                    f"Desired time window start: {start_dt.isoformat()} end: {end_dt.isoformat()}. "
                    "Use the appropriate log ingestion tool to fetch all audit logs, group by activity, "
                    "and save one JSON file per unique activity into a unique .cache/run_* directory. "
                    "Return ONLY the absolute path to the created directory."
                )
                task = Task(description=task_text, expected_output="Absolute path to the run directory only.", agent=ingestion_agent)
                crew = Crew(agents=[ingestion_agent], tasks=[task], process=Process.sequential, verbose=True)

                with st.spinner("Running ingestion agent..."):
                    result = crew.kickoff()

                # Try to derive a path string from the agent result
                out_dir = None
                for attr in ("output", "raw"):
                    if hasattr(result, attr):
                        out_dir = getattr(result, attr)
                        break
                if not out_dir:
                    out_dir = str(result).strip()
            else:
                # Direct handler call (no LLM involvement)
                with st.spinner("Fetching and grouping logs via handler..."):
                    if provider == "GCP":
                        out_dir = fetch_and_format_gcp_logs(days)
                    else:
                        out_dir = fetch_and_format_aws_logs(days)

            st.success(f"Ingestion complete. Output directory: {out_dir}")
            st.caption(f"Time window used: {start_dt.isoformat()} to {end_dt.isoformat()} (days window={days})")

            # List created files for verification
            out_path = Path(out_dir)
            if out_path.exists() and out_path.is_dir():
                files: List[Path] = sorted([p for p in out_path.iterdir() if p.is_file() and p.suffix == ".json"])
                if not files:
                    st.warning("No JSON files found in the output directory. Check credentials and permissions.")
                else:
                    st.info(f"Found {len(files)} JSON file(s) in {out_dir}")
                    for p in files:
                        st.write(f"- {p.name}")
                        with p.open("r", encoding="utf-8") as f:
                            preview = f.read(5000)
                        with st.expander(f"Preview: {p.name}"):
                            st.code(preview or "<empty>")
            else:
                st.error("The returned directory does not exist. Please verify credentials and try again.")

        except Exception as e:
            st.error(f"Ingestion failed: {e}")

with col2:
    st.markdown("### Notes")
    st.markdown("- The output is written under the project-root `.cache/` folder in a unique `run_*` subdirectory.")
    st.markdown("- Files are grouped by activity (`methodName` for GCP, `eventName` for AWS). One JSON per activity.")
    st.markdown("- Use Agent mode to verify that the CrewAI agent can autonomously choose the correct tool.")
    st.markdown("- Use Direct mode to test the core ingestion handlers without LLM involvement.")

st.markdown("---")
st.markdown("Example of expected file naming: `gcp_storage_buckets_create.json`, `aws_iam_createuser.json`, etc.")


