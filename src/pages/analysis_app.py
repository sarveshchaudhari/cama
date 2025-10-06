from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import re

import streamlit as st
from dotenv import load_dotenv
import pandas as pd

# Ensure the project's src is on sys.path so we can import our package if needed
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Load .env if present
load_dotenv(dotenv_path=PROJECT_ROOT / ".env", override=False)

st.set_page_config(page_title="CAMA Analysis UI", layout="wide")
st.title("CAMA Analysis UI")
st.caption("Analyze previously ingested logs from .cache/run_* and present them in organized views.")

# ---- Helpers ----

def _parse_dt(val: Any) -> Optional[datetime]:
    if not val:
        return None
    try:
        dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        try:
            return datetime.fromtimestamp(float(val), tz=timezone.utc)
        except Exception:
            return None


def _first(items: Iterable[Any]) -> Optional[Any]:
    for x in items:
        if x is not None and x != "":
            return x
    return None


def _extract_region_from_resource_name(rn: str) -> Optional[str]:
    if not rn:
        return None
    for key in ("locations", "zones", "regions"):
        m = re.search(rf"/{key}/([^/]+)", rn)
        if m:
            return m.group(1)
    return None


def _normalize_gcp(entry: Dict[str, Any], source_file: str) -> Dict[str, Any]:
    pp = entry.get("protoPayload", {}) or {}
    jpay = entry.get("jsonPayload", {}) or {}
    res = entry.get("resource", {}) or {}
    rm = pp.get("requestMetadata", {}) or {}

    action = pp.get("methodName") or jpay.get("methodName") or "unknown"
    service = pp.get("serviceName") or res.get("type") or entry.get("logName")
    user = (
        pp.get("authenticationInfo", {}).get("principalEmail")
        or pp.get("serviceAccountKeyName")
        or None
    )
    resource = (
        pp.get("resourceName")
        or res.get("labels", {}).get("resource_name")
        or None
    )
    ip_addr = rm.get("callerIp") or entry.get("httpRequest", {}).get("remoteIp")

    time_val = _first(
        [entry.get("timestamp"), entry.get("receiveTimestamp"), pp.get("timestamp")]
    )
    when = _parse_dt(time_val)

    region = (
        (pp.get("resourceLocation", {}).get("currentLocations") or [None])[0]
        if isinstance(pp.get("resourceLocation", {}).get("currentLocations"), list)
        else None
    )
    if not region:
        region = res.get("labels", {}).get("location")
    if not region and isinstance(resource, str):
        region = _extract_region_from_resource_name(resource)

    return {
        "provider": "GCP",
        "time": when,
        "user": user,
        "action": action,
        "service": service,
        "resource": resource,
        "ip_address": ip_addr,
        "region": region,
        "source_file": source_file,
        "raw": entry,
    }


def _normalize_aws(event: Dict[str, Any], source_file: str) -> Dict[str, Any]:
    action = event.get("EventName") or "unknown"
    when = _parse_dt(event.get("EventTime"))
    user = event.get("Username")

    cte_raw = event.get("CloudTrailEvent")
    cte: Dict[str, Any] = {}
    if isinstance(cte_raw, str):
        try:
            cte = json.loads(cte_raw)
        except Exception:
            cte = {}

    event_source = cte.get("eventSource") or event.get("EventSource")
    ip_addr = cte.get("sourceIPAddress") or event.get("SourceIpAddress")
    region = cte.get("awsRegion") or event.get("AwsRegion")

    res_name = None
    resources = event.get("Resources")
    if isinstance(resources, list) and resources:
        names = [r.get("ResourceName") for r in resources if isinstance(r, dict)]
        names = [n for n in names if n]
        if names:
            res_name = ", ".join(sorted(set(names)))
    if not res_name:
        rp = cte.get("requestParameters") or {}
        for key in ("bucketName", "groupName", "instanceId", "streamName", "dbInstanceIdentifier"):
            if key in rp and rp.get(key):
                res_name = rp.get(key)
                break

    if not user:
        ui = cte.get("userIdentity") or {}
        user = ui.get("userName") or ui.get("arn") or ui.get("principalId")

    return {
        "provider": "AWS",
        "time": when,
        "user": user,
        "action": action,
        "service": event_source,
        "resource": res_name,
        "ip_address": ip_addr,
        "region": region,
        "source_file": source_file,
        "raw": event,
    }


def _load_run_dir(run_dir: Path) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    records: List[Dict[str, Any]] = []
    raw_files: Dict[str, List[Dict[str, Any]]] = {}

    for p in sorted(run_dir.glob("*.json")):
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        raw_files[p.name] = data
        if p.name.startswith("gcp_"):
            for entry in data:
                if isinstance(entry, dict):
                    records.append(_normalize_gcp(entry, p.name))
        elif p.name.startswith("aws_"):
            for entry in data:
                if isinstance(entry, dict):
                    records.append(_normalize_aws(entry, p.name))
        else:
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                if "protoPayload" in entry or "jsonPayload" in entry:
                    records.append(_normalize_gcp(entry, p.name))
                else:
                    records.append(_normalize_aws(entry, p.name))

    return records, raw_files


# ---- Sidebar: Run directory selection ----
st.sidebar.header("Data Source")
cache_root = PROJECT_ROOT / ".cache"
run_dirs = [p for p in cache_root.glob("run_*") if p.is_dir()]
run_dirs_sorted = sorted(run_dirs, key=lambda p: p.stat().st_mtime, reverse=True)
run_dir_labels = [str(p) for p in run_dirs_sorted]

selected_label = st.sidebar.selectbox(
    "Select a run directory", run_dir_labels, index=0 if run_dir_labels else None
)

custom_path = st.sidebar.text_input("Or enter a run directory path", value="")

selected_path = None
if "run_dir" in st.session_state and st.session_state.get("run_dir"):
    maybe = Path(str(st.session_state["run_dir"]))
    if maybe.exists() and maybe.is_dir():
        selected_path = maybe
        st.info(f"Using run directory from previous step: {selected_path}")

if not selected_path and custom_path:
    p = Path(custom_path)
    if p.exists() and p.is_dir():
        selected_path = p
    else:
        st.sidebar.error("Custom path is not a valid directory")
elif not selected_path and run_dirs_sorted:
    selected_path = run_dirs_sorted[0]

if not selected_path:
    st.info("No run directory found. Please use the ingestion app first.")
    st.stop()

st.success(f"Using run directory: {selected_path}")

# ---- Load and normalize ----
records, raw_files = _load_run_dir(selected_path)
if not records:
    st.warning("No records found in the selected directory.")
    st.stop()

# Convert to DataFrame for tabular views
rows: List[Dict[str, Any]] = []
for r in records:
    rows.append(
        {
            "time": r.get("time"),
            "User": r.get("user"),
            "Action": r.get("action"),
            "Service": r.get("service"),
            "Resource": r.get("resource"),
            "IP Address": r.get("ip_address"),
            "Region": r.get("region"),
            "Provider": r.get("provider"),
            "Source File": r.get("source_file"),
        }
    )

df = pd.DataFrame(rows)
if not df.empty and pd.api.types.is_datetime64_any_dtype(df["time"]) is False:
    # Ensure datetime dtype
    df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")

df_sorted = df.sort_values(by=["time"], ascending=True).reset_index(drop=True)

# ---- Detection Button ----
st.markdown("---")
st.subheader("Detection")
if st.button("Start Detection", type="primary"):
    st.session_state["start_detection"] = True
    try:
        st.switch_page("pages/detection_app.py")
    except Exception:
        st.warning("Navigation issue detected.")

# ---- Step 1: Detect actions ----
st.subheader("Detected Actions")
all_actions = sorted([a for a in df_sorted["Action"].dropna().unique().tolist()])
st.write(f"Found {len(all_actions)} unique action(s).")

action_counts = (
    df_sorted.groupby(["Provider", "Action"], dropna=False).size().reset_index(name="Count")
)
st.dataframe(action_counts, width="stretch")

# Filter controls
st.markdown("---")
st.subheader("Action Summary Table")
selected_actions = st.multiselect(
    "Filter by action", options=all_actions, default=all_actions[: min(10, len(all_actions))]
)
if selected_actions:
    view = df_sorted[df_sorted["Action"].isin(selected_actions)]
else:
    view = df_sorted

cols = ["time", "User", "Action", "Service", "Resource", "IP Address", "Region", "Provider", "Source File"]
view = view[cols]
st.dataframe(view, width="stretch")

# ---- Step 3: Event timeline ----
st.markdown("---")
st.subheader("Event Timeline")

st.write("Chronological list of events:")
st.dataframe(df_sorted[cols], width="stretch", height=300)

try:
    import altair as alt
    tmp = df_sorted.copy()
    tmp = tmp.dropna(subset=["time"]).copy()
    if not tmp.empty:
        tmp["bucket"] = tmp["time"].dt.floor("15min")
        counts = tmp.groupby(["bucket", "Provider"], dropna=False).size().reset_index(name="Events")
        chart = (
            alt.Chart(counts)
            .mark_line(point=True)
            .encode(x="bucket:T", y="Events:Q", color="Provider:N", tooltip=["bucket:T", "Provider:N", "Events:Q"])
            .properties(height=250)
        )
        st.altair_chart(chart, use_container_width=True)
except Exception:
    pass

# ---- Step 4: Full event details (raw JSON files) ----
st.markdown("---")
st.subheader("Full Event Details")
file_names = sorted(raw_files.keys())
sel_file = st.selectbox("Select a JSON file", options=file_names, index=0 if file_names else None)
if sel_file:
    st.write(f"Showing contents of: {sel_file}")
    pretty = st.checkbox("Pretty-print JSON", value=True)
    data = raw_files.get(sel_file, [])

    st.write(f"Total records: {len(data)}")
    if data:
        idx = st.number_input("Record index", min_value=0, max_value=max(0, len(data) - 1), value=0, step=1)
        rec = data[int(idx)]
        if pretty:
            st.json(rec)
        else:
            st.code(json.dumps(rec))

    with st.expander("View entire file (may be large)"):
        if pretty:
            st.json(data)
        else:
            st.code(json.dumps(data, ensure_ascii=False, indent=2))

st.markdown("---")
st.caption(
    "Notes: Actions are derived from GCP protoPayload.methodName or AWS EventName. "
    "User, Resource, IP, and Region are extracted on a best-effort basis from available fields."
)
