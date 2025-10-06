import streamlit as st
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
from collections import Counter
import google.cloud.logging
from google.oauth2 import service_account
from google.api_core.exceptions import GoogleAPICallError


# --- Helper Function to Convert GCP Log Entries to Clean Dictionaries ---
# This is the key to solving the formatting problem.
def entry_to_dict(entry):
    """Converts a GCP LogEntry object to a JSON-serializable dictionary."""
    # Use the official `to_api_repr()` method to get a dictionary representation
    log_dict = entry.to_api_repr()

    # Ensure all datetime objects are converted to strings
    def convert_datetimes(obj):
        if isinstance(obj, dict):
            return {k: convert_datetimes(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_datetimes(i) for i in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return obj

    return convert_datetimes(log_dict)


# --- Streamlit App UI ---
st.set_page_config(page_title="GCP Log Inspector", layout="wide")
st.title("🕵️‍♂️ GCP Log Inspector")
st.markdown("Fetch and analyze GCP Audit Logs to investigate activity in your project.")

# --- Step 1: Fetch Logs from GCP ---
st.subheader("Step 1: Configure and Fetch GCP Logs")

# Use session state to store credentials path and logs
if 'gcp_creds_path' not in st.session_state:
    st.session_state.gcp_creds_path = ""
if 'logs' not in st.session_state:
    st.session_state.logs = []

# Input for credentials file path
creds_path = st.text_input(
    "Enter the path to your GCP Service Account JSON file:",
    st.session_state.gcp_creds_path
)
st.session_state.gcp_creds_path = creds_path

days_to_fetch = st.slider("Select how many days of logs to fetch", 1, 30, 1)

if st.button("🚀 Fetch Logs"):
    if not creds_path:
        st.error("Please provide the path to your GCP credentials file.")
    else:
        try:
            with st.spinner(f"Fetching logs from the last {days_to_fetch} day(s)..."):
                cred = service_account.Credentials.from_service_account_file(creds_path)
                client = google.cloud.logging.Client(credentials=cred)

                end_time = datetime.now(timezone.utc)
                start_time = end_time - timedelta(days=days_to_fetch)
                start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

                # Filter specifically for audit logs, which are most interesting
                filter_str = f'logName:"cloudaudit.googleapis.com" AND timestamp >= "{start_time_str}" AND timestamp <= "{end_time_str}"'

                all_log_entries = list(client.list_entries(filter_=filter_str, page_size=500))  # Limit page size

                if not all_log_entries:
                    st.warning("No audit logs found for the specified time period.")
                    st.session_state.logs = []
                else:
                    # Convert all entries to clean dictionaries
                    st.session_state.logs = [entry_to_dict(entry) for entry in all_log_entries]
                    st.success(f"Successfully fetched {len(st.session_state.logs)} log entries.")

        except FileNotFoundError:
            st.error(f"Credentials file not found at: {creds_path}")
        except GoogleAPICallError as e:
            st.error(f"GCP API Error: {e.message}. Check your permissions and filter syntax.")
        except Exception as e:
            st.error(f"An unexpected error occurred: {e}")

# --- Step 2: Analyze Logs (only if logs are fetched) ---
if st.session_state.logs:
    # Extract unique actions (methodName) from the logs
    unique_actions = sorted(set(
        log.get("protoPayload", {}).get("methodName", "Unknown")
        for log in st.session_state.logs if "protoPayload" in log
    ))

    with st.expander("View All Detected Actions"):
        st.code(", ".join(unique_actions))

    st.subheader("🔍 Step 2: Select a GCP Action to Investigate")
    action_query = st.selectbox("Select an action from the list", ["-- Select Action --"] + unique_actions)

    if action_query != "-- Select Action --":
        matches = []
        for log in st.session_state.logs:
            proto_payload = log.get("protoPayload", {})
            if proto_payload.get("methodName") == action_query:
                matches.append({
                    "Time": log.get("timestamp"),
                    "User": proto_payload.get("authenticationInfo", {}).get("principalEmail", "Unknown"),
                    "Action": proto_payload.get("methodName"),
                    "Service": proto_payload.get("serviceName", "Unknown").replace(".googleapis.com", ""),
                    "Resource": proto_payload.get("resourceName", "N/A"),
                    "IP Address": proto_payload.get("requestMetadata", {}).get("callerIp", "N/A"),
                    "Region": log.get("resource", {}).get("labels", {}).get("location", "global"),
                    "Full Record": log  # Keep the full record for detailed view
                })

        if matches:
            st.success(f"Found {len(matches)} `{action_query}` events.")
            df = pd.DataFrame(matches).drop(columns=["Full Record"])

            # --- Filters ---
            st.subheader("🔧 Filter the Results")
            col1, col2 = st.columns(2)
            selected_region = col1.selectbox("🌎 Filter by Region", ["All"] + sorted(df["Region"].unique().tolist()))
            selected_user = col2.selectbox("👤 Filter by User", ["All"] + sorted(df["User"].unique().tolist()))

            filtered_df = df.copy()
            if selected_region != "All":
                filtered_df = filtered_df[filtered_df["Region"] == selected_region]
            if selected_user != "All":
                filtered_df = filtered_df[filtered_df["User"] == selected_user]

            st.dataframe(filtered_df, use_container_width=True)

            # --- Summary Cards ---
            st.subheader("Top Users Summary")
            user_counts = Counter(filtered_df['User'])
            for user, count in user_counts.most_common(5):
                with st.expander(f"👤 {user} — {count} events"):
                    user_events = filtered_df[filtered_df['User'] == user]
                    st.table(user_events[['Time', 'Region', 'IP Address', 'Resource']])

            # --- Timeline ---
            st.subheader("Event Timeline")
            timeline_df = filtered_df.copy()
            timeline_df['Time'] = pd.to_datetime(timeline_df['Time'])
            timeline_df.sort_values('Time', inplace=True)
            for _, row in timeline_df.iterrows():
                st.markdown(
                    f"**{row['Time']}** — `{row['Action']}` by `{row['User']}` from `{row['IP Address']}` in **{row['Region']}**")

            # --- Raw JSON Viewer with Search ---
            st.subheader("📂 Full Event Details (Searchable)")
            json_search = st.text_input("🔎 Search text inside events (e.g., IP, resource, etc.)")

            # Filter matches based on the filtered DataFrame indices
            filtered_matches = [matches[i] for i in filtered_df.index]

            for i, match in enumerate(filtered_matches):
                match_str = json.dumps(match["Full Record"]).lower()
                if not json_search or json_search.lower() in match_str:
                    with st.expander(f"🧾 Event #{i + 1} - {match['Time']} by {match['User']}"):
                        st.json(match["Full Record"])
        else:
            st.warning("No events found for that action.")