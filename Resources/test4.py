import streamlit as st
import json
import pandas as pd
from datetime import datetime
from collections import Counter
import plotly.express as px

st.set_page_config(page_title="CloudTrail Inspector", layout="wide")
st.title("🕵️‍♂️ CloudTrail Inspector - Sleek Log Assistant")
st.markdown("Investigating suspicious AWS activity? Upload your logs and let's break it down 🧠")

# Step 1: Upload JSON
st.subheader("Step 1: Upload CloudTrail JSON Logs")
uploaded_files = st.file_uploader("Upload one or more CloudTrail log files", type="json", accept_multiple_files=True)

# Collect all events
all_records = []

if uploaded_files:
    for file in uploaded_files:
        try:
            data = json.load(file)
            all_records.extend(data.get("Records", []))
        except Exception as e:
            st.error(f"Error in {file.name}: {e}")

if all_records:
    unique_actions = sorted(set(record.get("eventName") for record in all_records))
    
    with st.expander("View All Detected Actions"):
        st.code(", ".join(unique_actions))

    st.subheader("🔍 Step 2: Select an AWS Action to Investigate")
    action_query = st.selectbox("Select an action from the list", ["-- Select Action --"] + unique_actions)

    if action_query != "-- Select Action --":
        matches = []
        for record in all_records:
            if record.get("eventName") == action_query:
                matches.append({
                    "Time": record.get("eventTime"),
                    "User": record.get("userIdentity", {}).get("arn", "Unknown"),
                    "Action": record.get("eventName"),
                    "Service": record.get("eventSource"),
                    "Resource": record.get("requestParameters", {}).get("bucketName", "N/A"),
                    "IP Address": record.get("sourceIPAddress"),
                    "Region": record.get("awsRegion", "Unknown"),
                    "Full Record": record
                })

        if matches:
            st.success(f"Found {len(matches)} `{action_query}` events.")
            df = pd.DataFrame(matches).drop(columns=["Full Record"])

            # Filters
            st.subheader("🔧 Filter the Results")
            col1, col2 = st.columns(2)
            selected_region = col1.selectbox("🌎 Filter by Region", ["All"] + df["Region"].unique().tolist())
            selected_user = col2.selectbox("👤 Filter by User", ["All"] + df["User"].unique().tolist())

            filtered_df = df.copy()
            if selected_region != "All":
                filtered_df = filtered_df[filtered_df["Region"] == selected_region]
            if selected_user != "All":
                filtered_df = filtered_df[filtered_df["User"] == selected_user]

            st.dataframe(filtered_df, use_container_width=True)

            # Summary Cards
            st.subheader("Top Users Summary")
            user_counts = Counter(filtered_df['User'])
            for user, count in user_counts.most_common(5):
                with st.expander(f"👤 {user} — {count} events"):
                    user_events = filtered_df[filtered_df['User'] == user]
                    st.table(user_events[['Time', 'Region', 'IP Address', 'Resource']])


            # Region vs User Heatmap
            st.subheader("Region vs User Activity")
            heatmap_data = pd.crosstab(filtered_df['Region'], filtered_df['User'])
            st.dataframe(heatmap_data)

            # Timeline
            st.subheader("Event Timeline")
            timeline_df = filtered_df.copy()
            timeline_df['Time'] = pd.to_datetime(timeline_df['Time'])
            timeline_df.sort_values('Time', inplace=True)
            for _, row in timeline_df.iterrows():
                st.markdown(f"**{row['Time']}** — `{row['Action']}` by `{row['User']}` from `{row['IP Address']}` in **{row['Region']}**")

            # Download filtered results
            csv = filtered_df.to_csv(index=False)
            st.download_button("Download Filtered Results as CSV", csv, file_name="cloudtrail_filtered.csv", mime="text/csv")

            # Raw JSON Viewer with Search
            st.subheader("📂 Full Event Details (Searchable)")
            json_search = st.text_input("🔎 Search text inside events (e.g., IP, resource, etc.)")
            for i, match in enumerate(matches):
                match_str = json.dumps(match["Full Record"]).lower()
                if json_search.lower() in match_str:
                    with st.expander(f"🧾 Event #{i+1} - {match['Time']} by {match['User']}"):
                        st.json(match["Full Record"])
        else:
            st.warning("No events found for that action.")
else:
    st.info("Upload CloudTrail logs to begin.")
