from __future__ import annotations

from pathlib import Path

import streamlit as st

# Ensure Streamlit recognizes pages in ./pages relative to this file
BASE = Path(__file__).resolve().parent

st.set_page_config(page_title="CAMA", layout="wide")

st.title("CAMA")
st.caption("Multi-agent ingestion and analysis of cloud audit logs.")

st.info("Opening the Ingestion page...")
try:
    st.switch_page("pages/ingestion_app.py")
except Exception:
    st.write("If not redirected, click the button below.")
    if st.button("Go to Ingestion"):
        st.switch_page("pages/ingestion_app.py")
