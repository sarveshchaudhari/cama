import streamlit as st
import json
import os
from pathlib import Path
from dotenv import load_dotenv
from groq import Groq
import chromadb
from chromadb.config import Settings
from langchain_community.embeddings import HuggingFaceEmbeddings

# ------------------- Load Environment Variables -------------------
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY)

# ------------------- ChromaDB CONFIG -------------------
BASE_DIR = Path(__file__).resolve().parent
PERSIST_DIR = BASE_DIR / "chroma_aws_db"
CHROMA_COLLECTION_NAME = "aws_sigma_rules"
TOP_K = 3

chroma_client = chromadb.PersistentClient(path=PERSIST_DIR)
collection = chroma_client.get_collection(CHROMA_COLLECTION_NAME)
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# ------------------- Streamlit CONFIG -------------------
st.set_page_config(page_title="☁️ Multi-Cloud Log Inspector", layout="wide")
st.title("🕵️ Multi-Cloud Log Inspector")
st.markdown("Investigate suspicious activity in **AWS CloudTrail**, **GCP Audit Logs**, and **Azure Activity Logs** 🧠")

# ------------------- Step 1: Select Cloud Service -------------------
service_choice = st.radio("Select your cloud service", ["AWS CloudTrail", "GCP Audit Logs", "Azure Activity Logs"])

# ------------------- Step 2: AWS Log Source Choice -------------------
aws_log_source = None
if service_choice == "AWS CloudTrail":
    aws_log_source = st.radio("Choose AWS log source", ["Upload manually", "Fetch via credentials (coming soon)"])

# ------------------- Step 3: Upload Log Files -------------------
uploaded_files = st.file_uploader("Upload log files (JSON)", type="json", accept_multiple_files=True)
all_records = []

if uploaded_files:
    for file in uploaded_files:
        try:
            data = json.load(file)

            if service_choice == "AWS CloudTrail":
                all_records.extend(data.get("Records", []))

            elif service_choice == "GCP Audit Logs":
                if isinstance(data, dict) and "protoPayload" in data:
                    all_records.append(data)
                elif isinstance(data, list):
                    all_records.extend(data)
                else:
                    st.error(f"{file.name}: Unexpected GCP log format")

            elif service_choice == "Azure Activity Logs":
                if isinstance(data, dict) and "value" in data:
                    all_records.extend(data["value"])
                elif isinstance(data, list):
                    all_records.extend(data)
                else:
                    st.error(f"{file.name}: Unexpected Azure log format")

        except Exception as e:
            st.error(f"Error parsing {file.name}: {e}")

# ------------------- Step 4: AWS Analysis -------------------
if all_records and service_choice == "AWS CloudTrail":
    unique_actions = sorted(set(r.get("eventName") for r in all_records))
    st.subheader("🔍 Investigate AWS Actions")
    action_query = st.selectbox("Select an AWS action", ["-- Select Action --"] + unique_actions)

    if action_query != "-- Select Action --":
        matches = [r for r in all_records if r.get("eventName") == action_query]

        def summarize_record(record):
            return {
                "eventTime": record.get("eventTime"),
                "eventName": record.get("eventName"),
                "userIdentity": record.get("userIdentity", {}).get("arn"),
                "sourceIPAddress": record.get("sourceIPAddress"),
                "awsRegion": record.get("awsRegion"),
                "requestParameters": record.get("requestParameters"),
                "responseElements": record.get("responseElements"),
            }

        summary_logs = [summarize_record(r) for r in matches]
        logs_text = json.dumps(summary_logs, indent=2)

        st.subheader("🧾 Summarized Logs Preview")
        st.json(summary_logs)

        # ------------------- Vector DB Query -------------------
        query_embedding = embedding_model.embed_query(action_query)
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=TOP_K,
            include=["documents", "metadatas"]
        )

        vector_insights = ""
        for i, (doc, meta) in enumerate(zip(results["documents"][0], results["metadatas"][0])):
            vector_insights += f"\n--- Rule {i+1} ---\nTitle: {meta.get('title')}\nID: {meta.get('rule_id')}\nDescription:\n{doc[:500]}\n"

        # ------------------- LLM Threat Analysis -------------------
        if st.button("🔐 Analyze AWS Threats with Groq"):
            with st.spinner("Groq is analyzing AWS logs..."):
                try:
                    response = client.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=[
                            {
                                "role": "user",
                                "content": f"""
You are a cybersecurity expert.

The user uploaded AWS CloudTrail logs and selected the operation: **{action_query}**.

Here are the summarized log entries:
{logs_text}

Here are the top matching threat detection rules from the vector database:
{vector_insights}

Task:
1. Analyze the logs and identify potential threats. Use the rules only as reference—make final decisions based on your expertise.
2. Explain why these activities are suspicious.
3. Provide a deep threat summary in bullet points.
4. Recommend mitigation strategies.
(do not show rule errors)
"""
                            }
                        ]
                    )
                    st.subheader("🧠 Groq Threat Analysis")
                    st.markdown(response.choices[0].message.content)
                except Exception as e:
                    st.error(f"Groq API error: {e}")

# ------------------- GCP Logic (Unchanged) -------------------
elif all_records and service_choice == "GCP Audit Logs":
    unique_methods = sorted(set(r.get("protoPayload", {}).get("methodName") for r in all_records if "protoPayload" in r))
    st.subheader("🔍 Investigate GCP Methods")
    action_query = st.selectbox("Select a GCP method", ["-- Select Method --"] + unique_methods)

    if action_query != "-- Select Method --":
        matches = [r for r in all_records if r.get("protoPayload", {}).get("methodName") == action_query]

        def summarize_record(record):
            payload = record.get("protoPayload", {})
            return {
                "timestamp": record.get("timestamp"),
                "methodName": payload.get("methodName"),
                "resourceName": payload.get("resourceName"),
                "authenticationInfo": payload.get("authenticationInfo", {}),
                "request": payload.get("request"),
                "response": payload.get("response"),
            }

        summary_logs = [summarize_record(r) for r in matches]
        st.subheader("🧾 Summarized Logs Preview")
        st.json(summary_logs)

# ------------------- Azure Logic -------------------
elif all_records and service_choice == "Azure Activity Logs":
    unique_ops = sorted(set(r.get("operationName", {}).get("value") for r in all_records if "operationName" in r))
    st.subheader("🔍 Investigate Azure Operations")
    action_query = st.selectbox("Select an Azure operation", ["-- Select Operation --"] + unique_ops)

    if action_query != "-- Select Operation --":
        matches = [r for r in all_records if r.get("operationName", {}).get("value") == action_query]

        def summarize_record(record):
            return {
                "eventTimestamp": record.get("eventTimestamp"),
                "operationName": record.get("operationName", {}).get("value"),
                "caller": record.get("caller"),
                "resourceId": record.get("resourceId"),
                "status": record.get("status", {}).get("value"),
                "properties": record.get("properties"),
            }

        summary_logs = [summarize_record(r) for r in matches]
        logs_text = json.dumps(summary_logs, indent=2)

        st.subheader("🧾 Summarized Logs Preview")
        st.json(summary_logs)

        # ------------------- Vector DB Query -------------------
        query_embedding = embedding_model.embed_query(action_query)
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=TOP_K,
            include=["documents", "metadatas"]
        )

        vector_insights = ""
        for i, (doc, meta) in enumerate(zip(results["documents"][0], results["metadatas"][0])):
            vector_insights += f"\n--- Rule {i+1} ---\nTitle: {meta.get('title')}\nID: {meta.get('rule_id')}\nDescription:\n{doc[:500]}\n"

        # ------------------- LLM Threat Analysis -------------------
        if st.button("🔐 Analyze Azure Threats with Groq"):
            with st.spinner("Groq is analyzing Azure logs..."):
                try:
                    response = client.chat.completions.create(
                        model="llama-3.3-70b-versatile",
                        messages=[
                            {
                                "role": "user",
                                "content": f"""
You are a cybersecurity expert.

The user uploaded Azure Activity Logs and selected the operation: **{action_query}**.

Here are the summarized log entries:
{logs_text}

Here are the top matching threat detection rules from the vector database:
{vector_insights}

Task:
1. Analyze these logs and identify potential threats. Use the rules only as reference—make final decisions based on your expertise.
2. Explain why these operations might be suspicious.
3. Provide a detailed threat summary in bullet points.
4. Recommend mitigation strategies.
(do not show rule errors)
"""
                            }
                        ]
                    )
                    st.subheader("🧠 Groq Threat Analysis")
                    st.markdown(response.choices[0].message.content)
                except Exception as e:
                    st.error(f"Groq API error: {e}")

else:
    st.info("Upload logs to begin.")
