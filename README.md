# CAMA: Agentic Cloud Audit Log Analysis

This project ingests cloud audit logs (GCP Cloud Audit Logs and AWS CloudTrail), groups them by action, and analyzes them using a two-agent CrewAI pipeline powered by Gemini 1.5 Flash. The UI is built with Streamlit.

Key points
- Two CrewAI agents (no YAML config):
  - Ingestion Agent: fetches logs and writes grouped JSON files under .cache/run_*
  - Analysis Agent: validates the run directory and signals the UI to render summaries and timelines
- Single entrypoint: src/cama/main.py exposes run() used by `crewai run`
- Streamlit pages live under src/pages (ingestion_app.py, analysis_app.py)
- LLM: Google Gemini 1.5 Flash via langchain-google-genai
- Output: .cache/run_YYYYMMDD_HHMMSS/*.json (one file per action)

Requirements
- Python 3.10–3.13
- Packages: streamlit, pandas, altair, python-dotenv, crewai, langchain-google-genai, google-cloud-logging, google-auth, boto3
- Network access to cloud APIs

Setup
1) Create a .env file in the project root:
   - GOOGLE_API_KEY=your_gemini_api_key
   - GOOGLE_GENAI_MODEL=gemini-1.5-flash
   Optionally (UI can also prompt at runtime):
   - GOOGLE_APPLICATION_CREDENTIALS_JSON=<full service account JSON string>
   - AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION

2) Install dependencies (examples):
   - pip install -U streamlit pandas altair python-dotenv crewai langchain-google-genai google-cloud-logging google-auth boto3

Run the application (CrewAI)
- crewai run
  - This calls cama.main:run(), which launches Streamlit on src/pages/ingestion_app.py
  - Configure provider and credentials, then click the fixed bottom button “Start Analysis”
  - The two-agent pipeline runs (ingestion -> analysis) and navigates to the analysis page

Alternative ways to run
- Streamlit directly:
  - streamlit run src/pages/ingestion_app.py
- CLI (no UI):
  - python -m cama.main --provider GCP --days 1
  - python -m cama.main --provider AWS --days 1

Notes
- Output files are grouped by action: methodName for GCP, eventName for AWS
- The .cache directory is recreated per run; previous contents are purged by the handlers
- No agents.yaml or tasks.yaml are used for the running pipeline; agent and task definitions are in code (see src/cama/agents and src/cama/crew.py)
- LLM defaults to gemini-1.5-flash; override via GOOGLE_GENAI_MODEL if desired
- Legacy copies under Resources/ remain but are unused; active pages are under src/pages/

Troubleshooting
- If navigation between pages fails, open the analysis page manually: streamlit run src/pages/analysis_app.py
- GCP: ensure valid Service Account JSON (with project_id) and Logs API permissions
- AWS: ensure CloudTrail is enabled and the IAM identity has lookup_events permissions
