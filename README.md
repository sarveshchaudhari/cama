# CAMA: Agentic Cloud Audit Log Analysis

CAMA ingests cloud audit logs (GCP Cloud Audit Logs and AWS CloudTrail), groups them by action, and analyzes them using a lightweight three‑agent CrewAI pipeline powered by Google Gemini (via langchain-google-genai). The UI is built with Streamlit.

Highlights
- Two sequential agents:
  - Ingestion Agent: fetches logs and writes grouped JSON files under .cache/run_*
  - Analysis Agent: validates the run directory and summarizes results for the UI
- Streamlit app with pages (ingestion, analysis)
- LLM: Gemini 1.5 Flash by default (configurable)
- Outputs: one JSON per unique activity (GCP: methodName, AWS: eventName)

Requirements
- Python 3.10–3.13
- Internet access for cloud APIs when using API ingestion
- Dependencies (managed by pyproject.toml):
  - crewai[tools], langchain-google-genai
  - google-cloud-logging, google-auth
  - boto3, botocore
  - streamlit, python-dotenv
  - reportlab, cvss, cvsslib

Environment variables (.env supported)
- GOOGLE_API_KEY: Gemini API key (required)
- GOOGLE_GENAI_MODEL: defaults to gemini-1.5-flash
- GCP only
  - GOOGLE_APPLICATION_CREDENTIALS_JSON: full Service Account JSON string
- AWS (API mode)
  - AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
- AWS (Local Directory mode)
  - AWS_CLOUDTRAIL_DIR: folder path containing CloudTrail .json files (optional if provided in UI)

Setup
1) Create and activate a virtual environment
   - Windows: py -3 -m venv .venv, then .venv\\Scripts\\activate
   - macOS/Linux: python3 -m venv .venv, then source .venv/bin/activate
2) Install the project (installs all dependencies)
   - pip install -e .
3) Create a .env file (optional; you can also paste values in the UI)
   - GOOGLE_API_KEY=your_gemini_api_key
   - GOOGLE_GENAI_MODEL=gemini-1.5-flash
   - Optionally add provider credentials as described above

Ways to run
- CrewAI (recommended):
  - crewai run
    - Calls cama.main:run() and launches Streamlit (src/app.py)
- Streamlit directly:
  - streamlit run src/app.py
  - or streamlit run src/pages/ingestion_app.py
- CLI (no UI; runs the two-agent pipeline and prints the result):
  - python -m cama.main --provider GCP --days 1
  - python -m cama.main --provider AWS --days 1

How to use (UI)
1) Open the app (see “Ways to run”).
2) In the sidebar, pick your Cloud Provider: GCP or AWS.
3) Enter your Gemini key (GOOGLE_API_KEY) in the sidebar field or via .env.
4) Provide provider inputs:
   - GCP: paste your Service Account JSON into the text area.
   - AWS: choose ingestion source:
     - Local Directory: set the folder with CloudTrail .json files (defaults to Resources/CloudTrail). No AWS keys needed.
     - API: provide AWS key, secret, and region.
5) Select the timeframe (Days slider or Custom Range). Timeframe is ignored for AWS Local Directory mode.
6) Click “Start Analysis” (fixed footer button).
   - The Ingestion Agent writes grouped JSON files to .cache/run_YYYYMMDD_HHMMSS.
   - The Analysis Agent validates the run and summarizes counts.
7) You will be navigated to the Analysis page. If not, use the sidebar to open “analysis_app”.

Demo: Multi-agent flow
- Goal: see the two agents (ingestion -> analysis) end-to-end without external credentials.
- Use AWS Local Directory mode with the sample CloudTrail logs under Resources/CloudTrail.

Steps (UI)
- Ensure the project is installed and you have a valid GOOGLE_API_KEY.
- Start the app (e.g., crewai run or streamlit run src/app.py).
- In the sidebar:
  - Cloud Provider: AWS
  - Source: Local Directory
  - CloudTrail directory: Resources/CloudTrail (default path is prefilled)
- Click Start Analysis.
- Observe:
  - A folder .cache/run_YYYYMMDD_HHMMSS is created.
  - Multiple JSON files appear in that folder, one per eventName.
  - The app navigates to the Analysis page showing counts and a summary.
- Tip: Use the Clear Cache button to reset between runs.

Steps (CLI, headless)
- Set environment variables before running:
  - GOOGLE_API_KEY=your_gemini_api_key
  - AWS_CLOUDTRAIL_DIR=<absolute path to Resources/CloudTrail>
- Run the pipeline:
  - python -m cama.main --provider AWS --days 1
- Expected:
  - Console shows CrewAI logs and a final confirmation line from the analysis task.
  - A .cache/run_* directory with grouped JSON files is created.

GCP demo (requires credentials)
- In the UI, choose GCP and paste a valid Service Account JSON with Logs API access.
- Provide a timeframe and Start Analysis.
- Outputs are grouped by methodName under .cache/run_* and summarized on the Analysis page.

Where to see agent logs
- The terminal where Streamlit is running prints CrewAI verbose logs showing:
  - Ingestion Agent starting, tool selection (AWS/GCP), and writing files.
  - Analysis Agent validating the run directory and summarizing counts.

Outputs
- Location: project-root/.cache/run_*
- Content: one JSON file per unique activity
  - GCP: grouped by methodName
  - AWS: grouped by eventName
- The app previews the latest run and lists detected files.

Project layout (key paths)
- src/app.py: Streamlit entry; redirects to pages
- src/pages/ingestion_app.py: configuration + agentic run
- src/pages/analysis_app.py: post-ingestion summary view
- src/cama/crew.py: CrewAI setup (ingestion -> analysis)
- src/cama/agents/*: agent definitions
- src/cama/lib/*: provider log handlers (GCP/AWS)
- pyproject.toml: project metadata and dependencies

Troubleshooting
- Missing Gemini key
  - Set GOOGLE_API_KEY in .env or enter it in the sidebar field.
- GCP auth errors
  - Ensure the pasted Service Account JSON is valid and has Logs API access (with project_id).
- AWS API errors
  - Ensure CloudTrail is enabled and your IAM identity has permissions (e.g., lookup_events).
- Page navigation didn’t switch
  - Open the analysis page directly: streamlit run src/pages/analysis_app.py
- Clearing previous runs
  - Use the “Clear Cache” button in the sidebar; outputs live under .cache/

Notes
- The agents run sequentially; the analysis agent expects the run directory path from ingestion.
- The active implementation lives under src/; older experiments under Resources/ may exist but are not required to run the app.
