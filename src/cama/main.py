#!/usr/bin/env python
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

from cama.crew import CamaCrew  # noqa: F401

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run() -> None:
    """Entry point for `crewai run`.

    Launch the Streamlit root app (src/app.py) which recognizes src/pages/* as pages.
    """
    app_path = PROJECT_ROOT / "src" / "app.py"
    if not app_path.exists():
        raise FileNotFoundError(f"Streamlit app not found at: {app_path}")

    if not os.getenv("GOOGLE_API_KEY"):
        print("Warning: GOOGLE_API_KEY is not set. You can set it in .env or in the UI.")

    cmd = [sys.executable, "-m", "streamlit", "run", str(app_path)]
    subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=True)


def run_cli() -> int:
    parser = argparse.ArgumentParser(description="Run the CAMA two-agent pipeline (ingestion -> analysis)")
    parser.add_argument("--provider", choices=["GCP", "AWS"], required=True, help="Cloud provider")
    parser.add_argument("--days", type=int, default=1, help="Number of days back to fetch logs")
    parser.add_argument("--start", type=str, default="", help="Optional start time ISO8601")
    parser.add_argument("--end", type=str, default="", help="Optional end time ISO8601")
    args = parser.parse_args()

    if not os.getenv("GOOGLE_API_KEY"):
        print("ERROR: GOOGLE_API_KEY is not set in environment/.env")
        return 2

    start_iso = args.start or datetime.now(timezone.utc).isoformat()
    end_iso = args.end or datetime.now(timezone.utc).isoformat()

    from cama.crew import CamaCrew  # local import to avoid issues when only running Streamlit

    crew = CamaCrew().build(provider=args.provider, days=args.days, start_iso=start_iso, end_iso=end_iso)
    result = crew.kickoff()
    print("\nCrew finished. Result:")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
