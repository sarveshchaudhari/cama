from __future__ import annotations

from crewai.tools import BaseTool

from ..lib.aws_handler import fetch_and_format_aws_logs


class AWSLogIngestionTool(BaseTool):
    """CrewAI tool to fetch and format AWS CloudTrail logs.

    Input: a string representing number of days (e.g., "7").
    Output: absolute path string to the unique cache subdirectory containing JSON files.
    """

    name: str = "aws_log_ingestion_tool"
    description: str = (
        "Fetch and group AWS CloudTrail events by eventName for the given number of days. "
        "Returns the absolute path to a .cache/run_* directory containing one JSON file per activity."
    )

    def _run(self, days: str) -> str:  # type: ignore[override]
        try:
            days_int = int(days)
        except Exception as exc:
            raise ValueError("'days' must be an integer string") from exc
        return fetch_and_format_aws_logs(days_int)
