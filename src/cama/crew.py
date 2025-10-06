from __future__ import annotations

import os
from typing import Optional, cast

from crewai import Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent

from .agents.ingestion_agent import IngestionAgents
from .agents.analysis_agent import AnalysisAgents


class CamaCrew:
    """CAMA multi-agent crew orchestrating ingestion then analysis.

    This crew uses two agents:
    - Ingestion Agent: fetches logs for a provider and writes grouped JSON files into .cache/run_*.
    - Analysis Agent: validates the run directory and prepares a concise summary signal for the UI.

    Notes:
    - We use Gemini 1.5 Flash via langchain-google-genai. Ensure GOOGLE_API_KEY is set in .env.
    - No YAML config is used; agent and task descriptions are inline for clarity.
    """

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        self.model = model or os.getenv("GOOGLE_GENAI_MODEL", "gemini-1.5-flash")
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")

        # Build agents
        self.ingestion_agent = cast(BaseAgent, IngestionAgents(model=self.model, api_key=self.api_key).log_ingestion_agent())
        self.analysis_agent = cast(BaseAgent, AnalysisAgents(model=self.model, api_key=self.api_key).log_analysis_agent())

    def build(self, provider: str, days: int, start_iso: str = "", end_iso: str = "") -> Crew:
        """Build a Crew that first ingests, then analyzes.

        provider: "GCP" or "AWS"
        days: positive integer timeframe window (consistent with ingestion handlers)
        start_iso/end_iso: only used for logging/context in the ingestion task prompt
        """
        # Task 1: Ingestion (must return ONLY the absolute run directory path)
        ingestion_task = Task(
            agent=self.ingestion_agent,
            description=(
                f"Provider: {provider}. Days: {days}. "
                f"Desired time window start: {start_iso} end: {end_iso}. "
                "Use the appropriate log ingestion tool to fetch all audit logs, group by activity, "
                "and save one JSON file per unique activity into a unique .cache/run_* directory. "
                "Return ONLY the absolute path to the created directory."
            ),
            expected_output="Absolute path to the run directory only.",
        )

        # Task 2: Analysis (consumes the path output from Task 1)
        analysis_task = Task(
            agent=self.analysis_agent,
            description=(
                "You will receive the absolute path to a .cache/run_* directory that contains grouped JSON logs. "
                "Validate that this path looks correct, list how many JSON files exist, and summarize how many "
                "unique actions are present per provider. Output a short confirmation line including the directory path."
            ),
            expected_output=(
                "A short confirmation line of the form: 'Analysis ready for <path> with <N> files and <M> actions.'"
            ),
            context=[ingestion_task],
        )

        crew = Crew(
            agents=[self.ingestion_agent, self.analysis_agent],
            tasks=[ingestion_task, analysis_task],
            process=Process.sequential,
            verbose=True,
        )
        return crew
