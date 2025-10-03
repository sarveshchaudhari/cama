from __future__ import annotations

import os

from ..tools.gcp_tools import GCPLogIngestionTool
from ..tools.aws_tools import AWSLogIngestionTool


class IngestionAgents:
    """Factory for ingestion-related CrewAI agents."""

    def __init__(self, model: str | None = None, api_key: str | None = None, temperature: float = 0.2):
        self.model = model or os.getenv("GOOGLE_GENAI_MODEL", "gemini-1.5-pro")
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.temperature = temperature

    def log_ingestion_agent(self) -> object:
        """Create the agent responsible for cloud log ingestion and formatting.

        The agent can choose between AWS and GCP ingestion tools and must return the
        absolute path to the cache subdirectory created for the current run.
        """
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            from crewai import Agent
        except Exception as exc:
            raise RuntimeError(
                "Required packages 'langchain-google-genai' and 'crewai' must be installed to create the agent"
            ) from exc

        llm = ChatGoogleGenerativeAI(
            model=self.model,
            google_api_key=self.api_key,
            temperature=self.temperature,
        )

        return Agent(
            role="Cloud Log Ingestion and Formatting Agent",
            goal=(
                "Fetch cloud audit logs from the selected provider for the requested timeframe, "
                "group them by activity (methodName/eventName), and save one JSON file per "
                "unique activity into a unique .cache/run_* directory. Return the directory path."
            ),
            backstory=(
                "You efficiently collect and format ephemeral security logs for downstream "
                "analysis. You must ensure logs are grouped by activity name and saved into "
                "separate JSON files per activity in a unique run directory under .cache/."
            ),
            tools=[GCPLogIngestionTool(), AWSLogIngestionTool()],
            llm=llm,
            verbose=True,
            allow_delegation=False,
        )
