from __future__ import annotations

import os


class AnalysisAgents:
    """Factory for analysis-related CrewAI agents."""

    def __init__(self, model: str | None = None, api_key: str | None = None, temperature: float = 0.2):
        raw_model = model or os.getenv("GOOGLE_GENAI_MODEL", "gemini-1.5-flash")
        raw_model = raw_model.replace("models/", "")
        self.model = f"gemini/{raw_model}" if "/" not in raw_model else raw_model
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.temperature = temperature

    def log_analysis_agent(self) -> object:
        """Return an analysis Agent that coordinates analysis of a run directory."""
        try:
            from crewai import Agent, LLM
        except Exception as exc:
            raise RuntimeError("'crewai' must be installed to create the agent") from exc

        if not self.api_key:
            raise RuntimeError("GOOGLE_API_KEY is required for Gemini LLM")

        llm = LLM(model=self.model, api_key=self.api_key, temperature=self.temperature)

        return Agent(
            role="Security Log Analysis Agent",
            goal=(
                "Given a run directory path containing grouped JSON logs, validate the location, "
                "identify present actions, and signal the UI to render timelines and tables."
            ),
            backstory=(
                "You orchestrate the analysis workflow. The UI handles visualization, "
                "while you verify inputs and produce concise summaries."
            ),
            tools=[],
            llm=llm,
            verbose=True,
            allow_delegation=False,
        )
