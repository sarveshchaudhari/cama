from __future__ import annotations

import os


class DetectionAgents:
    """Factory for detection-related agents (cloud-agnostic)."""

    def __init__(self, model: str | None = None, api_key: str | None = None, temperature: float = 0.2):
        raw_model = model or os.getenv("GOOGLE_GENAI_MODEL", "gemini-1.5-flash")
        raw_model = raw_model.replace("models/", "")
        self.model = f"gemini/{raw_model}" if "/" not in raw_model else raw_model
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.temperature = temperature

    def threat_detection_agent(self) -> object:
        """Create the Threat Detection agent using Gemini only (no web search).

        Responsibilities:
        - Analyze grouped audit logs (provider-agnostic) to identify threats/vulnerabilities.
        - Assign CVSS v3.x severity scores and provide remediation steps.
        - Map to compliance controls relevant to the provider (GCP or AWS).
        """
        try:
            from crewai import Agent, LLM
        except Exception as exc:
            raise RuntimeError("'crewai' must be installed to create the detection agent") from exc

        if not self.api_key:
            raise RuntimeError("GOOGLE_API_KEY is required for Gemini LLM")

        llm = LLM(model=self.model, api_key=self.api_key, temperature=self.temperature)

        return Agent(
            role="Threat, Vulnerability, and Compliance Detection Agent",
            goal=(
                "From provided audit log summaries, detect threats and misconfigurations, include CVSS scores, "
                "evidence, provider-specific compliance mapping, and actionable remediation steps."
            ),
            backstory=(
                "You specialize in cloud audit log analysis across providers (GCP, AWS). You correlate events, "
                "apply security best practices and compliance frameworks, and produce high-signal findings with clear remediation."
            ),
            tools=[],
            llm=llm,
            verbose=True,
            allow_delegation=False,
        )
