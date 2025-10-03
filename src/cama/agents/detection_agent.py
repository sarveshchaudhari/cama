from __future__ import annotations


class DetectionAgents:
    """Placeholder factory for detection-related agents."""

    def threat_detection_agent(self) -> object:
        """Return a basic threat detection Agent skeleton.

        Goal: Cross-reference activities with a knowledge base to detect potential threats and misconfigurations.
        """
        from crewai import Agent  # Lazy import to avoid import-time dependency errors

        return Agent(
            role="Threat Detection Agent",
            goal=(
                "Cross-reference activities with a knowledge base to detect potential threats and misconfigurations."
            ),
            backstory=(
                "You specialize in mapping activity patterns to known risks and configuration issues."
            ),
            tools=[],
            verbose=True,
            allow_delegation=False,
        )
