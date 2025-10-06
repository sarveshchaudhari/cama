from __future__ import annotations


class ReportingAgents:
    """Placeholder factory for reporting-related agents."""

    def reporting_agent(self) -> object:
        """Return a basic reporting Agent skeleton.

        Goal: Generate comprehensive security reports in markdown format, including a threat summary and an activity log.
        """
        from crewai import Agent  # Lazy import to avoid import-time dependency errors

        return Agent(
            role="Security Reporting Agent",
            goal=(
                "Generate comprehensive security reports in markdown format, including a threat summary and an activity log."
            ),
            backstory=(
                "You transform analytical findings into concise, actionable security reports for stakeholders."
            ),
            tools=[],
            verbose=True,
            allow_delegation=False,
        )
