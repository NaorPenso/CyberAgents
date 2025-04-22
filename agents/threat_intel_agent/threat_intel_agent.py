"""Threat Intelligence Agent focused on gathering threat data for domains/IPs.

This agent utilizes VirusTotal API (via vt-py) to collect information on
malicious activities, resolutions, and related entities associated with a target.
"""

import logging
import os
from typing import Any

# Restore crewai import
from crewai import Agent

from agents.base_agent import BaseAgent
from tools.threat_intel_analyzer.threat_tool import ThreatTool

logger = logging.getLogger(__name__)


class ThreatIntelAgent(BaseAgent):
    """Agent specialized in threat intelligence gathering.

    Uses the ThreatTool to query external sources like VirusTotal.
    """

    def __init__(self, llm: Any):
        """Initialize the Threat Intelligence Agent with the passed LLM."""
        super().__init__(llm)
        self.agent_name = "ThreatIntelAgent"
        self.agent_role = "Threat Intelligence Analyst"
        self.agent_goal = (
            "Gather and analyze threat intelligence data (VirusTotal) for a given domain"
            " or IP address."
        )
        self.agent_backstory = (
            "You are a Threat Intelligence Analyst, adept at navigating the complex "
            "landscape of cyber threats. You utilize external data sources like "
            "VirusTotal to assess the reputation of domains and IPs, identifying "
            "potential malicious activity, associated indicators (like malware hashes "
            "or C2 servers), and known vulnerabilities. Your analysis helps "
            "prioritize risks and inform defensive strategies."
        )
        self.agent_tools = [ThreatTool()]
        logger.info("Threat Intelligence Agent initialized")

        # Check for required API keys
        if not os.environ.get("VIRUSTOTAL_API_KEY"):
            # Raise error if key is missing (skip is only for pytest context)
            raise ValueError(
                "VIRUSTOTAL_API_KEY environment variable is not set and is required for ThreatIntelAgent"
            )

        # Restore Agent initialization using PASSED LLM
        self.agent = Agent(
            role="Threat Intelligence Analyst",
            goal="Analyze security threats associated with a specific domain using external intelligence sources.",
            backstory="A seasoned security analyst specializing in threat intelligence. You leverage external databases like VirusTotal to assess domain reputation, identify malicious associations, and provide a structured threat score and summary.",
            tools=[ThreatTool()],
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
        )

    def get_agent(self) -> Agent:
        """Return the initialized crewai Agent instance."""
        return self.agent
