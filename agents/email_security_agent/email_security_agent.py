"""Agent responsible for validating email addresses and checking associated security records.

This agent combines email syntax validation with DNS checks (MX, DMARC, SPF) to
assess the deliverability and security posture of an email address.
"""

import logging
from typing import Any

# Import necessary components
from crewai import Agent

from agents.base_agent import BaseAgent
from tools.email_validation.email_validation_tool import EmailValidationTool

logger = logging.getLogger(__name__)


class EmailSecurityAgent(BaseAgent):
    """Agent specialized in email security analysis.

    Uses the EmailSecurityTool to check MX, SPF, and DMARC records.
    """

    def __init__(self, llm: Any):
        """Initialize the Email Security Agent with the passed LLM."""
        super().__init__(llm)
        self.agent_name = "EmailSecurityAgent"
        self.agent_role = "Email Security Specialist"
        self.agent_goal = (
            "Validate email addresses and analyze their security configuration (MX, SPF,"
            " DMARC)."
        )
        self.agent_backstory = (
            "An expert focused on email address validation and security. You verify email"
            " syntax, check for domain existence and MX records, and analyze SPF and"
            " DMARC policies to assess email deliverability and security posture."
        )
        self.agent_tools = [EmailValidationTool()]
        logger.info("Email Security Agent initialized")

        # Initialize the crewai Agent using PASSED LLM
        self.agent = Agent(
            role=self.agent_role,
            goal=self.agent_goal,
            backstory=self.agent_backstory,
            tools=self.agent_tools,
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
        )

    def get_agent(self) -> Agent:
        """Return the initialized crewai Agent instance."""
        return self.agent
