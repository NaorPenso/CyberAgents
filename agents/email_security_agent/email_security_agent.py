"""Agent responsible for validating email addresses and checking associated security records.

This agent combines email syntax validation with DNS checks (MX, DMARC, SPF) to
assess the deliverability and security posture of an email address.
"""

import logging

# Import necessary components
from crewai import Agent

from agents.base_agent import BaseAgent
from tools.email_validation.email_validation_tool import EmailValidationTool
from utils.llm_utils import create_central_llm

logger = logging.getLogger(__name__)


class EmailSecurityAgent(BaseAgent):
    """Agent specialized in email security analysis.

    Uses the EmailSecurityTool to check MX, SPF, and DMARC records.
    """

    def __init__(self):
        """Initialize the Email Security Agent."""
        super().__init__()
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

        # Initialize the crewai Agent
        self.agent = Agent(
            role=self.agent_role,
            goal=self.agent_goal,
            backstory=self.agent_backstory,
            tools=self.agent_tools,
            llm=create_central_llm(),
            verbose=True,
            allow_delegation=False,
        )
