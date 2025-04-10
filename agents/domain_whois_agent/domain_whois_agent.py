"""Domain WHOIS Agent specialized in retrieving WHOIS information for domains.

This agent utilizes WHOIS lookup tools to gather registration and contact
details associated with a given domain name.
"""

import logging

# Import necessary components
from crewai import Agent

from tools.whois_lookup.whois_tool import WhoisTool

from ..base_agent import BaseAgent

logger = logging.getLogger(__name__)


class DomainWhoisAgent(BaseAgent):
    """Agent specialized in performing WHOIS lookups for domains.

    Uses the WhoisLookupTool to retrieve domain registration information.
    """

    def __init__(self):
        """Initialize the Domain Registrar Analyst agent."""
        super().__init__()
        self.whois_tool = WhoisTool()
        self.agent = Agent(
            role="Domain Registrar Analyst",
            goal="Retrieve and structure WHOIS information for a domain.",
            backstory=(
                "You are an analyst focused on domain registration data. You use WHOIS "
                "lookups to find details about domain ownership, registration dates, "
                "and nameservers, providing structured information."
            ),
            tools=[self.whois_tool],
            verbose=True,
            allow_delegation=False,
        )
        self.agent_name = "DomainWhoisAgent"
        self.agent_role = "Domain Registrar Analyst"
        self.agent_goal = "Retrieve and structure WHOIS information for a domain."
        self.agent_backstory = (
            "A meticulous analyst specializing in domain registration data. You query"
            " WHOIS servers to find domain ownership, contact information, registration"
            " dates, and name server details, presenting findings clearly."
        )
        logger.info("Domain WHOIS Agent initialized")
