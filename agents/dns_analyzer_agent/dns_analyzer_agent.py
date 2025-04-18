"""
DNS Analyzer Agent specialized in DNS record lookup and analysis.

This agent uses DNS lookup tools to gather information about domain names.
"""

import logging

# Import necessary components
from crewai import Agent

from agents.base_agent import BaseAgent
from tools.dns_lookup.dns_tool import DNSTool
from utils.llm_utils import create_central_llm

logger = logging.getLogger(__name__)


class DNSAnalyzerAgent(BaseAgent):
    """Agent specialized in performing DNS lookups and analysis.

    Uses the DNSLookupTool to query various DNS record types.
    """

    def __init__(self):
        """Initialize the DNS Analyzer Agent."""
        super().__init__()
        self.agent_name = "DNSAnalyzerAgent"
        self.agent_role = "DNS Specialist"
        self.agent_goal = "Perform DNS lookups and analyze domain records."
        self.agent_backstory = (
            "An expert in DNS protocols and tools, specialized in querying and"
            " interpreting DNS records for domain intelligence."
        )
        self.agent_tools = [DNSTool()]
        logger.info("DNS Analyzer Agent initialized")

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
