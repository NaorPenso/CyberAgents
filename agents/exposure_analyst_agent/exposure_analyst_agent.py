"""Agent responsible for identifying external exposure and attack surface."""

import logging

from crewai import Agent

from agents.base_agent import BaseAgent  # Import BaseAgent

# Import all relevant tools
from tools import (
    ASNIPLookupTool,
    NmapPortScanTool,
    ShodanHostSearchTool,
    SubdomainFinderTool,
)
from utils.llm_utils import create_central_llm

logger = logging.getLogger(__name__)


class ExposureAnalystAgent(BaseAgent):  # Inherit from BaseAgent
    """Creates and configures the Exposure Analyst agent.
    This agent identifies potential external facing assets like subdomains,
    IP blocks, and internet-connected hosts/services for a given domain or organization.
    It dynamically uses tools based on available API keys and system capabilities (Nmap).
    """

    def __init__(self):
        """Initializes the agent, dynamically selecting tools."""

        available_tools = []
        tool_descriptions = []

        # Tool 1: Subdomain Finder (crt.sh - no key needed)
        try:
            crtsh_tool = SubdomainFinderTool()
            available_tools.append(crtsh_tool)
            tool_descriptions.append(f"- {crtsh_tool.name}: {crtsh_tool.description}")
            logger.info(f"Tool added: {crtsh_tool.name}")
        except Exception as e:
            logger.error(f"Failed to initialize SubdomainFinderTool: {e}")

        # Tool 2: Shodan Host Search (requires SHODAN_API_KEY)
        try:
            shodan_tool = ShodanHostSearchTool()
            if shodan_tool.api is not None:
                available_tools.append(shodan_tool)
                tool_descriptions.append(
                    f"- {shodan_tool.name}: {shodan_tool.description}"
                )
                logger.info(f"Tool added: {shodan_tool.name}")
            else:
                logger.warning("Shodan tool not added (API key missing/invalid).")
        except Exception as e:
            logger.error(f"Failed to initialize ShodanHostSearchTool: {e}")

        # Tool 3: ASN/IP Lookup (no key needed)
        try:
            asn_tool = ASNIPLookupTool()
            available_tools.append(asn_tool)
            tool_descriptions.append(f"- {asn_tool.name}: {asn_tool.description}")
            logger.info(f"Tool added: {asn_tool.name}")
        except Exception as e:
            logger.error(f"Failed to initialize ASNIPLookupTool: {e}")

        # Tool 4: Nmap Port Scanner (requires nmap executable)
        try:
            nmap_tool = NmapPortScanTool()
            if nmap_tool.nm is not None:
                available_tools.append(nmap_tool)
                tool_descriptions.append(f"- {nmap_tool.name}: {nmap_tool.description}")
                logger.info(f"Tool added: {nmap_tool.name}")
            else:
                logger.warning(
                    "Nmap tool not added (nmap executable not found or failed init)."
                )
        except Exception as e:
            logger.error(f"Failed to initialize NmapPortScanTool: {e}")

        if not available_tools:
            logger.warning(
                "ExposureAnalystAgent initialized, but no tools are available/configured."
            )

        # Dynamically generate part of the goal/backstory based on available tools
        dynamic_tools_list = []
        if any(t.name == "subdomain_finder_crtsh" for t in available_tools):
            dynamic_tools_list.append("crt.sh subdomain search")
        if any(t.name == "shodan_host_search" for t in available_tools):
            dynamic_tools_list.append("Shodan host search")
        if any(t.name == "asn_ip_lookup" for t in available_tools):
            dynamic_tools_list.append("ASN/IP block lookup")
        if any(t.name == "nmap_port_scanner" for t in available_tools):
            dynamic_tools_list.append("Nmap port scanning")

        dynamic_goal_part = f"using available tools ({', '.join(dynamic_tools_list) or 'basic methods'}) to map the external attack surface, including subdomains, IP ranges, and open ports/services."

        dynamic_backstory_part = f"You utilize various techniques, such as {', '.join(dynamic_tools_list) or 'standard reconnaissance methods'}, to discover assets."

        self.agent = Agent(
            role="Exposure Analyst",
            goal=(
                "Identify potential externally facing assets (subdomains, IP blocks, hosts, services) for a given domain/organization, "
                + dynamic_goal_part
            ),
            backstory=(
                "An expert in attack surface management and reconnaissance. "
                + dynamic_backstory_part
                + " You provide a structured list and summary of discovered assets and their potential exposures."
            ),
            tools=available_tools,
            llm=create_central_llm(),
            verbose=True,
            allow_delegation=False,
        )
