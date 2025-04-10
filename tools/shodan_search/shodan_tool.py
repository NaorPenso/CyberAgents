"""Tool for searching Shodan for hosts associated with a domain."""

import logging
import os
from typing import Any, ClassVar, Dict, Optional

import shodan
from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

# Import the shared validation function
from ..validation_utils import is_potentially_valid_domain_for_tool

logger = logging.getLogger(__name__)


class ShodanHostInput(BaseModel):
    """Input for Shodan host search."""

    domain: str = Field(
        ..., description="Domain name to search for associated hosts in Shodan"
    )


class ShodanHostSearchTool(BaseTool):
    """Tool for querying Shodan's host search API."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "shodan_host_search"
    description: str = (
        "Searches Shodan for hosts, open ports, and services associated with a given domain. "
        "Requires the SHODAN_API_KEY environment variable to be set."
    )
    input_schema: ClassVar[type] = ShodanHostInput
    api_key: Optional[str] = None
    api: Optional[shodan.Shodan] = None

    def __init__(self, **kwargs):
        """Initialize the tool, checking for the Shodan API key."""
        super().__init__(**kwargs)
        self.api_key = os.getenv("SHODAN_API_KEY")
        if self.api_key:
            try:
                self.api = shodan.Shodan(self.api_key)
                # Test API key validity
                self.api.info()
                logger.info("Shodan API key loaded and validated successfully.")
            except shodan.APIError as e:
                logger.error(f"Shodan API key is invalid or failed validation: {e}")
                self.api = None  # Invalidate API object
            except Exception as e:
                logger.error(f"Unexpected error initializing Shodan API: {e}")
                self.api = None
        else:
            logger.warning(
                "SHODAN_API_KEY not found in environment variables. ShodanHostSearchTool will be unavailable."
            )

    def _check_api(self) -> bool:
        """Check if the Shodan API is available and initialized."""
        if self.api is None:
            if not self.api_key:
                logger.error("Shodan API key not set.")
            else:
                logger.error("Shodan API initialization failed.")
            return False
        return True

    def _run(self, domain: str) -> Dict[str, Any]:
        """Run Shodan host search for a domain."""
        # --- Input Validation ---
        if not is_potentially_valid_domain_for_tool(domain):
            logger.error(
                f"ShodanHostSearchTool received invalid domain input: '{domain}'"
            )
            return {
                "error": f"Invalid domain format provided: '{domain}'. Please provide a valid domain name."
            }
        # --- End Input Validation ---

        if not self._check_api():
            return {"error": "Shodan API key not configured or invalid."}

        logger.info(f"Searching Shodan for hosts matching domain: {domain}")
        try:
            # Search Shodan
            # Note: Shodan search syntax might need refinement for accuracy (e.g., using ssl:domain or hostname:)
            query = f"hostname:{domain}"
            results = self.api.search(query)

            hosts_data = []
            count = results.get("total", 0)
            logger.info(f"Shodan found {count} potential hosts for query '{query}'")

            for host in results.get("matches", []):
                host_info = {
                    "ip_str": host.get("ip_str"),
                    "port": host.get("port"),
                    "org": host.get("org"),
                    "hostname": host.get("hostnames"),  # List of hostnames
                    "location": host.get("location", {}).get("country_name"),
                    "product": host.get("product"),
                    "timestamp": host.get("timestamp"),
                    # Add more fields as needed, e.g., vulnerabilities (if available/paid API)
                }
                hosts_data.append(host_info)

            return {
                "domain": domain,
                "shodan_query": query,
                "total_results": count,
                "hosts": hosts_data,  # Return a limited subset or summary if needed
                "source": "shodan",
            }

        except shodan.APIError as e:
            logger.error(f"Shodan API error for domain {domain}: {e}")
            return {"error": f"Shodan API error: {e}"}
        except Exception as e:
            logger.error(
                f"Unexpected error during Shodan search for {domain}: {e}",
                exc_info=True,
            )
            return {"error": f"An unexpected error occurred during Shodan search: {e}"}

    async def _arun(self, domain: str) -> Dict[str, Any]:
        """Run Shodan host search asynchronously (delegates to sync)."""
        # The official shodan library is synchronous.
        return self._run(domain)
