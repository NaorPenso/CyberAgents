"""WHOIS lookup tool for domain analysis."""

import socket
from typing import Any, ClassVar, Dict, Optional

import whois
from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field


class WhoisInput(BaseModel):
    """Input for WHOIS lookup."""

    domain: str = Field(..., description="Domain name to lookup")
    timeout: Optional[int] = Field(
        30, description="Timeout in seconds for the WHOIS query"
    )


class WhoisResult(BaseModel):
    """Structured result from a WHOIS lookup."""

    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: Optional[list] = None
    status: Optional[str] = None
    emails: Optional[str] = None
    dnssec: Optional[str] = None
    updated_date: Optional[str] = None


class WhoisError(BaseModel):
    """Error result from a WHOIS lookup."""

    error: str


class WhoisTool(BaseTool):
    """Tool for performing WHOIS lookups.

    This tool retrieves domain registration information using the WHOIS protocol.
    It handles various error conditions and returns structured data.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "whois_lookup"
    description: str = (
        "Lookup WHOIS information for a domain to retrieve registration details"
    )
    input_schema: ClassVar[type] = WhoisInput

    def _run(self, domain: str, timeout: int = 30) -> Dict[str, Any]:
        """Run WHOIS lookup for a domain.

        Args:
            domain: The domain name to lookup (e.g., "example.com")
            timeout: Timeout in seconds for the WHOIS query

        Returns:
            Dictionary containing structured WHOIS information or an error message

        Raises:
            No exceptions are raised; all errors are returned in the result dictionary
        """
        if not domain or not isinstance(domain, str):
            return {"error": "Invalid domain: must be a non-empty string"}

        # Basic domain format validation
        if ".." in domain or domain.startswith(".") or domain.endswith("."):
            return {"error": f"Invalid domain format: {domain}"}

        try:
            # Set a socket timeout to prevent hanging on unreachable servers
            socket.setdefaulttimeout(timeout)

            # Perform the WHOIS lookup
            w = whois.whois(domain)

            # Check if we got a valid response
            if w.domain_name is None:
                return {
                    "error": f"Domain not found or no WHOIS record available for {domain}"
                }

            # Extract and format the response
            result = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": (
                    str(w.expiration_date) if w.expiration_date else None
                ),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "updated_date": str(w.updated_date) if w.updated_date else None,
            }

            return result

        except whois.parser.PywhoisError as e:
            # Handle specific WHOIS parsing errors
            if "No match for domain" in str(e):
                return {"error": f"Domain not found: {domain}"}
            elif "Rate limit exceeded" in str(e):
                return {
                    "error": "WHOIS lookup rate limit exceeded. Please try again later."
                }
            else:
                return {"error": f"WHOIS parsing error: {str(e)}"}

        except socket.timeout:
            return {"error": f"WHOIS lookup timed out after {timeout} seconds"}

        except socket.error as e:
            return {"error": f"Network error during WHOIS lookup: {str(e)}"}

        except Exception as e:
            return {"error": f"Unexpected error during WHOIS lookup: {str(e)}"}

    async def _arun(self, domain: str, timeout: int = 30) -> Dict[str, Any]:
        """Run WHOIS lookup asynchronously.

        This method is a simple wrapper around the synchronous method as
        the python-whois package doesn't support async operations.

        Args:
            domain: The domain name to lookup
            timeout: Timeout in seconds for the WHOIS query

        Returns:
            Dictionary containing structured WHOIS information or an error message
        """
        return self._run(domain, timeout)
