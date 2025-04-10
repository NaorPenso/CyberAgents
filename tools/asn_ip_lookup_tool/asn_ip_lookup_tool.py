"""Tool for looking up ASN and IP blocks for an IP address."""

import ipaddress  # Import ipaddress for validation
import logging
from typing import Any, ClassVar, Dict

from crewai.tools import BaseTool
from ipwhois import IPWhois
from pydantic import BaseModel, ConfigDict, Field


# --- Add validation helper ---
def is_valid_ip_address(ip_str: str) -> bool:
    """Checks if the string is a valid IPv4 or IPv6 address."""
    if not isinstance(ip_str, str) or not ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


# --- End validation helper ---

logger = logging.getLogger(__name__)


class ASNIPInput(BaseModel):
    """Input for ASN/IP lookup."""

    ip_address: str = Field(
        ..., description="IP address to look up ASN and network information for"
    )


class ASNIPLookupTool(BaseTool):
    """Tool for querying WHOIS data for an IP address to find ASN and netblocks."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "asn_ip_lookup"
    description: str = (
        "Looks up the ASN (Autonomous System Number), associated IP network blocks (CIDRs), and organization name for a given IP address using WHOIS data."
    )
    input_schema: ClassVar[type] = ASNIPInput

    def _run(self, ip_address: str) -> Dict[str, Any]:
        """Run ASN/IP lookup."""
        # --- Input Validation ---
        if not is_valid_ip_address(ip_address):
            logger.error(
                f"ASNIPLookupTool received invalid IP address input: '{ip_address}'"
            )
            return {
                "error": f"Invalid IP address format provided: '{ip_address}'. Please provide a valid IPv4 or IPv6 address."
            }
        # --- End Input Validation ---

        logger.info(f"Looking up ASN and network info for IP: {ip_address}")
        try:
            obj = IPWhois(ip_address)
            results = obj.lookup_whois(inc_raw=False)

            asn_info = {
                "ip_address": ip_address,
                "asn": results.get("asn"),
                "asn_cidr": results.get("asn_cidr"),
                "asn_description": results.get("asn_description"),
                "asn_registry": results.get("asn_registry"),
                "nets": results.get("nets"),  # List of network blocks
            }

            # Try to extract primary organization name from nested nets
            org_name = "Unknown"
            if asn_info["nets"] and isinstance(asn_info["nets"], list):
                for net in asn_info["nets"]:
                    if isinstance(net, dict) and net.get("name"):
                        org_name = net["name"]
                        break
            asn_info["organization_name"] = org_name

            logger.info(
                f"Found ASN {asn_info['asn']} ({asn_info['organization_name']}) for IP {ip_address}"
            )
            return asn_info

        except Exception as e:
            logger.error(
                f"Error during ASN/IP lookup for {ip_address}: {e}", exc_info=True
            )
            return {"error": f"Failed to lookup ASN/IP info for {ip_address}: {e}"}

    async def _arun(self, ip_address: str) -> Dict[str, Any]:
        """Run ASN/IP lookup asynchronously (delegates to sync)."""
        # ipwhois is synchronous
        return self._run(ip_address)
