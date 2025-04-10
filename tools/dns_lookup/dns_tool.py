"""DNS lookup tool for domain analysis."""

from typing import Any, ClassVar, Dict, List, Optional

import dns.resolver
from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field


class DNSInput(BaseModel):
    """Input for DNS lookup."""

    domain: str = Field(..., description="Domain name to lookup")
    record_types: List[str] = Field(
        default=["A", "MX", "NS", "TXT", "AAAA"],
        description="DNS record types to query",
    )


class DNSTool(BaseTool):
    """Tool for performing DNS lookups."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "dns_lookup"
    description: str = "Lookup DNS records for a domain"
    input_schema: ClassVar[type] = DNSInput

    def _run(
        self, domain: str, record_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Run DNS lookup for a domain."""
        if record_types is None:
            record_types = ["A", "MX", "NS", "TXT", "AAAA"]

        results = {}
        resolver = dns.resolver.Resolver()

        try:
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    results[record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    results[record_type] = []
                except Exception as e:
                    results[record_type] = {"error": str(e)}

            # Check DNSSEC
            try:
                answers = resolver.resolve(domain, "DNSKEY")
                results["dnssec"] = True
            except BaseException:
                results["dnssec"] = False

            return results
        except Exception as e:
            return {"error": str(e)}

    async def _arun(
        self, domain: str, record_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Run DNS lookup asynchronously."""
        return self._run(domain, record_types)
