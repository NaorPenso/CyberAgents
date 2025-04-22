"""Threat intelligence tool for domain analysis."""

import os
from typing import Any, ClassVar, Dict, List, Optional

import vt
from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from utils.rate_limiter import RateLimiter


class ThreatInput(BaseModel):
    """Input for domain threat scoring lookup."""

    domain: str = Field(..., description="Domain name to analyze")
    whois_data: Optional[Dict[str, Any]] = Field(
        default=None, description="WHOIS data for correlation"
    )


class DomainThreatScoreTool(BaseTool):
    """Tool for performing domain threat scoring analysis using VirusTotal."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: ClassVar[str] = "threat_intelligence"
    description: str = (
        "Analyze domain for security threats using VirusTotal and derive a threat score."
    )
    input_schema: ClassVar[type] = ThreatInput
    vt_client: Optional[vt.Client] = None
    rate_limiter: Optional[RateLimiter] = None

    def __init__(self):
        """Initialize the tool with API key."""
        super().__init__()
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            raise ValueError("VIRUSTOTAL_API_KEY environment variable is not set")
        self.vt_client = vt.Client(api_key)
        self.rate_limiter = RateLimiter()

    async def _analyze_virustotal(self, domain: str) -> Dict[str, Any]:
        """Analyze domain using VirusTotal."""
        try:
            # Apply rate limiting
            await self.rate_limiter.acquire()

            domain_obj = await self.vt_client.get_object_async(f"/domains/{domain}")
            return {
                "reputation": domain_obj.reputation,
                "last_analysis_stats": domain_obj.last_analysis_stats,
                "total_votes": domain_obj.total_votes,
                "last_analysis_date": str(domain_obj.last_analysis_date),
            }
        except Exception as e:
            logger.error(
                f"Unexpected error in DomainThreatScoreTool for {domain}: {e}",
                exc_info=True,
            )
            return {"error": str(e)}

    def _analyze_whois_indicators(
        self, whois_data: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Analyze WHOIS data for suspicious indicators."""
        indicators = []

        if whois_data:
            # Check for privacy protection
            if any(
                word in str(whois_data.get("registrar", "")).lower()
                for word in ["privacy", "proxy", "private", "redacted"]
            ):
                indicators.append("Privacy protection service used")

            # Check for recent registration
            creation_date = whois_data.get("creation_date")
            if creation_date and "error" not in str(creation_date).lower():
                indicators.append("Recently registered domain")

        return indicators

    def _run(
        self, domain: str, whois_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run threat analysis for a domain."""
        try:
            # For synchronous operation, we'll use a simple error response
            return {
                "error": "This tool requires async operation. Please use _arun instead.",
                "threat_score": 0.0,
                "virustotal_data": {},
                "indicators": [],
                "sources": [],
                "recommendations": ["Use async interface for threat analysis"],
            }
        except Exception as e:
            return {"error": str(e)}

    async def _arun(
        self, domain: str, whois_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run threat analysis asynchronously."""
        try:
            vt_results = await self._analyze_virustotal(domain)
            whois_indicators = self._analyze_whois_indicators(whois_data)

            threat_score = 0.0
            if "reputation" in vt_results and not "error" in vt_results:
                threat_score = max(0, min(100, abs(vt_results["reputation"]))) / 100

            return {
                "threat_score": threat_score,
                "virustotal_data": vt_results,
                "indicators": whois_indicators,
                "sources": ["VirusTotal", "WHOIS Analysis"],
                "recommendations": [
                    (
                        "Monitor domain for suspicious activity"
                        if threat_score > 0.3
                        else "No immediate action needed"
                    )
                ],
            }
        except Exception as e:
            return {"error": str(e)}
