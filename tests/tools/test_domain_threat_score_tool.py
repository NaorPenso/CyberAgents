"""Tests for the DomainThreatScoreTool."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import vt

from tools.domain_threat_scoring.domain_threat_score_tool import (
    DomainThreatScoreTool,
    ThreatInput,
)


@pytest.fixture
def mock_env_api_key(monkeypatch):
    """Fixture to mock the VIRUSTOTAL_API_KEY environment variable."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "mock-vt-api-key")


class TestDomainThreatScoreTool:
    """Test suite for the DomainThreatScoreTool."""

    def test_initialization_success(self, mock_env_api_key):
        """Test successful initialization with API key."""
        with patch("vt.Client") as mock_vt_client:
            tool = DomainThreatScoreTool()
            assert tool.vt_client is not None
            assert tool.rate_limiter is not None
            mock_vt_client.assert_called_once_with("mock-vt-api-key")

    def test_initialization_missing_key(self):
        """Test initialization raises ValueError if API key is missing."""
        with pytest.raises(
            ValueError, match="VIRUSTOTAL_API_KEY environment variable is not set"
        ):
            DomainThreatScoreTool()

    @pytest.mark.asyncio
    async def test_arun_success(self, mock_env_api_key):
        """Test successful asynchronous run with mocked VirusTotal response."""
        domain = "example.com"
        with patch(
            "tools.domain_threat_scoring.domain_threat_score_tool.DomainThreatScoreTool._analyze_virustotal",
            new_callable=AsyncMock,
        ) as mock_analyze_vt:
            with patch(
                "tools.domain_threat_scoring.domain_threat_score_tool.DomainThreatScoreTool._analyze_whois_indicators"
            ) as mock_analyze_whois:

                # Configure mock return values
                mock_analyze_vt.return_value = {
                    "reputation": -5,
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 0,
                        "harmless": 65,
                    },
                    "total_votes": {"malicious": 10, "harmless": 5},
                    "last_analysis_date": "2023-10-27 10:00:00",
                }
                mock_analyze_whois.return_value = ["Privacy protection service used"]

                tool = DomainThreatScoreTool()
                result = await tool._arun(
                    domain=domain, whois_data={}
                )  # Pass empty dict for whois for now

                assert "error" not in result
                assert result["domain"] == domain
                assert result["threat_score"] > 0  # Example assertion
                assert result["virustotal_data"] == mock_analyze_vt.return_value
                assert result["indicators"] == mock_analyze_whois.return_value
                mock_analyze_vt.assert_awaited_once_with(domain)
                mock_analyze_whois.assert_called_once()

    def test_run_returns_error(self, mock_env_api_key):
        """Test that the synchronous _run method returns the expected error."""
        tool = DomainThreatScoreTool()
        result = tool._run(domain="example.com")
        assert "error" in result
        assert "requires async operation" in result["error"]

    @pytest.mark.asyncio
    async def test_arun_vt_error(self, mock_env_api_key):
        """Test _arun handling when VirusTotal analysis fails."""
        # TODO: Implement test
        pass

    @pytest.mark.asyncio
    async def test_arun_unexpected_error(self, mock_env_api_key):
        """Test _arun handling for unexpected errors."""
        # TODO: Implement test
        pass

    # Add tests for _analyze_virustotal and _analyze_whois_indicators if needed
    # Add tests for input validation
