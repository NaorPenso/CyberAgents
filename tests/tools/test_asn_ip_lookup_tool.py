"""Tests for the ASNIPLookupTool."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from tools.asn_ip_lookup_tool.asn_ip_lookup_tool import ASNIPLookupTool

# Constants for testing
TEST_DOMAIN = "google.com"
TEST_IP = "8.8.8.8"
TEST_INVALID_TARGET = "invalid-"
EXPECTED_IP_FOR_DOMAIN = "142.250.180.142"  # Example, may change
EXPECTED_ASN_FOR_IP = 15169
EXPECTED_ASN_NAME = "GOOGLE"


@pytest.fixture
def asn_tool():
    """Create an instance of ASNIPLookupTool for testing."""
    return ASNIPLookupTool()


def test_tool_initialization(asn_tool):
    """Test the tool initializes correctly."""
    assert asn_tool.name == "asn_ip_lookup"
    assert asn_tool.description is not None
    assert asn_tool.args_schema is not None


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_lookup_ip(mock_ipwhois, asn_tool):
    """Test looking up an IP address."""
    mock_instance = MagicMock()
    mock_instance.lookup_whois.return_value = {
        "asn": str(EXPECTED_ASN_FOR_IP),
        "asn_description": EXPECTED_ASN_NAME,
        "nets": [
            {"cidr": "8.8.8.0/24", "name": "LVLT-GOGL-8-8-8", "description": "Google"}
        ],
    }
    mock_ipwhois.return_value = mock_instance

    result = await asn_tool._arun(ip_address=TEST_IP)

    assert result is not None
    assert "error" not in result
    assert result.get("asn") == str(EXPECTED_ASN_FOR_IP)
    assert result.get("organization_name") == "LVLT-GOGL-8-8-8"
    mock_ipwhois.assert_called_once_with(TEST_IP)
    mock_instance.lookup_whois.assert_called_once()


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_lookup_domain(mock_ipwhois, asn_tool):
    """Test invalid domain input (tool expects IP)."""
    result = await asn_tool._arun(ip_address=TEST_DOMAIN)

    assert "error" in result
    assert "Invalid IP address format" in result["error"]
    mock_ipwhois.assert_not_called()


@pytest.mark.asyncio
async def test_invalid_target(asn_tool):
    """Test handling of an invalid target."""
    result = await asn_tool._arun(ip_address=TEST_INVALID_TARGET)
    assert "error" in result
    assert "Invalid IP address format" in result["error"]


@pytest.mark.asyncio
async def test_dns_failure(asn_tool):
    """Test invalid domain input (tool expects IP)."""
    result = await asn_tool._arun(ip_address="nonexistent.domain.xyz")

    assert "error" in result
    assert "Invalid IP address format" in result["error"]


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_ipwhois_failure(mock_ipwhois, asn_tool):
    """Test handling of IPWhois lookup failure."""
    mock_instance = MagicMock()
    mock_instance.lookup_whois.side_effect = Exception("WHOIS lookup failed")
    mock_ipwhois.return_value = mock_instance

    result = await asn_tool._arun(ip_address=TEST_IP)

    assert "error" in result
    assert "Failed to lookup ASN/IP info" in result["error"]
    assert "WHOIS lookup failed" in result["error"]
    mock_ipwhois.assert_called_once_with(TEST_IP)
    mock_instance.lookup_whois.assert_called_once()


@pytest.mark.asyncio
@patch("tools.asn_ip_lookup_tool.asn_ip_lookup_tool.IPWhois")
async def test_ipwhois_partial_data(mock_ipwhois, asn_tool):
    """Test handling when IPWhois returns partial data."""
    mock_instance = MagicMock()
    mock_instance.lookup_whois.return_value = {
        "asn": str(EXPECTED_ASN_FOR_IP),
        "nets": [{"cidr": "8.8.8.0/24"}],
    }
    mock_ipwhois.return_value = mock_instance

    result = await asn_tool._arun(ip_address=TEST_IP)

    assert result is not None
    assert "error" not in result
    assert result.get("asn") == str(EXPECTED_ASN_FOR_IP)
    assert result.get("organization_name") == "Unknown"
