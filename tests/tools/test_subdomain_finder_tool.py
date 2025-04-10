"""Tests for the SubdomainFinderTool, including input validation."""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from tools import SubdomainFinderTool
from tools.subdomain_finder.subdomain_finder_tool import SubdomainInput

# Mock response from requests.get for crt.sh
MOCK_CRT_RESPONSE_JSON = [
    {"name_value": "test.example.com"},
    {"name_value": "www.example.com"},
    {"name_value": "mail.example.com"},
    {"name_value": "*.example.com"},  # Should be filtered out
    {"name_value": "example.com"},  # Base domain, should be filtered
]


@pytest.fixture
def subdomain_tool():
    """Fixture to create an instance of the SubdomainFinderTool."""
    return SubdomainFinderTool()


def test_tool_initialization(subdomain_tool):
    """Test basic tool attributes."""
    assert subdomain_tool.name == "subdomain_finder_crtsh"
    assert subdomain_tool.description is not None
    assert subdomain_tool.input_schema is not None


# Mock successful request for valid domain tests
@patch("tools.subdomain_finder.subdomain_finder_tool.requests.get")
def test_run_valid_domain(mock_get, subdomain_tool):
    """Test running the tool with a valid domain."""
    mock_response = MagicMock()
    # Simulate a minimal valid JSON response from crt.sh
    mock_response.json.return_value = [
        {"name_value": "test.example.com"},
        {"name_value": "sub.example.com"},
    ]
    mock_response.status_code = 200
    mock_response.text = '[{"name_value": "test.example.com"}]'  # Needed for null check
    mock_get.return_value = mock_response

    domain = "example.com"
    result = subdomain_tool._run(domain=domain)

    assert "error" not in result
    assert result["domain"] == domain
    assert isinstance(result["subdomains"], list)
    mock_get.assert_called_once()
    # Check if the URL construction looks right
    assert domain in mock_get.call_args[0][0]
    assert "output=json" in mock_get.call_args[0][0]


# Parameterize tests for various invalid inputs
@pytest.mark.parametrize(
    "invalid_input, description",
    [
        ("domain<script>.com", "XSS attempt"),
        ("dom;ain.com", "Command injection attempt (semicolon)"),
        ("dom ain.com", "Domain with space"),
        ("../../etc/passwd", "Path traversal attempt"),
        (".leadingdot.com", "Leading dot in label"),
        ("trailingdot.", "Trailing dot"),
        ("-leadinghyphen.com", "Leading hyphen in label"),
        ("trailinghyphen-.com", "Trailing hyphen in label"),
        ("", "Empty string"),
        ("a" * 600, "Domain exceeding length limit"),
        (".com", "Missing domain part"),
        (None, "None input"),
        (123, "Integer input"),
    ],
)
def test_run_invalid_inputs(subdomain_tool, invalid_input, description):
    """Test running the tool with various invalid inputs."""
    result = subdomain_tool._run(domain=invalid_input)

    print(
        f"Testing {description}: Input='{invalid_input}', Result='{result}'"
    )  # Debugging output
    assert "error" in result
    assert isinstance(result["error"], str)
    # Check if the error message indicates invalid input
    assert "Invalid domain format" in result["error"]
    # Check if the original invalid input is reflected in the error message (optional but good)
    assert str(invalid_input) in result["error"]


# Explicit test for None, although covered by parametrize
def test_run_none_input(subdomain_tool):
    """Test running the tool with None as input."""
    result = subdomain_tool._run(domain=None)
    assert "error" in result
    assert "Invalid domain format" in result["error"]


# Explicit test for empty string, although covered by parametrize
def test_run_empty_string_input(subdomain_tool):
    """Test running the tool with an empty string as input."""
    result = subdomain_tool._run(domain="")
    assert "error" in result
    assert "Invalid domain format" in result["error"]


@pytest.mark.asyncio
@patch("requests.get")
async def test_arun_success(mock_get, subdomain_tool):
    """Test a successful run retrieving and parsing subdomains."""
    # Mock the requests.get call
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_CRT_RESPONSE_JSON
    mock_get.return_value = mock_response

    domain = "example.com"
    result = await subdomain_tool._arun(domain=domain)

    assert "error" not in result
    assert "subdomains" in result
    assert len(result["subdomains"]) == 3  # test, www, mail
    assert "test.example.com" in result["subdomains"]
    assert "www.example.com" in result["subdomains"]
    assert "mail.example.com" in result["subdomains"]
    assert "*.example.com" not in result["subdomains"]
    assert "example.com" not in result["subdomains"]

    # Verify requests.get was called correctly
    mock_get.assert_called_once()
    assert f"crt.sh/?q=%25.{domain}&output=json" in mock_get.call_args[0][0]


@pytest.mark.asyncio
@patch("requests.get")
async def test_arun_crtsh_error(mock_get, subdomain_tool):
    """Test handling errors from the crt.sh API."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_get.return_value = mock_response

    result = await subdomain_tool._arun(domain="example.com")

    assert "error" in result
    assert "crt.sh request failed" in result["error"]
    assert "Status code: 500" in result["error"]


@pytest.mark.asyncio
@patch("requests.get")
async def test_arun_crtsh_timeout(mock_get, subdomain_tool):
    """Test handling timeouts when contacting crt.sh."""
    mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

    result = await subdomain_tool._arun(domain="example.com")

    assert "error" in result
    assert "crt.sh request timed out" in result["error"]


@pytest.mark.asyncio
@patch("requests.get")
async def test_arun_crtsh_connection_error(mock_get, subdomain_tool):
    """Test handling connection errors when contacting crt.sh."""
    mock_get.side_effect = requests.exceptions.ConnectionError("Connection failed")

    result = await subdomain_tool._arun(domain="example.com")

    assert "error" in result
    assert "crt.sh connection error" in result["error"]


@pytest.mark.asyncio
@patch("requests.get")
async def test_arun_invalid_json(mock_get, subdomain_tool):
    """Test handling invalid JSON response from crt.sh."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "{", 0)
    mock_get.return_value = mock_response

    result = await subdomain_tool._arun(domain="example.com")

    assert "error" in result
    assert "Failed to parse JSON response from crt.sh" in result["error"]


@pytest.mark.asyncio
async def test_arun_invalid_domain(subdomain_tool):
    """Test running the tool with an invalid domain format."""
    # The tool's Pydantic model should handle this, but we test the run method too
    result = await subdomain_tool._arun(domain="invalid domain name")
    # The exact error might depend on whether validation happens before _arun
    # or if requests simply fails. Aim for a general error message.
    assert "error" in result
    # A more specific check might be fragile, e.g., "Invalid domain format"
