"""Tests for the ExposureAnalystAgent."""

import os
from unittest.mock import MagicMock, patch

import pytest

from agents.exposure_analyst_agent.exposure_analyst_agent import ExposureAnalystAgent


@pytest.fixture
def mock_env():
    """Fixture to mock environment variables."""
    with patch.dict(
        os.environ,
        {"SHODAN_API_KEY": "test_key", "OPENAI_API_KEY": "test_key"},
        clear=True,
    ):
        yield


# Apply mocks needed for ExposureAnalystAgent initialization
@patch(
    "tools.nmap_port_scan_tool.nmap_port_scan_tool.subprocess.run"
)  # Mock nmap executable check
@patch(
    "tools.nmap_port_scan_tool.nmap_port_scan_tool.nmap.PortScanner"
)  # Mock nmap library scanner init
@patch("tools.shodan_search.shodan_tool.shodan.Shodan")  # Mock Shodan client
def test_exposure_analyst_agent_initialization(
    mock_shodan_client,
    mock_nmap_scanner,  # Renamed for clarity
    mock_subprocess_run,
    mock_env,  # Use the fixture
):
    """Test that the ExposureAnalystAgent initializes correctly (with mocks)."""
    # Configure the nmap executable check mock
    mock_subprocess_run.return_value = None  # Simulate nmap executable found

    # Configure the mock for nmap.PortScanner() called within NmapPortScanTool.__init__
    mock_nmap_scanner_instance = MagicMock()
    mock_nmap_scanner.return_value = (
        mock_nmap_scanner_instance  # Ensure the constructor returns our mock
    )

    # Configure the Shodan mock
    mock_shodan_instance = MagicMock()
    mock_shodan_client.return_value = mock_shodan_instance
    mock_shodan_instance.info.return_value = {"some_info": "value"}

    try:
        # Agent initialization will now call the mocked initializers/checks
        agent_instance = ExposureAnalystAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Exposure Analyst"

        tool_names = {tool.name for tool in agent_instance.agent.tools}

        # Check that expected tools were added based on mocks
        assert "subdomain_finder_crtsh" in tool_names
        assert "asn_ip_lookup" in tool_names
        assert "nmap_port_scanner" in tool_names
        assert "shodan_host_search" in tool_names

        assert len(agent_instance.agent.tools) == 4  # Expecting all 4 tools with mocks

    except ValueError as e:
        pytest.fail(f"ExposureAnalystAgent initialization failed: {e}")
    except Exception as e:
        pytest.fail(
            f"An unexpected error occurred during ExposureAnalystAgent initialization: {e}"
        )


# Add more specific tests later
