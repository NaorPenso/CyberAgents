"""Tests for the AppSec Engineer Agent."""

import os
import shutil
from unittest.mock import MagicMock, patch

import pytest
import yaml
from pydantic import ValidationError

# Import the refactored agent and the tool it uses
from agents.appsec_engineer_agent.appsec_engineer_agent import (
    AgentYamlModel,
    AppSecEngineerAgent,
)
from tools.semgrep_scanner.semgrep_scanner import SemgrepTool

# Remove unused RateLimiter import
# from utils.rate_limiter import RateLimiter

# Check if semgrep executable exists - less critical now as tests should mock the tool
SEMGREP_EXECUTABLE = shutil.which("semgrep")
skip_if_no_semgrep = pytest.mark.skipif(
    SEMGREP_EXECUTABLE is None,
    reason="Semgrep executable not found in PATH (though tests should mock)",
)

# Mock config data matching the simplified AgentYamlModel
MOCK_AGENT_YAML_DATA = {
    "role": "Test AppSec Engineer",
    "goal": "Test code analysis",
    "backstory": "A test agent.",
    "allow_delegation": False,
    "verbose": True,
    "memory": False,
    "max_iterations": 5,
    "max_rpm": 20,
    "cache": False,
    # Extra fields ignored by AgentYamlModel due to extra='ignore'
    "supported_languages": ["python"],
    "config": {"temp_dir": "/tmp/test"},
}


@pytest.fixture
def mock_yaml_load(monkeypatch):
    """Fixture to mock yaml.safe_load."""
    mock_load = MagicMock(return_value=MOCK_AGENT_YAML_DATA)
    monkeypatch.setattr("yaml.safe_load", mock_load)
    # Also mock Path.is_file to always return True for config loading
    monkeypatch.setattr("pathlib.Path.is_file", MagicMock(return_value=True))
    return mock_load


@pytest.fixture
def appsec_agent(mock_yaml_load):  # Depend on the mock fixture
    """Create an AppSec Engineer Agent instance for testing, using mocked config."""
    try:
        # Initialization should now use the mocked yaml.safe_load
        agent_wrapper = AppSecEngineerAgent()
        return agent_wrapper
    except Exception as e:
        pytest.fail(f"Failed to initialize AppSecEngineerAgent with mocked config: {e}")


# --- Remove TestCodeLanguageDetector --- (Class removed from agent)

# --- Remove TestSemgrepRunner --- (Class removed from agent)


class TestAppSecEngineerAgent:
    """Test the refactored AppSec Engineer Agent functionality."""

    def test_initialization_success(self, appsec_agent):
        """Test that the agent initializes correctly with mocked config."""
        assert appsec_agent is not None
        # Check config loaded correctly via Pydantic model
        assert isinstance(appsec_agent.config, AgentYamlModel)
        assert appsec_agent.config.role == MOCK_AGENT_YAML_DATA["role"]
        assert appsec_agent.config.goal == MOCK_AGENT_YAML_DATA["goal"]
        assert (
            appsec_agent.config.max_iterations == MOCK_AGENT_YAML_DATA["max_iterations"]
        )

        # Check the underlying CrewAI agent instance
        assert hasattr(appsec_agent, "agent")
        assert appsec_agent.agent.role == MOCK_AGENT_YAML_DATA["role"]
        assert appsec_agent.agent.goal == MOCK_AGENT_YAML_DATA["goal"]
        assert (
            appsec_agent.agent.allow_delegation
            == MOCK_AGENT_YAML_DATA["allow_delegation"]
        )

        # Check that the SemgrepTool is instantiated and assigned
        assert hasattr(appsec_agent, "semgrep_tool")
        assert isinstance(appsec_agent.semgrep_tool, SemgrepTool)

        # Check that the tool is correctly passed to the CrewAI agent
        assert appsec_agent.agent.tools == [appsec_agent.semgrep_tool]

    def test_initialization_missing_config_file(self, monkeypatch):
        """Test initialization failure when agent.yaml is missing."""
        # Mock Path.is_file to return False
        monkeypatch.setattr("pathlib.Path.is_file", MagicMock(return_value=False))
        with pytest.raises(FileNotFoundError):
            AppSecEngineerAgent()

    def test_initialization_invalid_yaml(self, monkeypatch):
        """Test initialization failure with invalid YAML content."""
        mock_load = MagicMock(side_effect=yaml.YAMLError("Invalid YAML"))
        monkeypatch.setattr("yaml.safe_load", mock_load)
        monkeypatch.setattr("pathlib.Path.is_file", MagicMock(return_value=True))
        with pytest.raises(yaml.YAMLError):
            AppSecEngineerAgent()

    def test_initialization_validation_error(self, monkeypatch):
        """Test initialization failure with invalid config data (missing required field)."""
        invalid_data = MOCK_AGENT_YAML_DATA.copy()
        del invalid_data["role"]  # Remove a required field
        mock_load = MagicMock(return_value=invalid_data)
        monkeypatch.setattr("yaml.safe_load", mock_load)
        monkeypatch.setattr("pathlib.Path.is_file", MagicMock(return_value=True))
        with pytest.raises(ValidationError):
            AppSecEngineerAgent()

    # --- Remove tests related to analyze_code --- (Method removed)

    # --- Remove tests related to analyze_repository --- (Method removed)

    # --- Remove test_github_url_validation --- (Method removed)

    # --- Remove test_process_scan_results --- (Method removed)

    # --- Remove test_process_scan_results_with_error --- (Method removed)
