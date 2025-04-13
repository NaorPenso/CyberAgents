"""Tests for the GitExposureAnalystAgent."""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from agents.git_exposure_analyst_agent.git_exposure_analyst_agent import (
    GitExposureAnalystAgent,
    GitExposureAnalystAgentConfig,
)


@pytest.fixture
def valid_config_dict():
    """Fixture to provide a valid configuration dictionary."""
    return {
        "role": "Git Exposure Analyst",
        "goal": "Identify exposed secrets in repositories",
        "backstory": "Security researcher with expertise in finding secrets",
        "tools": ["github_search", "trufflehog_scanner"],
        "allow_delegation": False,
        "verbose": True,
        "memory": False,
    }


@pytest.fixture
def valid_config_yaml():
    """Fixture to provide a valid configuration YAML string."""
    return """
role: Git Exposure Analyst
goal: Identify exposed secrets in repositories
backstory: Security researcher with expertise in finding secrets
tools:
  - github_search
  - trufflehog_scanner
allow_delegation: false
verbose: true
memory: false
"""


@pytest.fixture
def invalid_config_yaml():
    """Fixture to provide an invalid configuration YAML string missing required fields."""
    return """
role: Git Exposure Analyst
# Missing goal
backstory: Security researcher with expertise in finding secrets
# Missing tools
allow_delegation: false
"""


@pytest.fixture
def temp_config_file(valid_config_yaml):
    """Fixture to create a temporary config file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as temp:
        temp.write(valid_config_yaml)
        temp_path = temp.name
    yield temp_path
    os.unlink(temp_path)


@pytest.fixture
def temp_invalid_config_file(invalid_config_yaml):
    """Fixture to create a temporary invalid config file."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as temp:
        temp.write(invalid_config_yaml)
        temp_path = temp.name
    yield temp_path
    os.unlink(temp_path)


def test_config_model_validation(valid_config_dict):
    """Test that the config model correctly validates inputs."""
    # Valid configuration should not raise exceptions
    config = GitExposureAnalystAgentConfig(**valid_config_dict)
    assert config.role == "Git Exposure Analyst"
    assert config.goal == "Identify exposed secrets in repositories"
    assert len(config.tools) == 2
    assert config.tools[0] == "github_search"
    assert config.tools[1] == "trufflehog_scanner"
    assert config.allow_delegation is False
    assert config.verbose is True

    # Invalid configuration should raise ValidationError
    invalid_config = valid_config_dict.copy()
    del invalid_config["role"]  # Remove required field
    with pytest.raises(ValidationError, match="role"):
        GitExposureAnalystAgentConfig(**invalid_config)


@patch("agents.git_exposure_analyst_agent.git_exposure_analyst_agent.GitHubSearchTool")
@patch("agents.git_exposure_analyst_agent.git_exposure_analyst_agent.TruffleHogScannerTool")
@patch("agents.git_exposure_analyst_agent.git_exposure_analyst_agent.Agent")
@patch("agents.git_exposure_analyst_agent.git_exposure_analyst_agent.create_llm")
def test_agent_initialization(
    mock_create_llm, mock_agent, mock_trufflehog, mock_github_search, temp_config_file
):
    """Test that the GitExposureAnalystAgent initializes correctly."""
    # Set up mocks
    mock_github_instance = MagicMock()
    mock_trufflehog_instance = MagicMock()
    mock_github_search.return_value = mock_github_instance
    mock_trufflehog.return_value = mock_trufflehog_instance
    mock_llm = MagicMock()
    mock_create_llm.return_value = mock_llm
    mock_crew_agent = MagicMock()
    mock_agent.return_value = mock_crew_agent

    # Test with temporary config file path
    with patch.object(
        GitExposureAnalystAgent, "_load_config", return_value=GitExposureAnalystAgentConfig(
            role="Git Exposure Analyst",
            goal="Test goal",
            backstory="Test backstory",
            tools=["github_search", "trufflehog_scanner"],
            allow_delegation=False,
        )
    ):
        agent = GitExposureAnalystAgent()
        assert agent is not None
        assert agent.agent_name == "GitExposureAnalystAgent"
        assert agent.agent_role == "Git Exposure Analyst"

        # Check that tools were initialized
        assert mock_github_search.called
        assert mock_trufflehog.called

        # Check that Agent was created with correct parameters
        mock_agent.assert_called_once()
        call_kwargs = mock_agent.call_args.kwargs
        assert call_kwargs["role"] == "Git Exposure Analyst"
        assert call_kwargs["goal"] == "Test goal"
        assert call_kwargs["backstory"] == "Test backstory"
        assert len(call_kwargs["tools"]) == 2
        assert call_kwargs["verbose"] is True
        assert call_kwargs["allow_delegation"] is False
        assert call_kwargs["llm"] is mock_llm


def test_load_config_valid(temp_config_file):
    """Test loading a valid configuration file."""
    with patch.object(
        GitExposureAnalystAgent, "__init__", return_value=None
    ):
        agent = GitExposureAnalystAgent()
        config = agent._load_config(temp_config_file)
        assert isinstance(config, GitExposureAnalystAgentConfig)
        assert config.role == "Git Exposure Analyst"
        assert config.goal == "Identify exposed secrets in repositories"
        assert len(config.tools) == 2
        assert config.tools[0] == "github_search"
        assert config.tools[1] == "trufflehog_scanner"


def test_load_config_invalid(temp_invalid_config_file):
    """Test loading an invalid configuration file returns default config."""
    with patch.object(
        GitExposureAnalystAgent, "__init__", return_value=None
    ):
        agent = GitExposureAnalystAgent()
        config = agent._load_config(temp_invalid_config_file)
        # Should return default config when validation fails
        assert isinstance(config, GitExposureAnalystAgentConfig)
        assert config.role == "Git Exposure Analyst"
        # Check it's using the default config
        assert "github_search" in config.tools
        assert "trufflehog_scanner" in config.tools


def test_load_config_missing_file():
    """Test handling of a missing configuration file."""
    with patch.object(
        GitExposureAnalystAgent, "__init__", return_value=None
    ):
        agent = GitExposureAnalystAgent()
        config = agent._load_config("/path/does/not/exist.yaml")
        # Should return default config when file doesn't exist
        assert isinstance(config, GitExposureAnalystAgentConfig)
        assert config.role == "Git Exposure Analyst"
        # Check it's using the default config
        assert "github_search" in config.tools
        assert "trufflehog_scanner" in config.tools


def test_analyze_repository_local():
    """Test analyzing a local repository."""
    # Mock the entire agent and its dependencies
    agent = MagicMock(spec=GitExposureAnalystAgent)
    mock_trufflehog_tool = MagicMock()
    mock_trufflehog_tool._run.return_value = "Local scan results"
    
    # Set up the mock for the agent
    agent.trufflehog_tool = mock_trufflehog_tool
    
    # Get the real method but bound to our mock
    analyze_repo_method = GitExposureAnalystAgent.analyze_repository.__get__(agent)
    
    # Call the method on our mock
    result = analyze_repo_method("/path/to/local/repo", is_local=True)
    
    # Check that the correct tool was called
    mock_trufflehog_tool._run.assert_called_once_with("local:/path/to/local/repo")
    assert result == "Local scan results"


def test_analyze_repository_remote():
    """Test analyzing a remote repository."""
    # Mock the entire agent and its dependencies
    agent = MagicMock(spec=GitExposureAnalystAgent)
    mock_github_tool = MagicMock()
    mock_trufflehog_tool = MagicMock()
    mock_github_tool._run.return_value = "GitHub info"
    mock_trufflehog_tool._run.return_value = "TruffleHog scan results"
    
    # Set up the mocks for the agent
    agent.github_tool = mock_github_tool
    agent.trufflehog_tool = mock_trufflehog_tool
    
    # Get the real method but bound to our mock
    analyze_repo_method = GitExposureAnalystAgent.analyze_repository.__get__(agent)
    
    # Call the method on our mock
    result = analyze_repo_method("owner/repo", is_local=False)
    
    # Check that both tools were called with correct parameters
    mock_github_tool._run.assert_called_once_with("repo:owner/repo")
    mock_trufflehog_tool._run.assert_called_once_with("github:owner/repo")
    
    # Check that the result contains both tool outputs
    assert "GitHub info" in result
    assert "TruffleHog scan results" in result
    assert "Repository Information" in result
    assert "Secret Scan Results" in result
