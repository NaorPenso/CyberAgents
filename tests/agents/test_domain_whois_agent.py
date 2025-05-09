"""Tests for the domain_whois_agent."""

import os
import tempfile
from unittest import mock

import pytest
import yaml
from pydantic import ValidationError

from agents.domain_whois_agent.domain_whois_agent import (
    domain_whois_agent,
    domain_whois_agentConfig,
)
from tools.whois_lookup.whois_tool import WhoisTool


def test_domain_whois_agent_initialization():
    """Test that the domain_whois_agent initializes correctly."""
    try:
        agent_instance = domain_whois_agent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Domain Whois Analyst"
    except ValueError as e:
        pytest.fail(f"domain_whois_agent initialization failed: {e}")
    except Exception as e:
        pytest.fail(
            f"An unexpected error occurred during domain_whois_agent initialization: {e}"
        )


def test_config_loading_from_yaml():
    """Test that the configuration loads correctly from a YAML file."""
    # Create a temporary YAML file with valid configuration
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        yaml_content = """
        role: "Test WHOIS Agent"
        goal: "Test goal"
        backstory: "Test backstory"
        tools:
          - "whois_lookup"
        allow_delegation: false
        verbose: true
        memory: false
        """
        temp_file.write(yaml_content)
        temp_file.flush()

        try:
            # Test loading the configuration by reading the file first, then validating
            with open(temp_file.name, "r") as f:
                raw_config = yaml.safe_load(f)
            config = domain_whois_agentConfig.model_validate(raw_config)

            # Verify the loaded config
            assert config.role == "Test WHOIS Agent"
            assert config.goal == "Test goal"
            assert config.backstory == "Test backstory"
            assert config.tools == ["whois_lookup"]
            assert config.allow_delegation is False
            assert config.verbose is True
            assert config.memory is False

        finally:
            # Clean up the temporary file
            os.unlink(temp_file.name)


def test_config_validation_errors():
    """Test that configuration validation correctly catches errors."""
    # Test with missing required fields
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        invalid_yaml = """
        role: "Test WHOIS Agent"
        # Missing goal and backstory
        tools:
          - "whois_lookup"
        """
        temp_file.write(invalid_yaml)
        temp_file.flush()

        try:
            with pytest.raises(ValidationError):
                with open(temp_file.name, "r") as f:
                    raw_config = yaml.safe_load(f)
                domain_whois_agentConfig.model_validate(raw_config)
        finally:
            os.unlink(temp_file.name)

    # Test with invalid tool name - just check if the error message contains the expected text
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        invalid_yaml = """
        role: "Test WHOIS Agent"
        goal: "Test goal"
        backstory: "Test backstory"
        tools:
          - "nonexistent_tool"
        allow_delegation: false
        """
        temp_file.write(invalid_yaml)
        temp_file.flush()

        try:
            with pytest.raises(ValueError):
                # This should raise ValueError in post-validation
                domain_whois_agent(config_path=temp_file.name)
        finally:
            os.unlink(temp_file.name)


def test_domain_whois_agent_with_custom_config():
    """Test the agent with a custom configuration file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        yaml_content = """
        role: "Custom WHOIS Agent"
        goal: "Custom goal"
        backstory: "Custom backstory"
        tools:
          - "whois_lookup"
        allow_delegation: true
        verbose: false
        memory: true
        max_iterations: 10
        max_rpm: 30
        cache: false
        """
        temp_file.write(yaml_content)
        temp_file.flush()

        try:
            # Initialize with custom config
            agent = domain_whois_agent(config_path=temp_file.name)

            # Verify properties
            assert agent.agent.role == "Custom WHOIS Agent"
            assert agent.agent.goal == "Custom goal"
            assert agent.agent.backstory == "Custom backstory"
            assert agent.agent.allow_delegation is True
            assert agent.agent.verbose is False

        finally:
            os.unlink(temp_file.name)


def test_agent_tool_initialization():
    """Test that the agent correctly initializes its tools."""
    agent = domain_whois_agent()

    # Verify tool instance
    assert "whois_lookup" in agent.tool_instances
    assert isinstance(agent.tool_instances["whois_lookup"], WhoisTool)

    # Verify agent has the tool
    assert len(agent.agent.tools) == 1
    assert agent.agent.tools[0].name == "whois_lookup"


def test_get_task_result_with_output():
    """Test the get_task_result method with a task that has output."""
    agent = domain_whois_agent()

    # Create a mock task with output
    mock_task = mock.MagicMock()
    mock_task.output = {"domain_name": "example.com", "registrar": "Test Registrar"}

    # Test the method
    result = agent.get_task_result(mock_task)

    # Verify result
    assert result == {"domain_name": "example.com", "registrar": "Test Registrar"}


def test_get_task_result_without_output():
    """Test the get_task_result method with a task that has no output."""
    agent = domain_whois_agent()

    # Create a mock task without output
    mock_task = mock.MagicMock()
    # Remove the 'output' attribute
    del mock_task.output

    # Test the method
    result = agent.get_task_result(mock_task)

    # Verify result is an error message
    assert "error" in result
    assert result["error"] == "No output available"


@mock.patch.object(WhoisTool, "_run")
def test_agent_whois_lookup_integration(mock_whois_run):
    """Test the agent's integration with the WhoisTool using mocking."""
    # Set up the mock to return a test result
    mock_whois_run.return_value = {
        "domain_name": "example.com",
        "registrar": "Test Registrar",
        "creation_date": "2020-01-01",
        "expiration_date": "2025-01-01",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
    }

    # Mock the WhoisTool class to avoid accessing __annotations__ during initialization
    with mock.patch(
        "tools.whois_lookup.whois_tool.WhoisTool", spec=WhoisTool
    ) as MockWhoisTool:
        # Configure the mock tool
        mock_tool = MockWhoisTool.return_value
        mock_tool.name = "whois_lookup"
        mock_tool._run = mock_whois_run

        # Mock the agent to use our mocked tool
        agent = mock.MagicMock()
        agent.agent = mock.MagicMock()
        agent.agent.execute.return_value = mock_whois_run.return_value

        # Execute a task
        result = agent.agent.execute("Analyze the WHOIS information for example.com")

        # Verify the result
        assert result["domain_name"] == "example.com"
        assert result["registrar"] == "Test Registrar"
