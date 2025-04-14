"""Tests for the DomainWhoisAgent."""

import os
import tempfile
from unittest import mock

import pytest
import yaml
from pydantic import ValidationError

from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent, DomainWhoisAgentConfig
from tools.whois_lookup.whois_tool import WhoisTool


def test_domain_whois_agent_initialization():
    """Test that the DomainWhoisAgent initializes correctly."""
    try:
        agent_instance = DomainWhoisAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Domain Registrar Analyst"
    except ValueError as e:
        pytest.fail(f"DomainWhoisAgent initialization failed: {e}")
    except Exception as e:
        pytest.fail(
            f"An unexpected error occurred during DomainWhoisAgent initialization: {e}"
        )


def test_config_loading_from_yaml():
    """Test that the configuration loads correctly from a YAML file."""
    # Create a temporary YAML file with valid configuration
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as temp_file:
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
            # Test loading the configuration
            config = DomainWhoisAgentConfig.from_yaml(temp_file.name)
            
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
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as temp_file:
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
                DomainWhoisAgentConfig.from_yaml(temp_file.name)
        finally:
            os.unlink(temp_file.name)
    
    # Test with invalid tool name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as temp_file:
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
            with pytest.raises(ValueError, match="requires the 'whois_lookup' tool"):
                # This should raise ValueError in post-validation
                config = DomainWhoisAgentConfig.from_yaml(temp_file.name)
                # Create an agent with the config to trigger validation
                DomainWhoisAgent(config_path=temp_file.name)
        finally:
            os.unlink(temp_file.name)


def test_domain_whois_agent_with_custom_config():
    """Test the agent with a custom configuration file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as temp_file:
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
            agent = DomainWhoisAgent(config_path=temp_file.name)
            
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
    agent = DomainWhoisAgent()
    
    # Verify tool instance
    assert "whois_lookup" in agent.tool_instances
    assert isinstance(agent.tool_instances["whois_lookup"], WhoisTool)
    
    # Verify agent has the tool
    assert len(agent.agent.tools) == 1
    assert agent.agent.tools[0].name == "whois_lookup"


def test_get_task_result_with_output():
    """Test the get_task_result method with a task that has output."""
    agent = DomainWhoisAgent()
    
    # Create a mock task with output
    mock_task = mock.MagicMock()
    mock_task.output = {"domain_name": "example.com", "registrar": "Test Registrar"}
    
    # Test the method
    result = agent.get_task_result(mock_task)
    
    # Verify result
    assert result == {"domain_name": "example.com", "registrar": "Test Registrar"}


def test_get_task_result_without_output():
    """Test the get_task_result method with a task that has no output."""
    agent = DomainWhoisAgent()
    
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
        "name_servers": ["ns1.example.com", "ns2.example.com"]
    }
    
    agent = DomainWhoisAgent()
    
    # Mock the execute method to simulate task execution and return data from the tool
    with mock.patch.object(agent.agent, "execute") as mock_execute:
        mock_execute.return_value = mock_whois_run.return_value
        
        # Execute a task
        result = agent.agent.execute("Analyze the WHOIS information for example.com")
        
        # Verify that the WhoisTool was called
        mock_whois_run.assert_called_once()
        
        # Verify the result
        assert result["domain_name"] == "example.com"
        assert result["registrar"] == "Test Registrar"
