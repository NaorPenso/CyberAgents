"""Tests for the SecurityManagerAgent."""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
import yaml
from pydantic import ValidationError

from agents.security_manager_agent.security_manager_agent import (
    AgentConfigModel,
    SecurityManagerAgent,
)


def test_security_manager_agent_initialization():
    """Test that the SecurityManagerAgent initializes correctly."""
    # This is an integration test that requires the actual agent to initialize
    # Skip this for now due to CrewAI I18N loading issues
    pytest.skip(
        "Skipping initialization test due to CrewAI I18N loading issues in test environment"
    )


def test_config_validation():
    """Test that the config validation works correctly."""
    # Valid minimal config
    valid_config = {
        "role": "Test Role",
        "goal": "Test Goal",
        "backstory": "Test Backstory",
        "tools": [],
        "allow_delegation": True,
    }

    # Validate a proper config
    config_model = AgentConfigModel.model_validate(valid_config)
    assert config_model.role == "Test Role"
    assert config_model.goal == "Test Goal"
    assert config_model.backstory == "Test Backstory"
    assert config_model.tools == []
    assert config_model.allow_delegation is True
    assert config_model.verbose is True  # Default value

    # Invalid config (missing required field)
    invalid_config = {
        "role": "Test Role",
        "goal": "Test Goal",
        "backstory": "Test Backstory",
        # Missing tools
        "allow_delegation": True,
    }

    with pytest.raises(ValidationError):
        AgentConfigModel.model_validate(invalid_config)


def test_load_config_file_not_found():
    """Test handling of missing config file."""
    agent = SecurityManagerAgent.__new__(SecurityManagerAgent)
    # Call the method with a non-existent path
    result = agent._load_config("/path/does/not/exist.yaml")
    assert result is None


def test_load_config_invalid_yaml():
    """Test handling of invalid YAML in config file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        # Write invalid YAML
        temp_file.write("role: 'Test\nThis is not valid YAML")
        temp_file_path = temp_file.name

    try:
        agent = SecurityManagerAgent.__new__(SecurityManagerAgent)
        result = agent._load_config(temp_file_path)
        assert result is None
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_load_config_empty_file():
    """Test handling of empty config file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        # Write nothing (empty file)
        temp_file_path = temp_file.name

    try:
        agent = SecurityManagerAgent.__new__(SecurityManagerAgent)
        result = agent._load_config(temp_file_path)
        assert result is None
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_load_config_validation_error():
    """Test handling of config that fails validation."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        # Write config missing required fields
        yaml.dump({"role": "Test Role"}, temp_file)  # Missing other required fields
        temp_file_path = temp_file.name

    try:
        agent = SecurityManagerAgent.__new__(SecurityManagerAgent)
        result = agent._load_config(temp_file_path)
        assert result is None
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_load_config_success():
    """Test successful config loading and validation."""
    valid_config = {
        "role": "Test Role",
        "goal": "Test Goal",
        "backstory": "Test Backstory",
        "tools": [],
        "allow_delegation": True,
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        yaml.dump(valid_config, temp_file)
        temp_file_path = temp_file.name

    try:
        agent = SecurityManagerAgent.__new__(SecurityManagerAgent)
        result = agent._load_config(temp_file_path)
        assert result is not None
        assert result.role == "Test Role"
        assert result.goal == "Test Goal"
        assert result.backstory == "Test Backstory"
        assert result.tools == []
        assert result.allow_delegation is True
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def test_agent_attributes_after_config_loading():
    """Test that agent attributes are set correctly from config without initializing the actual CrewAI Agent."""
    valid_config = {
        "role": "Test Security Manager",
        "goal": "Test Security Goal",
        "backstory": "Test Security Backstory",
        "tools": [],
        "allow_delegation": True,
    }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as temp_file:
        yaml.dump(valid_config, temp_file)
        temp_file_path = temp_file.name

    try:
        # Create an agent without calling __init__
        agent = SecurityManagerAgent.__new__(SecurityManagerAgent)

        # Set up the config directly
        agent.config = agent._load_config(temp_file_path)

        # Set agent attributes manually (as would happen in __init__)
        agent.agent_name = "SecurityManagerAgent"
        agent.agent_role = agent.config.role
        agent.agent_goal = agent.config.goal
        agent.agent_backstory = agent.config.backstory

        # Test that the attributes are set correctly
        assert agent.agent_name == "SecurityManagerAgent"
        assert agent.agent_role == "Test Security Manager"
        assert agent.agent_goal == "Test Security Goal"
        assert agent.agent_backstory == "Test Security Backstory"

        # Test that config is correct
        assert agent.config.role == "Test Security Manager"
        assert agent.config.goal == "Test Security Goal"
        assert agent.config.backstory == "Test Security Backstory"
        assert agent.config.tools == []
        assert agent.config.allow_delegation is True

    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
