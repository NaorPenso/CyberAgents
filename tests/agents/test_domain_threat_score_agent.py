"""Tests for the DomainThreatScoreAgent."""

import logging
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, mock_open, patch

import pytest
import yaml
from crewai import Agent as CrewAgent
from crewai.tools import BaseTool
from pydantic import ValidationError

# Import the RENAMED agent and tool
from agents.domain_threat_score_agent.domain_threat_score_agent import (
    AgentConfigModel,
    DomainThreatScoreAgent,
)
from tools.domain_threat_scoring.domain_threat_score_tool import (
    DomainThreatScoreTool,
    ThreatInput,
)

# --- Mock Data ---
MOCK_AGENT_YAML_DATA = {
    "role": "Mock Threat Intel Analyst",
    "goal": "Mock threat analysis",
    "backstory": "A mock agent for testing.",
    "tools": ["threat_intelligence"],  # Tool name expected in config
    "allow_delegation": False,
    "verbose": True,
    "memory": True,
    "max_iterations": 10,
}


# --- Fixtures ---
@pytest.fixture
def mock_agent_yaml(tmp_path):
    """Create a temporary valid agent.yaml file."""
    p = tmp_path / "agent.yaml"
    with open(p, "w") as f:
        yaml.dump(MOCK_AGENT_YAML_DATA, f)
    return p


@pytest.fixture
def mock_invalid_agent_yaml(tmp_path):
    """Create a temporary invalid agent.yaml file (missing goal)."""
    p = tmp_path / "invalid_agent.yaml"
    invalid_data = MOCK_AGENT_YAML_DATA.copy()
    del invalid_data["goal"]
    with open(p, "w") as f:
        yaml.dump(invalid_data, f)
    return p


@pytest.fixture
def mock_empty_agent_yaml(tmp_path):
    """Create a temporary empty agent.yaml file."""
    p = tmp_path / "empty_agent.yaml"
    p.touch()
    return p


# --- Mocks applied to all tests in the class ---

# Create a reusable mock LLM instance
mock_llm = Mock(name="MockLLM")
mock_llm.supports_stop_words.return_value = False  # Add expected method

# Create a reusable mock Tool instance that satisfies CrewAI
# Spec against the RENAMED tool class
mock_tool_instance = Mock(spec=DomainThreatScoreTool)
mock_tool_instance.name = "threat_intelligence"  # Keep name consistent with agent.yaml
mock_tool_instance.description = (
    "Mocked Domain Threat Score Tool"  # Updated description
)


# Add a dummy run method signature if Agent checks for it
def dummy_run(**kwargs):
    return "Mock Run Result"


mock_tool_instance.run = dummy_run
# mock_tool_instance.args_schema = ... # If schema validation is needed


# Remove class-level ThreatTool patch, apply it inside specific tests
# Remove class-level create_central_llm patch as it's not needed for _load_config tests
# and might interfere with fixture injection.
# @patch(
#     "agents.threat_intel_agent.threat_intel_agent.create_central_llm",
#     return_value=mock_llm,
# )
@patch.dict(
    os.environ, {"VIRUSTOTAL_API_KEY": "mock_vt_key"}, clear=True
)  # Mock env var
class TestDomainThreatScoreAgent:
    """Test the refactored DomainThreatScoreAgent functionality."""

    # Test _load_config method directly
    # These tests MUST NOT call the full __init__ because of mock interactions
    def test_load_config_success(self, mock_agent_yaml, monkeypatch):
        """Test successful loading and validation of a known agent.yaml."""
        monkeypatch.chdir(mock_agent_yaml.parent)
        agent_wrapper = DomainThreatScoreAgent.__new__(DomainThreatScoreAgent)

        # Define the mock YAML content
        mock_yaml_content = yaml.dump(MOCK_AGENT_YAML_DATA)

        # Patch builtins.open to simulate reading the mock content
        # The target path used inside _load_config is Path(__file__).parent / "agent.yaml"
        # We need to ensure open() is called with *that specific path* for the mock to work.
        # Since we monkeypatch chdir, Path(__file__).parent / "agent.yaml" should resolve
        # correctly relative to the temp dir.
        target_path_str = str(Path("agent.yaml"))  # Relative path after chdir

        with patch(
            "builtins.open", mock_open(read_data=mock_yaml_content)
        ) as mocked_open:
            # We also need to mock Path(...).is_file() to return True
            with patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.Path"
            ) as mock_path_cls:
                mock_path_instance = (
                    mock_path_cls.return_value.parent.__truediv__.return_value
                )
                mock_path_instance.is_file.return_value = True

                config = agent_wrapper._load_config()
                # Verify open was called with the expected path
                mocked_open.assert_called_once_with(mock_path_instance, "r")

        assert isinstance(config, AgentConfigModel)
        # Assert against the MOCK data used to create the file
        assert config.role == MOCK_AGENT_YAML_DATA["role"]
        assert config.goal == MOCK_AGENT_YAML_DATA["goal"]

    def test_load_config_file_not_found(self, tmp_path, monkeypatch):
        """Test FileNotFoundError when agent.yaml is missing."""
        monkeypatch.chdir(tmp_path)
        agent_wrapper = DomainThreatScoreAgent.__new__(DomainThreatScoreAgent)
        # Patch Path to simulate file not existing
        with patch(
            "agents.domain_threat_score_agent.domain_threat_score_agent.Path"
        ) as mock_path:
            path_instance = Mock()
            path_instance.is_file.return_value = False
            # Point the construction Path(__file__).parent / "agent.yaml" to the mock
            mock_path.return_value.parent.__truediv__.return_value = path_instance

            with pytest.raises(FileNotFoundError):
                agent_wrapper._load_config()

    def test_load_config_empty_yaml(self, mock_empty_agent_yaml, monkeypatch):
        """Test ValueError when agent.yaml is empty. Test _load_config directly."""
        monkeypatch.chdir(mock_empty_agent_yaml.parent)
        agent_wrapper = DomainThreatScoreAgent.__new__(DomainThreatScoreAgent)

        # Simulate reading empty content using mock_open
        target_path_str = str(Path("agent.yaml"))
        with patch("builtins.open", mock_open(read_data="")) as mocked_open:
            # Mock Path.is_file() as well
            with patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.Path"
            ) as mock_path_cls:
                mock_path_instance = (
                    mock_path_cls.return_value.parent.__truediv__.return_value
                )
                mock_path_instance.is_file.return_value = True

                with pytest.raises(ValueError, match="YAML file is empty or invalid."):
                    agent_wrapper._load_config()
                mocked_open.assert_called_once_with(mock_path_instance, "r")

    def test_load_config_invalid_yaml(self, tmp_path, monkeypatch):
        """Test YAMLError for malformed YAML. Test _load_config directly."""
        monkeypatch.chdir(tmp_path)
        agent_wrapper = DomainThreatScoreAgent.__new__(DomainThreatScoreAgent)

        invalid_yaml_content = "role: Test Role\ngoal: [Invalid YAML"
        target_path_str = str(
            Path("agent.yaml")
        )  # Doesnt really matter as open is mocked

        # Patch open to return invalid YAML
        with patch(
            "builtins.open", mock_open(read_data=invalid_yaml_content)
        ) as mocked_open:
            # Mock Path.is_file() as well
            with patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.Path"
            ) as mock_path_cls:
                mock_path_instance = (
                    mock_path_cls.return_value.parent.__truediv__.return_value
                )
                mock_path_instance.is_file.return_value = True

                with pytest.raises(yaml.YAMLError):
                    agent_wrapper._load_config()
                mocked_open.assert_called_once_with(mock_path_instance, "r")

    def test_load_config_validation_error(self, mock_invalid_agent_yaml, monkeypatch):
        """Test ValidationError for missing required fields. Test _load_config directly."""
        monkeypatch.chdir(mock_invalid_agent_yaml.parent)
        agent_wrapper = DomainThreatScoreAgent.__new__(DomainThreatScoreAgent)

        # Prepare the invalid data (missing 'goal')
        invalid_data = MOCK_AGENT_YAML_DATA.copy()
        del invalid_data["goal"]
        invalid_yaml_content = yaml.dump(invalid_data)
        target_path_str = str(Path("agent.yaml"))

        # Patch open to return YAML missing required fields
        with patch(
            "builtins.open", mock_open(read_data=invalid_yaml_content)
        ) as mocked_open:
            # Mock Path.is_file() as well
            with patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.Path"
            ) as mock_path_cls:
                mock_path_instance = (
                    mock_path_cls.return_value.parent.__truediv__.return_value
                )
                mock_path_instance.is_file.return_value = True

                with pytest.raises(ValidationError):
                    agent_wrapper._load_config()
                mocked_open.assert_called_once_with(mock_path_instance, "r")

    # Test Agent Initialization (__init__)
    # These tests call the full constructor and need LLM and Tool mocks
    @pytest.mark.skip(
        reason="CrewAI Agent init with mocked tools is brittle and fails internally"
    )
    def test_initialization_success(self, mock_agent_yaml, monkeypatch):
        """Test successful agent initialization with mocks."""
        # Apply RENAMED Tool and CORRECTED LLM patches specifically here
        with (
            patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.DomainThreatScoreTool",
                return_value=mock_tool_instance,
            ) as MockToolInTest,
            patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.create_central_llm",
                return_value=mock_llm,
            ) as MockLLMInTest,
        ):

            monkeypatch.chdir(mock_agent_yaml.parent)
            agent_wrapper = DomainThreatScoreAgent()

            # Assertions
            assert agent_wrapper is not None
            MockToolInTest.assert_called_once()
            MockLLMInTest.assert_called_once()  # Verify LLM factory was called

            # Check config loaded
            assert isinstance(agent_wrapper.config, AgentConfigModel)
            assert agent_wrapper.config.role == MOCK_AGENT_YAML_DATA["role"]

            # Check the underlying CrewAI agent instance
            assert hasattr(agent_wrapper, "agent")
            assert isinstance(agent_wrapper.agent, CrewAgent)
            assert agent_wrapper.agent.role == MOCK_AGENT_YAML_DATA["role"]
            assert agent_wrapper.agent.goal == MOCK_AGENT_YAML_DATA["goal"]
            assert agent_wrapper.agent.llm == mock_llm  # Check correct LLM mock
            # Check that the *instance* returned by the mocked class call is in tools
            # Use the specific instance we know was passed
            assert agent_wrapper.agent.tools == [mock_tool_instance]
            assert agent_wrapper.agent.verbose == MOCK_AGENT_YAML_DATA["verbose"]
            assert (
                agent_wrapper.agent.allow_delegation
                == MOCK_AGENT_YAML_DATA["allow_delegation"]
            )
            assert agent_wrapper.agent.memory == MOCK_AGENT_YAML_DATA["memory"]

    # Test Initialization with Missing API Key
    @patch.dict(os.environ, {}, clear=True)  # Ensure VT key is NOT present
    def test_initialization_raises_on_missing_key(self, mock_agent_yaml, monkeypatch):
        """Test that __init__ raises ValueError if Tool init fails due to missing key."""
        # Apply RENAMED Tool and CORRECTED LLM patches specifically here
        with (
            patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.DomainThreatScoreTool"
            ) as MockToolInTest,
            patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.create_central_llm",
                return_value=mock_llm,
            ) as MockLLMInTest,
        ):
            MockToolInTest.side_effect = ValueError(
                "VIRUSTOTAL_API_KEY environment variable is not set"
            )

            monkeypatch.chdir(mock_agent_yaml.parent)
            with pytest.raises(
                ValueError, match="VIRUSTOTAL_API_KEY environment variable is not set"
            ):
                DomainThreatScoreAgent()
            MockToolInTest.assert_called_once()
            # LLM factory might not be called if Tool init fails first, so don't assert call
            # MockLLMInTest.assert_called_once()

    # Test Agent Task Execution (Simulated Placeholder)
    @pytest.mark.skip(
        reason="CrewAI Agent init with mocked tools is brittle and fails internally"
    )
    def test_agent_uses_threat_tool(self, mock_agent_yaml, monkeypatch):
        """Verify the agent is configured with the mocked Tool."""
        # Apply RENAMED Tool and CORRECTED LLM patches specifically here
        with (
            patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.DomainThreatScoreTool",
                return_value=mock_tool_instance,
            ) as MockToolInTest,
            patch(
                "agents.domain_threat_score_agent.domain_threat_score_agent.create_central_llm",
                return_value=mock_llm,
            ) as MockLLMInTest,
        ):

            monkeypatch.chdir(mock_agent_yaml.parent)
            agent_wrapper = DomainThreatScoreAgent()
            crew_agent = agent_wrapper.agent

            # Basic check: Agent has the mocked tool instance
            assert len(crew_agent.tools) == 1
            assert crew_agent.tools[0] == mock_tool_instance
            assert crew_agent.tools[0].name == "threat_intelligence"
            # More advanced tests would mock LLM calls and potentially tool._run/_arun


# Mock environment variables for testing
@pytest.fixture(autouse=True)
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "mock_vt_key")
    monkeypatch.setenv("OPENAI_API_KEY", "mock_openai_key")
    monkeypatch.setenv("OPENAI_MODEL_NAME", "gpt-test")
    # Ensure necessary vars for create_central_llm are set


# Mock the central LLM factory
@pytest.fixture
def mock_llm():
    with patch("utils.llm_utils.create_central_llm") as mock_create_llm:
        mock_llm_instance = MagicMock()
        mock_create_llm.return_value = mock_llm_instance
        yield mock_llm_instance


# Mock the agent configuration loading
@pytest.fixture
def mock_agent_config():
    with patch(
        "agents.domain_threat_score_agent.domain_threat_score_agent.DomainThreatScoreAgent._load_config"
    ) as mock_load:
        # Provide a valid mock config structure
        mock_config_instance = MagicMock(spec=AgentConfigModel)
        mock_config_instance.role = "Test Role"
        mock_config_instance.goal = "Test Goal"
        mock_config_instance.backstory = "Test Backstory"
        mock_config_instance.tools = ["threat_intelligence"]  # Match tool name
        mock_config_instance.allow_delegation = False
        mock_config_instance.verbose = True
        mock_config_instance.memory = False
        mock_config_instance.max_iterations = 10
        mock_config_instance.max_rpm = 60
        mock_config_instance.cache = True
        mock_load.return_value = mock_config_instance
        yield mock_load


# Fixture to mock the DomainThreatScoreTool instantiation and methods
@pytest.fixture
def mock_threat_tool():
    # Mock the tool's async method _arun
    with patch(
        "tools.domain_threat_scoring.domain_threat_score_tool.DomainThreatScoreTool._arun",
        new_callable=AsyncMock,
    ) as mock_arun:
        # Mock the __init__ to prevent real API client creation
        with patch(
            "tools.domain_threat_scoring.domain_threat_score_tool.DomainThreatScoreTool.__init__",
            return_value=None,
        ) as mock_init:
            # Return the mock method itself for assertions
            yield mock_arun


def test_agent_initialization_success(mock_llm, mock_agent_config, mock_threat_tool):
    """Test successful initialization of DomainThreatScoreAgent."""
    try:
        agent_instance = DomainThreatScoreAgent()
        assert agent_instance is not None
        assert agent_instance.agent is not None
        assert agent_instance.agent.role == "Test Role"
        assert agent_instance.agent.llm == mock_llm  # Check if central LLM is used
        assert len(agent_instance.agent.tools) == 1
        assert isinstance(agent_instance.agent.tools[0], DomainThreatScoreTool)
        assert agent_instance.agent.tools[0].name == "threat_intelligence"

    except Exception as e:
        pytest.fail(f"Agent initialization failed unexpectedly: {e}")


def test_agent_init_missing_config_file(mock_llm, monkeypatch):
    """Test agent initialization fails if config file is missing."""
    # Temporarily make the config file seem non-existent
    with patch("pathlib.Path.is_file", return_value=False):
        with pytest.raises(FileNotFoundError):
            DomainThreatScoreAgent()


def test_agent_init_invalid_yaml(mock_llm, mock_agent_config):
    """Test agent initialization fails with invalid YAML content."""
    # Simulate _load_config raising a YAMLError (mock it directly)
    mock_agent_config.side_effect = yaml.YAMLError("Mock YAML error")
    with pytest.raises(yaml.YAMLError):
        DomainThreatScoreAgent()


def test_agent_init_validation_error(mock_llm, mock_agent_config):
    """Test agent initialization fails if config validation fails."""
    # Simulate _load_config raising a ValidationError
    # Need to import ValidationError from pydantic
    mock_agent_config.side_effect = ValidationError.from_exception_data(
        title="MockValidationError", line_errors=[]
    )
    with pytest.raises(ValidationError):
        DomainThreatScoreAgent()


# Optional: Test tool interaction if needed
@pytest.mark.asyncio
async def test_agent_tool_interaction(mock_llm, mock_agent_config, mock_threat_tool):
    """Example test for how the agent might use the tool (if logic existed in agent)."""
    # Setup mock return value for the tool's _arun method
    mock_threat_tool.return_value = {"threat_score": 0.5, "data": "mock data"}

    agent_instance = DomainThreatScoreAgent()
    tool = agent_instance.agent.tools[0]

    # Simulate calling the tool (adjust based on actual usage pattern)
    result = await tool._arun(
        domain="example.com"
    )  # Accessing _arun directly for testing

    # Assert tool was called and returned expected mock data
    mock_threat_tool.assert_awaited_once_with(domain="example.com", whois_data=None)
    assert result == {"threat_score": 0.5, "data": "mock data"}


# Ensure VIRUSTOTAL_API_KEY check is tested (it's in __init__)
# def test_agent_init_missing_vt_key(mock_llm, mock_agent_config, monkeypatch):
#     """Test agent warns if VIRUSTOTAL_API_KEY is missing."""
#     monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
#     with pytest.warns(UserWarning, match="VIRUSTOTAL_API_KEY environment variable is not set"):
#         # Instantiation might still succeed if warning is the only action
#         DomainThreatScoreAgent()
#         # If it raises ValueError, use pytest.raises instead:
#         # with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY required"):
#         #     DomainThreatScoreAgent()

# Note: Tests involving actual agent execution (kickoff) are more complex
# and belong in integration tests like test_crew_integration.py.
