"""Domain WHOIS Agent specialized in retrieving WHOIS information for domains.

This agent utilizes WHOIS lookup tools to gather registration and contact
details associated with a given domain name.
"""

import logging
import os
from typing import Any, ClassVar, Dict, List, Optional

import yaml
from common.interfaces.agent import AgentBase
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError

from tools.whois_lookup.whois_tool import WhoisTool

logger = logging.getLogger(__name__)


# Define nested models for llm_config, function_calling_llm, and security_context
class LLMConfig(BaseModel):
    """Configuration for the LLM used by the agent."""

    model: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0, le=2)
    api_key: Optional[str] = None
    base_url: Optional[HttpUrl] = None
    model_config = ConfigDict(extra="forbid")


class FunctionCallingLLM(BaseModel):
    """Configuration for the function calling LLM."""

    model: Optional[str] = None
    temperature: Optional[float] = Field(None, ge=0, le=2)
    model_config = ConfigDict(extra="forbid")


class FileAnalysisLimits(BaseModel):
    """Limits for file analysis operations."""

    max_file_size: Optional[int] = Field(5242880, ge=1)  # 5MB default
    allowed_extensions: Optional[List[str]] = None
    disallowed_extensions: Optional[List[str]] = None
    model_config = ConfigDict(extra="forbid")


class SecurityContext(BaseModel):
    """Security context and permissions for the agent."""

    allowed_domains: Optional[List[str]] = None
    max_request_size: Optional[int] = Field(1048576, ge=1)  # 1MB default
    timeout: Optional[int] = Field(30, ge=1)
    allow_internet_access: Optional[bool] = False
    logging_level: Optional[str] = Field(
        "INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$"
    )
    allow_code_execution: Optional[bool] = False
    allow_ocr: Optional[bool] = False
    allow_file_analysis: Optional[bool] = False
    file_analysis_limits: Optional[FileAnalysisLimits] = None
    model_config = ConfigDict(extra="forbid")


class DomainWhoisAgentConfig(BaseModel):
    """Configuration model for the DomainWhoisAgent."""

    # Required fields
    role: str
    goal: str
    backstory: str
    tools: List[str]
    allow_delegation: bool

    # Optional fields with defaults matching schema
    verbose: bool = True
    memory: bool = False

    # Performance settings with proper constraints
    max_iterations: int = Field(15, ge=1)
    max_rpm: int = Field(60, ge=1)
    cache: bool = True

    # Advanced configuration - optional
    llm_config: Optional[LLMConfig] = None
    function_calling_llm: Optional[FunctionCallingLLM] = None
    security_context: Optional[SecurityContext] = None

    # Prevent additional properties
    model_config = ConfigDict(extra="forbid")

    @classmethod
    def from_yaml(cls, file_path: str) -> "DomainWhoisAgentConfig":
        """Load configuration from a YAML file.

        Args:
            file_path: Path to the YAML configuration file

        Returns:
            A validated DomainWhoisAgentConfig instance

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the YAML file is malformed or can't be parsed
            ValidationError: If the configuration doesn't match the required schema
            ValueError: If the configuration has invalid values (post-load validation)
        """
        if not os.path.exists(file_path):
            logger.error(f"Configuration file not found: {file_path}")
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        try:
            # Load and parse the YAML file
            with open(file_path, "r") as f:
                config = yaml.safe_load(f)

            if config is None:
                logger.error(f"Empty or invalid YAML file: {file_path}")
                raise ValueError(f"Empty or invalid YAML file: {file_path}")

            # Create the config instance (Pydantic will validate schema compliance)
            config_instance = cls(**config)

            # Additional validation beyond Pydantic's automatic validation
            if "whois_lookup" not in config_instance.tools:
                logger.warning(
                    f"Configuration missing required 'whois_lookup' tool in {file_path}"
                )
                raise ValueError("DomainWhoisAgent requires the 'whois_lookup' tool")

            logger.info(
                f"Successfully loaded and validated configuration from {file_path}"
            )
            return config_instance

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {file_path}: {e}")
            raise
        except ValidationError as e:
            logger.error(f"Configuration validation failed for {file_path}: {e}")
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error loading configuration from {file_path}: {e}"
            )
            raise


class DomainWhoisAgent(AgentBase):
    """Agent for retrieving and parsing WHOIS data for a domain."""

    # Class-level attributes
    NAME: ClassVar[str] = "DomainWhoisAgent"
    DESCRIPTION: ClassVar[str] = (
        "An agent that retrieves and structures WHOIS information for domains"
    )

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the DomainWhoisAgent.

        Args:
            config_path: Path to the configuration YAML file. If None, uses default.
        """
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "agent.yaml"
            )

        # Load configuration
        self.config = DomainWhoisAgentConfig.from_yaml(config_path)

        # Initialize tools
        self.tool_instances = {"whois_lookup": WhoisTool()}

        # Initialize base agent properties
        super().__init__(
            role=self.config.role,
            goal=self.config.goal,
            backstory=self.config.backstory,
            tools=[self.tool_instances[tool_name] for tool_name in self.config.tools],
            allow_delegation=self.config.allow_delegation,
            verbose=self.config.verbose,
            memory=self.config.memory,
            max_iterations=self.config.max_iterations,
            max_rpm=self.config.max_rpm,
            cache=self.config.cache,
        )

        logger.info(f"DomainWhoisAgent initialized with role: {self.config.role}")

    def get_task_result(self, task: Any) -> Dict:
        """Process the result of a task execution.

        Args:
            task: The executed task with results

        Returns:
            A dictionary containing the structured WHOIS information or error
        """
        # Implementation would depend on how task results are structured
        # This is a placeholder that would be implemented based on the actual task result format
        if hasattr(task, "output"):
            return task.output
        else:
            return {"error": "No output available"}
