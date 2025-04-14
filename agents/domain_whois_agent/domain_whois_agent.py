"""Domain WHOIS Agent specialized in retrieving WHOIS information for domains.

This agent utilizes WHOIS lookup tools to gather registration and contact
details associated with a given domain name.
"""

import logging
import os
from typing import Any, ClassVar, Dict, List, Optional

import yaml
from crewai import Agent
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError

from tools.whois_lookup.whois_tool import WhoisTool

from ..base_agent import BaseAgent

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


class domain_whois_agentConfig(BaseModel):
    """Configuration model for the domain_whois_agent."""

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


class domain_whois_agent(BaseAgent):
    """Agent for retrieving and parsing WHOIS data for a domain."""

    # Class-level attributes
    NAME: ClassVar[str] = "domain_whois_agent"
    DESCRIPTION: ClassVar[str] = (
        "An agent that retrieves and structures WHOIS information for domains"
    )

    config: domain_whois_agentConfig

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the domain_whois_agent.

        Args:
            config_path: Path to the configuration YAML file. If None, uses default.
        """
        # Call super() first for consistency
        super().__init__()

        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "agent.yaml"
            )

        # Load configuration using the internal _load_config method
        loaded_config = self._load_config(config_path)
        if loaded_config is None:
            logger.error(
                "Failed to load or validate agent configuration. Initialization aborted."
            )
            # Optionally raise an error or handle it as needed
            raise ValueError("Agent configuration failed to load or validate.")
        self.config = loaded_config

        # Initialize tools
        self.tool_instances = {"whois_lookup": WhoisTool()}
        agent_tools = [
            self.tool_instances[tool_name] for tool_name in self.config.tools
        ]

        # Explicitly create the crewai.Agent instance
        self.agent = Agent(
            role=self.config.role,
            goal=self.config.goal,
            backstory=self.config.backstory,
            tools=agent_tools,
            allow_delegation=self.config.allow_delegation,
            verbose=self.config.verbose,
            memory=self.config.memory,
            max_iter=self.config.max_iterations,
            max_rpm=self.config.max_rpm,
            cache=self.config.cache,
            # Assuming default LLM if not specified, or add llm_config handling here
            # llm=create_llm() # Might need to import create_llm if needed
        )

        # Assign attributes for potential direct access (optional but consistent)
        self.agent_name = self.NAME
        self.agent_role = self.config.role
        self.agent_goal = self.config.goal
        self.agent_backstory = self.config.backstory

        logger.info(f"domain_whois_agent initialized with role: {self.config.role}")

    def _load_config(self, config_path: str) -> Optional[domain_whois_agentConfig]:
        """Load and validate the agent configuration from a YAML file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Validated domain_whois_agentConfig object or None if loading/validation fails.
        """
        if not os.path.exists(config_path):
            logger.error(f"Config file not found at {config_path}.")
            return None

        try:
            with open(config_path, "r") as f:
                raw_config = yaml.safe_load(f)
            if raw_config is None:
                logger.error(f"Config file {config_path} is empty or invalid YAML.")
                return None

            # Validate using Pydantic's model_validate
            validated_config = domain_whois_agentConfig.model_validate(raw_config)

            # Additional validation (already present in previous version, kept for robustness)
            if "whois_lookup" not in validated_config.tools:
                logger.warning(
                    f"Configuration missing required 'whois_lookup' tool in {config_path}"
                )
                raise ValueError("domain_whois_agent requires the 'whois_lookup' tool")

            logger.info(f"Successfully loaded and validated config from {config_path}")
            return validated_config

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {config_path}: {e}")
            return None
        except ValidationError as e:
            logger.error(f"Configuration validation failed for {config_path}:\n{e}")
            return None
        except ValueError as e:  # Catch specific ValueError from custom validation
            logger.error(f"Configuration value error for {config_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error loading config from {config_path}: {e}")
            return None

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
