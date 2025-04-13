"""Agent responsible for managing and orchestrating security analysis tasks."""

import logging
import os
from typing import List, Literal, Optional

import yaml
from crewai import Agent
from pydantic import BaseModel, Field, HttpUrl, ValidationError

from agents.base_agent import BaseAgent
from utils.llm_utils import create_llm

logger = logging.getLogger(__name__)


# Pydantic Models based on agent_schema.yaml
class LLMConfig(BaseModel):
    model: Optional[str] = None
    temperature: Optional[float] = Field(ge=0, le=2)
    api_key: Optional[str] = None
    base_url: Optional[HttpUrl] = None
    model_config = {"extra": "ignore"}


class FunctionCallingLLM(BaseModel):
    model: Optional[str] = None
    temperature: Optional[float] = Field(ge=0, le=2)
    model_config = {"extra": "ignore"}


class FileAnalysisLimits(BaseModel):
    max_file_size: Optional[int] = Field(ge=1)
    allowed_extensions: Optional[List[str]] = None
    disallowed_extensions: Optional[List[str]] = None
    model_config = {"extra": "ignore"}


class SecurityContext(BaseModel):
    allowed_domains: Optional[List[str]] = None
    max_request_size: Optional[int] = Field(ge=1, default=1048576)
    timeout: Optional[int] = Field(ge=1, default=30)
    allow_internet_access: Optional[bool] = False
    logging_level: Optional[
        Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    ] = "INFO"
    allow_code_execution: Optional[bool] = False
    allow_ocr: Optional[bool] = False
    allow_file_analysis: Optional[bool] = False
    file_analysis_limits: Optional[FileAnalysisLimits] = None
    model_config = {"extra": "ignore"}


class AgentConfigModel(BaseModel):
    role: str
    goal: str
    backstory: str
    tools: List[str]
    allow_delegation: bool
    verbose: Optional[bool] = True
    memory: Optional[bool] = False
    llm_config: Optional[LLMConfig] = None
    function_calling_llm: Optional[FunctionCallingLLM] = None
    max_iterations: Optional[int] = Field(ge=1, default=15)
    max_rpm: Optional[int] = Field(ge=1, default=60)
    cache: Optional[bool] = True
    security_context: Optional[SecurityContext] = None
    model_config = {"extra": "ignore"}


class SecurityManagerAgent(BaseAgent):
    """Creates and configures the Security Manager agent.

    This agent acts as the central orchestrator. It interprets user requests,
    identifies necessary analysis types, delegates tasks to specialist agents,
    and synthesizes their findings into a final report.
    """

    config: AgentConfigModel

    def __init__(self):
        """Initializes the agent with its configuration."""
        super().__init__()

        # Load configuration from YAML file
        config_path = os.path.join(os.path.dirname(__file__), "agent.yaml")
        loaded_config = self._load_config(config_path)
        if loaded_config is None:
            logger.error("Failed to load or validate agent configuration. Exiting.")
            raise ValueError("Agent configuration failed to load or validate.")

        self.config = loaded_config

        # Initialize the agent with the loaded configuration
        self.agent = Agent(
            role=self.config.role,
            goal=self.config.goal,
            backstory=self.config.backstory,
            tools=[],  # Uses empty tools list from config
            verbose=self.config.verbose,
            allow_delegation=self.config.allow_delegation,
            memory=self.config.memory,
            cache=self.config.cache,
            max_iter=self.config.max_iterations,
            max_rpm=self.config.max_rpm,
            llm=create_llm(),
        )

        self.agent_name = "SecurityManagerAgent"
        self.agent_role = self.config.role
        self.agent_goal = self.config.goal
        self.agent_backstory = self.config.backstory

        logger.info(f"Security Manager Agent '{self.config.role}' initialized")

    def _load_config(self, config_path: str) -> Optional[AgentConfigModel]:
        """Load and validate the agent configuration from a YAML file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Validated AgentConfigModel object or None if loading/validation fails.
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

            validated_config = AgentConfigModel.model_validate(raw_config)
            logger.info(f"Successfully loaded and validated config from {config_path}")
            return validated_config

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {config_path}: {e}")
            return None
        except ValidationError as e:
            logger.error(f"Configuration validation failed for {config_path}:\n{e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error loading config from {config_path}: {e}")
            return None
