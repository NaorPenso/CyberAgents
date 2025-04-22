"""Threat Intelligence Agent focused on gathering threat data for domains/IPs.

This agent utilizes VirusTotal API (via vt-py) to collect information on
malicious activities, resolutions, and related entities associated with a target.
"""

import logging
import os

# Add necessary imports
from pathlib import Path
from typing import Any, List, Literal, Optional

import yaml
from crewai import Agent

# Add Pydantic imports
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationError,
)

from agents.base_agent import BaseAgent
from tools.domain_threat_scoring.domain_threat_score_tool import DomainThreatScoreTool

logger = logging.getLogger(__name__)


# --- Pydantic Models based on agent_schema.yaml ---
# Reusing models similar to other agents for consistency
class LLMConfig(BaseModel):
    model: Optional[str] = None
    temperature: Optional[float] = Field(ge=0, le=2)
    api_key: Optional[str] = None
    base_url: Optional[HttpUrl] = None
    model_config = ConfigDict(extra="ignore")


class FunctionCallingLLM(BaseModel):
    model: Optional[str] = None
    temperature: Optional[float] = Field(ge=0, le=2)
    model_config = ConfigDict(extra="ignore")


class FileAnalysisLimits(BaseModel):
    max_file_size: Optional[int] = Field(ge=1)
    allowed_extensions: Optional[List[str]] = None
    disallowed_extensions: Optional[List[str]] = None
    model_config = ConfigDict(extra="ignore")


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
    model_config = ConfigDict(extra="ignore")


class AgentConfigModel(BaseModel):
    role: str
    goal: str
    backstory: str
    tools: List[str]  # List of tool names from YAML
    allow_delegation: bool
    verbose: Optional[bool] = True
    memory: Optional[bool] = False
    llm_config: Optional[LLMConfig] = None
    function_calling_llm: Optional[FunctionCallingLLM] = None
    max_iterations: Optional[int] = Field(ge=1, default=15)
    max_rpm: Optional[int] = Field(ge=1, default=60)
    cache: Optional[bool] = True
    security_context: Optional[SecurityContext] = None
    model_config = ConfigDict(extra="ignore")  # Ignore extra fields


# --- End Pydantic Models ---


class DomainThreatScoreAgent(BaseAgent):
    """Agent specialized in assessing domain threat scores.

    Uses the DomainThreatScoreTool to query external sources like VirusTotal.
    Loads configuration from agent.yaml.
    """

    config: AgentConfigModel
    agent: Agent
    domain_threat_score_tool: DomainThreatScoreTool

    def __init__(self, llm: Any):
        """Initialize the Domain Threat Score Agent with the passed LLM."""
        super().__init__(llm)

        # Load and validate configuration from YAML
        self.config = self._load_config()

        # Initialize required tools
        self.domain_threat_score_tool = DomainThreatScoreTool()
        # TODO: Dynamically instantiate tools based on self.config.tools if needed
        agent_tools = [
            self.domain_threat_score_tool
        ]  # For now, assume DomainThreatScoreTool is always needed

        # Check for required API keys AFTER loading config, as keys *could* be in config
        # Although DomainThreatScoreTool likely checks its own env vars/config
        if not os.environ.get("VIRUSTOTAL_API_KEY"):
            logger.warning(
                "VIRUSTOTAL_API_KEY environment variable is not set. DomainThreatScoreTool might fail."
            )
            # Consider raising ValueError if the tool *requires* the key and can't get it otherwise
            # raise ValueError("VIRUSTOTAL_API_KEY required")

        # Instantiate the CrewAI Agent using loaded configuration and PASSED LLM
        try:
            self.agent = Agent(
                role=self.config.role,
                goal=self.config.goal,
                backstory=self.config.backstory,
                verbose=self.config.verbose,
                memory=self.config.memory,
                allow_delegation=self.config.allow_delegation,
                tools=agent_tools,  # Use the instantiated tool list
                llm=self.llm,
                max_iter=self.config.max_iterations,
                max_rpm=self.config.max_rpm,
                cache=self.config.cache,
            )
            logger.info(
                f"Domain Threat Score Agent '{self.config.role}' initialized successfully."
            )
        except Exception as e:
            logger.error(
                f"Error initializing CrewAI Agent for DomainThreatScoreAgent: {e}"
            )
            raise

    def _load_config(self) -> AgentConfigModel:
        """Load and validate the agent configuration from agent.yaml."""
        config_path = Path(__file__).parent / "agent.yaml"

        if not config_path.is_file():
            logger.error(f"Configuration file not found at {config_path}")
            raise FileNotFoundError(f"Configuration file not found at {config_path}")

        try:
            with open(config_path, "r") as file:
                yaml_content = yaml.safe_load(file)
                if not yaml_content:
                    raise ValueError("YAML file is empty or invalid.")

            validated_config = AgentConfigModel.model_validate(yaml_content)
            logger.info(
                f"Successfully loaded and validated agent config from {config_path}"
            )
            return validated_config

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {config_path}: {e}")
            raise
        except ValidationError as e:
            logger.error(f"Configuration validation failed for {config_path}")
            logger.error(f"Validation Errors: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading config: {e}")
            raise

    # Remove hardcoded attributes if they are now in config
    # self.agent_name = "ThreatIntelAgent"
    # self.agent_role = "Threat Intelligence Analyst"
    # self.agent_goal = ...
    # self.agent_backstory = ...
    # self.agent_tools = [ThreatTool()]
