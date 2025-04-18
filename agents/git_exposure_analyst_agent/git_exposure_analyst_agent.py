"""Git Exposure Analyst Agent specialized in identifying secrets in git repositories.

This agent specializes in detecting exposed secrets, API keys, credentials and other
sensitive information in git repositories to mitigate security risks.
"""

import logging
import os
from typing import Dict, List, Optional, Union

import yaml
from crewai import Agent
from pydantic import BaseModel, Field, PrivateAttr, ValidationError

from tools.github_search.github_search_tool import GitHubSearchTool
from tools.trufflehog_scanner.trufflehog_scanner_tool import TruffleHogScannerTool
from utils.llm_utils import create_central_llm

from ..base_agent import BaseAgent

logger = logging.getLogger(__name__)


class FileAnalysisLimits(BaseModel):
    """File analysis limits configuration."""

    max_file_size: int = Field(
        default=5242880, description="Maximum file size in bytes"
    )
    allowed_extensions: List[str] = Field(
        default_factory=list, description="List of file extensions that can be analyzed"
    )
    disallowed_extensions: List[str] = Field(
        default_factory=list,
        description="List of file extensions that cannot be analyzed",
    )


class SecurityContext(BaseModel):
    """Security context and permissions for the agent."""

    allowed_domains: List[str] = Field(
        default_factory=list,
        description="List of domains the agent is allowed to interact with",
    )
    max_request_size: int = Field(
        default=1048576, description="Maximum size of requests in bytes (1MB)"
    )
    timeout: int = Field(default=30, description="Timeout in seconds for operations")
    allow_internet_access: bool = Field(
        default=False,
        description="Whether the agent is allowed to make external network requests",
    )
    logging_level: str = Field(
        default="INFO", description="Logging level for the agent's operations"
    )
    allow_code_execution: bool = Field(
        default=False,
        description="Whether the agent is allowed to execute code or scripts",
    )
    allow_ocr: bool = Field(
        default=False,
        description="Whether the agent is allowed to perform OCR operations",
    )
    allow_file_analysis: bool = Field(
        default=False,
        description="Whether the agent is allowed to analyze file contents",
    )
    file_analysis_limits: Optional[FileAnalysisLimits] = Field(
        default=None, description="Limits for file analysis operations"
    )


class GitHubApiSettings(BaseModel):
    """GitHub API settings."""

    rate_limit_handling: bool = Field(default=True)
    include_forks: bool = Field(default=False)
    default_max_results: int = Field(default=50)


class TruffleHogSettings(BaseModel):
    """TruffleHog scanner settings."""

    max_depth: int = Field(default=50)
    include_historical: bool = Field(default=True)
    entropy_checks: bool = Field(default=True)
    regex_rules: bool = Field(default=True)


class ScanSettings(BaseModel):
    """General scan settings."""

    timeout_seconds: int = Field(default=300)
    max_file_size_mb: int = Field(default=5)
    concurrency: int = Field(default=4)


class AnalysisSettings(BaseModel):
    """Analysis settings container."""

    github_api: GitHubApiSettings = Field(default_factory=GitHubApiSettings)
    trufflehog: TruffleHogSettings = Field(default_factory=TruffleHogSettings)
    scan_settings: ScanSettings = Field(default_factory=ScanSettings)


class Patterns(BaseModel):
    """Secret detection patterns."""

    high_priority: List[str] = Field(default_factory=list)
    file_targets: Optional[List[str]] = Field(default_factory=list)


class ReportTemplates(BaseModel):
    """Report templates."""

    basic: str = Field(default="")
    detailed: str = Field(default="")


class GitExposureAnalystAgentConfig(BaseModel):
    """Configuration for the Git Exposure Analyst Agent."""

    # Core required fields
    role: str = Field(description="The specific role the agent plays")
    goal: str = Field(description="The primary objective or purpose of the agent")
    backstory: str = Field(
        description="Background information about the agent's expertise and experience"
    )
    tools: List[str] = Field(
        description="List of tool names (strings) used by the agent"
    )
    allow_delegation: bool = Field(
        description="Whether the agent can delegate tasks to other agents"
    )

    # Optional fields
    verbose: bool = Field(default=True, description="Enable verbose logging")
    memory: bool = Field(default=False, description="Enable memory for the agent")

    # Advanced configuration
    max_iterations: int = Field(
        default=15,
        description="Maximum number of iterations for the agent to perform",
        ge=1,
    )
    max_rpm: int = Field(
        default=60, description="Maximum requests per minute for the agent", ge=1
    )
    cache: bool = Field(
        default=True, description="Enable/disable caching for the agent"
    )

    # Security settings
    security_context: SecurityContext = Field(
        default_factory=SecurityContext,
        description="Security context and permissions for the agent",
    )

    # Custom agent settings
    settings: Optional[AnalysisSettings] = Field(
        default=None, description="Analysis settings for the agent"
    )
    patterns: Optional[Patterns] = Field(
        default=None, description="Secret detection patterns"
    )
    report_templates: Optional[ReportTemplates] = Field(
        default=None, description="Report templates for agent output"
    )

    # Add metadata section - not used by CrewAI but kept for documentation
    metadata: Optional[Dict[str, Union[str, List[str]]]] = Field(
        default=None, description="Additional metadata about the agent"
    )


class GitExposureAnalystAgent(BaseAgent):
    """Agent specialized in identifying secrets and sensitive data in git repositories.

    Scans repositories for exposed secrets, API keys, credentials, and other
    sensitive information using GitHub search capabilities and tools like TruffleHog.
    """

    _config: GitExposureAnalystAgentConfig = PrivateAttr()

    def __init__(self):
        """Initialize the Git Exposure Analyst Agent."""
        super().__init__()

        # Load configuration
        config_path = os.path.join(
            os.path.dirname(__file__), "config", "git_exposure_analyst_agent.yaml"
        )
        self._config = self._load_config(config_path)

        # Initialize tools
        self.github_tool = GitHubSearchTool()
        self.trufflehog_tool = TruffleHogScannerTool()

        # Determine tools based on config
        agent_tools = []
        if "github_search_tool" in self._config.tools:
            agent_tools.append(self.github_tool)
        if "trufflehog_scanner_tool" in self._config.tools:
            agent_tools.append(self.trufflehog_tool)

        # LLM instantiation
        central_llm = create_central_llm()

        self.agent = Agent(
            role=self._config.role,
            goal=self._config.goal,
            backstory=self._config.backstory,
            tools=agent_tools,
            verbose=self._config.verbose,
            allow_delegation=self._config.allow_delegation,
            memory=self._config.memory,
            cache=self._config.cache,
            max_iter=self._config.max_iterations,
            max_rpm=self._config.max_rpm,
            llm=central_llm,
        )

        self.agent_name = "GitExposureAnalystAgent"
        self.agent_role = self._config.role
        self.agent_goal = self._config.goal
        self.agent_backstory = self._config.backstory

        logger.info(f"Git Exposure Analyst Agent {self._config.role} initialized")

    def _load_config(self, config_path) -> GitExposureAnalystAgentConfig:
        """Load the agent configuration from a YAML file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Validated GitExposureAnalystAgentConfig object
        """
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config_dict = yaml.safe_load(f)
                try:
                    return GitExposureAnalystAgentConfig(**config_dict)
                except ValidationError as e:
                    logger.error(
                        f"Error validating config from {config_path}: {e}. Using defaults."
                    )
                    return self._get_default_config()
            else:
                logger.warning(
                    f"Config file not found at {config_path}. Using defaults."
                )
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
            return self._get_default_config()

    def _get_default_config(self) -> GitExposureAnalystAgentConfig:
        """Get default configuration when loading fails.

        Returns:
            Default GitExposureAnalystAgentConfig
        """
        return GitExposureAnalystAgentConfig(
            role="Git Exposure Analyst",
            goal="Identify exposed secrets and sensitive information in git repositories.",
            backstory=(
                "A specialized security researcher with deep expertise in identifying "
                "exposed secrets and sensitive information in source code repositories. "
                "You're adept at using GitHub's search capabilities and specialized tools "
                "like TruffleHog to discover accidentally committed secrets, API keys, "
                "credentials, and other sensitive data."
            ),
            tools=["github_search", "trufflehog_scanner"],
            allow_delegation=False,
            verbose=True,
        )

    def analyze_repository(self, repo_url_or_path, is_local=False):
        """Analyze a specific git repository for exposed secrets.

        This is a convenience method for directly analyzing a specific repository
        rather than relying on the agent's autonomous decision making.

        Args:
            repo_url_or_path: URL of a GitHub repository or path to a local repo
            is_local: Whether the repository is local or remote

        Returns:
            Analysis results as a string
        """
        logger.info(
            f"Directly analyzing {'local' if is_local else 'remote'} repository: "
            f"{repo_url_or_path}"
        )

        if is_local:
            return self.trufflehog_tool._run(f"local:{repo_url_or_path}")
        else:
            # For remote repos, first gather info with GitHub API, then scan with TruffleHog
            github_info = self.github_tool._run(f"repo:{repo_url_or_path}")
            trufflehog_scan = self.trufflehog_tool._run(f"github:{repo_url_or_path}")

            return (
                f"## Git Repository Analysis\n\n"
                f"### Repository Information\n\n{github_info}\n\n"
                f"### Secret Scan Results\n\n{trufflehog_scan}"
            )
