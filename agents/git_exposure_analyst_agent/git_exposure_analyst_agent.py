"""Git Exposure Analyst Agent specialized in identifying secrets in git repositories.

This agent specializes in detecting exposed secrets, API keys, credentials and other
sensitive information in git repositories to mitigate security risks.
"""

import logging
import os

import yaml
from crewai import Agent
from pydantic import Field, PrivateAttr

from tools.github_search.github_search_tool import GitHubSearchTool
from tools.trufflehog_scanner.trufflehog_scanner_tool import TruffleHogScannerTool
from utils.llm_utils import create_llm

from ..base_agent import BaseAgent

logger = logging.getLogger(__name__)


class GitExposureAnalystAgent(BaseAgent):
    """Agent specialized in identifying secrets and sensitive data in git repositories.

    Scans repositories for exposed secrets, API keys, credentials, and other
    sensitive information using GitHub search capabilities and tools like TruffleHog.
    """

    def __init__(self):
        """Initialize the Git Exposure Analyst Agent."""
        super().__init__()

        # Load configuration
        config_path = os.path.join(
            os.path.dirname(__file__), "config", "git_exposure_analyst_agent.yaml"
        )
        self.config = self._load_config(config_path)

        # Initialize tools
        self.github_tool = GitHubSearchTool()
        self.trufflehog_tool = TruffleHogScannerTool()

        self.agent = Agent(
            role=self.config["agent"]["role"],
            goal=self.config["agent"]["goal"],
            backstory=self.config["agent"]["backstory"],
            tools=[self.github_tool, self.trufflehog_tool],
            verbose=True,
            allow_delegation=False,
            llm=create_llm(),
        )

        self.agent_name = "GitExposureAnalystAgent"
        self.agent_role = self.config["agent"]["role"]
        self.agent_goal = self.config["agent"]["goal"]
        self.agent_backstory = self.config["agent"]["backstory"]

        logger.info("Git Exposure Analyst Agent initialized")

    def _load_config(self, config_path):
        """Load the agent configuration from a YAML file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Dictionary containing the configuration
        """
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    return yaml.safe_load(f)
            else:
                logger.warning(
                    f"Config file not found at {config_path}. Using defaults."
                )
                return {
                    "agent": {
                        "role": "Git Exposure Analyst",
                        "goal": "Identify exposed secrets and sensitive information in git repositories to reduce security risks.",
                        "backstory": (
                            "A specialized security researcher with deep expertise in identifying "
                            "exposed secrets and sensitive information in source code repositories. "
                            "You're adept at using GitHub's search capabilities and specialized tools "
                            "like TruffleHog to discover accidentally committed secrets, API keys, "
                            "credentials, and other sensitive data that could lead to security breaches."
                        ),
                    }
                }
        except Exception as e:
            logger.error(f"Error loading config: {e}. Using defaults.")
            return {
                "agent": {
                    "role": "Git Exposure Analyst",
                    "goal": "Identify exposed secrets and sensitive information in git repositories to reduce security risks.",
                    "backstory": (
                        "A specialized security researcher with deep expertise in identifying "
                        "exposed secrets and sensitive information in source code repositories. "
                        "You're adept at using GitHub's search capabilities and specialized tools "
                        "like TruffleHog to discover accidentally committed secrets, API keys, "
                        "credentials, and other sensitive data that could lead to security breaches."
                    ),
                }
            }

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
            f"Directly analyzing {'local' if is_local else 'remote'} repository: {repo_url_or_path}"
        )

        if is_local:
            return self.trufflehog_tool._run(f"local:{repo_url_or_path}")
        else:
            # For remote repos, first gather info with GitHub API, then scan with TruffleHog
            github_info = self.github_tool._run(f"repo:{repo_url_or_path}")
            trufflehog_scan = self.trufflehog_tool._run(f"github:{repo_url_or_path}")

            return f"## Git Repository Analysis\n\n### Repository Information\n\n{github_info}\n\n### Secret Scan Results\n\n{trufflehog_scan}"
