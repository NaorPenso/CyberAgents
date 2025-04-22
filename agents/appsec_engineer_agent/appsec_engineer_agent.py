"""
AppSec Engineer Agent for security code scanning and vulnerability detection.

This agent leverages the SemgrepTool to analyze code for security vulnerabilities.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from crewai import Agent
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agents.base_agent import BaseAgent

# Import the actual tool
from tools.semgrep_scanner.semgrep_scanner import SemgrepTool

# Remove unused RateLimiter import
# from utils.rate_limiter import RateLimiter


logger = logging.getLogger(__name__)


# --- Pydantic Models for agent.yaml Structure ---


# Simplify the model to standard Agent fields loaded from YAML
class AgentYamlModel(BaseModel):
    """Pydantic model representing the standard agent.yaml structure for CrewAI Agent."""

    role: str
    goal: str
    backstory: str
    # Tools list from YAML might not be directly used if we instantiate tools here
    # tools: List[str]
    allow_delegation: bool
    verbose: bool = True
    memory: bool = False  # Note: CrewAI Agent does not use this directly in constructor
    max_iterations: int = 15
    max_rpm: Optional[int] = None
    cache: bool = True  # Note: CrewAI Agent does not use this directly in constructor

    # Remove non-standard fields (metadata, custom config, inputs, outputs, etc.)
    # These should be defined elsewhere or are part of tool schemas

    model_config = ConfigDict(extra="ignore")  # Ignore extra fields found in YAML


# --- End Pydantic Models ---


# --- Remove CodeLanguageDetector Class --- (No longer needed in agent)


# --- Remove SemgrepRunner Class --- (Logic moved to SemgrepTool)


class AppSecEngineerAgent(BaseAgent):
    """
    Application Security Engineer Agent that identifies security vulnerabilities in code.

    This agent uses the SemgrepTool to scan code for security issues.
    It loads its configuration from agent.yaml and initializes the necessary tool.
    """

    config: AgentYamlModel
    agent: Agent  # Add type hint for the CrewAI agent instance
    semgrep_tool: SemgrepTool  # Store the tool instance

    def __init__(self, llm: Any):
        """
        Initialize the AppSec Engineer Agent with the passed LLM.
        Loads config and initializes the SemgrepTool.
        """
        super().__init__(llm)  # Pass llm to BaseAgent

        self.config = self._load_config()

        # Initialize the SemgrepTool
        # Tool configuration (rules, timeout etc.) should be handled within the tool itself,
        # potentially loading its own tool.yaml or using defaults.
        self.semgrep_tool = SemgrepTool()

        # Initialize the CrewAI Agent
        self.agent = Agent(
            role=self.config.role,
            goal=self.config.goal,
            backstory=self.config.backstory,
            verbose=self.config.verbose,
            allow_delegation=self.config.allow_delegation,
            # Pass the instantiated tool
            tools=[self.semgrep_tool],
            max_iter=self.config.max_iterations,
            max_rpm=self.config.max_rpm,
            # <<< UPDATED: LLM assignment >>>
            llm=self.llm,  # Use the llm passed via __init__ / stored in self.llm by super()
        )
        logger.info(
            f"AppSecEngineerAgent initialized with tool: {self.semgrep_tool.name}"
        )

    def _load_config(self) -> AgentYamlModel:
        """
        Load the agent configuration from agent.yaml and validate it using Pydantic.
        """
        current_dir = Path(__file__).parent
        config_path = current_dir / "agent.yaml"

        if not config_path.is_file():
            logger.error(f"Configuration file not found at {config_path}")
            raise FileNotFoundError(f"Configuration file not found at {config_path}")

        try:
            with open(config_path, "r") as file:
                yaml_content = yaml.safe_load(file)
                if not yaml_content:
                    raise ValueError("YAML file is empty or invalid.")

            # Use the simplified AgentYamlModel
            validated_config = AgentYamlModel.model_validate(yaml_content)
            logger.info("Agent configuration loaded and validated successfully.")
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

    def get_agent(self) -> Agent:
        """Return the initialized crewai Agent instance."""
        return self.agent

    # --- Remove analyze_code method --- (Handled by SemgrepTool)

    # --- Remove analyze_repository method --- (Handled by SemgrepTool)

    # --- Remove _is_valid_github_url method --- (Handled by SemgrepTool or not needed)

    # --- Remove _clone_repository method --- (Handled by SemgrepTool)

    # --- Remove _get_directory_size method --- (Handled by SemgrepTool or not needed)

    # --- Remove _process_scan_results method --- (Handled by SemgrepTool)

    # --- Remove _forward_to_defect_review method --- (Placeholder removed)


# Example of how to potentially use the agent (outside the class definition)
# if __name__ == "__main__":
#     from crewai import Task
#
#     appsec_agent_wrapper = AppSecEngineerAgent()
#     agent = appsec_agent_wrapper.agent # Get the initialized CrewAI agent
#
#     # Example Task: Scan a code snippet
#     scan_task = Task(
#         description=(
#             "Scan the provided Python code snippet for security vulnerabilities. "
#             "Use the semgrep_code_scanner tool."
#         ),
#         expected_output="A JSON report summarizing the findings from the Semgrep scan.",
#         agent=agent,
#         inputs={"code": "import os\nos.system('ls')", "language": "python"}
#         # Note: inputs need to match the SemgrepTool's args_schema
#     )
#
#     # Example Task: Scan a file path
#     # scan_file_task = Task(
#     #     description="Scan the file /path/to/vulnerable.py for security issues.",
#     #     expected_output="A JSON report summarizing the findings.",
#     #     agent=agent,
#     #     inputs={"file_path": "/path/to/vulnerable.py"}
#     # )
#
#     # To run the task, you would typically use a Crew
#     # result = crew.kickoff(inputs=scan_task.inputs)
#     # print(result)
