import importlib
import logging
import os
from typing import Any, Dict, List, Type

import yaml
from crewai import Crew, Process, Task
from pydantic import BaseModel, Field, ValidationError, field_validator

from agents.agent_registry import AGENT_REGISTRY

# Assume BaseAgent is updated to accept llm in __init__
from agents.base_agent import BaseAgent

# Assume a central LLM creation function exists
from utils.llm_utils import create_central_llm

logger = logging.getLogger(__name__)


class TaskConfig(BaseModel):
    # Placeholder for TaskConfig fields
    pass


class CrewConfig(BaseModel):
    # Placeholder for CrewConfig fields
    pass


class CrewFactory:
    """Factory class to create CrewAI crews from configuration files."""

    config: CrewConfig
    central_llm: Any

    def __init__(self, config_path: str):
        """Initialize the factory with the path to the crew config file."""
        self.config_path = config_path
        self.config = self._load_crew_config()
        # Create the central LLM instance once
        self.central_llm = create_central_llm()

    def _load_crew_config(self) -> CrewConfig:
        """Load and validate the crew configuration from a YAML file."""
        # Placeholder for loading logic
        pass

    def _create_agents(self) -> Dict[str, BaseAgent]:
        """Create agent instances based on the configuration."""
        agents = {}
        for agent_config in self.config.agents:
            agent_name = agent_config.name
            if agent_name not in AGENT_REGISTRY:
                raise ValueError(
                    f"Agent '{agent_name}' not found in registry. "
                    f"Available: {list(AGENT_REGISTRY.keys())}"
                )

            agent_class: Type[BaseAgent] = AGENT_REGISTRY[agent_name]
            try:
                # Instantiate the agent wrapper, passing the central LLM
                agent_instance_wrapper = agent_class(llm=self.central_llm)
                # Retrieve the actual CrewAI agent object from the wrapper
                crewai_agent = agent_instance_wrapper.get_agent()
                if crewai_agent is None:
                    raise ValueError(
                        f"Agent class '{agent_name}' did not return a valid CrewAI agent."
                    )
                # Store the actual CrewAI agent instance
                agents[agent_name] = crewai_agent
                logger.info(f"Successfully created agent: {agent_name}")
            except Exception as e:
                logger.error(
                    f"Failed to create agent '{agent_name}': {e}", exc_info=True
                )
                raise  # Re-raise after logging
        return agents

    def _create_tasks(self, agents: Dict[str, BaseAgent]) -> List[Task]:
        """Create task instances based on the configuration."""
        # Placeholder for task creation logic
        pass

    def create_crew(self) -> Crew:
        """Create the full CrewAI crew."""
        # Placeholder for crew creation logic
        pass


# </rewritten_file>
