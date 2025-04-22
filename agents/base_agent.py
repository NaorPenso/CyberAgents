import logging
from abc import ABC, abstractmethod
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all CrewAI agents in CyberAgents."""

    agent: Any  # Generic agent type
    llm: Any  # Add llm attribute
    agent_name: Optional[str] = None
    dependencies: List[str] = []

    @abstractmethod
    def __init__(self, llm: Any):  # Add llm parameter
        """Initialize the BaseAgent with an LLM instance.

        Args:
            llm: The language model instance to use.
        """
        if llm is None:
            raise ValueError("An LLM instance must be provided to initialize an agent.")
        self.llm = llm  # Store the LLM instance
        logger.debug(f"BaseAgent initialized with LLM: {type(llm).__name__}")

    @abstractmethod
    def get_agent(self) -> Any:  # Keep Any for now, consider refining later
        pass  # Add pass to fix IndentationError
