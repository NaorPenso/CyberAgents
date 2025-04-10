"""Integration tests for the domain analysis crew."""

from agents.security_manager_agent.security_manager_agent import SecurityManagerAgent
from agents.dns_analyzer_agent.dns_analyzer_agent import DNSAnalyzerAgent
import asyncio
import copy
import json
import os

import pytest
from crewai import Agent, Crew, Process, Task
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from tools import DNSTool, ThreatTool, WhoisTool

# Load environment variables
load_dotenv()

# Get model configuration
MODEL_NAME = os.environ.get("OPENAI_MODEL_NAME", "o3-mini")

# Import necessary agent classes


class CustomChatOpenAI(ChatOpenAI):
    """Custom ChatOpenAI class that doesn't use temperature for the o3-mini model."""

    @property
    def _invocation_params(self):
        """Get the parameters used to invoke the model."""
        params = super()._invocation_params
        if self.model_name == "o3-mini" and "temperature" in params:
            # Remove temperature for o3-mini model
            del params["temperature"]
        return params

    @property
    def _llm_type(self) -> str:
        """Return type of llm."""
        return "custom_chat_openai"

    def dict(self, **kwargs):
        """Return a dict representation of the instance."""
        result = super().dict(**kwargs)
        if self.model_name == "o3-mini" and "temperature" in result:
            # Remove temperature for o3-mini model in dict serialization
            del result["temperature"]
        return result

    def to_json(self) -> str:
        """Return a JSON representation of the instance."""
        if self.model_name == "o3-mini":
            # Create a copy to avoid modifying the original object
            temp_dict = copy.deepcopy(self.__dict__)
            if "_temperature" in temp_dict:
                del temp_dict["_temperature"]

            clean_dict = {
                "name": None,
                "model_name": self.model_name,
                "class": self.__class__.__name__,
            }
            return json.dumps(clean_dict)
        else:
            clean_dict = {
                "name": None,
                "model_name": self.model_name,
                "temperature": self.temperature,
                "class": self.__class__.__name__,
            }
            return json.dumps(clean_dict)

    # Override _generate method to remove temperature from requests
    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        if self.model_name == "o3-mini" and "temperature" in kwargs:
            del kwargs["temperature"]
        return await super()._agenerate(messages, stop, run_manager, **kwargs)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if self.model_name == "o3-mini" and "temperature" in kwargs:
            del kwargs["temperature"]
        return super()._generate(messages, stop, run_manager, **kwargs)


# Monkey patch Agent to handle CustomChatOpenAI serialization
original_init = Agent.__init__


def create_llm():
    """Create a custom LLM configuration based on the model name."""
    api_key = os.environ.get("OPENAI_API_KEY")
    api_base = os.environ.get("OPENAI_API_BASE")

    if MODEL_NAME == "o3-mini":
        return CustomChatOpenAI(
            model=MODEL_NAME, openai_api_key=api_key, openai_api_base=api_base
        )
    else:
        return CustomChatOpenAI(
            model=MODEL_NAME,
            temperature=0.7,
            openai_api_key=api_key,
            openai_api_base=api_base,
        )


def create_whois_agent():
    """Create a WHOIS analysis agent."""
    if not os.environ.get("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")
    return Agent(
        role="WHOIS Analyst",
        goal="Analyze WHOIS data for domains",
        backstory="Expert in domain registration and ownership analysis",
        tools=[WhoisTool()],
        llm=create_llm(),
        verbose=True,
    )


def create_dns_agent():
    """Create a DNS analysis agent."""
    if not os.environ.get("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY not set")
    return Agent(
        role="DNS Analyst",
        goal="Analyze DNS records for domains",
        backstory="Expert in DNS record analysis and domain infrastructure",
        tools=[DNSTool()],
        llm=create_llm(),
        verbose=True,
    )


def create_threat_agent():
    """Create a threat intelligence agent."""
    if not os.environ.get("OPENAI_API_KEY") or not os.environ.get("VIRUSTOTAL_API_KEY"):
        pytest.skip("Required API keys not set")
    return Agent(
        role="Threat Intelligence Analyst",
        goal="Analyze threat intelligence data for domains",
        backstory="Expert in threat intelligence and security analysis",
        tools=[ThreatTool()],
        llm=create_llm(),
        verbose=True,
    )


class DomainIntelligenceCrew:
    """Crew for analyzing domain intelligence."""

    def __init__(self):
        """Initialize the crew with agents."""
        self.whois_agent = create_whois_agent()
        self.dns_agent = create_dns_agent()
        self.threat_agent = create_threat_agent()

    async def analyze_domain(self, domain: str) -> dict:
        """Analyze a domain using the crew.

        Args:
            domain: Domain name to analyze

        Returns:
            Dictionary containing analysis results
        """
        try:
            # Create tasks
            whois_task = Task(
                description=f"Analyze WHOIS data for {domain}", agent=self.whois_agent
            )

            dns_task = Task(
                description=f"Analyze DNS records for {domain}", agent=self.dns_agent
            )

            threat_task = Task(
                description=f"Analyze threat intelligence for {domain}",
                agent=self.threat_agent,
            )

            # Create and run crew
            crew = Crew(
                agents=[self.whois_agent, self.dns_agent, self.threat_agent],
                tasks=[whois_task, dns_task, threat_task],
                verbose=True,
            )

            result = await crew.kickoff()
            return result

        except Exception as e:
            return {"error": str(e)}


@pytest.mark.asyncio
async def test_domain_analysis():
    """Test domain analysis for walla.co.il"""
    # Skip if using o3-mini model, which doesn't support temperature
    if MODEL_NAME == "o3-mini":
        pytest.skip("o3-mini model doesn't support temperature parameter")

    crew = DomainIntelligenceCrew()
    domain = "walla.co.il"

    # Run the analysis
    results = await crew.analyze_domain(domain)

    # Verify WHOIS data
    assert "whois_data" in results
    assert "dns_data" in results
    assert "threat_data" in results


@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling for invalid domain"""
    crew = DomainIntelligenceCrew()
    domain = "invalid-domain-that-does-not-exist.local"

    # Run the analysis
    results = await crew.analyze_domain(domain)

    # Verify error handling
    assert "error" in results


@pytest.mark.asyncio
async def test_concurrent_analysis():
    """Test concurrent domain analysis"""
    # Skip if using o3-mini model, which doesn't support temperature
    if MODEL_NAME == "o3-mini":
        pytest.skip("o3-mini model doesn't support temperature parameter")

    crew = DomainIntelligenceCrew()
    domains = ["walla.co.il", "ynet.co.il", "mako.co.il"]

    # Run analyses concurrently with rate limiting
    tasks = []
    for domain in domains:
        task = asyncio.create_task(crew.analyze_domain(domain))
        tasks.append(task)
        # Add a small delay between task creation to respect rate limits
        await asyncio.sleep(1)

    results = await asyncio.gather(*tasks)

    assert len(results) == 3
    for result in results:
        assert "whois_data" in result
        assert "dns_data" in result
        assert "threat_data" in result


@pytest.mark.integration
@pytest.mark.asyncio
# Remove fixture, instantiate agents locally
async def test_dns_agent_task():
    """Test a simple task delegation to the DNS agent."""
    # Instantiate required agents directly
    try:
        dns_agent_wrapper = DNSAnalyzerAgent()
        manager_agent_wrapper = SecurityManagerAgent()
    except Exception as e:
        pytest.fail(f"Failed to initialize agents for test_dns_agent_task: {e}")

    # Skip test if agents failed initialization (though fail above is more likely)
    # Redundant check, kept for parallel structure if needed
    # if not dns_agent_wrapper or not manager_agent_wrapper:
    #     pytest.skip("Required agents (DNS, Manager) not initialized")

    task = Task(
        description="Perform a DNS lookup for A records on google.com.",
        agent=dns_agent_wrapper.agent,  # Access the underlying crewai Agent
        expected_output="A list of IP addresses for google.com.",
    )

    # Minimal crew to test delegation
    crew = Crew(
        agents=[dns_agent_wrapper.agent, manager_agent_wrapper.agent],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )
    # Kickoff is synchronous
    result = crew.kickoff()
    assert result is not None
    # Check the raw output string representation for expected content
    assert isinstance(result.raw, str)
    assert "142.251." in result.raw  # Check for part of expected IP


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
