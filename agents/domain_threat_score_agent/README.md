# Domain Threat Score Agent

This agent is responsible for assessing the security threat level of a domain or other indicators using external threat intelligence sources, primarily VirusTotal, and calculating a threat score.

## Configuration (`agent.yaml`)

The agent's behavior and core parameters are defined in `agents/domain_threat_score_agent/agent.yaml`. This file adheres to the schema defined in `schemas/agent_schema.yaml` and includes:

- **role:** "Domain Threat Score Analyst"
- **goal:** Describes the objective of consuming domain info and VT data to evaluate threat level and provide a score.
- **backstory:** Details the agent's expertise in quantifying domain threat.
- **tools:** Specifies the tools used, primarily `["threat_intelligence"]`.
- **allow_delegation:** Usually `false` as it focuses on analysis.
- Other CrewAI parameters like `verbose`, `memory`, `max_iterations`, etc.

The agent automatically loads and validates this configuration upon initialization using Pydantic.

## Initialization

To use the agent, simply instantiate the class. The constructor handles loading `agent.yaml`, initializing the required `DomainThreatScoreTool`, and setting up the underlying CrewAI agent with a central LLM provided by `utils.llm_utils.create_central_llm`.

```python
from agents.domain_threat_score_agent.domain_threat_score_agent import (
    DomainThreatScoreAgent,
)

# Ensure necessary environment variables (e.g., VIRUSTOTAL_API_KEY) are set

try:
    domain_score_agent_wrapper = DomainThreatScoreAgent()
    crewai_agent = domain_score_agent_wrapper.agent
    print("Domain Threat Score Agent initialized successfully!")
except Exception as e:
    print(f"Error initializing agent: {e}")
```

## Role

Domain Threat Score Analyst

## Goal

Consume domain information and VirusTotal data to evaluate the potential threat level associated with a specific domain, providing a calculated threat score and actionable advice based on reputation and analysis data.

## Backstory

You are a specialized security analyst focused on quantifying the threat level of internet domains. Using data primarily from VirusTotal (via the threat_intelligence tool), you analyze domain reputation, last analysis statistics, and community voting to generate a threat score. You contextualize this score with indicators from WHOIS data if available and provide clear recommendations.

## Tools

- `DomainThreatScoreTool`: (Corresponds to `threat_intelligence` in `agent.yaml`) Performs threat analysis using VirusTotal for indicators like domains, IPs, and hashes and calculates a threat score.

## Tasks

Tasks assigned to this agent typically involve analyzing a specific indicator to determine its threat score.

### Expected Input to Task

- A description string containing the indicator to analyze (e.g., a domain name).

### Expected Output from Task

- A textual summary of the findings from the threat analysis, including the calculated threat score, supporting data (VT results, indicators), and potential recommendations.

## Example Usage

```python
import os
from crewai import Task, Crew
from agents.domain_threat_score_agent.domain_threat_score_agent import (
    DomainThreatScoreAgent,
)

# Ensure API Keys are set (replace with your actual keys or env var loading)
# os.environ["VIRUSTOTAL_API_KEY"] = "YOUR_VT_API_KEY"
# os.environ["OPENAI_API_KEY"] = "YOUR_OPENAI_API_KEY"

if not os.getenv("VIRUSTOTAL_API_KEY") or not os.getenv("OPENAI_API_KEY"):
    print(
        "Error: VIRUSTOTAL_API_KEY and OPENAI_API_KEY environment variables must be set."
    )
    exit()

try:
    # 1. Initialize the Agent
    domain_score_agent_wrapper = DomainThreatScoreAgent()
    domain_scorer = domain_score_agent_wrapper.agent  # Get the CrewAI Agent instance

    # 2. Define the Task
    analysis_task = Task(
        description="Analyze the threat level and calculate a score for the domain 'example-suspicious-domain.com'.",
        expected_output="A comprehensive report detailing the domain's reputation, known associations, detection ratios, a calculated threat score, and an overall threat assessment with recommendations.",
        agent=domain_scorer,
    )

    # 3. Define the Crew (even if it's just one agent for this example)
    security_crew = Crew(
        agents=[domain_scorer], tasks=[analysis_task], verbose=2  # Set verbosity level
    )

    # 4. Execute the Task
    print("\n--- Running Domain Threat Score Task ---")
    result = security_crew.kickoff()

    print("\n--- Analysis Result ---")
    print(result)

except Exception as e:
    print(f"An error occurred: {e}")
```
