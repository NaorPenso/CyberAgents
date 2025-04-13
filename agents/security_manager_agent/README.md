# Security Manager Agent

### Overview
The Security Manager Agent serves as the central orchestrator in the CyberAgents system. It interprets user requests, identifies the specific information required, delegates specialized analysis tasks to other agents, and compiles their findings into comprehensive reports.

### Responsibilities
- Interpret user security analysis requests
- Identify target entities and required analysis types
- Delegate specialized tasks to appropriate agent specialists
- Manage data flow between interdependent analyses
- Synthesize results into structured, comprehensive reports

### Configuration
The agent configuration adheres to the CyberAgents agent schema and is defined in the `agent.yaml` file. This file is automatically loaded and validated during initialization using Pydantic models.

#### Required Configuration Fields
- `role`: The specific role the agent plays (e.g., "Security Analysis Manager")
- `goal`: The agent's primary objective
- `backstory`: Background information about the agent's expertise
- `tools`: List of tools used by the agent (empty list for the manager as it relies on delegation)
- `allow_delegation`: Must be set to `true` for the manager to delegate tasks to specialists

#### Optional Configuration Fields
- `verbose`: Enables verbose logging (default: true)
- `memory`: Enables agent memory (default: false)
- `cache`: Enables response caching (default: true)
- `max_iterations`: Maximum number of iterations (default: 15)
- `max_rpm`: Maximum requests per minute (default: 60)

### Implementation Details
The agent is implemented using:
- Pydantic models for configuration validation
- YAML configuration loading with proper error handling
- CrewAI Agent framework for task delegation and execution

### Usage in the Crew
The Security Manager Agent must be included in the same crew as the specialist agents it delegates tasks to. The delegation system is dynamic, and the manager will have access to all properly loaded agents in the crew.

No special configuration is needed beyond setting `allow_delegation: true` and ensuring all specialist agents are properly registered and loaded.

### Error Handling
The agent includes robust error handling for:
- Missing or invalid configuration files
- Schema validation errors
- Agent initialization failures

### Example Usage
```python
# The manager is typically initialized by the main.py script
security_manager = SecurityManagerAgent()
crew = Crew(
    agents=[security_manager.agent, specialist1.agent, specialist2.agent],
    tasks=[...]
)
```

## Role

Security Analysis Manager

## Goal

Understand user requests related to security analysis (primarily domain intelligence). Identify the specific information required (e.g., WHOIS, DNS, Threat Intel). Dynamically delegate the appropriate analysis tasks to available specialist agents. Compile the structured results from each specialist into a cohesive and comprehensive final report.

## Backstory

An experienced security operations manager responsible for coordinating diverse security analyses. Excels at interpreting user needs, identifying the right expert for each task from the available team, and integrating disparate findings into actionable intelligence.

## Tools

- None directly. This agent relies on its `allow_delegation=True` capability to assign tasks to other agents within the Crew.

## Expected Input to Task

- A user prompt describing the desired analysis (e.g., "Analyze domain example.com", "Get WHOIS and DNS for badsite.org").

## Expected Output from Task

- A comprehensive security report (likely a string or structured JSON/Markdown, depending on LLM generation) synthesizing the findings from all delegated tasks (WHOIS, DNS, Threat Intelligence, etc.). The structure should reflect the information gathered by the specialist agents.
