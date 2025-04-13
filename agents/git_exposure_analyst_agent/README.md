# Git Exposure Analyst Agent

A specialized agent for identifying exposed secrets, API keys, credentials, and other sensitive information in Git repositories. This agent helps security teams detect and remediate potential data leaks before they lead to security breaches.

## Overview

The Git Exposure Analyst Agent specializes in detecting sensitive information across both public GitHub repositories and local Git codebases. Using a combination of GitHub search capabilities and the TruffleHog scanner, it can identify a wide range of secrets and credentials that may have been accidentally committed.

## Capabilities

- Analyze public GitHub repositories for exposed secrets
- Scan local Git repositories for sensitive information
- Detect various types of secrets (API keys, passwords, tokens, etc.)
- Provide risk assessments for identified exposures
- Recommend remediation steps

## Tools Used

1. **GitHub Search Tool**: Performs targeted searches across GitHub repositories using the GitHub API
2. **TruffleHog Scanner Tool**: Deep scanning for secrets using entropy analysis and pattern matching

## Usage

### Example 1: Analyze a GitHub Repository

```python
from agents.git_exposure_analyst_agent.git_exposure_analyst_agent import GitExposureAnalystAgent

# Initialize the agent
agent = GitExposureAnalystAgent()

# Analyze a public GitHub repository
result = agent.analyze_repository("owner/repo-name")
print(result)
```

### Example 2: Scan a Local Repository

```python
from agents.git_exposure_analyst_agent.git_exposure_analyst_agent import GitExposureAnalystAgent

# Initialize the agent
agent = GitExposureAnalystAgent()

# Analyze a local repository
result = agent.analyze_repository("/path/to/local/repo", is_local=True)
print(result)
```

### Example 3: Using the Agent within a Crew

```python
from crewai import Crew, Task
from agents.git_exposure_analyst_agent.git_exposure_analyst_agent import GitExposureAnalystAgent

# Initialize the agent
git_analyst = GitExposureAnalystAgent().agent

# Create tasks
repo_scan_task = Task(
    description="Scan our company's public repositories for any exposed secrets or credentials",
    agent=git_analyst,
    expected_output="A comprehensive report of any exposed secrets with risk assessment"
)

# Create a crew with the git analyst
security_crew = Crew(
    agents=[git_analyst],
    tasks=[repo_scan_task],
    verbose=True
)

# Run the crew
result = security_crew.kickoff()
print(result)
```

## Configuration

The agent can be configured via the `config/git_exposure_analyst_agent.yaml` file, which allows you to customize:

- GitHub API settings (rate limits, max results)
- TruffleHog scan settings (depth, historical analysis)
- Secret detection patterns
- Report templates

## Implementation Details

The GitExposureAnalystAgent inherits from the BaseAgent class and automatically loads its configuration from a YAML file. It initializes the necessary tools (GitHub Search and TruffleHog Scanner) and provides methods for direct repository analysis.

The agent implements a robust detection strategy:
1. For remote GitHub repositories:
   - First gathers repository information using the GitHub API
   - Then performs a deep scan with TruffleHog
2. For local repositories:
   - Performs a direct filesystem scan using TruffleHog

## Response Format

The agent produces structured analysis reports that include:
- Summary of findings
- Details on exposed secrets (if any)
- Risk assessment
- Remediation recommendations

## Dependencies

- GitHub API access (token optional but recommended)
- TruffleHog binary installed and available in PATH
- Git command-line tools 