# Domain Threat Score Tool

This tool provides capabilities to analyze a domain's threat profile using external intelligence sources, primarily VirusTotal.

## Features

- Fetches domain reputation, analysis statistics, and voting data from VirusTotal.
- Analyzes basic WHOIS data (if provided) for indicators like privacy protection usage.
- Calculates a basic threat score based on VirusTotal reputation.
- Returns structured data including the score, raw VirusTotal data, and indicators.

## Class: `DomainThreatScoreTool`

Located in `tools/domain_threat_scoring/domain_threat_score_tool.py`.

### Initialization

Requires the `VIRUSTOTAL_API_KEY` environment variable to be set for VirusTotal API access.

```python
import os
from tools.domain_threat_scoring.domain_threat_score_tool import DomainThreatScoreTool

# Ensure API key is set in environment
# os.environ["VIRUSTOTAL_API_KEY"] = "YOUR_VT_API_KEY"

if os.getenv("VIRUSTOTAL_API_KEY"):
    try:
        tool = DomainThreatScoreTool()
        print("Tool initialized successfully")
    except ValueError as e:
        print(f"Initialization failed: {e}")
else:
    print("Error: VIRUSTOTAL_API_KEY environment variable not set.")
```

### Name for Agent Configuration

When assigning this tool to an agent in `agent.yaml`, use the name:

```yaml
tools:
  - threat_intelligence
```

*(Note: The internal tool name `threat_intelligence` was kept for consistency with existing agent configurations, even though the class is named `DomainThreatScoreTool`)*

### Input Schema (`ThreatInput`)

- `domain` (str, required): The domain name to analyze.
- `whois_data` (dict, optional): Pre-fetched WHOIS data dictionary for correlation.

### Core Methods

- **`_run(domain: str, whois_data: Optional[Dict] = None) -> Dict`**: Synchronous execution wrapper. Currently returns an error advising to use `_arun`.
- **`_arun(domain: str, whois_data: Optional[Dict] = None) -> Dict`**: Asynchronous execution method. Performs the VirusTotal lookup and WHOIS analysis.
- **`_analyze_virustotal(domain: str) -> Dict`**: (Internal async helper) Fetches and processes data from VirusTotal.
- **`_analyze_whois_indicators(whois_data: Optional[Dict]) -> List[str]`**: (Internal helper) Extracts simple indicators from WHOIS data.

### Output Schema (from `_arun`)

A dictionary containing:

- `threat_score` (float): Calculated score (0-1 based on VT reputation).
- `virustotal_data` (dict): Results from VirusTotal analysis (or `{"error": ...}`).
- `indicators` (list): List of strings indicating findings (e.g., "Privacy protection service used").
- `sources` (list): List of data sources used (e.g., `["VirusTotal", "WHOIS Analysis"]`).
- `recommendations` (list): Basic recommendations based on the score.
- `error` (str, optional): Present if an error occurred during execution.

## Usage within an Agent Task

The agent using this tool would typically construct a task description that includes the target domain. The CrewAI framework passes the necessary arguments based on the task context and the tool's `input_schema`.

```python
# Within a Crew definition
from crewai import Task

# Assume 'domain_scorer' is the initialized CrewAI agent instance
domain_analysis_task = Task(
    description="Perform a threat score analysis for the domain suspicious-site.net",
    expected_output="A summary report including the threat score, VirusTotal findings, and any relevant indicators.",
    agent=domain_scorer,  # The agent using DomainThreatScoreTool
)
```

## Dependencies

- `vt-py`: For VirusTotal API interaction.
- `requests`: (Used by `vt-py`).
- `pydantic`: For input schema definition.
- `crewai`: For BaseTool integration.

## Configuration

- **Environment Variables:**
  - `VIRUSTOTAL_API_KEY`: **Required**.
- **Tool YAML (`tool.yaml`):** Defines metadata and dependencies (see `tools/domain_threat_scoring/tool.yaml`).

## Error Handling

The tool includes error handling for:

- Missing or invalid API key during initialization.
- Invalid domain format input.
- VirusTotal API errors (e.g., rate limits, not found, invalid key).
- Network/Request exceptions during API calls.
- Unexpected internal errors.

Errors are typically returned within the output dictionary under the `"error"` key.
