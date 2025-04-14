# Domain WHOIS Agent

This agent is responsible for retrieving and parsing WHOIS registration data for a given domain name.

## Role

Domain Registrar Analyst

## Goal

Retrieve and structure WHOIS information for a domain.

## Backstory

An expert specializing in domain registration and ownership data. Meticulously retrieves WHOIS records and parses them into a consistent, structured format, focusing on key details like registrar, creation/expiration dates, and name servers.

## Configuration

The agent is configured using the `agent.yaml` file which strictly follows the standardized `agent_schema.yaml` schema. Key configuration properties include:

```yaml
role: "Domain Registrar Analyst"
goal: "Retrieve and structure WHOIS information for a domain."
backstory: "An expert specializing in domain registration and ownership data..."
tools: 
  - "whois_lookup"
allow_delegation: false
verbose: true
memory: false
max_iterations: 15
max_rpm: 60
cache: true
```

## Tools

- `WhoisTool`: Performs the actual WHOIS lookup for domain names to retrieve registration information.

## Implementation Details

- Uses Pydantic models with comprehensive validation for robust configuration
- Implements proper error handling for YAML parsing and validation
- Loads tools dynamically based on the configuration
- Provides detailed error handling for WHOIS lookups with informative messages
- Returns structured WHOIS data in a consistent format
- Handles various edge cases in domain registration information

## Expected Input to Task

- A domain name (implicitly provided via the context or manager's delegation).
- Example: `"Perform a WHOIS lookup for example.com"`

## Expected Output from Task

A dictionary containing structured WHOIS information:
```json
{
  "domain_name": "example.com",
  "registrar": "Example Registrar, LLC",
  "creation_date": "1995-08-14T04:00:00Z",
  "expiration_date": "2023-08-13T04:00:00Z",
  "name_servers": ["ns1.example.com", "ns2.example.com"],
  "status": ["clientTransferProhibited"],
  "emails": ["abuse@example.com"],
  "dnssec": "unsigned",
  "updated_date": "2022-08-14T04:00:00Z"
}
```

## Error Handling

The agent handles several error scenarios and returns structured error responses:

### Domain Not Found:
```json
{
  "error": "Failed to retrieve WHOIS data: Domain example123456.com not found"
}
```

### Rate Limiting:
```json
{
  "error": "WHOIS lookup rate limit exceeded. Please try again later."
}
```

### Network Issues:
```json
{
  "error": "Network error during WHOIS lookup: Connection timeout"
}
```

### Invalid Domain Format:
```json
{
  "error": "Invalid domain format: example..com"
}
```

## Integration with CrewAI

This agent integrates with the CrewAI framework as follows:
- Initialized by the DomainIntelligenceCrew in main.py
- Receives tasks from the SecurityManagerAgent
- Returns structured results that can be used by other agents

## Usage Example

```python
from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent
from crewai import Task

# Initialize the agent
whois_agent = DomainWhoisAgent()

# Create a task for the agent
whois_task = Task(
    description="Retrieve WHOIS information for github.com",
    expected_output="Structured WHOIS data for github.com",
    agent=whois_agent.agent
)

# Execute the task
result = whois_agent.agent.execute("Perform a WHOIS lookup for github.com")
print(result)
```
