# WHOIS Lookup Tool

## Overview

The WHOIS Lookup tool is a Python-based utility that retrieves domain registration information using the WHOIS protocol. It provides detailed information about domain ownership, registration dates, and nameservers. The tool conforms to the `tool_schema.yaml` specification for CrewAI tools.

## Schema Compliance

This tool follows the standardized `tool_schema.yaml` schema with the following configuration:

```yaml
tool:
  name: "whois_lookup"
  description: "Lookup WHOIS information for a domain"
  version: "1.0.0"

configuration:
  parameters:
    domain:
      type: "string"
      description: "Domain name to lookup"
      required: true
  dependencies:
    - "python-whois>=0.8.0"
```

## Features

- Domain registration information retrieval
- Configurable timeout settings
- Comprehensive error handling and reporting
- Standardized output format
- Integration with CrewAI tools framework

## Implementation

The tool is implemented as a class that extends `BaseTool` from the CrewAI framework:

```python
class WhoisTool(BaseTool):
    name = "whois_lookup"
    description = "Lookup WHOIS information for a domain"
    input_schema = WhoisInput
```

## Usage

### In Python

```python
from tools.whois_lookup.whois_tool import WhoisTool

# Create an instance
whois_tool = WhoisTool()

# Execute a lookup
result = whois_tool._run("example.com")
print(result)
```

### From CrewAI Agent

```python
from agents.domain_whois_agent.domain_whois_agent import DomainWhoisAgent

# The WhoisTool is automatically loaded by the agent
agent = DomainWhoisAgent()

# Execute through the agent
result = agent.agent.execute("Lookup WHOIS information for example.com")
```

## Output Format

The tool returns a dictionary containing the following information:

- `domain_name`: The domain being queried
- `registrar`: The registrar service managing the domain
- `creation_date`: When the domain was first registered
- `expiration_date`: When the domain registration expires
- `name_servers`: DNS servers handling the domain
- `status`: Current domain status codes
- `emails`: Contact email addresses
- `dnssec`: DNSSEC status
- `updated_date`: Last update date

## Error Handling

The tool implements comprehensive error handling for various failure scenarios:

### Domain Not Found
```python
{"error": "Domain not found or no WHOIS record available"}
```

### Connection Issues
```python
{"error": "Failed to connect to WHOIS server: Connection timed out"}
```

### Rate Limiting
```python
{"error": "WHOIS query rate limit exceeded. Please try again later."}
```

### Parsing Errors
```python
{"error": "Failed to parse WHOIS response: Invalid format received"}
```

### General Errors
```python
{"error": "<detailed exception message>"}
```

## Dependencies

- `python-whois>=0.8.0` - Core WHOIS protocol implementation
- `crewai>=0.1.0` - CrewAI framework integration

## Security Considerations

- Rate limiting may apply from WHOIS servers
- Some registrars may restrict access to WHOIS data
- Consider implementing caching for frequent lookups
- Privacy regulations (like GDPR) may limit available information

## Example Full Output

```json
{
    "domain_name": "GITHUB.COM",
    "registrar": "MarkMonitor Inc.",
    "creation_date": "2007-10-09T18:20:50Z",
    "expiration_date": "2023-10-09T07:00:00Z",
    "name_servers": [
        "DNS1.P01.NSONE.NET",
        "DNS2.P01.NSONE.NET",
        "DNS3.P01.NSONE.NET",
        "DNS4.P01.NSONE.NET",
        "NS-520.AWSDNS-01.NET",
        "NS-421.AWSDNS-52.COM",
        "NS-1707.AWSDNS-21.CO.UK",
        "NS-1283.AWSDNS-32.ORG"
    ],
    "status": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited",
    "emails": "abusecomplaints@markmonitor.com",
    "dnssec": "unsigned",
    "updated_date": "2022-09-07T09:10:44Z"
}
```
