# WAF Analysis Tool

**Version:** `1.0.0`

## Purpose

This tool connects to various Web Application Firewall (WAF) providers to retrieve configuration details and protected assets information. It supports multiple industry-leading WAF solutions including Imperva, Cloudflare, AWS WAF, and Azure WAF.

## Supported WAF Providers

- Imperva Cloud WAF
- Cloudflare WAF
- AWS WAF
- Azure Web Application Firewall

## Configuration

This tool's behavior is configured via the `tool.yaml` file in this directory, adhering to the `schemas/tool_schema.yaml`.

Key configurable parameters (defined in `tool.yaml`):

- `request_timeout`: Timeout in seconds for API requests
- `enabled_providers`: List of WAF providers to enable

## API Keys

The tool requires API keys for each WAF provider you want to connect to. These should be set in your environment variables or `.env` file:

- `IMPERVA_API_KEY`: API key for Imperva WAF integration
- `CLOUDFLARE_API_KEY`: API key for Cloudflare WAF integration
- `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`: Credentials for AWS WAF
- `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID`: Credentials for Azure WAF

## Usage

This tool is designed to be used by CrewAI agents. It accepts input defined by the `WAFAnalysisInput` schema within the tool's Python code.

**Input Schema:**

- `provider` (string, required): WAF provider to query ('imperva', 'cloudflare', 'aws', 'azure')
- `query_type` (string, required): Type of information to retrieve ('configuration', 'assets', 'rules')
- `resource_id` (string, optional): Specific resource ID to query (if applicable)

## Capabilities

The tool can retrieve:

1. **WAF Configurations** - Policy settings, rule configurations, and protection levels
2. **Protected Assets** - List of applications, domains, or resources protected by the WAF
3. **Rule Information** - Details about specific WAF rules and their current status
4. **Security Events** - Recent security events and blocked attacks (where supported)

## Example Usage

```python
# Example usage in an agent
waf_info = waf_analysis_tool(
    provider="cloudflare",
    query_type="configuration",
    resource_id="my-website.com"
)
```

## Change History

- **2023-04-15** - v`1.0.0` - Initial implementation with support for Imperva, Cloudflare, AWS, and Azure WAF integration
