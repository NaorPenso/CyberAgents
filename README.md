# CyberAgents

CyberAgents is a framework for defining, documenting, and orchestrating AI-powered cybersecurity agents. Each agent represents a specialized function within modern security operations, from detection to governance to remediation. The goal is to enable scalable, modular, and automated cybersecurity processes using agent-based architecture.

## 📌 Project Objectives

- **Modularization** of cybersecurity roles into discrete agents
- **Declarative definitions** using structured YAML for clarity and automation
- **Asynchronous coordination** of agents via defined workflows
- **Extensibility** for new agents, tools, knowledge, and domains
- **Documentation-first** to ensure clarity, auditability, and usability
- **Quality Assurance** through automated validation and testing

Each agent is defined with:

- A unique identifier and responsibilities
- A system prompt (for LLM-backed agents)
- A list of tools and external knowledge used
- Clearly defined inputs and outputs
- A sequenced list of steps and logic
- Associated documentation and knowledge artifacts

## 🧠 Repository Structure

```plaintext
CyberAgents/
├── agents/
│   ├── <agent_name>/
│   │   ├── agent.yaml      # Agent definition and configuration
│   │   ├── README.md       # Agent documentation
│   │   └── knowledge/      # Agent-specific knowledge base
├── workflows/
│   ├── incident_response.yaml
│   └── README.md
├── schemas/
│   ├── agent_schema.yaml   # YAML schema for agent definitions
│   └── workflow_schema.yaml # YAML schema for workflow definitions
├── scripts/
│   ├── validate_yaml.py    # YAML validation script
│   └── validate_agent_structure.py
├── tests/
│   └── test_yaml_validation.py
├── .github/
│   └── workflows/
│       └── pr-validation.yml
├── .pre-commit-config.yaml
├── requirements.txt
├── .gitignore
└── README.md
```

## 🧩 Agent Status Overview

| Agent Name                | Description (Placeholder)                                     | Documentation Status | Version |
| ------------------------- | ------------------------------------------------------------- | -------------------- | ------- |
| Defect Review Agent       | Reviews code and system defects for security implications     | ❌ Draft             | 0.0.1   |
| Exposure Analyst          | Analyzes external exposure and attack surface                 | ❌ Draft             | 0.0.1   |
| SOC Analyst               | Simulates Level 1–2 Security Operations Center analyst duties | ❌ Draft             | 0.0.1   |
| Incident Responder        | Performs containment, eradication, and recovery steps         | ❌ Draft             | 0.0.1   |
| Red Team Agent            | Simulates offensive attacker behavior to validate defenses    | ❌ Draft             | 0.0.1   |
| Governance Agent          | Evaluates organizational adherence to security governance     | ❌ Draft             | 0.0.1   |
| Compliance Agent          | Maps system posture against compliance frameworks             | ❌ Draft             | 0.0.1   |
| Evidence Collection Agent | Collects forensic data and artifacts for investigations       | ❌ Draft             | 0.0.1   |
| Security Operations Agent | Oversees operational security controls and metrics            | ❌ Draft             | 0.0.1   |
| Change Management Analyst | Assesses security impacts of change requests                  | ❌ Draft             | 0.0.1   |
| Network Security Agent    | Monitors and enforces network segmentation and firewall rules | ❌ Draft             | 0.0.1   |
| Endpoint Security Agent   | Manages EDR-related logic and response                        | ❌ Draft             | 0.0.1   |
| Cloud Security Agent      | Enforces cloud security configurations and alerts             | ❌ Draft             | 0.0.1   |
| Security Reporting Agent  | Generates security KPIs, dashboards, and reports              | ❌ Draft             | 0.0.1   |

> **Legend**:
>
> - `❌ Draft`: Placeholder YAML and README created.
> - `✅ Complete`: Full definition and documentation available.
> - `🧪 In Progress`: Under active development.

## 🚀 Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/your-org/CyberAgents.git
   cd CyberAgents
   ```

1. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

1. Install pre-commit hooks:

   ```bash
   pre-commit install
   ```

1. Start defining each agent's YAML configuration and replace placeholder READMEs.

## 🧪 Testing and Validation

The project includes several validation mechanisms:

1. **YAML Schema Validation**

   - Validates agent definitions against `schemas/agent_schema.yaml`
   - Validates workflow definitions against `schemas/workflow_schema.yaml`
   - Ensures proper structure and required fields

1. **Agent Structure Validation**

   - Verifies presence of required files and directories
   - Checks documentation completeness
   - Validates knowledge base organization

1. **Pre-commit Hooks**

   - Code formatting (Black)
   - Linting (Flake8)
   - Type checking (MyPy)
   - YAML validation

1. **GitHub Actions**

   - Runs on every pull request to main
   - Executes all validation checks
   - Ensures tests pass
   - Validates YAML files and agent structure

## 📦 Releases

- Each agent will be versioned independently using [semantic-release](https://semantic-release.gitbook.io/semantic-release/)
- Version tags reflect only meaningful changes to that specific agent
- Central changelogs will be published per agent under `/agents/<agent>/CHANGELOG.md`

## 📬 Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines on:

- Submitting issues
- Creating pull requests
- Following semantic commit conventions
- Writing documentation
- Adding new agents or workflows

## 📖 License

This project is licensed under the MIT License. See `LICENSE` for details.

# Domain Intelligence Crew

A powerful domain intelligence analysis system that combines WHOIS, DNS, and threat intelligence analysis.

## Features

- WHOIS data analysis
- DNS configuration analysis
- Threat intelligence correlation
- OpenTelemetry integration for observability
- Comprehensive security testing
- Concurrent domain analysis

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/domain-intelligence-crew.git
cd domain-intelligence-crew
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Usage

### Basic Usage

```python
from main import DomainIntelligenceCrew

async def analyze_domain():
    crew = DomainIntelligenceCrew()
    results = await crew.analyze_domain("example.com")
    print(results)

# Run the analysis
import asyncio
asyncio.run(analyze_domain())
```

### Configuration

The crew supports the following environment variables:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: OpenTelemetry endpoint for remote telemetry
- `WHOIS_API_KEY`: API key for WHOIS service
- `VIRUSTOTAL_API_KEY`: API key for VirusTotal
- `DNS_SERVERS`: Comma-separated list of DNS servers

### Observability

The crew includes comprehensive observability through OpenTelemetry:

- Traces for operation flow
- Metrics for performance monitoring
- Logs for debugging
- Local console output and remote export support

### Security Features

- Input validation and sanitization
- Rate limiting
- Memory protection
- Protection against common attacks:
  - Buffer overflow
  - SQL injection
  - Command injection
  - XSS
  - Path traversal
  - Unicode attacks
  - DoS attempts

## Testing

Run the test suite:

```bash
pytest tests/
```

Run security tests:

```bash
pytest tests/test_security.py
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Security

Please report security vulnerabilities to security@cyberagents.com.

## License

MIT License
