"""Tests for the Defect Review Agent."""

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

import pytest
import yaml

from agents.defect_review_agent.defect_review_agent import (
    DefectReviewAgent,
    DefectReviewAgentConfig,
    LLMConfig,
    SecurityContext,
)


@pytest.fixture
def mock_yaml_config():
    """Create a mock YAML configuration."""
    return {
        "role": "Defect Reviewer",
        "goal": "Analyze security vulnerabilities and provide remediation",
        "backstory": "You are a security expert specializing in remediation",
        "tools": [],
        "allow_delegation": True,
        "verbose": True,
        "memory": False,
        "max_iterations": 15,
        "max_rpm": 60,
        "cache": True,
        "include_code_examples": True,
        "max_suggestions_per_finding": 3,
        "prioritize_critical": True,
        "enable_collaborative_analysis": True,
        "collaborative_agents": [
            "exposure_analyst_agent",
            "threat_intelligence_agent",
            "security_architect_agent",
            "evidence_collection_agent",
        ],
    }


@pytest.fixture
def mock_defect_agent(mock_yaml_config):
    """Create a mocked Defect Review Agent for testing."""
    with (
        patch("builtins.open", mock_open(read_data=yaml.dump(mock_yaml_config))),
        patch("agents.defect_review_agent.defect_review_agent.Agent"),
    ):
        agent = DefectReviewAgent()
        return agent


@pytest.fixture
def mock_defect_agent_with_crew(mock_yaml_config):
    """Create a mocked Defect Review Agent with a crew for testing."""
    mock_crew = MagicMock()
    mock_crew.get_agent = MagicMock(return_value=MagicMock())
    mock_crew.run_task = AsyncMock(return_value={"test": "result"})

    with (
        patch("builtins.open", mock_open(read_data=yaml.dump(mock_yaml_config))),
        patch("agents.defect_review_agent.defect_review_agent.Agent"),
    ):
        agent = DefectReviewAgent(crew=mock_crew)
        return agent


@pytest.fixture
def sample_findings():
    """Create sample security findings for testing."""
    return {
        "scan_id": "test-scan-123",
        "component_name": "test-component",
        "affected_systems": ["system1", "system2"],
        "findings": [
            {
                "rule_id": "sql-injection",
                "message": "Possible SQL injection vulnerability",
                "severity": "high",
                "path": "app/db.py",
                "line": 42,
                "code": 'query = "SELECT * FROM users WHERE id = " + user_input',
            },
            {
                "rule_id": "xss",
                "message": "Possible cross-site scripting vulnerability",
                "severity": "medium",
                "path": "app/views.py",
                "line": 27,
                "code": "return render_template('page.html', content=user_input)",
            },
        ],
        "severity_summary": {
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0,
            "info": 0,
        },
    }


@pytest.fixture
def mock_analysis_results():
    """Create mock results from specialist agents."""
    exposure_result = {
        "exposure_level": "high",
        "internet_exposed": True,
        "attack_path": "Internet -> Load Balancer -> Web Server -> Application Server -> Database",
        "waf_protected": False,
    }

    threat_result = {
        "threat_level": "medium",
        "active_exploitation": False,
        "exploit_available": True,
        "exploit_links": [
            "https://example.com/exploit1",
            "https://example.com/exploit2",
        ],
    }

    architecture_result = {
        "exploitation_difficulty": "moderate",
        "defense_in_depth": ["WAF", "Input Validation"],
        "potential_impact": "Data breach",
        "recommendations": [
            "Implement parameterized queries",
            "Add additional validation",
        ],
    }

    evidence_package = {
        "findings_summary": "2 vulnerabilities found",
        "evidence_items": ["Evidence 1", "Evidence 2"],
        "methodology": "OWASP Testing Guide",
        "references": ["https://example.com/ref1", "https://example.com/ref2"],
    }

    return {
        "exposure": exposure_result,
        "threat": threat_result,
        "architecture": architecture_result,
        "evidence": evidence_package,
    }


class TestDefectReviewAgentConfig:
    """Test the DefectReviewAgentConfig model."""

    def test_config_validation_success(self):
        """Test that valid configuration passes validation."""
        config = {
            "role": "Defect Reviewer",
            "goal": "Analyze security vulnerabilities",
            "backstory": "You are a security expert",
            "tools": ["tool1", "tool2"],
            "allow_delegation": True,
            "verbose": True,
            "memory": False,
            "max_iterations": 15,
            "max_rpm": 60,
            "cache": True,
            "include_code_examples": True,
            "max_suggestions_per_finding": 3,
            "prioritize_critical": True,
            "enable_collaborative_analysis": True,
        }
        agent_config = DefectReviewAgentConfig(**config)
        assert agent_config.role == "Defect Reviewer"
        assert agent_config.goal == "Analyze security vulnerabilities"
        assert len(agent_config.tools) == 2
        assert agent_config.include_code_examples is True
        assert agent_config.enable_collaborative_analysis is True

    def test_config_validation_with_nested_models(self):
        """Test that nested models are properly validated."""
        config = {
            "role": "Defect Reviewer",
            "goal": "Analyze security vulnerabilities",
            "backstory": "You are a security expert",
            "tools": [],
            "allow_delegation": True,
            "llm_config": {
                "model": "gpt-4",
                "temperature": 0.5,
                "api_key": "test-key",
            },
            "security_context": {
                "allowed_domains": ["example.com"],
                "allow_internet_access": True,
            },
        }
        agent_config = DefectReviewAgentConfig(**config)
        assert isinstance(agent_config.llm_config, LLMConfig)
        assert agent_config.llm_config.model == "gpt-4"
        assert isinstance(agent_config.security_context, SecurityContext)
        assert agent_config.security_context.allowed_domains == ["example.com"]


class TestDefectReviewAgent:
    """Test the Defect Review Agent functionality."""

    def test_initialization(self, mock_defect_agent):
        """Test that the agent initializes correctly with mocked config."""
        assert mock_defect_agent is not None
        assert isinstance(mock_defect_agent.config, DefectReviewAgentConfig)
        assert mock_defect_agent.config.role == "Defect Reviewer"
        assert mock_defect_agent.config.include_code_examples is True
        assert mock_defect_agent.config.enable_collaborative_analysis is True

    def test_initialization_file_not_found(self):
        """Test that the agent handles missing configuration file."""
        # Mock the open function to raise FileNotFoundError
        with patch("builtins.open") as mock_file:
            mock_file.side_effect = FileNotFoundError("No such file")
            with pytest.raises(FileNotFoundError):
                DefectReviewAgent()

    def test_initialization_with_config_override(self, mock_yaml_config):
        """Test that the agent handles configuration overrides."""
        override = {
            "include_code_examples": False,
            "max_suggestions_per_finding": 5,
            "enable_collaborative_analysis": False,
        }
        with (
            patch("builtins.open", mock_open(read_data=yaml.dump(mock_yaml_config))),
            patch("agents.defect_review_agent.defect_review_agent.Agent"),
        ):
            agent = DefectReviewAgent(config=override)
            assert agent.config.include_code_examples is False
            assert agent.config.max_suggestions_per_finding == 5
            assert agent.config.enable_collaborative_analysis is False

    def test_should_use_collaborative_analysis(self, mock_defect_agent):
        """Test the determination of when to use collaborative analysis."""
        # Test with complex vulnerability
        findings = {"findings": [{"rule_id": "sql-injection", "severity": "medium"}]}
        assert mock_defect_agent._should_use_collaborative_analysis(findings) is True

        # Test with high severity
        findings = {"findings": [{"rule_id": "some-vulnerability", "severity": "high"}]}
        assert mock_defect_agent._should_use_collaborative_analysis(findings) is True

        # Test with many findings
        findings = {
            "findings": [
                {"rule_id": "simple-bug-1", "severity": "low"},
                {"rule_id": "simple-bug-2", "severity": "low"},
                {"rule_id": "simple-bug-3", "severity": "low"},
                {"rule_id": "simple-bug-4", "severity": "low"},
                {"rule_id": "simple-bug-5", "severity": "low"},
                {"rule_id": "simple-bug-6", "severity": "low"},
            ]
        }
        assert mock_defect_agent._should_use_collaborative_analysis(findings) is True

        # Test with few simple findings
        findings = {
            "findings": [
                {"rule_id": "simple-bug-1", "severity": "low"},
                {"rule_id": "simple-bug-2", "severity": "low"},
            ]
        }
        assert mock_defect_agent._should_use_collaborative_analysis(findings) is False

    @pytest.mark.asyncio
    async def test_review_vulnerabilities(self, mock_defect_agent, sample_findings):
        """Test the review_vulnerabilities method returns expected structure."""
        # Force standard analysis by turning off collaborative analysis
        mock_defect_agent.config.enable_collaborative_analysis = False

        # Run the review_vulnerabilities method
        result = await mock_defect_agent.review_vulnerabilities(sample_findings)

        # Basic checks on the result structure
        assert isinstance(result, dict)
        assert "scan_id" in result
        assert result["scan_id"] == "test-scan-123"
        assert "remediation_suggestions" in result
        assert isinstance(result["remediation_suggestions"], list)
        assert len(result["remediation_suggestions"]) == len(
            sample_findings["findings"]
        )

        # Check the structure of the first suggestion
        if result["remediation_suggestions"]:
            suggestion = result["remediation_suggestions"][0]
            assert "rule_id" in suggestion
            assert suggestion["rule_id"] == "sql-injection"
            assert "severity" in suggestion
            assert suggestion["severity"] == "high"
            assert "message" in suggestion
            assert "path" in suggestion
            assert suggestion["path"] == "app/db.py"
            assert "line" in suggestion
            assert "recommendation" in suggestion
            assert "code_example" in suggestion

        # Check the summary
        assert "summary" in result
        assert "total_findings" in result["summary"]
        assert "prioritized" in result["summary"]
        assert (
            result["summary"]["prioritized"]
            == mock_defect_agent.config.prioritize_critical
        )
        assert result["summary"]["analysis_type"] == "standard"

    @pytest.mark.asyncio
    async def test_review_vulnerabilities_invalid_input(self, mock_defect_agent):
        """Test the review_vulnerabilities method handles invalid input."""
        # Force standard analysis
        mock_defect_agent.config.enable_collaborative_analysis = False

        # Test with empty findings
        result = await mock_defect_agent.review_vulnerabilities({})
        assert result["remediation_suggestions"] == []
        assert "error" in result["summary"]

        # Test with None
        result = await mock_defect_agent.review_vulnerabilities(None)
        assert result["remediation_suggestions"] == []
        assert "error" in result["summary"]

        # Test with findings but no items
        result = await mock_defect_agent.review_vulnerabilities({"findings": []})
        assert result["remediation_suggestions"] == []
        assert result["summary"]["total_findings"] == 0

    @pytest.mark.asyncio
    async def test_collaborative_analysis(
        self, mock_defect_agent_with_crew, sample_findings, mock_analysis_results
    ):
        """Test the collaborative analysis workflow."""
        # Mock the specialist analysis methods
        mock_defect_agent_with_crew._analyze_exposure = AsyncMock(
            return_value=mock_analysis_results["exposure"]
        )
        mock_defect_agent_with_crew._analyze_threats = AsyncMock(
            return_value=mock_analysis_results["threat"]
        )
        mock_defect_agent_with_crew._analyze_architecture = AsyncMock(
            return_value=mock_analysis_results["architecture"]
        )
        mock_defect_agent_with_crew._collect_evidence = AsyncMock(
            return_value=mock_analysis_results["evidence"]
        )

        # Run the collaborative analysis
        result = await mock_defect_agent_with_crew._perform_collaborative_analysis(
            sample_findings
        )

        # Check result structure
        assert "remediation_suggestions" in result
        assert "supporting_analysis" in result
        assert "evidence_package" in result
        assert "summary" in result

        # Check that specialist results were incorporated
        assert "exposure" in result["supporting_analysis"]
        assert "threat" in result["supporting_analysis"]
        assert "architecture" in result["supporting_analysis"]
        assert "risk_score" in result["summary"]
        assert "priority_level" in result["summary"]
        assert result["summary"]["analysis_type"] == "collaborative"

        # Verify that specialist methods were called
        mock_defect_agent_with_crew._analyze_exposure.assert_called_once()
        mock_defect_agent_with_crew._analyze_threats.assert_called_once()
        mock_defect_agent_with_crew._analyze_architecture.assert_called_once()
        mock_defect_agent_with_crew._collect_evidence.assert_called_once()

    @pytest.mark.asyncio
    async def test_specialist_agent_delegation(
        self, mock_defect_agent_with_crew, sample_findings
    ):
        """Test the delegation to specialist agents."""
        # Test exposure analysis
        exposure_result = await mock_defect_agent_with_crew._analyze_exposure(
            sample_findings, "test-component", ["sql-injection", "xss"]
        )
        assert exposure_result == {"test": "result"}
        mock_defect_agent_with_crew.crew.get_agent.assert_called_with(
            "exposure_analyst_agent"
        )
        mock_defect_agent_with_crew.crew.run_task.assert_called_once()

        # Reset mocks
        mock_defect_agent_with_crew.crew.get_agent.reset_mock()
        mock_defect_agent_with_crew.crew.run_task.reset_mock()

        # Test threat analysis
        threat_result = await mock_defect_agent_with_crew._analyze_threats(
            sample_findings, ["sql-injection", "xss"]
        )
        assert threat_result == {"test": "result"}
        mock_defect_agent_with_crew.crew.get_agent.assert_called_with(
            "threat_intelligence_agent"
        )
        mock_defect_agent_with_crew.crew.run_task.assert_called_once()

    def test_calculate_risk_score(self, mock_defect_agent):
        """Test risk score calculation."""
        # Test critical exposure, high threat, easy exploitation
        exposure_result = {"exposure_level": "critical"}
        threat_result = {"threat_level": "high"}
        architecture_result = {"exploitation_difficulty": "easy"}

        risk_score = mock_defect_agent._calculate_risk_score(
            exposure_result, threat_result, architecture_result
        )
        assert risk_score >= 8.5  # Should be critical priority

        # Test low exposure, low threat, difficult exploitation
        exposure_result = {"exposure_level": "low"}
        threat_result = {"threat_level": "low"}
        architecture_result = {"exploitation_difficulty": "difficult"}

        risk_score = mock_defect_agent._calculate_risk_score(
            exposure_result, threat_result, architecture_result
        )
        assert risk_score < 5.0  # Should be low priority

        # Test unknown values
        exposure_result = {"exposure_level": "unknown"}
        threat_result = {"threat_level": "unknown"}
        architecture_result = {"exploitation_difficulty": "unknown"}

        risk_score = mock_defect_agent._calculate_risk_score(
            exposure_result, threat_result, architecture_result
        )
        assert risk_score == 5.0  # Should be medium priority

    def test_risk_score_to_priority(self, mock_defect_agent):
        """Test conversion of risk score to priority level."""
        assert mock_defect_agent._risk_score_to_priority(9.0) == "P0 (Critical)"
        assert mock_defect_agent._risk_score_to_priority(7.5) == "P1 (High)"
        assert mock_defect_agent._risk_score_to_priority(6.0) == "P2 (Medium)"
        assert mock_defect_agent._risk_score_to_priority(3.0) == "P3 (Low)"
        assert mock_defect_agent._risk_score_to_priority(1.0) == "P4 (Lowest)"

    def test_generate_suggestion(self, mock_defect_agent):
        """Test the _generate_suggestion method."""
        finding = {
            "rule_id": "test-rule",
            "message": "Test message",
            "severity": "critical",
            "path": "test/path.py",
            "line": 100,
            "code": "test code",
        }

        # Test with include_code_examples=True (default)
        suggestion = mock_defect_agent._generate_suggestion(finding)
        assert suggestion["rule_id"] == "test-rule"
        assert suggestion["severity"] == "critical"
        assert suggestion["path"] == "test/path.py"
        assert suggestion["line"] == 100
        assert suggestion["code_example"] is not None

        # Test with include_code_examples=False
        mock_defect_agent.config.include_code_examples = False
        suggestion = mock_defect_agent._generate_suggestion(finding)
        assert suggestion["code_example"] is None

    def test_extract_vulnerability_types(self, mock_defect_agent):
        """Test extraction of unique vulnerability types."""
        findings = {
            "findings": [
                {"rule_id": "sql-injection"},
                {"rule_id": "xss"},
                {"rule_id": "sql-injection"},  # Duplicate
                {"rule_id": "csrf"},
            ]
        }

        vulnerability_types = mock_defect_agent._extract_vulnerability_types(findings)
        assert len(vulnerability_types) == 3
        assert "sql-injection" in vulnerability_types
        assert "xss" in vulnerability_types
        assert "csrf" in vulnerability_types
