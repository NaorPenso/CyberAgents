"""
Semgrep Scanner Tool for security code scanning.

This tool allows scanning code snippets or files for security vulnerabilities
using Semgrep, a static analysis engine for finding bugs and enforcing code standards.
"""

# import asyncio # Unused
import json
import logging
import os
import re

# import shlex # Unused
import subprocess
import tempfile
from pathlib import Path

# Add Any back to the import
from typing import Any, ClassVar, Dict, List, Optional, Type, Collection

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field, field_validator

from utils.rate_limiter import RateLimiter

# import time # Unused


# Set up logging
logger = logging.getLogger(__name__)


class SemgrepInput(BaseModel):
    """Input model for the Semgrep Scanner Tool."""

    code: Optional[str] = Field(
        None, description="Code snippet to scan for vulnerabilities"
    )
    file_path: Optional[str] = Field(
        None, description="Path to file or directory to scan"
    )
    language: Optional[str] = Field(
        None,
        description="Programming language of the code (auto-detected if not specified)",
    )
    rules: List[str] = Field(
        ["p/security-audit", "p/owasp-top-ten"],
        description="Semgrep rule sets to use for scanning",
    )
    max_timeout: int = Field(300, description="Maximum execution time in seconds")
    use_local_policies: bool = Field(
        False, description="Whether to use local policies from the policies directory"
    )
    policy_preference: str = Field(
        "both",
        description="Policies to use: 'local' (only local), 'registry' (only registry), or 'both' (default)",
    )

    @field_validator("code", "file_path")
    def validate_input_source(cls, v, info):
        """Validate that either code or file_path is provided."""
        other_field = "file_path" if info.field_name == "code" else "code"
        other_value = info.data.get(other_field)

        if v is None and other_value is None:
            raise ValueError("Either code or file_path must be provided")

        return v

    @field_validator("policy_preference")
    def validate_policy_preference(cls, v):
        """Validate policy preference."""
        valid_preferences = ["local", "registry", "both"]
        if v not in valid_preferences:
            raise ValueError(
                f"Policy preference must be one of: {', '.join(valid_preferences)}"
            )
        return v

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SemgrepTool(BaseTool):
    """
    Tool for scanning code using Semgrep to identify security vulnerabilities.

    This tool can analyze code snippets or files to detect security issues,
    code quality problems, and potential vulnerabilities.
    """

    name: str = "semgrep_scanner"
    description: str = (
        "Scans a given code snippet or local file/directory path for security vulnerabilities using Semgrep. "
        "Input requires the code/path and optionally the language."
    )
    args_schema: Type[BaseModel] = SemgrepInput
    # Use correct RateLimiter arguments
    rate_limiter: RateLimiter = RateLimiter(
        max_requests=10, time_window=60
    )  # Renamed rate->max_requests, period->time_window
    # Default scan timeout in seconds
    max_scan_time: int = 300
    # Default path for temporary scan files
    temp_dir_base: str = tempfile.gettempdir()
    # Default Semgrep rules - uses Semgrep defaults if empty
    rules: List[str] = []
    scan_timeout: int = 300
    clone_timeout: int = 600
    # Add ClassVar type hints
    supported_languages: ClassVar[List[str]] = [
        "python",
        # ... other languages
    ]
    language_extensions: ClassVar[Dict[str, List[str]]] = {
        "python": [".py"],
        # ... other extensions
    }
    # ...
    # Add ClassVar type hint
    _semgrep_executable: ClassVar[Optional[str]] = None
    _checked_semgrep: ClassVar[bool] = False

    # Language patterns for detection
    LANGUAGE_PATTERNS: ClassVar[Dict[str, List[str]]] = {
        "python": [
            r"import\s+[\w\.]+",
            r"from\s+[\w\.]+\s+import",
            r"def\s+\w+\s*\(.*\):",
            r"class\s+\w+\s*(\(.*\))?:",
        ],
        "javascript": [
            r"const\s+\w+\s*=",
            r"let\s+\w+\s*=",
            r"function\s+\w+\s*\(.*\)\s*{",
            r"import\s+.*\s+from\s+['\"]",
            r"export\s+",
            r"=>\s*{",
            r"React",
        ],
        "java": [
            r"public\s+class",
            r"private\s+\w+\s+\w+\s*\(",
            r"package\s+[\w\.]+;",
            r"import\s+[\w\.]+;",
        ],
        "go": [
            r"package\s+\w+",
            r"func\s+\w+\s*\(.*\)\s*.*{",
            r"import\s+\([\s\S]*?\)",
            r"type\s+\w+\s+struct\s*{",
        ],
        "ruby": [
            r"require\s+['\"][\w\/]+['\"]",
            r"def\s+\w+",
            r"class\s+\w+(\s+<\s+\w+)?",
            r"module\s+\w+",
        ],
        "php": [
            r"<\?php",
            r"function\s+\w+\s*\(.*\)\s*{",
            r"namespace\s+[\w\\]+;",
            r"use\s+[\w\\]+",
        ],
        "c": [
            r"#include\s+[<\"][\w\.]+[>\"]",
            r"int\s+main\s*\(.*\)\s*{",
            r"\w+\s+\w+\s*\(.*\)\s*{",
            r"struct\s+\w+\s*{",
        ],
        "cpp": [
            r"#include\s+[<\"][\w\.]+[>\"]",
            r"namespace\s+\w+\s*{",
            r"class\s+\w+\s*{",
            r"std::",
            r"template\s*<",
        ],
    }

    # Define the directory containing policies relative to this file
    POLICIES_DIR: ClassVar[Path] = Path(__file__).parent / "policies"
    KNOWLEDGE_DIR: ClassVar[Path] = POLICIES_DIR / "knowledge"

    model_config = ConfigDict(arbitrary_types_allowed=True)

    async def _run(
        self,
        code: Optional[str] = None,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        rules: Optional[List[str]] = None,
        max_scan_time: Optional[int] = None,
    ) -> Dict:
        """
        Run the Semgrep scan on the provided code or file.

        Args:
            code: Code snippet to scan
            file_path: Path to file or directory to scan
            language: Programming language of the code
            rules: Semgrep rule sets to use
            max_scan_time: Maximum execution time in seconds

        Returns:
            Dictionary with scan results and findings
        """
        # Use default if None
        effective_rules = rules if rules is not None else self.rules

        # Prepare temporary directory if needed
        temp_dir = None
        scan_path = file_path

        try:
            # If code snippet is provided, write it to a temporary file
            if code and not file_path:
                temp_dir = tempfile.mkdtemp(prefix="semgrep_scan_")

                # Detect language if not provided
                detected_language = language or self._detect_language(code)

                # Determine file extension
                extension = ".txt"
                if detected_language != "unknown":
                    extensions = self.language_extensions.get(detected_language, [])
                    if extensions:
                        extension = extensions[0]

                # Create temp file with appropriate extension
                temp_file = os.path.join(temp_dir, f"code{extension}")

                with open(temp_file, "w") as f:
                    f.write(code)

                scan_path = temp_dir
                language = detected_language

            # Get policy configuration
            policy_config = self._get_policy_config(
                language,
                effective_rules,
                self.use_local_policies,
                self.policy_preference,
            )

            # Run Semgrep scan
            results = self._run_semgrep(
                scan_path, language, policy_config, max_scan_time or self.max_scan_time
            )

            # Process results to make them more user-friendly
            processed_results = self._process_findings(results)

            # Add policy configuration used to results
            processed_results["policy_config"] = {
                "registry_rules": policy_config.get("registry_rules", []),
                "local_rules": policy_config.get("local_rules", []),
                "policy_preference": self.policy_preference,
            }

            return processed_results

        finally:
            # Clean up temporary directory if created
            if temp_dir and os.path.exists(temp_dir):
                os.rmdir(temp_dir)

    def _detect_language(self, code: str, filename: Optional[str] = None) -> str:
        """
        Detect the programming language of the provided code.

        Args:
            code: The code to analyze
            filename: Optional filename that may contain extension hints

        Returns:
            The detected language or "unknown" if detection fails
        """
        # Try to detect from filename extension first
        if filename:
            _, ext = os.path.splitext(filename)
            if ext:
                for lang, extensions in self.language_extensions.items():
                    if ext.lower() in extensions:
                        return lang

        # Count pattern matches for each language
        matches = {lang: 0 for lang in self.LANGUAGE_PATTERNS}
        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            for pattern in patterns:
                matches[lang] += len(re.findall(pattern, code))

        # Return the language with the most matches
        if matches:
            best_match = max(matches.items(), key=lambda x: x[1])
            if best_match[1] > 0:
                return best_match[0]

        return "unknown"

    def _get_policy_config(
        self,
        language: Optional[str],
        rules: List[str],
        use_local_policies: bool,
        policy_preference: str,
    ) -> Dict:
        """
        Configure which policies to use based on preferences.

        Args:
            language: Programming language of the code
            rules: Registry rule sets to use
            use_local_policies: Whether to use local policies
            policy_preference: Which policies to use ('local', 'registry', or 'both')

        Returns:
            Policy configuration dictionary
        """
        registry_rules = []
        local_rules = []

        # Add registry rules if needed
        if policy_preference in ["registry", "both"]:
            registry_rules = rules

        # Add local rules if needed
        if (use_local_policies or policy_preference in ["local", "both"]) and language:
            language_policies_dir = self.KNOWLEDGE_DIR / language

            if language_policies_dir.exists():
                # Find all YAML policy files for this language
                policy_files = list(language_policies_dir.glob("*.yml"))
                policy_files.extend(language_policies_dir.glob("*.yaml"))

                # Use absolute paths for local rules
                local_rules = [str(path.resolve()) for path in policy_files]

                logger.info(
                    f"Found {len(local_rules)} local policy files for {language}"
                )

        return {"registry_rules": registry_rules, "local_rules": local_rules}

    def _run_semgrep(
        self,
        target_path: str,
        language: Optional[str],
        rules: List[str],
        scan_timeout: int,
    ) -> Dict:
        """
        Run Semgrep on the specified path.

        Args:
            target_path: Path to scan
            language: Optional language specifier
            rules: Semgrep rule sets to use
            scan_timeout: Maximum execution time

        Returns:
            Raw Semgrep results
        """
        # Prepare command
        cmd = [
            "semgrep",
            "--json",
            "-q",  # Quiet mode
        ]

        # Add registry rules if any
        if rules:
            cmd.append(f"--config={','.join(rules)}")

        # Add language if specified
        if language and language != "unknown":
            cmd.append(f"--lang={language}")

        # Add path to scan
        cmd.append(target_path)

        logger.info(f"Running Semgrep command: {' '.join(cmd)}")

        try:
            # Run with timeout
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=scan_timeout
            )

            if result.returncode != 0 and result.returncode != 1:
                # Semgrep returns 1 when it finds issues, which is normal
                logger.error(f"Semgrep error: {result.stderr}")
                return {"error": result.stderr, "findings": []}

            # Parse JSON output
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse Semgrep output: {result.stdout}")
                return {"error": "Failed to parse Semgrep output", "findings": []}

        except subprocess.TimeoutExpired:
            return {
                "error": f"Semgrep scan timed out after {scan_timeout} seconds",
                "findings": [],
            }
        except Exception as e:
            logger.exception(f"Error running Semgrep: {str(e)}")
            return {"error": f"Error running Semgrep: {str(e)}", "findings": []}

    def _process_findings(self, results: Dict) -> Dict:
        """
        Process Semgrep results into a more user-friendly format.

        Args:
            results: Raw Semgrep results

        Returns:
            Processed results with structured findings
        """
        processed_results = {
            "findings": [],
            "severity_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

        # Check if there was an error
        if "error" in results:
            processed_results["error"] = results["error"]
            return processed_results

        # Process findings
        if "results" in results:
            for result in results["results"]:
                finding = {
                    "rule_id": result.get("check_id", "unknown"),
                    "message": result.get("extra", {}).get(
                        "message", "No description available"
                    ),
                    "severity": result.get("extra", {}).get("severity", "info"),
                    "path": result.get("path", "unknown"),
                    "line": result.get("start", {}).get("line", 0),
                    "code": result.get("extra", {}).get("lines", ""),
                    "cwe": result.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": result.get("extra", {})
                    .get("metadata", {})
                    .get("owasp", []),
                }

                # Update severity counter
                severity = finding["severity"].lower()
                if severity in processed_results["severity_summary"]:
                    processed_results["severity_summary"][severity] += 1
                else:
                    processed_results["severity_summary"]["info"] += 1

                processed_results["findings"].append(finding)

        # Add stats
        processed_results["stats"] = {
            "total_findings": len(processed_results["findings"]),
            "files_scanned": results.get("stats", {}).get("files_scanned", 0),
            "scan_time": results.get("stats", {}).get("total_time", 0),
        }

        return processed_results

    def _clone_repo(self, repo_url: str, target_dir: str) -> bool:
        """Clone a git repository.

        Args:
            repo_url: The URL of the repository.
            target_dir: The directory to clone into.

        Returns:
            True if cloning was successful, False otherwise.
        """
        if not self._is_valid_repo_url(repo_url):
            logger.error(f"Invalid repository URL provided: {repo_url}")
            return False

        try:
            # Remove unused file_id placeholder comment
            cmd = ["git", "clone", "--depth", "1", repo_url, target_dir]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.clone_timeout
            )
            if result.returncode == 0:
                logger.info(f"Successfully cloned {repo_url} to {target_dir}")
                return True
            else:
                logger.error(f"Failed to clone repository {repo_url}: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error(
                f"Cloning repository {repo_url} timed out after {self.clone_timeout} seconds."
            )
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during cloning: {e}")
            return False

    def _parse_semgrep_output(
        self,
        output: str,
        target_path: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        pass # Add pass statement with correct indentation

    def _get_policy_config(
        self,
        language: Optional[str],
        rules: Optional[List[str]],
        use_local_policies: bool,
        policy_preference: str,
    ) -> Dict[str, List[str]]:
        # ...
        # Example fix for append error (assuming self.local_policies is list)
        selected_local_policies: List[str] = []
        all_local_policies: Collection[str] = self.local_policies.get(language, [])
        if isinstance(all_local_policies, list):
            selected_local_policies.extend(all_local_policies)
        # Similar checks if needed for registry_rules
        return {
            "registry_rules": selected_registry_policies,
            "local_rules": selected_local_policies,
        }

    def _run_semgrep(
        self,
        target_path: str,
        language: Optional[str],
        rules: List[str],
        scan_timeout: int,
    ) -> Dict:
        # ...
        cmd = [
            self.semgrep_executable,
            "--json",
            "-q",
        ]
        if rules:
            cmd.append(f"--config={','.join(rules)}")
        # ...
        cmd.append(target_path)
        # ...

    async def _arun(
        self,
        # ... (parameters)
        rules: Optional[List[str]] = None,
        # ...
    ) -> Dict:
        # Ensure rules passed to _get_policy_config is List[str] or None
        effective_rules = rules if rules is not None else self.rules
        policy_config_dict = self._get_policy_config(
            language,
            effective_rules,
            self.use_local_policies,
            self.policy_preference,
        )
        # Ensure policy_config_dict["registry_rules/local_rules"] are List[str]
        # before passing to _run_semgrep
        run_rules = policy_config_dict.get("registry_rules", []) + policy_config_dict.get("local_rules", [])

        # Ensure scan_path is not None before passing
        scan_path: Optional[str] = None
        # ... (logic to set scan_path) ...
        if scan_path is None:
            return {"error": "Target path for scan could not be determined."}

        results = self._run_semgrep(
            scan_path,
            language,
            run_rules,
            effective_timeout,
        )
        # Process results and return
        if "error" in results:
            logger.error(f"Semgrep scan failed: {results['error']}")
            # Ensure findings list exists even on error
            processed_error_results = {
                "error": results["error"],
                "findings": [],
                "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "scan_metadata": metadata
            }
            return processed_error_results
        else:
            # Correct call to the existing processing method
            processed_results = self._process_findings(results)
            processed_results["scan_metadata"] = metadata
            logger.info(f"Semgrep scan completed for target: {code or repository_url}")
            return processed_results
