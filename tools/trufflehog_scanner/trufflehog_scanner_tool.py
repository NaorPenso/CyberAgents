"""TruffleHog scanner tool for detecting secrets in Git repositories.

This tool provides an interface to TruffleHog, a tool that scans Git repositories
for secrets, credentials, and other sensitive information.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import yaml
from crewai.tools import BaseTool
from pydantic import ConfigDict, Field, PrivateAttr

logger = logging.getLogger(__name__)


class TruffleHogScannerTool(BaseTool):
    """Tool to scan Git repositories for exposed secrets using TruffleHog (Sync Version)."""

    name: str = "trufflehog_scanner"
    description: str = """
    Scans Git repositories (GitHub, GitLab, local) for exposed secrets and sensitive data using TruffleHog.
    Input should be a repository target: "github:<owner>/<repo>", "gitlab:<owner>/<repo>", or "local:<path>".
    """

    # Internal state managed by Pydantic's PrivateAttr
    _trufflehog_executable: Optional[str] = PrivateAttr(default=None)
    _git_executable: Optional[str] = PrivateAttr(default=None)
    _is_available: bool = PrivateAttr(default=False)

    # Add model config for Pydantic
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(self, **kwargs):
        """Initialize the tool and check dependencies synchronously."""
        # Call super() first for Pydantic V2 initialization
        super().__init__(**kwargs)
        # Now assign to private attributes
        self._trufflehog_executable = shutil.which("trufflehog")
        self._git_executable = shutil.which("git")
        if self._trufflehog_executable and self._git_executable:
            self._is_available = True
            logger.info(f"TruffleHog found: {self._trufflehog_executable}")
            logger.info(f"Git found: {self._git_executable}")
        else:
            if not self._trufflehog_executable:
                logger.error("TruffleHog not found.")
            if not self._git_executable:
                logger.error("Git not found.")
            self._is_available = False
            # Optionally modify description or rely on _run check

    # --- Synchronous Core Logic --- #
    def _run(self, repo_target: str) -> str:
        """Run TruffleHog scan synchronously."""
        if not self._is_available:
            return (
                "Error: TruffleHogScannerTool unavailable. Missing TruffleHog or Git."
            )

        logger.info(f"Running sync TruffleHog scan on: {repo_target}")
        if not repo_target or not isinstance(repo_target, str):
            return "Error: Invalid target."
        repo_target = repo_target.strip()

        try:
            if repo_target.startswith("github:"):
                repo = repo_target[7:]
                if "/" not in repo or len(repo.split("/")) != 2:
                    return f"Error: Invalid GitHub format..."
                return self._scan_remote_repo(repo, "github")
            elif repo_target.startswith("gitlab:"):
                repo = repo_target[7:]
                if "/" not in repo or len(repo.split("/")) != 2:
                    return f"Error: Invalid GitLab format..."
                return self._scan_remote_repo(repo, "gitlab")
            elif repo_target.startswith("local:"):
                repo_path = repo_target[6:]
                return self._scan_local_repo(repo_path)
            else:
                logger.warning(f"Assuming local path for target: {repo_target}")
                return self._scan_local_repo(repo_target)
        except Exception as e:
            logger.exception(f"Error during TruffleHog scan: {e}")
            return f"Error during scan: {e}"

    def _scan_remote_repo(self, repo: str, platform: str) -> str:
        """Clone and scan a remote repository synchronously."""
        base_url = f"https://{platform}.com"
        clone_url = f"{base_url}/{repo}.git"
        with tempfile.TemporaryDirectory(prefix=f"trufflehog_{platform}_") as temp_dir:
            logger.info(f"Cloning {platform} repo {repo} into {temp_dir}")
            clone_command = [
                self._git_executable,
                "clone",
                "--depth",
                "1",
                clone_url,
                temp_dir,
            ]
            try:
                clone_result = subprocess.run(
                    clone_command, check=True, capture_output=True, text=True
                )
                logger.info(f"Clone successful. Scanning {temp_dir}")
                return self._scan_local_repo(temp_dir)
            except FileNotFoundError:
                logger.error(f"Git executable not found at {self._git_executable}")
                return "Error: Git executable not found."
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.strip() if e.stderr else e.stdout.strip()
                logger.error(f"Error cloning {platform} repo {repo}: {error_msg}")
                return f"Error cloning {platform} repo {repo}: {error_msg}"
            except Exception as e:
                logger.exception(f"Error scanning {platform} repo {repo}: {e}")
                return f"Error scanning {platform} repo {repo}: {e}"

    def _scan_local_repo(self, repo_path: str) -> str:
        """Scan a local Git repository synchronously."""
        if not os.path.exists(repo_path):
            return f"Error: Path does not exist: {repo_path}"
        if not os.path.isdir(repo_path):
            return f"Error: Path is not a directory: {repo_path}"

        rules_file_path: Optional[str] = None
        try:
            rules_file_path = self._get_custom_rules()
            # Use filesystem scan for better detection in tests/simple cases
            cmd = [self._trufflehog_executable, "filesystem", repo_path, "--json"]
            if rules_file_path:
                cmd.extend(["--rules", rules_file_path])
            logger.info(f"Executing sync TruffleHog command: {' '.join(cmd)}")

            scan_result = subprocess.run(cmd, capture_output=True, text=True)

            if scan_result.returncode > 1:
                error_msg = (
                    scan_result.stderr.strip()
                    if scan_result.stderr
                    else scan_result.stdout.strip()
                )
                logger.error(
                    f"TruffleHog error (code {scan_result.returncode}): {error_msg}"
                )
                return f"Error running TruffleHog scan: {error_msg}"
            elif scan_result.returncode == 1:
                logger.info("TruffleHog found potential secrets.")
            else:
                logger.info("TruffleHog scan completed. No secrets found.")

            return self._process_scan_results(scan_result.stdout)
        except FileNotFoundError:
            logger.error(
                f"Trufflehog executable not found at {self._trufflehog_executable}"
            )
            return "Error: Trufflehog executable not found."
        except Exception as e:
            logger.exception(f"Error scanning local repo {repo_path}: {e}")
            return f"Error scanning local repo {repo_path}: {e}"
        finally:
            if rules_file_path and os.path.exists(rules_file_path):
                try:
                    os.unlink(rules_file_path)
                    logger.debug(f"Removed temp rules: {rules_file_path}")
                except OSError as e:
                    logger.warning(
                        f"Failed to remove temp rules {rules_file_path}: {e}"
                    )

    # --- Synchronous Helper Methods --- #
    def _get_custom_rules(self) -> Optional[str]:
        """Generate custom rules file for TruffleHog based on policy patterns.
        Synchronous method.
        """
        try:
            patterns = self._load_patterns_from_policies()
            if not patterns or not any(patterns.values()):
                return None
            rules: Dict[str, Dict[str, str]] = {}
            severities = {
                "high_priority": "HIGH",
                "medium_priority": "MEDIUM",
                "low_priority": "LOW",
            }
            for severity_key, severity_val in severities.items():
                for idx, pattern in enumerate(patterns.get(severity_key, [])):
                    if not pattern or not isinstance(pattern, str):
                        continue
                    rule_name = f"{severity_key}_rule_{idx}"
                    rules[rule_name] = {
                        "description": f"{severity_val} priority pattern {idx}",
                        "regex": pattern,
                        "severity": severity_val,
                    }
            if not rules:
                return None
            rules_file = tempfile.NamedTemporaryFile(
                delete=False, mode="w", suffix=".json", prefix="trufflehog_rules_"
            )
            json.dump({"rules": rules}, rules_file)
            rules_file.close()
            logger.info(
                f"Created custom rules file with {len(rules)} rules: {rules_file.name}"
            )
            return rules_file.name
        except ImportError:
            logger.warning("PyYAML not needed/installed?")
            return None
        except Exception as e:
            logger.exception(f"Error creating custom TruffleHog rules: {e}")
            return None

    def _load_patterns_from_policies(self) -> Dict[str, List[str]]:
        """Load patterns from policy files (synchronous)."""
        patterns: Dict[str, List[str]] = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
        }
        try:
            import yaml

            script_dir = os.path.dirname(__file__)
            default_policies_dir = os.path.abspath(
                os.path.join(
                    script_dir,
                    "../../agents/git_exposure_analyst_agent/knowledge/policy",
                )
            )
            policies_dir = os.getenv("TRUFFLEHOG_POLICY_DIR", default_policies_dir)
            if not os.path.exists(policies_dir) or not os.path.isdir(policies_dir):
                return self._get_default_patterns()
            logger.info(
                f"Loading TruffleHog patterns from policy directory: {policies_dir}"
            )
            loaded_files = 0
            for filename in os.listdir(policies_dir):
                if filename.endswith((".yaml", ".yml")):
                    file_path = os.path.join(policies_dir, filename)
                    try:
                        with open(file_path, "r") as f:
                            policy_data = yaml.safe_load(f)
                            if not isinstance(policy_data, dict):
                                continue
                            loaded_files += 1
                            for key in patterns.keys():
                                p_list = policy_data.get(key, [])
                                if isinstance(p_list, list):
                                    patterns[key].extend([str(p) for p in p_list if p])
                    except Exception as e:
                        logger.error(f"Error loading policy file {filename}: {e}")
            for key in patterns:
                patterns[key] = sorted(list(set(patterns[key])))
            if loaded_files == 0 or not any(patterns.values()):
                return self._get_default_patterns()
            logger.info(
                f"Loaded patterns from {loaded_files} files: { {k: len(v) for k, v in patterns.items()} }"
            )
            return patterns
        except ImportError:
            return self._get_default_patterns()
        except Exception as e:
            logger.exception(f"Error loading patterns from policies: {e}")
            return self._get_default_patterns()

    def _get_default_patterns(self) -> Dict[str, List[str]]:
        """Get default patterns when policy files cannot be loaded (synchronous)."""
        logger.debug("Using default TruffleHog patterns.")
        return {
            "high_priority": [
                r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"](\S+)['\"]",
                r"(?i)(?:api_token|api_key|token|secret|access_key)\s*[:=]\s*['\"](\S+)['\"]",
                r"(?i)(?:private[_-]?key|key[_-]?file)\s*[:=]\s*['\"](.+\.(?:key|pem))['\"]",
                r"(^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})([^A-Za-z0-9/+=]|$)",  # AWS Access Key ID
                r"AIza[0-9A-Za-z\-_]{35}",  # Google API Key
                r"-----BEGIN\s+(?:RSA|DSA|EC|PGP|OPENSSH)\s+PRIVATE\s+KEY-----",
                r"xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-f0-9]{32}",  # Slack Token
            ],
            "medium_priority": [
                r"(?:jdbc|mysql|postgres(?:ql)?|mongodb(?:\+srv)?)://(?:\w+:\w+@)?[\w.-]+(?:\:\d+)?/\w+",  # Connection Strings
                r'"client_secret"\s*:\s*"[a-zA-Z0-9_\-]{20,}"',  # Common JSON client secret
            ],
            "low_priority": [
                r"(?i)(?:todo|fixme|hack):.*\b(?:key|secret|password|token|credentials?)\b"  # Comments mentioning secrets
            ],
        }

    def _process_scan_results(self, scan_output: str) -> str:
        """Process and format TruffleHog scan results (synchronous)."""
        if not scan_output or not scan_output.strip():
            return "### TruffleHog Scan Results\n\nNo secrets or sensitive information detected."

        findings: List[Dict[str, Any]] = []
        severity_counts: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for line in scan_output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                finding = json.loads(line)
                source_metadata = finding.get("SourceMetadata", {})
                commit = source_metadata.get("commit", "N/A")[:8]
                email = source_metadata.get("email", "N/A")
                timestamp = source_metadata.get("timestamp", "N/A")

                formatted_finding = {
                    "detector": finding.get("DetectorName", "Unknown"),
                    "severity": finding.get("Severity", "MEDIUM").upper(),
                    "file": finding.get("SourceMetadata", {}).get("file", "N/A"),
                    "commit": commit,
                    "line": finding.get("SourceMetadata", {}).get("line", "N/A"),
                    "raw": finding.get("Raw", "N/A")[:100]
                    + (
                        "..." if len(finding.get("Raw", "")) > 100 else ""
                    ),  # Truncate raw finding
                }
                findings.append(formatted_finding)
                severity_counts[formatted_finding["severity"]] = (
                    severity_counts.get(formatted_finding["severity"], 0) + 1
                )
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse TruffleHog JSON line: {line[:100]}...")
            except Exception as e:
                logger.warning(f"Error processing finding line: {e}")

        findings.sort(
            key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["severity"], 3)
        )

        report = "### TruffleHog Scan Results\n\n"
        total_findings = len(findings)
        report += f"**Total findings:** {total_findings}\n"
        if total_findings > 0:
            report += "**Severity breakdown:** "
            report += ", ".join(
                [
                    f"{sev}: {count}"
                    for sev, count in severity_counts.items()
                    if count > 0
                ]
            )
            report += "\n\n"
            report += "| Severity | Detector | File:Line | Commit | Raw Snippet (truncated) |\n"
            report += "| -------- | -------- | --------- | ------ | ----------------------- |\n"
            for f in findings[:20]:  # Limit results in report
                report += f"| {f['severity']} | {f['detector']} | {f['file']}:{f['line']} | {f['commit']} | `{f['raw']}` |\n"
            if total_findings > 20:
                report += f"\n... (results truncated to first 20 findings)\n"

            report += "\n### Recommendations\n"
            if severity_counts.get("HIGH", 0) > 0:
                report += "- **CRITICAL:** High severity findings detected! Investigate immediately, revoke/rotate exposed credentials, and remove from Git history.\n"
            report += "- Review all findings to determine if they are true positives.\n"
            report += "- Implement pre-commit hooks (e.g., gitleaks, detect-secrets) to prevent future leaks.\n"
            report += "- Use a dedicated secrets management solution.\n"
        else:
            report += "\nNo potential secrets detected based on the scan.\n"
            report += "\n### Recommendations\n"
            report += "- Continue using pre-commit hooks and secure practices.\n"

        return report.strip()
