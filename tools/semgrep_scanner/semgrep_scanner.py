"""
Semgrep Scanner Tool for security code scanning.

This tool scans a Git repository, local path, or code snippet using `semgrep scan`.
"""

# Standard library imports
import json
import logging
import os
import shutil  # Added for rmtree
import subprocess

# --- Start: Add project root to sys.path --- (Keep for potential direct execution/testing)
import sys
import tempfile
import uuid  # For unique temp dir names
from pathlib import Path
from typing import Any, ClassVar, Dict, Optional, Type

# CrewAI imports
from crewai.tools import BaseTool

# Pydantic imports
from pydantic import BaseModel, ConfigDict, Field, model_validator

_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)
# --- End: Add project root to sys.path ---

# Set up logging
logger = logging.getLogger(__name__)


class SemgrepInput(BaseModel):
    """Input model for the Semgrep Scanner Tool."""

    repo_url: Optional[str] = Field(
        None, description="URL of the Git repository to scan"
    )
    local_path: Optional[str] = Field(
        None, description="Path to a local directory or file to scan"
    )
    code_snippet: Optional[str] = Field(
        None, description="A string containing the code snippet to scan"
    )
    language: Optional[str] = Field(
        None,
        description=(
            "Optional specific language for Semgrep (--lang flag). "
            "Recommended for code_snippet."
        ),
    )
    save_repo: bool = Field(
        False,
        description="If true and repo_url was provided, keeps the cloned repository locally.",
    )
    download_folder: Optional[str] = Field(
        None,
        description=(
            "If repo_url was provided, optional path to clone into. "
            "Defaults to a temporary directory."
        ),
    )
    return_full_results: bool = Field(
        False,
        description=(
            "If true, returns all findings in full detail. "
            "Otherwise returns a summary."
        ),
    )
    max_findings_in_summary: int = Field(
        5,
        description=(
            "Maximum number of findings to include in the summary "
            "per severity level."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def check_input_source(cls, values):
        """Ensure exactly one input source is provided."""
        sources = ["repo_url", "local_path", "code_snippet"]
        provided_sources = [s for s in sources if values.get(s)]
        if len(provided_sources) != 1:
            raise ValueError(
                f"Exactly one of {', '.join(sources)} must be provided. "
                f"Found: {len(provided_sources)}"
            )
        return values

    # Optional: Add basic validation for repo_url if needed
    # @field_validator('repo_url')
    # def check_repo_url(cls, v):
    #     if v and not v.startswith(('http://', 'https://', 'git@')):
    #          # Basic check, could be more robust
    #         raise ValueError("repo_url does not look like a valid URL")
    #     return v

    # Optional: Add basic validation for local_path
    # @field_validator('local_path')
    # def check_local_path(cls, v):
    #     if v and not os.path.exists(v):
    #         raise ValueError(f"local_path does not exist: {v}")
    #     return v

    model_config = ConfigDict(arbitrary_types_allowed=True)


class SemgrepTool(BaseTool):
    """
    Tool for scanning Git repositories, local paths, or code snippets using Semgrep.

    Executes `semgrep scan --config=auto` against the specified target.
    Handles cloning repositories and cleaning up temporary files/folders.
    """

    name: str = "semgrep_scanner"
    description: str = (
        "Scans a Git repository URL, a local filesystem path, or a direct code snippet "
        "using `semgrep scan --config=auto`. Returns either a summary of findings "
        "or full results."
    )
    args_schema: Type[BaseModel] = SemgrepInput

    # Store the path to the semgrep executable
    _semgrep_executable: ClassVar[Optional[str]] = None
    _checked_semgrep: ClassVar[bool] = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._find_semgrep_executable()

    def _find_semgrep_executable(self):
        """Find the semgrep executable path and store it."""
        if not SemgrepTool._checked_semgrep:
            SemgrepTool._semgrep_executable = shutil.which("semgrep")
            if not SemgrepTool._semgrep_executable:
                logger.warning(
                    "Semgrep executable not found in PATH. "
                    "The semgrep_scanner tool will not work."
                )
            else:
                logger.info(
                    f"Found semgrep executable at: {SemgrepTool._semgrep_executable}"
                )
            SemgrepTool._checked_semgrep = True

    def _run(  # Synchronous execution for simplicity with subprocess
        self,
        repo_url: Optional[str] = None,
        local_path: Optional[str] = None,
        code_snippet: Optional[str] = None,
        language: Optional[str] = None,
        save_repo: bool = False,
        download_folder: Optional[str] = None,
        return_full_results: bool = False,
        max_findings_in_summary: int = 5,
    ) -> Dict[str, Any]:
        """Synchronous execution of the Semgrep scan."""
        if not self._semgrep_executable:
            return {"error": "Semgrep executable not found. Cannot run scan."}

        scan_target_path = None
        cleanup_path = None
        is_temporary = False
        temp_file_obj = None  # To manage NamedTemporaryFile lifecycle

        try:
            # 1. Determine Input and Path
            if repo_url:
                if download_folder:
                    # Use provided folder if it exists, otherwise attempt to create?
                    # For simplicity, let's assume it should exist or handle creation error.
                    clone_path = Path(download_folder).resolve()
                    # Ensure the directory exists if specified
                    try:
                        os.makedirs(clone_path, exist_ok=True)
                        # Add a unique subdirectory to avoid conflicts
                        clone_path = (
                            clone_path / f"semgrep_clone_{uuid.uuid4().hex[:8]}"
                        )
                        os.makedirs(clone_path)
                    except OSError as e:
                        return {
                            "error": (
                                f"Failed to create or use download_folder {clone_path}: "
                                f"{e}"
                            )
                        }
                    logger.info(f"Cloning repository to specified folder: {clone_path}")
                    # Don't clean up user-specified folders unless empty?
                    # For simplicity, we won't auto-clean specified folders.
                else:
                    # Create a unique temporary directory
                    temp_dir_name = f"semgrep_clone_{uuid.uuid4().hex[:8]}"
                    clone_path = Path(tempfile.gettempdir()) / temp_dir_name
                    os.makedirs(clone_path)
                    is_temporary = True
                    logger.info(f"Cloning repository to temporary folder: {clone_path}")

                success = self._clone_repository(repo_url, str(clone_path))
                if not success:
                    # Error logged in helper
                    # Attempt cleanup if temporary dir was created before failure
                    if is_temporary and os.path.exists(clone_path):
                        shutil.rmtree(clone_path, ignore_errors=True)
                    return {"error": f"Failed to clone repository: {repo_url}"}

                scan_target_path = str(clone_path)
                if is_temporary and not save_repo:
                    cleanup_path = scan_target_path

            elif local_path:
                resolved_path = str(Path(local_path).resolve())
                if not os.path.exists(resolved_path):
                    return {
                        "error": (
                            f"Provided local_path does not exist: " f"{resolved_path}"
                        )
                    }
                scan_target_path = resolved_path
                logger.info(f"Scanning local path: {scan_target_path}")

            elif code_snippet:
                # Determine suffix based on language hint
                suffix = ".py" if language == "python" else ".txt"
                # Create NamedTemporaryFile, keep it open until scan completes
                temp_file_obj = tempfile.NamedTemporaryFile(
                    mode="w", suffix=suffix, delete=False, encoding="utf-8"
                )
                temp_file_obj.write(code_snippet)
                temp_file_obj.flush()  # Ensure content is written
                scan_target_path = temp_file_obj.name
                is_temporary = True
                cleanup_path = scan_target_path  # Mark for cleanup
                logger.info(
                    "Scanning code snippet in temporary file: " f"{scan_target_path}"
                )

            # 2. Run Semgrep Scan
            if not scan_target_path:
                # Should not happen if input validation works
                return {"error": "Could not determine target path for scanning."}

            scan_results = self._run_semgrep_scan(
                scan_target_path, language, return_full_results, max_findings_in_summary
            )
            return scan_results  # Return the processed results

        finally:
            # 3. Cleanup
            # Close temp file if it was created and is open
            if temp_file_obj:
                try:
                    temp_file_obj.close()
                except Exception as e:
                    logger.warning(
                        f"Error closing temporary file {scan_target_path}: {e}"
                    )

            if cleanup_path and os.path.exists(cleanup_path):
                try:
                    if os.path.isdir(cleanup_path):
                        shutil.rmtree(cleanup_path)
                        logger.info(f"Removed temporary directory: {cleanup_path}")
                    elif os.path.isfile(cleanup_path):
                        os.remove(cleanup_path)
                        logger.info(f"Removed temporary file: {cleanup_path}")
                except Exception as e:
                    logger.error(
                        f"Failed to cleanup temporary path {cleanup_path}: {e}"
                    )

    def _clone_repository(self, repo_url: str, clone_path: str) -> bool:
        """Clones the repository using git subprocess. Returns True on success."""
        logger.info(f"Attempting to clone {repo_url} into {clone_path}")
        try:
            # Simple clone command
            cmd = ["git", "clone", "--depth", "1", repo_url, clone_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,  # 5 min timeout
            )
            if result.returncode != 0:
                logger.error(f"Git clone failed for {repo_url}. Error: {result.stderr}")
                return False
            logger.info(f"Successfully cloned {repo_url}")
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"Git clone timed out for {repo_url}")
            return False
        except FileNotFoundError:
            logger.error(
                "Git command not found. Please ensure git is installed and in PATH."
            )
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during git clone: {e}")
            return False

    def _run_semgrep_scan(
        self,
        scan_path: str,
        language: Optional[str],
        return_full_results: bool,
        max_findings_in_summary: int,
    ) -> Dict[str, Any]:
        """Runs `semgrep scan --config=auto` on the specified path and processes results."""
        # Always use --json for consistent parsing
        cmd = [
            self._semgrep_executable,
            "scan",
            "--config=auto",  # Use auto-detection for rules
            "--json",  # Always get JSON for parsing
        ]
        if language:
            cmd.extend(["--lang", language])

        cmd.append(scan_path)

        logger.info(f"Executing Semgrep command: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,  # 5 min timeout
            )
            logger.info(f"Semgrep scan completed with return code: {result.returncode}")

            # Always try to parse the JSON output
            try:
                if result.stdout:
                    json_output = json.loads(result.stdout)

                    # Process the results - either summarize or return full
                    if return_full_results:
                        # Include a header with finding counts
                        return self._format_full_results(json_output)
                    else:
                        # Create a summary
                        return self._create_summary(
                            json_output, max_findings_in_summary
                        )
                else:
                    # No output to parse
                    return {
                        "summary": "No findings were generated by the scan.",
                        "stderr": result.stderr,
                        "returncode": result.returncode,
                    }
            except json.JSONDecodeError:
                # If JSON parsing fails, return raw output
                logger.warning("Failed to parse JSON output from Semgrep scan")
                return {
                    "summary": "Semgrep output could not be parsed as JSON",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                }

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out for path: {scan_path}")
            return {"error": "Semgrep scan timed out", "returncode": -1}
        except FileNotFoundError:
            logger.error("Semgrep command not found during execution.")
            return {"error": "Semgrep executable not found.", "returncode": -1}
        except Exception as e:
            logger.error(f"An unexpected error occurred during Semgrep scan: {e}")
            return {
                "error": f"An unexpected error occurred during scan: {e}",
                "returncode": -1,
            }

    def _create_summary(
        self, json_output: Dict[str, Any], max_findings_in_summary: int
    ) -> Dict[str, Any]:
        """Creates a summarized version of Semgrep findings."""
        results = json_output.get("results", [])
        errors = json_output.get("errors", [])

        # Count findings by severity
        severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0, "UNKNOWN": 0}
        findings_by_severity = {"ERROR": [], "WARNING": [], "INFO": [], "UNKNOWN": []}

        # Group findings by severity
        for finding in results:
            severity = finding.get("extra", {}).get("severity", "UNKNOWN")
            severity_counts[severity] += 1
            findings_by_severity[severity].append(finding)

        # Generate summary data
        total_findings = len(results)

        # Create summary object with counts at the top
        summary = {
            "total_findings": total_findings,
            "finding_counts_by_severity": severity_counts,
            "top_findings": {},
            "errors": len(errors),
        }

        # Add files scanned and stats if available
        if "stats" in json_output:
            stats = json_output.get("stats", {})
            summary["files_scanned"] = stats.get("files_scanned", 0)
            summary["lines_scanned"] = stats.get("lines_scanned", 0)
            summary["rules_loaded"] = stats.get("rules_loaded", 0)
            summary["scan_time_ms"] = stats.get("total_time", 0)

        # Add top findings for each severity (limited to max_findings_in_summary)
        for severity, findings in findings_by_severity.items():
            if findings:
                # Take only the top N findings per severity
                top_findings = findings[:max_findings_in_summary]
                summary["top_findings"][severity] = []

                for finding in top_findings:
                    # Extract key information for each finding
                    simplified_finding = {
                        "check_id": finding.get("check_id", "unknown"),
                        "path": finding.get("path", "unknown"),
                        "line": finding.get("start", {}).get("line", 0),
                        "message": finding.get("extra", {}).get(
                            "message", "No message"
                        ),
                        "metadata": finding.get("extra", {}).get("metadata", {}),
                    }
                    summary["top_findings"][severity].append(simplified_finding)

                # Add note if there are more findings not shown
                if len(findings) > max_findings_in_summary:
                    not_shown = len(findings) - max_findings_in_summary
                    summary["top_findings"][severity].append(
                        {
                            "note": (
                                f"{not_shown} more {severity.lower()} findings not shown. "
                                "Request full results to see all."
                            )
                        }
                    )

        # Add some error details if they exist
        if errors:
            # Include up to 3 errors as examples
            summary["error_examples"] = errors[:3]
            if len(errors) > 3:
                summary["error_examples"].append(
                    {"note": f"{len(errors) - 3} more errors not shown"}
                )

        # Include prominent finding count message at the start
        finding_message = (
            f"🔍 SCAN RESULTS: Found {total_findings} total security findings "
            f"({severity_counts['ERROR']} errors, {severity_counts['WARNING']} warnings, "
            f"{severity_counts['INFO']} info)."
        )

        # Put the message at the top level for immediate visibility
        summary["scan_summary_message"] = finding_message

        return summary

    def _format_full_results(self, json_output: Dict[str, Any]) -> Dict[str, Any]:
        """Formats the full results with a header containing finding counts."""
        results = json_output.get("results", [])
        # Use _ for unused variable
        _ = json_output.get("errors", [])

        # Count findings by severity
        severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0, "UNKNOWN": 0}

        # Count findings by severity
        for finding in results:
            severity = finding.get("extra", {}).get("severity", "UNKNOWN")
            severity_counts[severity] += 1

        total_findings = len(results)

        # Create a prominent message about finding counts
        finding_message = (
            f"🔍 SCAN RESULTS: Found {total_findings} total security findings "
            f"({severity_counts['ERROR']} errors, {severity_counts['WARNING']} warnings, "
            f"{severity_counts['INFO']} info)."
        )

        # Return original output with the summary message at top level
        return {
            "scan_summary_message": finding_message,
            "full_results": json_output,
            "total_findings": total_findings,
            "finding_counts_by_severity": severity_counts,
        }


# --- Remove all previous helper methods and __main__ block ---
