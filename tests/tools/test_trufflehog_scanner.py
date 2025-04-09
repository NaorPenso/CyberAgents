"""Tests for the TruffleHog Scanner Tool."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from tools.trufflehog_scanner.trufflehog_scanner_tool import (  # noqa: E402
    TruffleHogScannerTool,
)


class TestTruffleHogScannerTool(unittest.TestCase):
    """Test cases for the TruffleHog Scanner Tool."""

    def setUp(self):
        """Set up test fixtures (mocks are applied per-test)."""
        pass  # Tool initialization moved to individual tests

    @patch("shutil.which", return_value="/fake/path/to/executable")
    def test_tool_initialization(self, mock_which):
        """Test successful tool initialization."""
        tool = TruffleHogScannerTool()
        assert tool._is_available is True
        assert tool._trufflehog_executable == "/fake/path/to/executable"
        assert tool._git_executable == "/fake/path/to/executable"

    @patch("shutil.which", return_value=None)
    def test_tool_unavailable_initialization(self, mock_which):
        """Test initialization when dependencies are missing."""
        tool = TruffleHogScannerTool()
        assert tool._is_available is False

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/fake/path/to/executable")
    def test_scan_local_repo_success_no_findings(self, mock_which, mock_run):
        """Test scanning a local repo with no findings."""
        tool = TruffleHogScannerTool()  # Initialize tool within test
        mock_process = MagicMock()
        mock_process.returncode = 0  # No findings
        mock_process.stdout = ""  # Empty output
        mock_run.return_value = mock_process

        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
        ):
            result = tool._run(repo_target="local:/fake/repo")
            assert "No secrets" in result
            mock_run.assert_called_once()
            cmd_args = mock_run.call_args[0][0]
            assert "filesystem" in cmd_args
            assert "/fake/repo" in cmd_args
            assert "--json" in cmd_args

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/fake/path/to/executable")
    def test_scan_local_repo_success_with_findings(self, mock_which, mock_run):
        """Test scanning a local repo with findings."""
        tool = TruffleHogScannerTool()  # Initialize tool within test
        mock_process = MagicMock()
        mock_process.returncode = 1  # Findings detected
        # Sample JSON output (one line per finding)
        mock_stdout = (
            json.dumps(
                {
                    "SourceMetadata": {
                        "file": "config.py",
                        "line": 10,
                        "commit": "abcdef12",
                    },
                    "DetectorName": "AWSKey",
                    "Severity": "HIGH",
                    "Raw": "AKIAIOSFODNN7EXAMPLE",
                }
            )
            + "\n"
        )
        mock_process.stdout = mock_stdout
        mock_run.return_value = mock_process

        with (
            patch("os.path.exists", return_value=True),
            patch("os.path.isdir", return_value=True),
        ):
            result = tool._run(repo_target="local:/fake/repo")
            assert "TruffleHog Scan Results" in result
            assert "**Total findings:** 1" in result
            assert "HIGH: 1" in result
            assert "config.py:10" in result
            assert "AWSKey" in result
            assert "`AKIAIOSFODNN7EXAMPLE`" in result
            mock_run.assert_called_once()

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/fake/path/to/executable")
    def test_scan_github_repo(self, mock_which, mock_run):
        """Test scanning a remote GitHub repo."""
        tool = TruffleHogScannerTool()
        mock_clone_process = MagicMock(returncode=0, stdout="Cloned.", stderr="")
        mock_scan_process = MagicMock(returncode=0, stdout="", stderr="")
        mock_run.side_effect = [mock_clone_process, mock_scan_process]

        with patch("tempfile.TemporaryDirectory") as mock_tempdir:
            fake_temp_path = "/fake/tempdir/repo"
            mock_tempdir.return_value.__enter__.return_value = fake_temp_path
            with (
                patch("os.path.exists") as mock_exists,
                patch("os.path.isdir") as mock_isdir,
            ):
                mock_exists.return_value = True
                mock_isdir.return_value = True
                result = tool._run(repo_target="github:owner/repo")

                # Assertions
                self.assertIn("No secrets or sensitive information detected", result)
                mock_exists.assert_any_call(fake_temp_path)
                mock_isdir.assert_any_call(fake_temp_path)
                self.assertEqual(mock_run.call_count, 2)
                # Check clone command
                clone_call_args = mock_run.call_args_list[0][0][0]
                # Check if the mocked git executable path is the first arg
                self.assertEqual(clone_call_args[0], tool._git_executable)
                self.assertIn("clone", clone_call_args)
                self.assertIn("https://github.com/owner/repo.git", clone_call_args)
                self.assertIn(fake_temp_path, clone_call_args)
                # Check scan command
                scan_call_args = mock_run.call_args_list[1][0][0]
                # Check if the mocked trufflehog executable path is the first arg
                self.assertEqual(scan_call_args[0], tool._trufflehog_executable)
                self.assertIn("filesystem", scan_call_args)
                self.assertIn(fake_temp_path, scan_call_args)

    @patch("shutil.which", return_value=None)  # Simulate missing dependencies
    def test_tool_unavailable(self, mock_which):
        """Test running the tool when dependencies are missing."""
        tool = TruffleHogScannerTool()  # Initialize tool within test
        result = tool._run(repo_target="local:/fake/repo")
        assert "Error: TruffleHogScannerTool unavailable" in result

    def test_invalid_repo_path(self):
        """Test handling of invalid repository path format."""
        # No need to mock dependencies if tool init happens in test
        with patch("shutil.which", return_value="/fake/path/to/executable"):
            tool = TruffleHogScannerTool()
        result = tool._run(repo_target="local:")  # Invalid path
        assert "Error: Path does not exist: " in result

    # Test processing empty results
    def test_process_scan_results_empty(self):
        """Test processing empty scan output."""
        with patch("shutil.which", return_value="/fake/path/to/executable"):
            tool = TruffleHogScannerTool()
        result = tool._process_scan_results("")
        assert "No secrets" in result

    # Test processing results with findings
    def test_process_scan_results_with_findings(self):
        """Test processing scan output with findings."""
        with patch("shutil.which", return_value="/fake/path/to/executable"):
            tool = TruffleHogScannerTool()
        mock_stdout = json.dumps(
            {
                "SourceMetadata": {
                    "file": "config.py",
                    "line": 10,
                    "commit": "abcdef12",
                },
                "DetectorName": "TestDetector",
                "Severity": "MEDIUM",
                "Raw": "some_secret_value",
            }
        )
        result = tool._process_scan_results(mock_stdout)
        assert "**Total findings:** 1" in result
        self.assertIn("| Severity |", result)
        self.assertIn("| MEDIUM", result)
        self.assertIn("| TestDetector", result)
        self.assertIn("config.py:10", result)
        assert "`some_secret_value`" in result


# Keep main guard if running directly
if __name__ == "__main__":
    unittest.main()
