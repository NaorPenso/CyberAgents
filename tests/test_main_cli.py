"""Tests for the main CLI script (main.py)"""

import logging  # Import logging module
import sys
from unittest.mock import MagicMock, patch

import pytest
from rich.panel import Panel  # Import Panel for type checking

# Import the main function or script object
# Assuming main logic is in main.main()
from main import main


# Test successful execution path with basic arguments
@patch("main.create_central_llm")
@patch("main.DomainIntelligenceCrew")
@patch("main.display_results")
@patch("main.setup_telemetry")  # Mock telemetry to avoid side effects
@patch("main.load_dotenv")  # Mock dotenv loading
def test_main_success_path(
    mock_load_dotenv,
    mock_setup_telemetry,
    mock_display_results,
    MockDomainIntelligenceCrew,
    mock_create_central_llm,
):
    """Test the main function runs successfully with default arguments."""
    # --- Arrange ---
    # Mock the LLM returned by the factory
    mock_llm = MagicMock()
    mock_create_central_llm.return_value = mock_llm

    # Mock the Crew orchestrator instance and its run_analysis method
    mock_crew_instance = MagicMock()
    mock_analysis_result = {"analysis_report": "Success!"}
    mock_crew_instance.run_analysis.return_value = mock_analysis_result
    MockDomainIntelligenceCrew.return_value = mock_crew_instance

    # Mock sys.argv to simulate command-line arguments
    test_prompt = "analyze example.com"
    test_args = [
        "main.py",
        test_prompt,
    ]  # Simulate 'python main.py "analyze example.com"'

    # --- Act ---
    with patch.object(sys, "argv", test_args):
        main()

    # --- Assert ---
    mock_load_dotenv.assert_called_once()
    mock_setup_telemetry.assert_called_once()
    mock_create_central_llm.assert_called_once()  # Verify LLM factory is called

    # Verify Crew is initialized with the mocked LLM and default verbosity (False)
    MockDomainIntelligenceCrew.assert_called_once_with(llm=mock_llm, verbose=False)

    # Verify analysis is run with the correct prompt and default output format
    mock_crew_instance.run_analysis.assert_called_once_with(
        test_prompt, output_format="rich"
    )

    # Verify results are displayed with the correct result and default output format
    mock_display_results.assert_called_once_with(
        mock_analysis_result, output_format="rich"
    )


# Test with verbose flag and different output format
@patch("main.create_central_llm")
@patch("main.DomainIntelligenceCrew")
@patch("main.display_results")
@patch("main.setup_telemetry")
@patch("main.load_dotenv")
def test_main_verbose_json_output(
    mock_load_dotenv,
    mock_setup_telemetry,
    mock_display_results,
    MockDomainIntelligenceCrew,
    mock_create_central_llm,
):
    """Test the main function with --verbose and --output json flags."""
    # --- Arrange ---
    mock_llm = MagicMock()
    mock_create_central_llm.return_value = mock_llm
    mock_crew_instance = MagicMock()
    mock_analysis_result = {"analysis_report": "JSON Report"}
    mock_crew_instance.run_analysis.return_value = mock_analysis_result
    MockDomainIntelligenceCrew.return_value = mock_crew_instance

    test_prompt = "check domain other.org"
    # Simulate 'python main.py "check domain other.org" --verbose --output json'
    test_args = ["main.py", test_prompt, "--verbose", "--output", "json"]

    # --- Act ---
    with patch.object(sys, "argv", test_args):
        main()

    # --- Assert ---
    # Verify Crew is initialized with verbose=True
    MockDomainIntelligenceCrew.assert_called_once_with(llm=mock_llm, verbose=True)

    # Verify analysis is run with output_format="json"
    mock_crew_instance.run_analysis.assert_called_once_with(
        test_prompt, output_format="json"
    )

    # Verify results are displayed with output_format="json"
    mock_display_results.assert_called_once_with(
        mock_analysis_result, output_format="json"
    )


# Test LLM Initialization Failure
@patch("main.create_central_llm")
@patch("main.DomainIntelligenceCrew")
@patch("main.display_results")
@patch("main.setup_telemetry")
@patch("main.load_dotenv")
@patch("main.Console")  # Mock Console to check panel output
def test_main_llm_init_failure(
    MockConsole,
    mock_load_dotenv,
    mock_setup_telemetry,
    mock_display_results,
    MockDomainIntelligenceCrew,
    mock_create_central_llm,
    caplog,  # Use caplog to check log messages
):
    """Test that main handles LLM initialization failure gracefully."""
    # --- Arrange ---
    # Make the LLM factory raise a RuntimeError
    error_message = "LLM config failed!"
    mock_create_central_llm.side_effect = RuntimeError(error_message)

    # Mock Console().print
    mock_console_instance = MagicMock()
    MockConsole.return_value = mock_console_instance

    test_prompt = "analyze some.domain"
    test_args = ["main.py", test_prompt]

    # --- Act ---
    with patch.object(sys, "argv", test_args):
        with caplog.at_level(logging.CRITICAL):
            # We expect main() to exit early, potentially via sys.exit or just returning
            # pytest doesn't easily capture sys.exit, so we check that subsequent mocks aren't called
            main()

    # --- Assert ---
    mock_load_dotenv.assert_called_once()
    mock_setup_telemetry.assert_called_once()
    mock_create_central_llm.assert_called_once()  # LLM creation was attempted

    # Verify critical error was logged (error is logged by llm_utils, but we check our handler)
    # Note: llm_utils already logs the specific error, so main() might log a more general critical message
    # Check if the specific runtime error message appears in our handling logs or console output
    console_print_called = mock_console_instance.print.called
    printed_panel_content = ""
    if console_print_called and mock_console_instance.print.call_args.args:
        panel_arg = mock_console_instance.print.call_args.args[0]
        if isinstance(panel_arg, Panel):
            # Accessing renderable content might need adjustment based on Panel structure
            # Trying common ways to get string content
            if hasattr(panel_arg.renderable, "text"):
                printed_panel_content = panel_arg.renderable.text
            else:
                printed_panel_content = str(panel_arg.renderable)

    assert error_message in caplog.text or error_message in printed_panel_content

    # Verify the error panel was printed to the console and check its title
    mock_console_instance.print.assert_called()
    assert console_print_called  # Redundant but explicit
    panel_arg = mock_console_instance.print.call_args.args[0]
    assert isinstance(panel_arg, Panel)
    assert panel_arg.title == "LLM Initialization Failed"

    # Verify that Crew initialization and subsequent steps were *not* called
    MockDomainIntelligenceCrew.assert_not_called()
    mock_display_results.assert_not_called()


# Test Crew Initialization Failure
@patch("main.create_central_llm")
@patch("main.DomainIntelligenceCrew")
@patch("main.display_results")
@patch("main.setup_telemetry")
@patch("main.load_dotenv")
@patch("main.Console")
def test_main_crew_init_failure(
    MockConsole,
    mock_load_dotenv,
    mock_setup_telemetry,
    mock_display_results,
    MockDomainIntelligenceCrew,
    mock_create_central_llm,
    caplog,
):
    """Test that main handles Crew initialization failure."""
    # --- Arrange ---
    mock_llm = MagicMock()
    mock_create_central_llm.return_value = mock_llm

    # Make Crew initialization raise an exception
    error_message = "Failed to load agents!"
    MockDomainIntelligenceCrew.side_effect = RuntimeError(error_message)

    mock_console_instance = MagicMock()
    MockConsole.return_value = mock_console_instance

    test_prompt = "analyze another.domain"
    test_args = ["main.py", test_prompt]

    # --- Act ---
    with patch.object(sys, "argv", test_args):
        with caplog.at_level(logging.ERROR):
            main()

    # --- Assert ---
    mock_create_central_llm.assert_called_once()
    MockDomainIntelligenceCrew.assert_called_once_with(llm=mock_llm, verbose=False)

    # Verify error was logged and printed
    assert error_message in caplog.text
    mock_console_instance.print.assert_called()
    panel_arg = mock_console_instance.print.call_args.args[0]
    assert isinstance(panel_arg, Panel)
    assert panel_arg.title == "Analysis Failed"
    # Check if error message is within the panel's renderable content
    panel_content = ""
    if hasattr(panel_arg.renderable, "text"):
        panel_content = panel_arg.renderable.text
    else:
        panel_content = str(panel_arg.renderable)
    assert error_message in panel_content

    # Verify analysis and display were not called
    mock_display_results.assert_not_called()


# Test Analysis Execution Failure
@patch("main.create_central_llm")
@patch("main.DomainIntelligenceCrew")
@patch("main.display_results")
@patch("main.setup_telemetry")
@patch("main.load_dotenv")
@patch("main.Console")
def test_main_analysis_failure(
    MockConsole,
    mock_load_dotenv,
    mock_setup_telemetry,
    mock_display_results,
    MockDomainIntelligenceCrew,
    mock_create_central_llm,
    caplog,
):
    """Test that main handles errors during crew.kickoff/run_analysis."""
    # --- Arrange ---
    mock_llm = MagicMock()
    mock_create_central_llm.return_value = mock_llm

    mock_crew_instance = MagicMock()
    error_message = "Analysis task failed!"
    mock_crew_instance.run_analysis.side_effect = Exception(error_message)
    MockDomainIntelligenceCrew.return_value = mock_crew_instance

    mock_console_instance = MagicMock()
    MockConsole.return_value = mock_console_instance

    test_prompt = "analyze failing.domain"
    test_args = ["main.py", test_prompt]

    # --- Act ---
    with patch.object(sys, "argv", test_args):
        with caplog.at_level(logging.ERROR):
            main()

    # --- Assert ---
    mock_create_central_llm.assert_called_once()
    MockDomainIntelligenceCrew.assert_called_once()
    mock_crew_instance.run_analysis.assert_called_once()

    # Verify error was logged and printed
    assert error_message in caplog.text
    mock_console_instance.print.assert_called()
    panel_arg = mock_console_instance.print.call_args.args[0]
    assert isinstance(panel_arg, Panel)
    assert panel_arg.title == "Analysis Failed"
    # Check if error message is within the panel's renderable content
    panel_content = ""
    if hasattr(panel_arg.renderable, "text"):
        panel_content = panel_arg.renderable.text
    else:
        panel_content = str(panel_arg.renderable)
    assert error_message in panel_content

    # Verify display_results was *not* called on analysis exception
    # (The error handling block in main() catches the exception before display_results)
    mock_display_results.assert_not_called()
