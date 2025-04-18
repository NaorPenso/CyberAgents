#!/usr/bin/env python3
"""
Main script to orchestrate the domain intelligence crew's operation, driven by user prompts.
Dynamically loads agents and assigns tasks to a central manager agent.
"""

import argparse  # Import argparse for CLI arguments
import csv  # Add csv import
import importlib
import inspect
import json
import logging
import os
import re  # Add re for regex validation
import time  # Import time for monotonic clock
from pathlib import Path
from typing import Any, Dict, Type

import yaml  # Add PyYAML import
from crewai import Agent, Crew, Task
from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.metrics import get_meter_provider, set_meter_provider
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

# Import Rich for console output
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Dynamically load agent base classes (adjust if base classes are defined elsewhere)
# Assuming agent classes are defined directly in modules like domain_whois_agent.py
# If there's a common base class, import it here.
from agents.base_agent import BaseAgent

# Import LLM Factory
from utils.llm_utils import create_central_llm

# Configure logging with OpenTelemetry
LoggingInstrumentor().instrument()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def setup_telemetry():
    """Configure OpenTelemetry with local and remote exporters."""
    # Create resource
    resource = Resource.create(
        {
            "service.name": "domain-intelligence-crew",
            "service.version": "1.0.0",
        }
    )

    # Configure tracing
    tracer_provider = TracerProvider(resource=resource)

    # Add console exporter for local development
    console_exporter = ConsoleSpanExporter()
    tracer_provider.add_span_processor(BatchSpanProcessor(console_exporter))

    # Add OTLP trace exporter if configured
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        otlp_trace_exporter = OTLPSpanExporter()
        tracer_provider.add_span_processor(BatchSpanProcessor(otlp_trace_exporter))

    trace.set_tracer_provider(tracer_provider)

    # Configure metrics
    metric_readers = []
    # Add OTLP metric exporter if configured
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        otlp_metric_exporter = OTLPMetricExporter()
        metric_reader = PeriodicExportingMetricReader(
            otlp_metric_exporter, export_interval_millis=5000
        )
        metric_readers.append(metric_reader)

    # If no readers are configured (e.g., no OTLP endpoint), don't set up metrics
    if metric_readers:
        meter_provider = MeterProvider(resource=resource, metric_readers=metric_readers)
        set_meter_provider(meter_provider)
    else:
        # Optionally set a no-op meter provider if no exporters are configured
        set_meter_provider(MeterProvider(resource=resource))
        logger.warning("No OTLP endpoint configured, metrics export is disabled.")


def discover_and_load_agents(base_path: str = "agents") -> Dict[str, Type]:
    """Dynamically discovers and loads agent classes from subdirectories."""
    agent_classes: Dict[str, Type[BaseAgent]] = {}
    agents_dir = Path(base_path)
    # Regex to allow only valid Python module characters (alphanumeric + underscore)
    # and prevent directory traversal or other malicious patterns.
    valid_module_name_pattern = re.compile(r"^[a-zA-Z0-9_]+$")

    if not agents_dir.is_dir():
        logger.error(f"Agents directory not found: {base_path}")
        return agent_classes

    for item in agents_dir.iterdir():
        # Check if it's a directory, contains __init__.py, and has a valid name
        if item.is_dir() and (item / "__init__.py").exists():
            module_name = item.name
            if not valid_module_name_pattern.match(module_name):
                logger.warning(f"Skipping directory with invalid name: {module_name}")
                continue

            # Construct the expected module path (e.g., agents.some_agent.some_agent)
            module_path = f"{base_path}.{module_name}.{module_name}"
            try:
                # nosemgrep: python.lang.security.audit.non-literal-import.non-literal-import
                module = importlib.import_module(module_path)

                # Find classes within the module inheriting from BaseAgent
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, BaseAgent)
                        and obj is not BaseAgent
                        and obj.__module__ == module.__name__
                    ):  # noqa: B950
                        if name in agent_classes:
                            logger.warning(
                                f"Duplicate agent class name found: {name}. Overwriting with class from {module_path}."
                            )
                        agent_classes[name] = obj
                        logger.info(
                            f"Discovered agent class: {name} from {module_path}"
                        )  # noqa: B950

            except ImportError as e:
                # Log if the expected agent module (e.g., agents.X.X) itself cannot be imported
                logger.error(
                    f"Failed to import primary agent module {module_path}: {e}"
                )  # noqa: B950
            except Exception as e:
                # Catch other potential errors during import or inspection
                logger.error(
                    f"Error loading agent from directory {module_name} (module path {module_path}): {e}"
                )

    if not agent_classes:
        logger.warning(
            f"No agent classes inheriting from BaseAgent were discovered in {base_path}."
        )

    return agent_classes


class DomainIntelligenceCrew:
    """Orchestrates the domain intelligence analysis crew, managed by a Security Manager."""

    def __init__(self, llm: Any, verbose: bool = False):
        """Initialize the crew by discovering and instantiating all agents."""
        self.tracer = trace.get_tracer(__name__)
        self.meter = get_meter_provider().get_meter(__name__)
        self.llm = llm  # Store the central LLM instance
        self.verbose_mode = verbose  # Store verbose mode

        # Metrics setup
        self.analysis_duration = self.meter.create_histogram(
            "analysis.duration", unit="ms", description="Duration of domain analysis"
        )
        self.analysis_errors = self.meter.create_counter(
            "analysis.errors", unit="1", description="Number of analysis errors"
        )

        # Discover and load agent classes
        self.agent_classes = discover_and_load_agents()  # noqa: B950
        if not self.agent_classes:
            raise RuntimeError("Failed to discover any agents. Cannot initialize crew.")

        # Instantiate agents
        self.agents_instances = {}
        self.crew_agents = []
        self.manager_agent = None

        for name, AgentClass in self.agent_classes.items():
            try:
                # Pass the LLM instance to the agent class constructor
                # Assumes AgentClass.__init__ accepts 'llm' and uses it for its internal crewai.Agent
                instance = AgentClass()
                self.agents_instances[name] = instance
                # Assuming each class instance has an 'agent' attribute holding the crewai.Agent
                if hasattr(instance, "agent") and isinstance(instance.agent, Agent):
                    self.crew_agents.append(instance.agent)
                    if name == "SecurityManagerAgent":  # Identify the manager
                        self.manager_agent = instance
                else:
                    logger.error(
                        f"Agent class {name} does not have a valid 'agent' attribute of type crewai.Agent."
                    )  # noqa: B950
            except Exception as e:
                logger.error(f"Failed to instantiate agent {name}: {e}")
                # Consider adding logic to handle agent instantiation failure more gracefully

        if not self.crew_agents:
            raise RuntimeError(
                "No valid crewai.Agent instances were created. Cannot initialize crew."
            )
        if not self.manager_agent:
            raise RuntimeError(
                "SecurityManagerAgent instance not found or failed to load. Cannot initialize crew."
            )

        # Create the Crew with all discovered agents
        self.crew = Crew(
            agents=self.crew_agents,
            tasks=[],
            verbose=self.verbose_mode,
            memory=True,
            # manager_llm=self.manager_agent.agent.llm # Example: Ensure manager uses its own LLM if needed
        )

    def run_analysis(self, user_prompt: str, output_format: str = "rich") -> Dict:
        """Runs analysis based on user prompt, orchestrated by the Security Manager."""
        with self.tracer.start_as_current_span("run_analysis") as span:
            span.set_attribute("user_prompt", user_prompt)
            logger.info(f'Received analysis request: "{user_prompt}"')
            start_time = time.monotonic()

            # Build dynamic description of available agents for the manager
            available_specialists_desc = "\nAvailable Specialist Agents:\n"
            for name, instance in self.agents_instances.items():
                if name != "SecurityManagerAgent":  # Exclude manager itself
                    agent = instance.agent
                    available_specialists_desc += (
                        f"- {agent.role}: Goal - {agent.goal}\n"
                    )
                    if agent.tools:
                        tool_names = ", ".join(
                            [tool.name for tool in agent.tools]
                        )  # noqa: B950
                        available_specialists_desc += f"    Tools: [{tool_names}]\n"

            manager_task_description = (
                f"Process the user request: '{user_prompt}'. "
                f"Identify the target entities (like domains) and required analysis types. "
                f"{available_specialists_desc}"
                f"Delegate specific analysis sub-tasks to the appropriate specialist agents based on their roles and tools. "  # noqa: B950
                f"Ensure you provide the necessary inputs for each delegated task (e.g., domain name). "  # noqa: B950
                f"If one task's output is needed for another (e.g., WHOIS data for Threat Intel), manage the data flow. "  # noqa: B950
                f"Synthesize the structured results from all delegated analyses into a comprehensive final report."  # noqa: B950
            )

            manager_expected_output = (
                "A comprehensive, well-structured security report addressing the user's request, "  # noqa: B950
                "integrating findings from all delegated analyses (e.g., WHOIS, DNS, Threat Intelligence). "  # noqa: B950
                "The report should clearly present the gathered data in an organized manner."
            )

            try:
                manager_task = Task(
                    description=manager_task_description,
                    agent=self.manager_agent.agent,
                    expected_output=manager_expected_output,
                )

                self.crew.tasks = [manager_task]

                final_result = None
                # Use Rich Progress only if output is 'rich' and not verbose (verbose already shows logs)
                if output_format == "rich" and not self.verbose_mode:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        transient=True,
                    ) as progress:
                        progress.add_task("Crew AI running analysis...", total=None)
                        final_result = self.crew.kickoff()
                else:
                    # Run without progress bar for JSON output or if verbose logging is enabled
                    final_result = self.crew.kickoff()

                duration = (time.monotonic() - start_time) * 1000

                # Record metrics
                try:
                    if self.analysis_duration:
                        self.analysis_duration.record(duration)
                except Exception as metric_err:
                    logger.warning(f"Failed to record duration metric: {metric_err}")

                # Return the raw result (likely a string)
                return {"analysis_report": str(final_result)}

            except Exception as e:
                try:
                    if self.analysis_errors:
                        self.analysis_errors.add(1)
                except Exception as metric_err:
                    logger.warning(f"Failed to record error metric: {metric_err}")

                error_message = (
                    f'Error running analysis for prompt "{user_prompt}": {str(e)}'
                )
                logger.error(error_message, exc_info=True)  # Log traceback
                span.record_exception(e)
                return {"error": error_message, "exception": str(e)}


def _write_report_to_file(
    report_content: str, filename: str, output_format: str, console: Console
):
    """Writes the report content to a file based on the specified format."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            if output_format == "yaml":
                # Try to dump as YAML if it looks like structured data, else dump string
                try:
                    # Attempt to parse as JSON first to see if it's structured
                    parsed_content = json.loads(report_content)
                    yaml.dump(parsed_content, f, default_flow_style=False)
                except json.JSONDecodeError:
                    # If not JSON, dump as a plain multi-line string
                    yaml.dump({"report": report_content}, f, default_flow_style=False)
            elif output_format == "csv":
                # Basic CSV handling: assumes report might be simple key-value pairs
                # This might need significant refinement based on actual report structure
                lines = report_content.strip().split("\n")
                writer = csv.writer(f)
                # Simple heuristic: if lines look like 'Key: Value', split them
                likely_kv = all(
                    ": " in line for line in lines[:5]
                )  # Check first few lines # noqa: B950
                if likely_kv:
                    writer.writerow(["Key", "Value"])  # Header
                    for line in lines:
                        parts = line.split(": ", 1)
                        if len(parts) == 2:
                            writer.writerow([parts[0].strip(), parts[1].strip()])
                        else:
                            writer.writerow([line])
                else:
                    # Write the whole report content as one cell/row if not key-value like
                    writer.writerow(["Report Content"])
                    writer.writerow([report_content])
            else:  # html or other text formats (currently only html handled here implicitly)
                f.write(report_content)
        console.print(f"[green]Report saved to {filename}[/green]")
    except Exception as e:
        console.print(f"[bold red]Error writing report to {filename}: {e}[/bold red]")


def display_results(results: Dict, output_format: str = "rich"):  # noqa: B950
    """Displays the analysis results based on the chosen format."""
    console = Console()

    if output_format == "rich":
        console.print("\n" + "-" * 50)

        if "error" in results:
            console.print(
                Panel(
                    f"[bold red]Error during analysis:[/bold red]\n\n{results.get('error', 'Unknown error')}\n\nException: {results.get('exception', 'N/A')}",  # noqa: B950
                    title="Analysis Failed",
                    border_style="red",
                )
            )
        elif "analysis_report" in results:
            report_content = results["analysis_report"]
            # Attempt to render as Markdown, fallback to plain text
            try:
                # Assuming the report is Markdown formatted
                markdown = Markdown(report_content)
                console.print(
                    Panel(
                        markdown,
                        title="[bold green]Analysis Report[/bold green]",
                        border_style="green",
                        expand=False,
                    )
                )
            except Exception:
                # Fallback if rendering Markdown fails or content isn't MD
                console.print(
                    Panel(
                        report_content,
                        title="[bold green]Analysis Report[/bold green]",
                        border_style="green",
                        expand=False,
                    )
                )
        else:
            console.print(
                Panel(
                    "Analysis completed, but no report data found.",
                    title="[yellow]Analysis Result[/yellow]",
                    border_style="yellow",
                )
            )
        console.print("-" * 50 + "\n")

    elif output_format == "json":
        print(json.dumps(results, indent=2))

    elif output_format in ["csv", "yaml", "html"]:
        if "error" in results:
            console.print(
                f"[bold red]Error during analysis:[/bold red] {results.get('error', 'Unknown error')}. Cannot generate {output_format} file."
            )
            return
        if "analysis_report" not in results:
            console.print(
                f"[yellow]Analysis completed, but no report data found.[/yellow] Cannot generate {output_format} file."
            )
            return

        report_content = results["analysis_report"]
        filename = f"analysis_report.{output_format}"
        # Call the helper function to handle file writing
        _write_report_to_file(report_content, filename, output_format, console)

    else:
        console.print(f"[bold red]Unknown output format: {output_format}[/bold red]")


def main():
    """Main execution function: parses args, initializes crew, runs analysis, displays results."""
    parser = argparse.ArgumentParser(
        description="Run the Domain Intelligence Crew with a specific prompt."
    )
    parser.add_argument(
        "prompt",
        help="The analysis prompt for the crew (e.g., 'Analyze domain example.com')",
    )
    parser.add_argument(
        "--output",
        default="rich",
        choices=["rich", "json", "yaml", "csv"],
        help="Output format for the final report (default: rich)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose logging for debugging (shows agent thoughts, tool usage, etc.)",
    )

    args = parser.parse_args()

    # Configure logging level based on verbosity
    if not args.verbose:
        # Set root logger level higher to suppress INFO messages from libraries like crewai
        logging.getLogger().setLevel(logging.WARNING)
        # You might need to specifically target crewai's logger if it configures itself
        logging.getLogger("crewai").setLevel(logging.WARNING)
        logging.getLogger("LiteLLM").setLevel(
            logging.WARNING
        )  # Also suppress LiteLLM info
        # Keep our own logger at INFO if needed for specific messages, or set it higher too
        logger.setLevel(logging.INFO)  # Keep main logger at INFO for start/end messages
    else:
        # Ensure our main logger and others are at INFO/DEBUG if verbose
        logging.getLogger().setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
        # crewai verbosity is handled by passing verbose=True to the Crew/Agent

    # Load environment variables (ensure this happens before agent init)
    load_dotenv()

    # Setup telemetry (optional, based on env vars)
    setup_telemetry()

    console = Console()

    # --- Initialize Central LLM --- #
    central_llm = None
    try:
        logger.info("Initializing central LLM via factory...")
        central_llm = create_central_llm()
        # Assuming create_central_llm logs success details internally
        logger.info("Central LLM initialized successfully.")
    except RuntimeError as e:
        # Error is already logged critically by create_central_llm if it raises RuntimeError
        console.print(
            Panel(
                f"[bold red]Fatal Error:[/bold red] Could not initialize LLM. Check logs for details.\nError: {e}",
                title="LLM Initialization Failed",
                border_style="red",
            )
        )
        return  # Exit gracefully
    except Exception as e:
        # Catch any other unexpected errors during LLM init
        logger.critical(
            f"Unexpected fatal error during LLM initialization: {e}", exc_info=True
        )
        console.print(
            Panel(
                "[bold red]Fatal Error:[/bold red] An unexpected error occurred during LLM initialization. Check logs.",
                title="LLM Initialization Failed",
                border_style="red",
            )
        )
        return  # Exit gracefully

    console.print(
        Panel(
            f"[bold cyan]Executing Prompt:[/bold cyan]\n[italic]{args.prompt}[/italic]",
            title="Domain Intelligence Crew",
            border_style="blue",
        )
    )

    try:
        logger.info("Initializing Domain Intelligence Crew...")
        # Pass verbose flag and the central LLM instance to the crew initializer
        crew_orchestrator = DomainIntelligenceCrew(
            llm=central_llm, verbose=args.verbose
        )

        logger.info(f'Starting analysis for prompt: "{args.prompt}"')
        # The run_analysis method internally handles the Rich progress bar for non-verbose rich output
        results = crew_orchestrator.run_analysis(
            args.prompt, output_format=args.output
        )  # noqa: B950
        logger.info("Analysis complete.")

        display_results(results, output_format=args.output)

    except Exception as e:
        logger.exception(
            "An error occurred during the analysis."
        )  # Log exception details
        console.print(
            Panel(
                f"[bold red]Error:[/bold red] {e}",
                title="Analysis Failed",
                border_style="red",
            )
        )


if __name__ == "__main__":
    main()
