#!/usr/bin/env python3
"""Synchronizes Semgrep policies from configured sources."""

import argparse
import logging
import subprocess
from pathlib import Path
from typing import List, Tuple, Union

import yaml

# Move import up
from .utils.policy_sync import (
    DEFAULT_SEMGREP_RULES_DIR,
    fetch_semgrep_rules_from_registry,
    get_existing_policies,
    write_policy_to_file,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")

# Remove import - now moved up
# from .utils.policy_sync import ...

# Add parent directory to path to allow imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Removed unused imports


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for the sync script."""
    parser = argparse.ArgumentParser(
        description="Synchronize Semgrep policies from configured sources."
    )

    # Command subparsers
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Sync command
    sync_parser = subparsers.add_parser("sync", help="Synchronize policies")
    sync_parser.add_argument(
        "languages",
        nargs="*",
        help="Languages to sync (default: all supported languages)",
    )

    return parser.parse_args()


def main() -> None:
    """Execute the main policy synchronization logic."""
    args = parse_arguments()
    # Assuming args provides config_path, rules_dir, force_update directly
    # If not, parse_arguments needs adjustment or defaults used here
    config_path_arg = getattr(args, 'config', "semgrep-config.yml")
    rules_dir_arg = getattr(args, 'rules_dir', DEFAULT_SEMGREP_RULES_DIR)
    force_update_arg = getattr(args, 'force', False)

    sync_policies(
        config_path=config_path_arg,
        rules_dir=rules_dir_arg,
        force_update=force_update_arg,
    )


def sync_policies(
    config_path: Union[str, Path] = "semgrep-config.yml",
    rules_dir: Union[str, Path] = DEFAULT_SEMGREP_RULES_DIR,
    force_update: bool = False,
) -> Tuple[int, int, int]:
    """Synchronize policies based on configuration.

    Args:
        config_path: Path to the Semgrep configuration file.
        rules_dir: Directory to store downloaded rules.
        force_update: Whether to force update even if rules exist.

    Returns:
        Tuple of (added_count, updated_count, skipped_count).
    """
    logger.info(f"Starting policy sync using config: {config_path}")
    added_count = 0
    updated_count = 0
    skipped_count = 0

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        return 0, 0, 0
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file {config_path}: {e}")
        return 0, 0, 0

    if not config or "rulesets" not in config:
        logger.warning(
            f"No 'rulesets' section found in {config_path}. Nothing to sync."
        )
        return 0, 0, 0

    registry_policies: List[str] = config["rulesets"]
    logger.info(f"Found {len(registry_policies)} policies listed in config.")

    # Ensure rules directory exists
    rules_path = Path(rules_dir)
    rules_path.mkdir(parents=True, exist_ok=True)

    existing_policies = get_existing_policies(rules_path)
    logger.info(f"Found {len(existing_policies)} existing policies in {rules_path}")

    for policy_ref in registry_policies:
        policy_name = policy_ref.split("/")[-1]  # Basic name extraction
        policy_file_path = rules_path / f"{policy_name}.yml"

        if policy_file_path.exists() and not force_update:
            logger.info(
                f"Skipping '{policy_name}' (already exists). Use --force to update."
            )
            skipped_count += 1
            continue

        logger.info(f"Fetching policy '{policy_ref}' from registry...")
        policy_content = fetch_semgrep_rules_from_registry(policy_ref)

        if policy_content:
            if policy_file_path.exists():  # Already exists, but force_update=True
                logger.info(f"Updating '{policy_name}'...")
                updated_count += 1
            else:
                logger.info(f"Adding '{policy_name}'...")
                added_count += 1
            write_policy_to_file(policy_file_path, policy_content)
        else:
            logger.warning(f"Failed to fetch or process policy: {policy_ref}")
            skipped_count += 1  # Count failed fetches as skipped

    logger.info(
        f"Policy sync completed. Added: {added_count}, Updated: {updated_count}, Skipped/Failed: {skipped_count}"
    )
    return added_count, updated_count, skipped_count


def _run_git_command(command: List[str], cwd: str) -> Tuple[bool, str]:
    """Run a Git command and return success status and output."""
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,  # Don't raise exception on non-zero exit code
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            # Fix F541 f-string
            command_str = " ".join(command)
            error_message = (
                f"Git command failed: {command_str}\nError: {result.stderr.strip()}"
            )
            logger.error(error_message)
            return False, result.stderr.strip()
    except FileNotFoundError:
        # Fix F541 f-string
        command_str = " ".join(command)
        error_message = f"Git command not found: {command_str}. Ensure git is installed and in PATH."
        logger.error(error_message)
        return False, "Git command not found"
    except Exception as e:
        # Fix F541 f-string
        command_str = " ".join(command)
        error_message = f"An unexpected error occurred running git command: {command_str}\nError: {e}"
        logger.exception(error_message)
        return False, str(e)


if __name__ == "__main__":
    main()
