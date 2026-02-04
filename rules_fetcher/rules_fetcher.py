# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Rules Fetcher - Clones Splunk rules repository and processes YAML rule files.
Removes mitre_attack_id from tags, mitre references, and tests from the rules.
"""

import argparse
import logging
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, List, Optional

import yaml

# Set up module-level logger
logger = logging.getLogger(__name__)


def clone_repository(repo_url: str, repos_dir: Path) -> Optional[Path]:
    """
    Clone the git repository to the repos directory.

    Args:
        repo_url: URL of the git repository to clone
        repos_dir: Directory where the repository will be cloned

    Returns:
        Path to the cloned repository
    """
    repos_dir.mkdir(parents=True, exist_ok=True)

    # Extract repository name from URL
    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    repo_path = repos_dir / repo_name

    if repo_path.exists():
        logger.debug("Repository already exists at %s, skipping clone", repo_path)
    else:
        logger.debug("Cloning repository from %s to %s", repo_url, repo_path)
        try:
            # Capture output unless debug logging is enabled
            capture_output = logger.level > logging.DEBUG
            subprocess.run(
                ["git", "clone", repo_url, str(repo_path)],
                check=True,
                capture_output=capture_output,
            )
            logger.debug("Successfully cloned repository to %s", repo_path)
        except subprocess.CalledProcessError as e:
            logger.error("Error cloning repository: %s", e)
            return None

    return repo_path


def find_yaml_files(repo_path: Path, pattern: str) -> List[Path]:
    """
    Find all YAML files matching the given pattern.

    Args:
        repo_path: Path to the repository root
        pattern: Glob pattern to match files (e.g., "**/*.yml")

    Returns:
        List of paths to matching YAML files
    """
    # Convert pattern to Path and find all matching files
    matching_files = list(repo_path.glob(pattern))

    # Filter to only include .yml and .yaml files
    yaml_files = [f for f in matching_files if f.suffix in [".yml", ".yaml"]]

    logger.debug("Found %d YAML files matching pattern '%s'", len(yaml_files), pattern)

    return yaml_files


def load_rules_list_from_file(file_path: Path) -> List[str]:
    """
    Load a list of rule name substrings from a file.

    Args:
        file_path: Path to the file containing rule name substrings
                   (one per line)

    Returns:
        List of substring filters
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            # Read lines, strip whitespace, and filter out empty lines
            substrings = [line.strip() for line in f if line.strip()]
        logger.debug("Loaded %d substrings from %s", len(substrings), file_path)
        return substrings
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Error reading rules list file %s: %s", file_path, e)
        sys.exit(1)


def filter_yaml_files_by_substrings(
    yaml_files: List[Path], substrings: List[str]
) -> List[Path]:
    """
    Filter YAML files to only include those whose filenames contain one of
    the substrings.

    Args:
        yaml_files: List of YAML file paths
        substrings: List of substrings to match against filenames

    Returns:
        Filtered list of paths to YAML files
    """
    filtered_files = []
    for yaml_file in yaml_files:
        filename = yaml_file.stem  # Get filename without extension
        if any(substring.casefold() in filename.casefold() for substring in substrings):
            filtered_files.append(yaml_file)
            logger.debug("Matched file: %s", yaml_file.name)

    logger.debug(
        "Filtered to %d files (from %d) matching substrings",
        len(filtered_files),
        len(yaml_files),
    )

    return filtered_files


def remove_mitre_attack_id_from_tags(rule_data: dict) -> dict:
    """
    Remove mitre_attack_id from tags in the rule data.

    Args:
        rule_data: Dictionary containing the parsed YAML rule

    Returns:
        Modified rule data with mitre_attack_id removed from tags
    """
    if "tags" not in rule_data:
        logger.debug("No 'tags' field found in rule")
        return rule_data

    tags = rule_data["tags"]

    # Handle both list and dict formats for tags
    if isinstance(tags, list):
        # Remove any tag entries that contain mitre_attack_id
        original_count = len(tags)
        tags = [
            tag
            for tag in tags
            if not isinstance(tag, dict) or "mitre_attack_id" not in tag
        ]
        removed_count = original_count - len(tags)
        if removed_count > 0:
            logger.debug(
                "Removed %d tag(s) containing mitre_attack_id",
                removed_count,
            )
        rule_data["tags"] = tags
    elif isinstance(tags, dict):
        # Remove mitre_attack_id key if it exists
        if "mitre_attack_id" in tags:
            del tags["mitre_attack_id"]
            logger.debug("Removed 'mitre_attack_id' from tags dictionary")

    return rule_data


def remove_mitre_references(rule_data: dict) -> dict:
    """
    Remove any reference lines that contain the 'mitre' substring.

    Args:
        rule_data: Dictionary containing the parsed YAML rule

    Returns:
        Modified rule data with mitre references removed
    """
    if "references" not in rule_data:
        logger.debug("No 'references' field found in rule")
        return rule_data

    references = rule_data["references"]

    # Handle references as a list
    if isinstance(references, list):
        original_count = len(references)
        # Remove any reference that contains 'mitre' (case-insensitive)
        references = [ref for ref in references if "mitre" not in str(ref).lower()]
        removed_count = original_count - len(references)
        if removed_count > 0:
            logger.debug("Removed %d reference(s) containing 'mitre'", removed_count)
        rule_data["references"] = references
    elif isinstance(references, str):
        # Handle single string reference
        if "mitre" in references.lower():
            del rule_data["references"]
            logger.debug("Removed reference containing 'mitre'")

    return rule_data


def remove_tests(rule_data: dict) -> dict:
    """
    Remove the tests element from the rule data.

    Args:
        rule_data: Dictionary containing the parsed YAML rule

    Returns:
        Modified rule data with tests removed
    """
    if "tests" in rule_data:
        del rule_data["tests"]
        logger.debug("Removed 'tests' element from rule")
    else:
        logger.debug("No 'tests' field found in rule")

    return rule_data


def redact_mitre_technique_ids(data: Any) -> Any:
    """
    Recursively traverse YAML data structure and replace MITRE
    technique/sub-technique IDs.

    Replaces:
    - Sub-techniques (T####.###) with T0000.000
    - Techniques (T####) with T0000

    Args:
        data: Any YAML data structure (dict, list, str, etc.)

    Returns:
        Modified data with technique IDs redacted
    """
    if isinstance(data, str):
        # Replace sub-techniques first (more specific pattern)
        # Pattern: T followed by 4 digits, dot, 3 digits
        data = re.sub(r"T\d{4}\.\d{3}", "T0000.000", data)
        # Replace techniques (T followed by 4 digits, but not part of
        # sub-technique). Use word boundary or ensure it's not followed
        # by a dot and digit
        data = re.sub(r"T\d{4}(?!\.\d)", "T0000", data)
        return data
    if isinstance(data, dict):
        return {key: redact_mitre_technique_ids(value) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_mitre_technique_ids(item) for item in data]
    # For other types (int, float, bool, None), return as-is
    return data


def remove_mitre_from_rule(rule_data: dict) -> dict:
    """
    Remove mitre_attack_id from tags, mitre references, tests, and redact
    technique IDs.

    Args:
        rule_data: Dictionary containing the parsed YAML rule

    Returns:
        Modified rule data with mitre_attack_id removed from tags, mitre
        references removed, tests removed, and Mitre technique IDs redacted
    """
    rule_data = remove_mitre_attack_id_from_tags(rule_data)
    rule_data = remove_mitre_references(rule_data)
    rule_data = remove_tests(rule_data)
    rule_data = redact_mitre_technique_ids(rule_data)
    return rule_data


def process_rule_file(
    rule_file: Path,
    original_dir: Path,
    untagged_dir: Path,
    skip_untagging: bool,
) -> None:
    """
    Process a single rule file: copy to original, then untag and save to
    untagged.

    Args:
        rule_file: Path to the rule file to process
        original_dir: Directory to copy original files to
        untagged_dir: Directory to save untagged files to
        skip_untagging: If True, skip the untagging step
    """
    # Ensure output directories exist
    original_dir.mkdir(parents=True, exist_ok=True)
    untagged_dir.mkdir(parents=True, exist_ok=True)

    # Get relative path from repo root to preserve directory structure
    rule_filename = rule_file.name

    # Copy original file to rules/original
    original_dest = original_dir / rule_filename
    shutil.copy2(rule_file, original_dest)
    logger.debug("Copied original rule to %s", original_dest)

    # If skip_untagging is True, don't process further
    if skip_untagging:
        logger.debug("Skipping untagging for %s", rule_filename)
        return

    # Parse YAML file
    try:
        with open(rule_file, "r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        if rule_data is None:
            logger.debug("Warning: %s is empty or invalid YAML", rule_filename)
            return

        rule_data = remove_mitre_from_rule(rule_data)

        # Save untagged version to rules/untagged
        untagged_dest = untagged_dir / rule_filename
        with open(untagged_dest, "w", encoding="utf-8") as f:
            yaml.dump(
                rule_data,
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )

        logger.debug("Saved untagged rule to %s", untagged_dest)

    except yaml.YAMLError as e:
        logger.error("Error parsing YAML file %s: %s", rule_file, e)
    except Exception as e:  # pylint: disable=broad-except
        logger.error("Error processing file %s: %s", rule_file, e)


def init_args_parser() -> argparse.Namespace:
    """Initialize the argument parser."""
    parser = argparse.ArgumentParser(
        description=("Clone Splunk rules repository and process YAML rules")
    )
    parser.add_argument(
        "--repo_url",
        type=str,
        default="https://github.com/splunk/security_content",
        help="URL of the Splunk rules git repository to clone",
    )

    parser.add_argument(
        "--rules-pattern",
        type=str,
        default="detections/**/*.yml",
        help='Glob pattern for rules folder path (e.g., "**/*.yml")',
    )

    # Create mutually exclusive group for rules-list and rules-list-file
    rules_filter_group = parser.add_mutually_exclusive_group()
    rules_filter_group.add_argument(
        "--rules-list",
        type=str,
        nargs="+",
        help=(
            "List of rule name substrings to filter rules found by pattern "
            "(e.g., TOR_Traffic Detect_PsExec)"
        ),
    )
    rules_filter_group.add_argument(
        "--rules-list-file",
        default="rules_fetcher/default_rules_list.txt",
        type=str,
        help=("Path to file containing rule name substrings (one per line)"),
    )

    parser.add_argument(
        "--max-rules",
        type=int,
        default=None,
        help=(
            "Maximum number of rules to process. "
            "If not set, all rules will be processed."
        ),
    )
    parser.add_argument(
        "--skip-untagging",
        action="store_true",
        default=False,
        help="Skip untagging rules (default: False)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Print debug messages (default: False)",
    )
    parser.add_argument(
        "--repos_dir",
        type=str,
        default="output/repos",
        help="Directory to save the cloned repository (default: output/repos)",
    )
    parser.add_argument(
        "--original_rules_dir",
        type=str,
        default="output/rules/original",
        help=(
            "Directory to save the original rules " "(default: output/rules/original)"
        ),
    )
    parser.add_argument(
        "--untagged_rules_dir",
        type=str,
        default="output/rules/untagged",
        help=(
            "Directory to save the untagged rules " "(default: output/rules/untagged)"
        ),
    )
    return parser.parse_args()


def get_filter_substrings(args: argparse.Namespace) -> Optional[List[str]]:
    """Get the filter substrings from the arguments."""

    if args.rules_list:
        filter_substrings = args.rules_list
        logger.debug("Rules list filter: %s", filter_substrings)
        return filter_substrings
    if args.rules_list_file:
        rules_list_file = Path(args.rules_list_file)
        logger.debug("Loading rules list from file: %s", rules_list_file)
        filter_substrings = load_rules_list_from_file(rules_list_file)
        return filter_substrings
    return None


def setup_logging(args: argparse.Namespace) -> None:
    """Set up logging."""
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )


def get_filtered_rule_files(repo_path: Path, args: argparse.Namespace) -> List[Path]:
    """Get the filtered YAML rule files from the arguments."""
    # Determine if we have a filter list (from command line or file)

    yaml_files = find_yaml_files(repo_path, args.rules_pattern)
    logger.debug("Found %d files matching pattern", len(yaml_files))

    filter_substrings = get_filter_substrings(args)
    if filter_substrings:
        yaml_files = filter_yaml_files_by_substrings(yaml_files, filter_substrings)
        logger.debug("After filtering: %d files", len(yaml_files))
    else:
        logger.debug("No filter substrings provided")
    return yaml_files


def main() -> int:
    """Main function to orchestrate the rule fetching and processing."""
    args = init_args_parser()
    setup_logging(args)

    # Set up directory paths
    repos_dir = Path(args.repos_dir)
    original_dir = Path(args.original_rules_dir)
    untagged_dir = Path(args.untagged_rules_dir)

    logger.debug("Repository URL: %s", args.repo_url)
    logger.debug("Rules pattern: %s", args.rules_pattern)

    logger.debug("Skip untagging: %s", args.skip_untagging)

    # Clone repository
    repo_path = clone_repository(args.repo_url, repos_dir)
    if not repo_path:
        logger.error("Failed to clone repository")
        return 1

    # Find YAML files using the pattern
    yaml_files = get_filtered_rule_files(repo_path, args)
    logger.debug("Found %d files matching pattern", len(yaml_files))

    # Apply max-rules limit if specified
    if args.max_rules is not None and args.max_rules > 0:
        yaml_files = yaml_files[: args.max_rules]

    if not yaml_files:
        logger.error("No YAML files found")
        return 1

    # Process each rule file
    logger.debug("Processing %d rule file(s)...", len(yaml_files))
    for rule_file in yaml_files:
        process_rule_file(rule_file, original_dir, untagged_dir, args.skip_untagging)

    logger.info("Successfully processed %d rule file(s)", len(yaml_files))
    logger.info("Original files saved to: %s", original_dir)
    if not args.skip_untagging:
        logger.info("Untagged files saved to: %s", untagged_dir)

    return 0


if __name__ == "__main__":
    main()
