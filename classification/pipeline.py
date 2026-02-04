# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""MITRE ATT&CK Technique Classification Pipeline.

Two-step classification approach:
    Step 1 (Plausible): Broad filtering from all techniques (e.g., top 10)
    Step 2 (Relevant): Refined selection from plausible set (e.g., top 1-3)

Single-step mode (optional): Skip Step 1 and directly classify relevant techniques.

Usage:
    python pipeline.py --config config.json --input path/to/data
    python pipeline.py --config config.json --input rules.parquet
    python pipeline.py --config config.json --input /path/to/yaml/folder
"""

import argparse
import json
import logging
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, TypeVar, cast

import pandas as pd
from openai import AuthenticationError, PermissionDeniedError
from tqdm import tqdm

from classification.merge_original_labels import (
    build_original_labels_mapping,
    augment_with_original_labels,
)
from classification.utils import (
    AnnotationResult,
    PipelineConfig,
    TechniqueClassifier,
    load_config,
    load_labels,
    save_annotations,
)

logger = logging.getLogger(__name__)
# Logger level will be set in main() based on --debug flag

T = TypeVar("T")

WorkItem = Tuple[str, str]
WorkerResult = Tuple[str, Optional[AnnotationResult], Optional[Exception]]

# Exceptions that should not be retried - these indicate configuration problems
NON_RETRYABLE_EXCEPTIONS = (AuthenticationError, PermissionDeniedError)


class NonRetryableError(Exception):
    """Exception wrapper for errors that should not be retried."""

    def __init__(self, message: str, original_exception: Exception):
        super().__init__(message)
        self.original_exception = original_exception


def retry_with_backoff(
    func: Callable[[], T],
    max_retries: int,
    base_delay: float = 1.0,
    rule_id: str = "",
) -> T:
    """Execute a function with exponential backoff retry logic.

    Args:
        func: The function to execute (no arguments, use closure/lambda)
        max_retries: Maximum number of retry attempts (0 = no retries)
        base_delay: Initial delay in seconds (doubles each retry)
        rule_id: Rule ID for logging purposes

    Returns:
        The result of func() if successful

    Raises:
        NonRetryableError: For authentication/permission errors that should abort
        The last exception if all retries are exhausted
    """
    last_exception: Optional[Exception] = None

    for attempt in range(max_retries + 1):  # +1 for initial attempt
        try:
            return func()
        except NON_RETRYABLE_EXCEPTIONS as e:
            # Authentication and permission errors should not be retried
            raise NonRetryableError(
                f"Non-retryable error (check API key/permissions): {e}", e
            ) from e
        except Exception as e:  # pylint: disable=broad-exception-caught
            last_exception = e
            error_type = type(e).__name__
            error_msg = str(e) or "(no message)"
            # Get underlying cause for more details (e.g., SSL errors, DNS errors)
            cause_msg = ""
            cause = e.__cause__
            if cause is not None:
                cause_msg = f" (caused by: {type(cause).__name__}: {cause})"
            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                logger.warning(
                    "Attempt %d/%d failed for %s: [%s] %s%s. Retrying in %.1fs...",
                    attempt + 1,
                    max_retries + 1,
                    rule_id,
                    error_type,
                    error_msg,
                    cause_msg,
                    delay,
                )
                time.sleep(delay)
            else:
                logger.error(
                    "All %d attempts failed for %s: [%s] %s%s",
                    max_retries + 1,
                    rule_id,
                    error_type,
                    error_msg,
                    cause_msg,
                )

    raise last_exception  # type: ignore[misc]


def load_yaml_files_from_directory(directory_path: Path) -> pd.DataFrame:
    """Load detection rules from a directory of YAML files.

    Args:
        directory_path: Path to directory containing YAML files

    Returns:
        DataFrame with columns: rule_id, file_content
    """
    yaml_files = list(directory_path.rglob("*.yml")) + list(
        directory_path.rglob("*.yaml")
    )

    if not yaml_files:
        raise ValueError(f"No YAML files found in {directory_path}")

    logger.debug("Found %d YAML files in %s", len(yaml_files), directory_path)

    data = []
    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                content = f.read()

                # Use relative path (including subfolders) as rule_id
                # This ensures uniqueness and provides context about file location
                relative_path = str(yaml_file.relative_to(directory_path))

                data.append(
                    {
                        "rule_id": relative_path,
                        "file_content": content,
                    }
                )
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.debug("Warning: Failed to load %s: %s", yaml_file, e)
            continue

    if not data:
        raise ValueError(f"Failed to load any valid YAML files from {directory_path}")

    return pd.DataFrame(data)


def load_parquet_data(parquet_path: str) -> pd.DataFrame:
    """Load detection rules from Parquet file."""
    df = pd.read_parquet(parquet_path)

    # Validate required columns
    required_cols = ["rule_id", "file_content"]
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Parquet missing required columns: {missing_cols}")

    return df


def load_data(input_path: str) -> Optional[pd.DataFrame]:
    """Load detection rules from either a Parquet file or directory of YAML files.

    Args:
        input_path: Path to parquet file or directory of YAML files

    Returns:
        DataFrame with columns: rule_id, file_content
    """
    path = Path(input_path)

    # Check if path exists
    if not path.exists():
        raise FileNotFoundError(f"Input path not found: {input_path}")

    # Determine if directory or file
    if path.is_dir():
        return load_yaml_files_from_directory(path)
    if path.is_file():
        if path.suffix == ".parquet":
            return load_parquet_data(input_path)

    logger.warning("Unsupported file type: %s", path.suffix)
    return None


def save_config_copy(config_dict: dict, output_dir: Path) -> Path:
    """Save a copy of the config."""
    config_path = output_dir / "config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_dict, f, indent=2)
    return config_path


def setup_output_directory(output_dir: Path, config_dict: dict) -> Path:
    """Setup output directory and save config snapshot.

    Args:
        output_dir: Path to output directory
        config_dict: Config dictionary to save

    Returns:
        output_dir
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    config_copy_path = save_config_copy(config_dict, output_dir)
    logger.debug("Config saved: %s", config_copy_path)

    return output_dir


def load_and_validate_data(input_path: str) -> tuple[pd.DataFrame, List[str]]:
    """Load detection rules and technique labels.

    Args:
        input_path: Path to input data (parquet file or directory of YAML files)

    Returns:
        Tuple of (dataframe, labels)
    """
    logger.debug("\nLoading data from: %s", input_path)
    df = load_data(input_path)
    if df is None or df.empty:
        raise ValueError("No rules to process")
    logger.debug("Loaded %d rules", len(df))

    labels = load_labels()
    logger.debug("Loaded %d technique labels", len(labels))

    return df, labels


def initialize_classifiers(
    config: PipelineConfig, labels: List[str], disable_ssl_verify: bool = False
) -> tuple[Optional[TechniqueClassifier], TechniqueClassifier]:
    """Initialize plausible and relevant classifiers.

    Returns:
        Tuple of (plausible_classifier, relevant_classifier)
    """
    plausible_classifier = None
    if config.plausible_step:
        logger.debug("\n=== Step 1: Plausible Classification (Broad Filtering) ===")
        plausible_classifier = TechniqueClassifier(
            config=config.plausible_step,
            labels=labels,
            disable_ssl_verify=disable_ssl_verify,
            step_name="plausible step",
        )

    logger.debug("\n=== Step 2: Relevant Classification (Refined Selection) ===")
    relevant_classifier = TechniqueClassifier(
        config=config.relevant_step,
        labels=labels,
        disable_ssl_verify=disable_ssl_verify,
        step_name="relevant step",
    )

    return plausible_classifier, relevant_classifier


def classify_single_rule(
    rule_id: str,
    rule_content: str,
    plausible_classifier: Optional[TechniqueClassifier],
    relevant_classifier: TechniqueClassifier,
) -> AnnotationResult:
    """Classify a single rule through the pipeline.

    Returns:
        AnnotationResult with plausible and relevant techniques
    """
    result = AnnotationResult()

    # Step 1: Get plausible techniques (if enabled)
    if plausible_classifier:
        logger.debug(
            "  Step 1: Identifying plausible techniques for rule %s...", rule_id
        )
        result.plausible = plausible_classifier.classify_plausible(rule_content)
        logger.debug("  → Plausible: %s", result.plausible)

    # Step 2: Get relevant techniques (using plausible as context if available)
    step_label = (
        "Step 2: Refining to most relevant..."
        if plausible_classifier
        else "Single-step: Classifying relevant techniques..."
    )
    logger.debug("  %s (rule %s...)", step_label, rule_id)
    result.relevant = relevant_classifier.classify_relevant(
        rule_content, result.plausible
    )
    logger.debug("  → Relevant: %s (rule %s)", result.relevant, rule_id)

    return result


def _build_work_items(df: pd.DataFrame) -> List[Tuple[str, str]]:
    return [(row["rule_id"], row["file_content"]) for _, row in df.iterrows()]


def _process_single_rule_with_retries(
    item: WorkItem,
    max_retries: int,
    plausible_classifier: Optional[TechniqueClassifier],
    relevant_classifier: TechniqueClassifier,
) -> WorkerResult:
    rule_id, content = item

    def classify() -> AnnotationResult:
        return classify_single_rule(
            rule_id=rule_id,
            rule_content=content,
            plausible_classifier=plausible_classifier,
            relevant_classifier=relevant_classifier,
        )

    try:
        result = retry_with_backoff(
            func=classify,
            max_retries=max_retries,
            base_delay=1.0,
            rule_id=rule_id,
        )
        return (rule_id, result, None)
    except Exception as e:  # pylint: disable=broad-exception-caught
        return (rule_id, None, e)


def _collect_results(
    futures: Dict[Future[WorkerResult], WorkItem],
    total: int,
) -> Tuple[Dict[str, AnnotationResult], List[str]]:
    annotations: Dict[str, AnnotationResult] = {}
    failed_rules: List[str] = []

    with tqdm(total=total, desc="Classifying rules", unit="rule") as pbar:
        for future in as_completed(futures.keys()):
            rule_id, result, error = future.result()
            if result is not None:
                annotations[rule_id] = result
            else:
                if isinstance(error, NonRetryableError):
                    for f in futures.keys():
                        f.cancel()
                    logger.error("FATAL: %s - aborting pipeline", error)
                    raise error
                failed_rules.append(rule_id)
            pbar.update(1)

    return annotations, failed_rules


def process_rules(
    df: pd.DataFrame,
    plausible_classifier: Optional[TechniqueClassifier],
    relevant_classifier: TechniqueClassifier,
    num_workers: int = 1,
    retries: int = 3,
) -> Tuple[Dict[str, AnnotationResult], List[str]]:
    """Process all rules through the classification pipeline.

    Args:
        df: DataFrame with rule_id and file_content columns
        plausible_classifier: Optional classifier for plausible techniques
        relevant_classifier: Classifier for relevant techniques
        num_workers: Number of parallel workers for API calls
        retries: Max retry attempts per rule with exponential backoff

    Returns:
        Tuple of (successful annotations dict, list of failed rule IDs)
    """
    logger.info(
        "Processing %d rules with %d workers, %d retries per rule",
        len(df),
        num_workers,
        retries,
    )
    if retries == 0:
        logger.warning("Retries is 0 - requests will fail without retry on first error")

    work_items = _build_work_items(df)

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures: Dict[Future[WorkerResult], WorkItem] = {
            executor.submit(
                _process_single_rule_with_retries,
                item,
                retries,
                plausible_classifier,
                relevant_classifier,
            ): item
            for item in work_items
        }

        annotations, failed_rules = _collect_results(futures, len(work_items))

    # Summary logging
    if failed_rules:
        logger.warning(
            "%d rules failed after all retries: %s",
            len(failed_rules),
            failed_rules[:10],  # Show first 10
        )
        if len(failed_rules) > 10:
            logger.warning("  ... and %d more", len(failed_rules) - 10)

    logger.info(
        "Successfully classified %d/%d rules",
        len(annotations),
        len(work_items),
    )

    return annotations, failed_rules


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify detection rules with MITRE ATT&CK techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic usage with default paths
    python pipeline.py --config config.json

    # Custom input and output paths
    python pipeline.py --config config.json \\
        --input-path custom/rules/ \\
        --output-file-path custom/output/results.json

    # Process only first 10 rules (for testing)
    python pipeline.py --config config.json --max-rules-to-process 10
        """,
    )
    parser.add_argument(
        "--config",
        default="classification/config_example_two_step.json",
        help="Path to JSON config file",
    )
    parser.add_argument(
        "--input-path",
        default="output/rules/untagged",
        help="Path to input data (parquet file or directory of YAML files)",
    )
    parser.add_argument(
        "--output-file-path",
        default="output/classification/classified_output.json",
        help="Path to output JSON file (default: output/classification/classified_output.json)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--disable-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (for proxy restrictions; use with caution)",
    )
    parser.add_argument(
        "--max-rules-to-process",
        type=int,
        default=None,
        help="Maximum number of rules to process (default: None - process all rules)",
    )
    parser.add_argument(
        "-n",
        "--num-workers",
        type=int,
        default=None,
        help="Number of parallel workers for API calls (default: 1, or from config)",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=None,
        help="Max retry attempts per rule with exponential backoff (default: 3, or from config)",
    )
    parser.add_argument(
        "--no-merge-existing-labels",
        action="store_false",
        dest="merge_existing_labels",
        default=True,
        help="Skip merging existing MITRE labels from original rules (default: merge enabled)",
    )
    parser.add_argument(
        "--original-rules-folder",
        default="output/rules/original",
        help=(
            "Path to folder containing original YAML rule files with original labels "
            "(default: output/rules/original)"
        ),
    )
    return parser


def _configure_logging(debug: bool) -> None:
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger.setLevel(log_level)
    logging.getLogger("classification.utils").setLevel(log_level)

    if not debug:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("openai").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


def _apply_cli_overrides(config: PipelineConfig, args: argparse.Namespace) -> None:
    if args.num_workers is not None:
        config.num_workers = args.num_workers
    if args.retries is not None:
        config.retries = args.retries


def merge_original_labels_if_enabled(
    annotations: Dict[str, AnnotationResult],
    merge_enabled: bool,
    original_rules_folder: str,
    output_file: Path,
) -> None:
    """Merge original labels from original rules if enabled.

    Args:
        annotations: Dictionary mapping rule IDs to classification results
        merge_enabled: Whether to perform merging
        original_rules_folder: Path to folder with original YAML rules
        output_file: Path to final output file (for deriving intermediate file name)

    Modifies annotations in place by merging original labels.
    If merging is enabled, saves unmerged results to an intermediate file first.
    """
    if not merge_enabled:
        logger.debug("Skipping original labels merge (disabled via flag)")
        return

    original_rules_path = Path(original_rules_folder)
    if not original_rules_path.exists():
        logger.info(
            "Original rules folder not found at %s - skipping original labels merge",
            original_rules_path,
        )
        return

    logger.info("Merging original labels from %s", original_rules_path)

    # Save unmerged results to intermediate file
    intermediate_file = output_file.parent / f"unmerged_{output_file.name}"
    save_annotations(annotations, intermediate_file)
    logger.info("Saved unmerged classification results to %s", intermediate_file)

    # Convert annotations to list format expected by merge functions
    rule_ids = list(annotations.keys())
    classifier_data = [
        {
            "id": rule_id,
            "plausible_techniques": annotations[rule_id].plausible,
            "relevant_techniques": annotations[rule_id].relevant,
        }
        for rule_id in rule_ids
    ]

    # Build original labels mapping and augment
    original_labels = build_original_labels_mapping(original_rules_path, rule_ids)
    augment_with_original_labels(classifier_data, original_labels)

    # Update annotations with merged data
    for item in classifier_data:
        rule_id = cast(str, item["id"])
        annotations[rule_id].relevant = list(item["relevant_techniques"])


def print_summary(annotations: Dict[str, AnnotationResult], total_rules: int) -> None:
    """Print processing summary statistics."""
    logger.debug("\n=== Summary ===")
    logger.debug("Processed: %d/%d rules", len(annotations), total_rules)

    if annotations:
        avg_plausible = sum(len(a.plausible) for a in annotations.values()) / len(
            annotations
        )
        avg_relevant = sum(len(a.relevant) for a in annotations.values()) / len(
            annotations
        )
        logger.debug("Avg plausible: %.1f", avg_plausible)
        logger.debug("Avg relevant: %.1f", avg_relevant)


def run_pipeline(  # pylint: disable=too-many-locals
    config: PipelineConfig,
    input_path: str,
    output_file_path: str,
    max_rules_to_process: Optional[int] = None,
    disable_ssl_verify: bool = False,
    merge_existing_labels: bool = True,
    original_rules_folder: str = "output/rules/original",
) -> None:
    """Run the complete classification pipeline.

    Args:
        config: Pipeline configuration
        config_dict: Raw config dictionary for saving
        input_path: Path to input data (parquet file or directory of YAML files)
        output_file_path: Path to output JSON file(default:
        output/classification/classified_output.json)
        max_rules_to_process: Maximum number of rules to process (None =
            process all)
        disable_ssl_verify: Disable SSL certificate verification (for
            proxy restrictions; use with caution)
        merge_existing_labels: Whether to merge existing MITRE labels from
            original rules with classifier predictions (default: True)
        original_rules_folder: Path to folder containing original YAML rule
            files with original labels

    Pipeline steps:
        1. Setup output directory and save config
        2. Load data and labels
        3. Initialize classifiers
        4. Process all rules
        5. Merge original labels if enabled (saves intermediate unmerged file)
        6. Save results and print summary
    """
    # Step 1: Setup output directory
    output_file = Path(output_file_path)
    output_dir = output_file.parent

    setup_output_directory(output_dir, config.config_dict)

    # Step 2: Load data
    df, labels = load_and_validate_data(input_path)

    # Limit number of rules if specified
    if max_rules_to_process is not None:
        original_count = len(df)
        df = df.head(max_rules_to_process)
        logger.debug("Limited to %d rules (out of %d total)", len(df), original_count)

    # Step 3: Initialize classifiers
    plausible_classifier, relevant_classifier = initialize_classifiers(
        config, labels, disable_ssl_verify
    )

    # Step 4: Process rules
    if config.num_workers == 1:
        logger.info(
            "TIP: Running with 1 worker (sequential processing). "
            "If this is too slow, you can stop the run (Ctrl+C), "
            "increase 'num_workers' in your config file (e.g., to 10-30), "
            "and re-run for significantly faster execution."
        )

    annotations, failed_rules = process_rules(
        df,
        plausible_classifier,
        relevant_classifier,
        num_workers=config.num_workers,
        retries=config.retries,
    )

    # Step 5: Merge original labels if enabled
    # This saves unmerged results to intermediate file before merging
    merge_original_labels_if_enabled(
        annotations, merge_existing_labels, original_rules_folder, output_file
    )

    # Step 6: Save results
    save_annotations(annotations, output_file)
    print_summary(annotations, len(df))

    if failed_rules:
        logger.info("Failed rule IDs: %s", failed_rules)


def main() -> int:
    """Main function."""

    parser = _build_arg_parser()
    args = parser.parse_args()

    _configure_logging(args.debug)

    config_path = Path(args.config)
    if not config_path.exists():
        logger.debug("Error: Config not found: %s", config_path)
        return 1

    logger.debug("Loading config: %s", config_path)

    config = load_config(config_path)

    _apply_cli_overrides(config, args)

    try:
        run_pipeline(
            config,
            input_path=args.input_path,
            output_file_path=args.output_file_path,
            max_rules_to_process=args.max_rules_to_process,
            disable_ssl_verify=args.disable_ssl_verify,
            merge_existing_labels=args.merge_existing_labels,
            original_rules_folder=args.original_rules_folder,
        )
        return 0
    except NonRetryableError as e:
        logger.error("Pipeline aborted due to non-retryable error: %s", e)
        logger.error("Please check your API key and permissions.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
