# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Aggregation Pipeline for Detection Rules.

This module orchestrates the aggregation of classified detection rules,
computing all necessary transformations and statistics WITHOUT making
any LLM calls. The insights generator is a separate tool.

Usage:
    python -m aggregation.pipeline \\
        --config aggregation/config_aggregation.json
    python -m aggregation.pipeline \\
        --input-file path/to/classified.json \\
        --output-dir output/aggregation
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict

from aggregation.config_utils import load_config_from_args, setup_logging
from aggregation.data_processor import process_classified_rules

logger = logging.getLogger(__name__)


def save_aggregated_data(data: Dict[str, Any], output_file: Path) -> None:
    """
    Save aggregated data to JSON file.

    Args:
        data: Aggregated data dictionary
        output_file: Path to output file
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    logger.info("Aggregated data saved to: %s", output_file)


def save_config_snapshot(config: Dict[str, Any], output_dir: Path) -> None:
    """
    Save a snapshot of the configuration used.

    Args:
        config: Configuration dictionary
        output_dir: Output directory
    """
    config_snapshot_path = output_dir / "config.json"
    with config_snapshot_path.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    logger.info("Configuration snapshot saved to: %s", config_snapshot_path)


def _log_pipeline_summary(
    aggregated_data: Dict[str, Any], output_file: Path, output_dir: str
) -> None:
    """
    Log pipeline completion summary and next steps.

    Args:
        aggregated_data: Aggregated data with metadata
        output_file: Path to output file
        output_dir: Output directory path
    """
    logger.info("=" * 60)
    logger.info("AGGREGATION COMPLETE")
    logger.info("=" * 60)
    logger.info("Summary:")
    logger.info("  - Total rules: %d", aggregated_data["metadata"]["total_rules"])
    logger.info(
        "  - Total techniques: %d", aggregated_data["metadata"]["total_techniques"]
    )
    logger.info("  - Total tactics: %d", aggregated_data["metadata"]["total_tactics"])
    logger.info(
        "  - Total kill chains: %d", aggregated_data["metadata"]["total_kill_chains"]
    )
    logger.info("=" * 60)
    logger.info("Next steps:")
    logger.info("  1. (Optional) Generate insights:")
    logger.info("     python -m aggregation.insights_generator \\")
    logger.info("       --input-file %s \\", output_file)
    logger.info("       --output-file %s/insights.json", output_dir)
    logger.info("  2. Visualize results:")
    logger.info("     streamlit run visualization/app.py -- \\")
    logger.info("       --classified-output-file-path %s", output_file)
    logger.info("=" * 60)


def run_aggregation_pipeline(
    input_file: str,
    output_dir: str,
    trending_techniques_source: str,
    save_config_snapshot_flag: bool = True,
    config_dict: Dict[str, Any] | None = None,
) -> None:
    """
    Run the complete aggregation pipeline.

    This function:
    1. Loads classified rules
    2. Processes and aggregates the data
    3. Saves the aggregated output
    4. Optionally saves a config snapshot

    Args:
        input_file: Path to classified rules JSON
        output_dir: Directory to save outputs
        trending_techniques_source: Path to trending techniques CSV
        save_config_snapshot_flag: Whether to save config snapshot
        config_dict: Configuration dictionary (for snapshot)
    """
    logger.info("=" * 60)
    logger.info("AGGREGATION PIPELINE")
    logger.info("=" * 60)
    logger.info("Input: %s", input_file)
    logger.info("Output: %s", output_dir)
    logger.info("=" * 60)

    # Process classified rules and generate all aggregations
    logger.info("Processing classified rules...")
    aggregated_data = process_classified_rules(input_file, trending_techniques_source)

    # Save aggregated data
    output_path = Path(output_dir)
    output_file = output_path / "aggregated_data.json"
    save_aggregated_data(aggregated_data, output_file)

    # Save config snapshot if requested
    if save_config_snapshot_flag and config_dict:
        save_config_snapshot(config_dict, output_path)

    # Log summary and next steps
    _log_pipeline_summary(aggregated_data, output_file, output_dir)


def _parse_pipeline_args() -> argparse.Namespace:
    """Parse command-line arguments for aggregation pipeline."""
    parser = argparse.ArgumentParser(
        description="Aggregate classified detection rules (no LLM calls)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic usage with config file
    python -m aggregation.pipeline --config aggregation/config_aggregation.json

    # Custom paths
    python -m aggregation.pipeline \\
        --input-file output/classification/classified_output.json \\
        --output-dir output/aggregation

    # With debug logging
    python -m aggregation.pipeline --config aggregation/config_aggregation.json --debug
        """,
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Path to JSON config file (optional if other args provided)",
    )
    parser.add_argument(
        "--input-file",
        type=str,
        default="output/classification/classified_output.json",
        help=(
            "Path to classified rules JSON file "
            "(default: output/classification/classified_output.json)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Directory to save aggregated data",
    )
    parser.add_argument(
        "--trending-techniques-source",
        type=str,
        help="Path to trending techniques CSV",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def _validate_pipeline_params(input_file: str, output_dir: str) -> bool:
    """Validate required pipeline parameters."""
    if not input_file:
        logger.error(
            "Error: --input-file or config.input.classified_output is required"
        )
        return False
    if not output_dir:
        logger.error("Error: --output-dir or config.output.aggregated_data is required")
        return False
    return True


def main() -> int:
    """Main function."""
    args = _parse_pipeline_args()

    # Set up logging
    setup_logging(debug=args.debug, module_names=["aggregation.data_processor"])

    # Load configuration
    try:
        config_dict = load_config_from_args(args.config)
    except FileNotFoundError:
        return 1

    # Determine parameters (CLI args override config)
    input_file = args.input_file or config_dict.get("input", {}).get(
        "classified_output"
    )
    output_dir = args.output_dir or config_dict.get("output", {}).get("aggregated_data")
    trending_source = args.trending_techniques_source or config_dict.get(
        "processing", {}
    ).get("trending_techniques_source", "visualization/data/trending_techniques.csv")

    # Extract output directory from output file path if needed
    if output_dir and "/" in output_dir:
        output_dir = str(Path(output_dir).parent)

    # Validate required parameters
    if not _validate_pipeline_params(input_file, output_dir):
        return 1

    # Get additional config flags
    save_config_snapshot_flag = config_dict.get("output", {}).get(
        "save_config_snapshot", True
    )

    # Run the pipeline
    try:
        run_aggregation_pipeline(
            input_file=input_file,
            output_dir=output_dir,
            trending_techniques_source=trending_source,
            save_config_snapshot_flag=save_config_snapshot_flag,
            config_dict=config_dict if config_dict else None,
        )
        return 0
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Pipeline failed: %s", e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
