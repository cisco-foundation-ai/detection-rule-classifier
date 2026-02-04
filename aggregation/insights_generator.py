# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Insights Generator for Detection Rules.

This standalone tool generates LLM-powered insights from aggregated detection data.
It can be run independently after the aggregation pipeline.

Initial implementation creates empty insights structure. LLM integration will be
added in future phases.

Usage:
    python -m aggregation.insights_generator \\
        --config aggregation/config_insights.json
    python -m aggregation.insights_generator \\
        --input-file output/aggregation/aggregated_data.json
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from aggregation.config_utils import load_config_from_args, setup_logging
from aggregation.prompts import format_prompt

logger = logging.getLogger(__name__)


def load_aggregated_data(input_file: Path) -> Dict[str, Any]:
    """
    Load aggregated data from JSON file.

    Args:
        input_file: Path to aggregated data JSON

    Returns:
        Aggregated data dictionary
    """
    if not input_file.exists():
        raise FileNotFoundError(f"Aggregated data file not found: {input_file}")

    with input_file.open("r", encoding="utf-8") as f:
        return json.load(f)


def call_llm_api(
    prompt: str, llm_config: Dict[str, Any], disable_ssl_verify: bool = False
) -> str:
    """
    Call LLM API with the given prompt.

    Args:
        prompt: Formatted prompt string
        llm_config: LLM configuration (model, temperature, etc.)
        disable_ssl_verify: Disable SSL certificate verification (use with caution)

    Returns:
        LLM response as string
    """
    try:
        import openai  # pylint: disable=import-outside-toplevel
        import httpx  # pylint: disable=import-outside-toplevel

        # Create httpx client with SSL verification control
        http_client = httpx.Client(verify=False) if disable_ssl_verify else None

        if disable_ssl_verify:
            logger.warning(
                "SSL verification is DISABLED - use only for development/"
                "testing to bypass proxy restrictions"
            )

        client = openai.OpenAI(
            api_key=os.environ.get("OPENAI_API_KEY"), http_client=http_client
        )

        response = client.chat.completions.create(
            model=llm_config.get("model", "gpt-4o"),
            messages=[
                {"role": "system", "content": "You are a security detection expert."},
                {"role": "user", "content": prompt},
            ],
            temperature=llm_config.get("temperature", 0.3),
            max_tokens=llm_config.get("max_tokens", 3000),
            response_format=llm_config.get("response_format", {"type": "json_object"}),
        )

        return response.choices[0].message.content or ""

    except ImportError:
        logger.error("OpenAI package not installed. Run: pip install openai")
        raise
    except Exception as e:
        logger.error("LLM API call failed: %s", e)
        raise


def parse_json_response(response: str, insight_type: str) -> Dict[str, Any]:
    """
    Parse and validate JSON response from LLM.

    Args:
        response: Raw LLM response
        insight_type: Type of insight for error logging

    Returns:
        Parsed JSON dict

    Raises:
        ValueError: If response is not valid JSON
    """
    try:
        return json.loads(response)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse %s response as JSON: %s", insight_type, e)
        logger.debug("Response was: %s", response)
        raise ValueError(f"Invalid JSON response for {insight_type}") from e


def generate_visualization_insights(
    aggregated_data: Dict[str, Any],
    llm_config: Dict[str, Any],
    disable_ssl_verify: bool = False,
) -> Dict[str, Any]:
    """
    Generate insights for each visualization in the dashboard.

    Args:
        aggregated_data: Aggregated detection data
        llm_config: LLM configuration
        disable_ssl_verify: Disable SSL certificate verification (use with caution)

    Returns:
        Dictionary mapping visualization IDs to insights
    """
    logger.info("Generating per-visualization insights...")

    # Define visualizations to analyze
    visualizations = [
        {
            "id": "tactic_coverage",
            "type": "horizontal_stacked_bar",
            "title": "Tactic Coverage",
            "description": "Detection rules mapped to MITRE ATT&CK tactics",
            "data_key": "tactic_coverage",
        },
        {
            "id": "kill_chain_coverage",
            "type": "horizontal_stacked_bar",
            "title": "Kill Chain Coverage",
            "description": "Detection rules mapped to Lockheed Martin kill chain stages",
            "data_key": "kill_chain_coverage",
        },
        {
            "id": "tactic_killchain_heatmap",
            "type": "heatmap",
            "title": "Tactic / Kill-Chain Coverage",
            "description": (
                "Intersection of tactics and kill chain stages "
                "showing unique rule counts"
            ),
            "data_key": "tactic_killchain_matrix",
        },
        {
            "id": "top_techniques",
            "type": "horizontal_bar",
            "title": "Top 20 Techniques by Rule Count",
            "description": "Most frequently mapped techniques across all detection rules",
            "data_key": "technique_counts",
        },
        {
            "id": "trending_coverage",
            "type": "table",
            "title": "Trending Attacks Coverage",
            "description": "Coverage of trending attack techniques from real-world incidents",
            "data_key": "trending_analysis",
        },
    ]

    insights_by_viz = {}

    for viz in visualizations:
        logger.info("Analyzing %s...", viz["title"])

        try:
            # Extract chart-specific data
            chart_data = aggregated_data.get("aggregations", {}).get(
                viz["data_key"], []
            )

            # Strategic data limiting:
            # - Send ALL for small, critical datasets (tactics, kill chains, trending)
            # - Limit to top N for large datasets (techniques)
            if viz["data_key"] in [
                "tactic_coverage",
                "kill_chain_coverage",
                "tactic_killchain_matrix",
                "trending_analysis",
            ]:
                # Send complete data - these are small and critical for gap analysis
                pass  # Keep chart_data as-is
            elif isinstance(chart_data, list) and len(chart_data) > 20:
                # Limit large datasets to top 20
                chart_data = chart_data[:20]
                logger.debug("Limited %s to top 20 items", viz["data_key"])

            # Format prompt
            prompt = format_prompt(
                insight_type="per_visualization",
                aggregated_data=json.dumps(
                    {
                        "metadata": aggregated_data.get("metadata", {}),
                        "summary_stats": {
                            "total_rules": aggregated_data.get("metadata", {}).get(
                                "total_rules", 0
                            ),
                            "total_techniques": aggregated_data.get("metadata", {}).get(
                                "total_techniques", 0
                            ),
                            "total_tactics": aggregated_data.get("metadata", {}).get(
                                "total_tactics", 0
                            ),
                        },
                    },
                    indent=2,
                ),
                chart_type=viz["type"],
                chart_title=viz["title"],
                chart_description=viz["description"],
                chart_data=json.dumps(chart_data, indent=2),
            )

            # Call LLM
            response = call_llm_api(prompt, llm_config, disable_ssl_verify)

            # Parse response
            insight = parse_json_response(response, f"viz_{viz['id']}")

            insights_by_viz[viz["id"]] = insight
            logger.info("✓ Generated insights for %s", viz["title"])

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to generate insights for %s: %s", viz["title"], e)
            # Provide empty structure on failure (new format)
            insights_by_viz[viz["id"]] = {
                "description": "Analysis unavailable",
                "insights": [],
            }

    return insights_by_viz


def _prepare_executive_summary_data(aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare data for executive summary generation.

    Args:
        aggregated_data: Aggregated detection data

    Returns:
        Strategic summary data for LLM prompt
    """
    aggregations = aggregated_data.get("aggregations", {})

    # Use pre-computed totals from data_processor
    tactic_totals = aggregations.get("tactic_totals", {})
    kill_chain_totals = aggregations.get("kill_chain_totals", {})

    summary_data = {
        "metadata": aggregated_data.get("metadata", {}),
        # Send ALL tactics (small, critical for gap analysis)
        "all_tactics": [
            {"tactic": tactic, "total_rules": count}
            for tactic, count in sorted(
                tactic_totals.items(), key=lambda x: x[1], reverse=True
            )
        ],
        # Send ALL kill chain stages (small, critical for gap analysis)
        "all_kill_chains": [
            {"stage": stage, "total_rules": count}
            for stage, count in sorted(
                kill_chain_totals.items(), key=lambda x: x[1], reverse=True
            )
        ],
        # Send ALL trending techniques (small-medium, critical for risk assessment)
        "all_trending": aggregations.get("trending_analysis", []),
        # Send top 20 techniques (large dataset, top N sufficient)
        "top_20_techniques": aggregations.get("technique_counts", [])[:20],
        # Send complete heatmap matrix (medium size, critical for intersection analysis)
        "tactic_killchain_matrix": aggregations.get("tactic_killchain_matrix", []),
    }

    logger.info(
        "Executive summary data prepared: %d tactics, %d kill chains, "
        "%d trending, top 20 techniques",
        len(summary_data["all_tactics"]),
        len(summary_data["all_kill_chains"]),
        len(summary_data["all_trending"]),
    )

    return summary_data


def generate_executive_summary(
    aggregated_data: Dict[str, Any],
    visualization_insights: Dict[str, Any],
    llm_config: Dict[str, Any],
    disable_ssl_verify: bool = False,
) -> Dict[str, Any]:
    """
    Generate executive summary synthesizing visualization insights.

    Args:
        aggregated_data: Aggregated detection data (only metadata used)
        visualization_insights: Already-generated per-viz insights
        llm_config: LLM configuration
        disable_ssl_verify: Disable SSL certificate verification (use with caution)

    Returns:
        Executive summary with critical_gaps and priority_actions
    """
    logger.info("Generating executive summary...")

    try:
        # Extract only minimal metadata for context
        metadata = aggregated_data.get("metadata", {})
        minimal_context = {
            "total_rules": metadata.get("total_rules", 0),
            "total_techniques": metadata.get("total_techniques", 0),
            "total_tactics": metadata.get("total_tactics", 0),
            "total_kill_chains": metadata.get("total_kill_chains", 0),
        }

        # Format prompt with MINIMAL metadata and visualization insights
        prompt = format_prompt(
            insight_type="executive_summary",
            aggregated_data=json.dumps(minimal_context, indent=2),
            visualization_insights=json.dumps(visualization_insights, indent=2),
        )

        # Call LLM
        response = call_llm_api(prompt, llm_config, disable_ssl_verify)

        # Parse response
        summary = parse_json_response(response, "executive_summary")

        # Log what we got (empty is OK if coverage is truly comprehensive)
        gap_count = len(summary.get("critical_gaps", []))
        action_count = len(summary.get("priority_actions", []))

        if gap_count == 0 and action_count == 0:
            logger.info(
                "✓ Executive summary: No critical gaps or priority actions "
                "(coverage may be comprehensive)"
            )
        else:
            logger.info(
                "✓ Generated executive summary: %d gaps, %d actions",
                gap_count,
                action_count,
            )

        return summary

    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Failed to generate executive summary: %s", e, exc_info=True)
        logger.error("This might be due to:")
        logger.error("  - Invalid API response format")
        logger.error("  - Network issues")
        logger.error("  - Prompt too complex for LLM to handle")
        # Provide empty structure on failure
        return {"critical_gaps": [], "priority_actions": []}


def generate_empty_insights(enabled_types: List[str]) -> Dict[str, Any]:
    """
    Generate empty insights structure.

    This is the fallback when LLM integration is not available or fails.

    Args:
        enabled_types: List of insight types to generate

    Returns:
        Empty insights structure
    """
    insights = {}

    if "executive_summary" in enabled_types:
        insights["executive_summary"] = {
            "summary_paragraph": "",
            "critical_gaps": [],
            "priority_actions": [],
        }

    if "visualization_insights" in enabled_types:
        insights["visualization_insights"] = {}

    if "coverage_gaps" in enabled_types:
        insights["coverage_gaps"] = {
            "summary": "Coverage gap analysis not yet implemented",
            "details": [],
        }

    if "recommendations" in enabled_types:
        insights["recommendations"] = []  # type: ignore[assignment]

    if "trends_analysis" in enabled_types:
        insights["trends_analysis"] = {  # type: ignore[assignment]
            "summary": "Trends analysis not yet implemented",
            "alignment_score": None,  # type: ignore[dict-item]
            "well_covered": [],
            "under_covered": [],
            "over_represented": [],
        }

    if "anomalies" in enabled_types:
        insights["anomalies"] = {  # type: ignore[assignment]
            "summary": "Anomaly detection not yet implemented",
            "anomalies": [],
            "statistics": {},  # type: ignore[dict-item]
        }

    return insights


def _generate_legacy_insights(enabled_types: List[str]) -> Dict[str, Any]:
    """
    Generate legacy insight types for backward compatibility.

    Args:
        enabled_types: List of enabled insight types

    Returns:
        Dictionary with legacy insight structures
    """
    insights = {}

    if "coverage_gaps" in enabled_types:
        logger.info("Generating coverage gaps (legacy)...")
        insights["coverage_gaps"] = {
            "summary": "Use executive_summary for gap analysis",
            "details": [],
        }

    if "recommendations" in enabled_types:
        logger.info("Generating recommendations (legacy)...")
        insights["recommendations"] = []  # type: ignore[assignment]

    if "trends_analysis" in enabled_types:
        logger.info("Generating trends analysis (legacy)...")
        insights["trends_analysis"] = {
            "summary": "Use visualization_insights for trend analysis",
            "alignment_score": None,  # type: ignore[dict-item]
            "well_covered": [],
            "under_covered": [],
            "over_represented": [],
        }

    if "anomalies" in enabled_types:
        logger.info("Generating anomalies (legacy)...")
        insights["anomalies"] = {
            "summary": "Use visualization_insights for anomaly detection",
            "anomalies": [],
            "statistics": {},  # type: ignore[dict-item]
        }

    return insights


def generate_insights_with_llm(  # pylint: disable=unused-argument
    aggregated_data: Dict[str, Any],
    enabled_types: List[str],
    llm_config: Dict[str, Any],
    coverage_gap_threshold: int,
    disable_ssl_verify: bool = False,
) -> Dict[str, Any]:
    """
    Generate insights using LLM.

    Execution order (Option 2):
    1. Generate visualization insights first
    2. Generate executive summary using viz insights as context
    3. Generate other insight types independently

    Args:
        aggregated_data: Aggregated detection data
        enabled_types: List of insight types to generate
        llm_config: LLM configuration (model, temperature, etc.)
        coverage_gap_threshold: Threshold for coverage gap detection
        disable_ssl_verify: Disable SSL certificate verification (use with caution)

    Returns:
        Generated insights dictionary
    """
    logger.info("=" * 60)
    logger.info("GENERATING INSIGHTS WITH LLM")
    logger.info("=" * 60)
    logger.info("Enabled insight types: %s", ", ".join(enabled_types))
    logger.info(
        "LLM config: model=%s, temp=%s",
        llm_config.get("model"),
        llm_config.get("temperature"),
    )
    logger.info("=" * 60)

    insights = {}

    # Check for OpenAI API key
    if not os.environ.get("OPENAI_API_KEY"):
        logger.warning(
            "OPENAI_API_KEY not set. Returning empty insights structure. "
            "Set the API key to enable LLM-powered insights."
        )
        return generate_empty_insights(enabled_types)

    try:
        # STEP 1: Generate per-visualization insights FIRST
        if "visualization_insights" in enabled_types:
            logger.info("\n[1/2] Generating visualization insights...")
            insights["visualization_insights"] = generate_visualization_insights(
                aggregated_data=aggregated_data,
                llm_config=llm_config,
                disable_ssl_verify=disable_ssl_verify,
            )
            logger.info("✓ Visualization insights complete\n")

        # STEP 2: Generate executive summary WITH viz insights as context
        if "executive_summary" in enabled_types:
            logger.info("[2/2] Generating executive summary...")
            insights["executive_summary"] = generate_executive_summary(
                aggregated_data=aggregated_data,
                visualization_insights=insights.get("visualization_insights", {}),
                llm_config=llm_config,
                disable_ssl_verify=disable_ssl_verify,
            )
            logger.info("✓ Executive summary complete\n")

        # Keep existing insight types (for backward compatibility)
        legacy_insights = _generate_legacy_insights(enabled_types)
        insights.update(legacy_insights)

        logger.info("=" * 60)
        logger.info("INSIGHTS GENERATION COMPLETE")
        logger.info("=" * 60)

        return insights

    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("LLM insight generation failed: %s", e, exc_info=True)
        logger.warning("Falling back to empty insights structure")
        return generate_empty_insights(enabled_types)


def save_insights(insights: Dict[str, Any], output_file: Path) -> None:
    """
    Save insights to JSON file.

    Args:
        insights: Insights dictionary
        output_file: Path to output file
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(insights, f, indent=2)

    logger.info("Insights saved to: %s", output_file)


def _build_insights_output(
    insights_data: Dict[str, Any],
    enabled_types: List[str],
    llm_config: Dict[str, Any],
    coverage_gap_threshold: int,
) -> Dict[str, Any]:
    """
    Build the insights output structure with metadata.

    Args:
        insights_data: Generated insights
        enabled_types: List of enabled insight types
        llm_config: LLM configuration
        coverage_gap_threshold: Threshold for coverage gap detection

    Returns:
        Output structure with insights and metadata
    """
    has_api_key = bool(os.environ.get("OPENAI_API_KEY"))
    has_real_insights = (
        "visualization_insights" in insights_data
        or "executive_summary" in insights_data
    )

    if has_api_key and has_real_insights:
        impl_status = "llm_enabled"
    elif has_api_key:
        impl_status = "llm_enabled_no_insights_requested"
    else:
        impl_status = "empty_structure_no_api_key"

    return {
        "insights": insights_data,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "llm_config": llm_config,
        "metadata": {
            "enabled_types": enabled_types,
            "coverage_gap_threshold": coverage_gap_threshold,
            "implementation_status": impl_status,
            "has_openai_key": has_api_key,
        },
    }


def _log_insights_summary(insights_data: Dict[str, Any], has_openai_key: bool) -> None:
    """
    Log summary of generated insights.

    Args:
        insights_data: Generated insights
        has_openai_key: Whether OpenAI API key is configured
    """
    logger.info("=" * 60)
    logger.info("INSIGHTS GENERATION COMPLETE")
    logger.info("=" * 60)

    if has_openai_key:
        logger.info("Status: LLM-powered insights generated")
        if "executive_summary" in insights_data:
            exec_sum = insights_data["executive_summary"]
            logger.info("  - Executive Summary:")
            logger.info(
                "      Critical Gaps: %d", len(exec_sum.get("critical_gaps", []))
            )
            logger.info(
                "      Priority Actions: %d", len(exec_sum.get("priority_actions", []))
            )
        if "visualization_insights" in insights_data:
            viz_count = len(insights_data["visualization_insights"])
            logger.info("  - Visualization Insights: %d charts analyzed", viz_count)
    else:
        logger.warning("Status: Empty insights (OPENAI_API_KEY not set)")
        logger.info("To enable LLM insights: export OPENAI_API_KEY=your-key")

    logger.info("=" * 60)


def run_insights_generator(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    input_file: str,
    output_file: str,
    enabled_types: List[str],
    llm_config: Dict[str, Any],
    coverage_gap_threshold: int = 5,
    disable_ssl_verify: bool = False,
) -> None:
    """
    Run the insights generator.

    Args:
        input_file: Path to aggregated data JSON
        output_file: Path to output insights JSON
        enabled_types: List of insight types to generate
        llm_config: LLM configuration
        coverage_gap_threshold: Threshold for coverage gap detection
        disable_ssl_verify: Disable SSL certificate verification (use with caution)
    """
    logger.info("=" * 60)
    logger.info("INSIGHTS GENERATOR")
    logger.info("=" * 60)
    logger.info("Input: %s", input_file)
    logger.info("Output: %s", output_file)
    logger.info("Enabled types: %s", ", ".join(enabled_types))
    logger.info("=" * 60)

    # Load aggregated data
    logger.info("Loading aggregated data...")
    input_path = Path(input_file)
    aggregated_data = load_aggregated_data(input_path)

    # Generate insights
    logger.info("Generating insights...")
    insights_data = generate_insights_with_llm(
        aggregated_data=aggregated_data,
        enabled_types=enabled_types,
        llm_config=llm_config,
        coverage_gap_threshold=coverage_gap_threshold,
        disable_ssl_verify=disable_ssl_verify,
    )

    # Build output structure
    output = _build_insights_output(
        insights_data, enabled_types, llm_config, coverage_gap_threshold
    )

    # Save insights
    output_path = Path(output_file)
    save_insights(output, output_path)

    # Log summary
    _log_insights_summary(insights_data, output["metadata"]["has_openai_key"])  # type: ignore[index]


def _parse_insights_args() -> argparse.Namespace:
    """Parse command-line arguments for insights generator."""
    parser = argparse.ArgumentParser(
        description="Generate LLM-powered insights from aggregated detection data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic usage with config file
    python -m aggregation.insights_generator --config aggregation/config_insights.json

    # Custom paths
    python -m aggregation.insights_generator \\
        --input-file output/aggregation/aggregated_data.json \\
        --output-file output/aggregation/insights.json

    # Generate specific insights only
    python -m aggregation.insights_generator \\
        --input-file output/aggregation/aggregated_data.json \\
        --insights coverage_gaps,recommendations

    # Disable SSL verification (for proxy environments)
    python -m aggregation.insights_generator \\
        --config aggregation/config_insights.json \\
        --disable-ssl-verify

Note: LLM integration not yet implemented. This currently generates empty insights
structure for testing the full pipeline.
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
        help="Path to aggregated data JSON file",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        help="Path to output insights JSON file",
    )
    parser.add_argument(
        "--insights",
        type=str,
        help=(
            "Comma-separated list of insight types "
            "(coverage_gaps,recommendations,trends_analysis,anomalies)"
        ),
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--disable-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (for proxy restrictions; use with caution)",
    )
    return parser.parse_args()


def _determine_output_file(
    args: argparse.Namespace, config_dict: Dict[str, Any], input_file: str
) -> str:
    """Determine the output file path from args and config."""
    if args.output_file:
        return args.output_file
    if "output" in config_dict:
        return config_dict["output"].get("insights", "output/aggregation/insights.json")
    # Default relative to input file
    if input_file:
        return str(Path(input_file).parent / "insights.json")
    return "output/aggregation/insights.json"


def _parse_enabled_types(
    args: argparse.Namespace, config_dict: Dict[str, Any]
) -> List[str]:
    """Parse enabled insight types from args and config."""
    if args.insights:
        return [t.strip() for t in args.insights.split(",")]
    return config_dict.get("insights", {}).get(
        "enabled_types",
        ["coverage_gaps", "recommendations", "trends_analysis", "anomalies"],
    )


def main() -> int:
    """Main function."""
    args = _parse_insights_args()

    # Set up logging
    setup_logging(debug=args.debug)

    # Load configuration
    try:
        config_dict = load_config_from_args(args.config)
    except FileNotFoundError:
        return 1

    # Determine parameters (CLI args override config)
    input_file = args.input_file or config_dict.get("input", {}).get("aggregated_data")
    output_file = _determine_output_file(args, config_dict, input_file)
    enabled_types = _parse_enabled_types(args, config_dict)

    # Get LLM config
    llm_config = config_dict.get(
        "llm",
        {
            "provider": "openai",
            "model": "gpt-4o",
            "temperature": 0.7,
            "max_tokens": 2000,
        },
    )

    # Get coverage gap threshold
    coverage_gap_threshold = config_dict.get("insights", {}).get(
        "coverage_gap_threshold", 5
    )

    # Validate required parameters
    if not input_file:
        logger.error("Error: --input-file is required")
        return 1

    # Check for OpenAI API key (for future LLM integration)
    if "OPENAI_API_KEY" not in os.environ:
        logger.warning(
            "OPENAI_API_KEY environment variable not set. "
            "This will be required when LLM integration is implemented."
        )

    # Run the generator
    try:
        run_insights_generator(
            input_file=input_file,
            output_file=output_file,
            enabled_types=enabled_types,
            llm_config=llm_config,
            coverage_gap_threshold=coverage_gap_threshold,
            disable_ssl_verify=args.disable_ssl_verify,
        )
        return 0
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Insights generation failed: %s", e, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
