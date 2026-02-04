# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-lines,redefined-outer-name,reimported,ungrouped-imports

"""
Detection Rules Viewer - Streamlit app to visualize detection rules and
their MITRE ATT&CK techniques.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse
from urllib.request import urlopen

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).parent.parent

try:
    from aggregation.enrichment import (  # noqa: E402
        canonical_tactic_order,
        enrich_kill_chain_data,
        enrich_tactic_data,
        enrich_technique_data,
    )
    from mitre_mapping.mitre_attack_mapper import get_mapper  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - runtime fallback
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from aggregation.enrichment import (  # noqa: E402
        canonical_tactic_order,
        enrich_kill_chain_data,
        enrich_tactic_data,
        enrich_technique_data,
    )
    from mitre_mapping.mitre_attack_mapper import get_mapper  # noqa: E402
# pylint: disable=wrong-import-position
from visualization.charts import (  # noqa: E402
    create_kill_chain_coverage_chart,
    create_sankey_chart,
    create_tactic_coverage_chart,
    create_top_techniques_chart,
)

st.set_page_config(layout="wide")

st.markdown(
    '<img src="https://fdtn.ai/_next/static/media/black-logo.99bfada1.svg" '
    'alt="Cisco Foundation AI logo" width="180" style="display:block; margin: 0;">',
    unsafe_allow_html=True,
)
st.title("LUCID: LLM-driven Understanding, Classification & Insight for Detections")
st.markdown(
    "LUCID from "
    "[Cisco Foundation AI](https://fdtn.ai/blog) enables you to classify security "
    "detection rules into relevant [MITRE ATT&CK](https://attack.mitre.org/) tactics, "
    "techniques, and sub-techniques, "
    "as well as corresponding Cyber Kill Chain stages. In this report, you can explore "
    "your detection categorizations, collect insights, and consider how to prioritize "
    "your detection strategy."
)


# Load JSON data
@st.cache_data
def load_detection_rules(classified_output_file: str) -> pd.DataFrame:
    """
    Load detection rules from a JSON file or URL.

    Args:
        classified_output_file: Path to local file or HTTP/HTTPS URL

    Returns:
        DataFrame containing the detection rules
    """
    # Check if the input is a URL
    parsed_url = urlparse(classified_output_file)
    is_url = parsed_url.scheme in ("http", "https")

    if is_url:
        # Load from URL
        with urlopen(classified_output_file) as response:
            data = json.loads(response.read().decode("utf-8"))
    else:
        # Load from local file
        classified_path = Path(classified_output_file)
        if not classified_path.is_absolute():
            classified_path = PROJECT_ROOT / classified_path
        if not classified_path.exists():
            raise FileNotFoundError(classified_path)
        with classified_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

    loaded_rules_df = pd.DataFrame(data)
    loaded_rules_df = loaded_rules_df.rename(
        columns={"id": "rule_id", "relevant_techniques": "technique_ids"}
    )

    return loaded_rules_df


@st.cache_data
def load_aggregated_data(aggregated_file: str) -> Dict[str, Any]:
    """
    Load pre-computed aggregated data from JSON file.

    Args:
        aggregated_file: Path to aggregated data JSON file

    Returns:
        Dictionary containing pre-computed aggregations and dataframes
    """
    aggregated_path = Path(aggregated_file)
    if not aggregated_path.is_absolute():
        aggregated_path = PROJECT_ROOT / aggregated_path
    if not aggregated_path.exists():
        raise FileNotFoundError(aggregated_path)

    with aggregated_path.open("r", encoding="utf-8") as f:
        return json.load(f)


@st.cache_data
def load_insights(insights_file: str) -> Dict[str, Any] | None:
    """
    Load insights data from JSON file.

    Args:
        insights_file: Path to insights JSON file

    Returns:
        Dictionary containing insights, or None if file doesn't exist
    """
    insights_path = Path(insights_file)
    if not insights_path.is_absolute():
        insights_path = PROJECT_ROOT / insights_path

    if not insights_path.exists():
        return None

    with insights_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def is_aggregated_data(data: Dict[str, Any] | list) -> bool:
    """
    Check if loaded data is aggregated format or classified format.

    Args:
        data: Loaded JSON data (dict for aggregated, list for classified)

    Returns:
        True if aggregated format, False if classified format
    """
    # Classified data is a list of rules
    if isinstance(data, list):
        return False

    # Aggregated data has 'metadata', 'aggregations', 'dataframes' keys
    return "metadata" in data and "aggregations" in data and "dataframes" in data


@st.cache_data
def load_trending_techniques() -> pd.DataFrame:
    """
    Load trending techniques from CSV file.

    Returns:
        DataFrame with columns: technique_id, mentions_in_incidents_percent
    """
    trending_file = Path(__file__).parent / "data" / "trending_techniques.csv"
    return pd.read_csv(trending_file)


def enrich_trending_techniques(
    trending_data_df: pd.DataFrame, techniques_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Enrich trending techniques with pretty names and rule counts.

    Args:
        trending_data_df: DataFrame with technique_id and mentions percentage
        techniques_df: DataFrame with rule-technique mappings

    Returns:
        DataFrame with columns:
        - technique_id: Raw technique ID (e.g., T1190)
        - technique_pretty: Pretty formatted (e.g.,
          [T1190] Exploit Public-Facing Application)
        - mentions_in_incidents_percent: Percentage value
        - rule_count: Number of rules matching this technique
    """
    # pylint: disable=duplicate-code  # Same logic as data_processor for consistency
    mapper = get_mapper()
    result_rows = []

    for _, row in trending_data_df.iterrows():
        technique_id = row["technique_id"]

        # Look up pretty name
        if "." in technique_id:
            sub_tech = mapper.get_sub_technique(technique_id)
            if sub_tech:
                technique_pretty = (
                    f"[{sub_tech.id}] {sub_tech.technique.name} > {sub_tech.name}"
                )
            else:
                technique_pretty = f"[{technique_id}] Unknown"
        else:
            tech = mapper.get_technique(technique_id)
            if tech:
                technique_pretty = f"[{tech.id}] {tech.name}"
            else:
                technique_pretty = f"[{technique_id}] Unknown"

        # Count matching rules
        rule_count = techniques_df[techniques_df["technique_id"] == technique_id][
            "rule_id"
        ].nunique()

        result_rows.append(
            {
                "technique_id": technique_id,
                "technique_pretty": technique_pretty,
                "mentions_in_incidents_percent": row["mentions_in_incidents_percent"],
                "rule_count": rule_count,
            }
        )

    return pd.DataFrame(result_rows)


def get_matching_rules(
    technique_id: str,
    techniques_df: pd.DataFrame,
    pretty_rules_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Get all rules matching a specific technique ID.

    Args:
        technique_id: Technique or sub-technique ID to filter by
        techniques_df: DataFrame with rule-technique mappings
        pretty_rules_df: DataFrame with aggregated rule data

    Returns:
        DataFrame with columns: rule_id, tactic, kill_chain
    """
    # Get rule_ids that match this technique
    matching_rule_ids = techniques_df[techniques_df["technique_id"] == technique_id][
        "rule_id"
    ].unique()

    # Filter rules_pretty_df to get full rule data
    matching_rules = pretty_rules_df[
        pretty_rules_df["rule_id"].isin(matching_rule_ids)
    ][["rule_id", "tactic", "kill_chain"]].copy()

    return matching_rules


def display_visualization_insights(
    viz_id: str, insights_data: Dict[str, Any] | None
) -> None:
    """
    Display insights for a specific visualization.

    Args:
        viz_id: Visualization ID (e.g., 'tactic_coverage')
        insights_data: Full insights data dictionary
    """
    if not insights_data:
        return

    viz_insights = insights_data.get("insights", {}).get("visualization_insights", {})
    if viz_id not in viz_insights:
        return

    insight = viz_insights[viz_id]

    # Only display if there's meaningful content
    description = insight.get("description", "")
    insights_list = insight.get("insights", [])

    # Support legacy format (interpretation/key_findings) for backward compatibility
    if not description and insight.get("interpretation"):
        description = insight.get("interpretation")
    if not insights_list and insight.get("key_findings"):
        insights_list = insight.get("key_findings", [])

    # Only show if there's something to display
    if not description and not insights_list:
        return

    # Show AI marker before insights
    st.info("🤖 **AI-Powered Insights**")

    with st.container():
        # Display description (1-2 sentences)
        if description:
            st.markdown(f"*{description}*")

        # Display actionable insights (0-3 bullets)
        if insights_list:
            for insight_item in insights_list:
                st.markdown(f"• {insight_item}")

    st.markdown("")  # Spacing


# Maximum rule count for gradient color scaling (values >= this get darkest green)
RULE_COUNT_COLOR_CAP = 15


def style_rule_count_column(
    df: pd.DataFrame, column: str
) -> "pd.io.formats.style.Styler":
    """
    Apply gradient green background to a numeric column.

    Args:
        df: DataFrame to style
        column: Column name to apply gradient to

    Returns:
        Styled DataFrame
    """
    max_val = df[column].max()

    def green_gradient(val: Any) -> str:
        if pd.isna(val) or val == 0:
            return "background-color: white"
        if max_val == 0:
            return "background-color: white"

        # For values >= 1, use a green gradient from lighter to darker
        # Normalize val from 1 to RULE_COUNT_COLOR_CAP into 0 to 1 range
        capped_val = min(val, RULE_COUNT_COLOR_CAP)
        intensity = (capped_val - 1) / (RULE_COUNT_COLOR_CAP - 1)

        # Start at lighter green (low values) and go to darker green (high values)
        # Lighter green: rgb(198, 228, 198) - light green
        # Darker green: rgb(76, 153, 76) - medium-dark green
        r = int(218 - 122 * intensity)  # 198 -> 76
        g = int(248 - 75 * intensity)  # 228 -> 153
        b = int(218 - 122 * intensity)  # 198 -> 76
        return f"background-color: rgb({r},{g},{b})"

    return df.style.map(green_gradient, subset=[column])


# Function to parse arguments
def parse_args(argv: List[str]) -> argparse.Namespace:
    """Parse arguments."""
    parser = argparse.ArgumentParser(description="Detection Rules Viewer")
    parser.add_argument(
        "--classified-output-file-path",
        default="output/aggregation/aggregated_data.json",
        help=(
            "Path to classified output file or URL "
            "(default: output/aggregation/aggregated_data.json)"
        ),
    )
    return parser.parse_args(argv)


# Only execute main app logic if not being imported for testing
if __name__ != "visualization.app":
    # Parse arguments (only when actually running the app, not during test imports)
    try:
        # Check if we're running under pytest (to avoid parsing pytest args)
        import sys

        is_pytest = "pytest" in sys.modules or any("pytest" in arg for arg in sys.argv)

        # When __name__ == "__main__" AND not in pytest, parse sys.argv
        # Otherwise use empty list (will use defaults or secrets)
        argv_to_parse = (
            sys.argv[1:] if (__name__ == "__main__" and not is_pytest) else []
        )

        args = parse_args(argv_to_parse)
    except SystemExit:
        # This exception is raised if --help or invalid arguments are used.
        # Streamlit prevents the program from exiting normally, so we handle it.
        st.error("Error parsing arguments. Check terminal for help message.")
        st.stop()  # Stop the app if arguments are invalid or help is requested
    # Load the data - supports both aggregated and classified formats
    # Use secrets if available, otherwise fall back to command line argument
    data_file_path = args.classified_output_file_path
    if "classified_output_file_path" in st.secrets:
        data_file_path = st.secrets["classified_output_file_path"]

    # Try to detect format and load appropriately
    # Track whether we're using demo data for display purposes
    using_demo_data = False
    try:
        # First, try to load as JSON to detect format
        data_path = Path(data_file_path)
        if not data_path.is_absolute():
            data_path = PROJECT_ROOT / data_path

        # Check if user data exists, otherwise fall back to demo data
        if not data_path.exists():
            demo_path = PROJECT_ROOT / "aggregation" / "demo" / "aggregated_data.json"
            if demo_path.exists():
                data_path = demo_path
                using_demo_data = True
            # If neither exists, let it fail naturally with FileNotFoundError

        logging.info("Loading data from %s", data_path)
        with data_path.open("r", encoding="utf-8") as f:
            raw_data = json.load(f)

        # Check if this is aggregated data or classified data
        if is_aggregated_data(raw_data):
            # Load pre-computed aggregated data
            aggregated_data = raw_data

            # Extract dataframes from aggregated data
            rule_techniques_df = pd.DataFrame(
                aggregated_data["dataframes"]["rule_techniques_raw"]
            )
            rule_tactics_df = pd.DataFrame(
                aggregated_data["dataframes"]["rule_tactics_raw"]
            )
            rule_kill_chains_df = pd.DataFrame(
                aggregated_data["dataframes"]["rule_kill_chains_raw"]
            )

            # Extract pretty dataframes
            rule_tactics_pretty_df = pd.DataFrame(
                aggregated_data["dataframes"]["rule_tactics"]
            )
            rule_techniques_pretty_df = pd.DataFrame(
                aggregated_data["dataframes"]["rule_techniques"]
            )
            rules_pretty_df = pd.DataFrame(
                aggregated_data["dataframes"]["rules_summary"]
            )

            # Create rules_df for backward compatibility
            rules_df = (
                rule_techniques_df.groupby("rule_id")
                .agg(
                    {
                        "technique_id": list,
                        "ts_or_st_pretty": list,
                    }
                )
                .reset_index()
                .rename(
                    columns={
                        "technique_id": "technique_ids",
                        "ts_or_st_pretty": "ts_or_sts_pretty",
                    }
                )
            )

            # Try to load insights if available
            # Use the same directory as the data file (user or demo)
            insights_file = data_path.parent / "insights.json"
            insights_data = load_insights(str(insights_file))

        else:
            # Process classified data in the traditional way (backward compatibility)
            st.info("Processing classified data...")
            input_rule_classfication_df = pd.DataFrame(raw_data)
            input_rule_classfication_df = input_rule_classfication_df.rename(
                columns={"id": "rule_id", "relevant_techniques": "technique_ids"}
            )
            input_rule_classfication_df = input_rule_classfication_df.sort_values(
                "rule_id"
            )

            # Step 1: Explode technique_ids to get one row per (rule_id, technique_id)
            rule_techniques_df = input_rule_classfication_df.explode(
                "technique_ids"
            ).rename(columns={"technique_ids": "technique_id"})
            # Enrich with technique-level data (ts_or_st_pretty, tactics list)
            rule_techniques_df = rule_techniques_df.apply(enrich_technique_data, axis=1)

            # Step 2: Explode tactics to get one row per
            # (rule_id, technique_id, tactic_id)
            rule_tactics_df = (
                rule_techniques_df.explode("tactics")
                .rename(columns={"tactics": "tactic"})
                .copy()
            )
            # Enrich with tactic-level data
            # (tactic_id, tactic_pretty, kill_chain_stages list)
            rule_tactics_df = rule_tactics_df.apply(enrich_tactic_data, axis=1)

            # Step 3: Explode kill_chain_stages to get one row per
            # (rule_id, technique_id, tactic_id, kill_chain_id)
            rule_kill_chains_df = (
                rule_tactics_df.explode("kill_chain_stages")
                .rename(columns={"kill_chain_stages": "kill_chain_stage"})
                .copy()
            )
            # Enrich with kill_chain-level data (kill_chain_id, kill_chain_pretty)
            rule_kill_chains_df = rule_kill_chains_df.apply(
                enrich_kill_chain_data, axis=1
            )

            # Clean up NaN values from the enriched dataframes
            rule_kill_chains_df = rule_kill_chains_df.dropna(
                subset=["kill_chain_pretty"]
            )
            rule_tactics_df = rule_tactics_df.dropna(subset=["tactic_pretty"])
            rule_techniques_df = rule_techniques_df.dropna(subset=["ts_or_st_pretty"])

            # Create pretty-formatted versions of the dataframes
            # pylint: disable=duplicate-code  # Same logic as data_processor for consistency
            rule_tactics_pretty_df = (
                rule_kill_chains_df.groupby(["rule_id", "technique_id", "tactic_id"])
                .agg(
                    {
                        "ts_or_st_pretty": "first",
                        "tactic_pretty": "first",
                        "kill_chain_pretty": lambda x: tuple(sorted(set(x))),
                    }
                )
                .reset_index()
                .rename(
                    columns={
                        "ts_or_st_pretty": "technique",
                        "tactic_pretty": "tactic",
                        "kill_chain_pretty": "kill_chain",
                    }
                )
            )

            rule_techniques_pretty_df = (
                rule_tactics_pretty_df.groupby(["rule_id", "technique_id"])
                .agg(
                    {
                        "technique": "first",
                        "tactic": lambda x: tuple(sorted(set(x))),
                        "kill_chain": lambda x: tuple(
                            sorted(set(item for tup in x for item in tup))
                        ),
                    }
                )
                .reset_index()
            )

            rules_pretty_df = (
                rule_techniques_pretty_df.groupby("rule_id")
                .agg(
                    {
                        "technique": lambda x: tuple(sorted(set(x))),
                        "tactic": lambda x: tuple(
                            sorted(set(item for tup in x for item in tup))
                        ),
                        "kill_chain": lambda x: tuple(
                            sorted(set(item for tup in x for item in tup))
                        ),
                    }
                )
                .reset_index()
            )

            # For backwards compatibility, create rules_df
            rules_df = (
                rule_techniques_df.groupby("rule_id")
                .agg(
                    {
                        "technique_id": list,
                        "ts_or_st_pretty": list,
                    }
                )
                .reset_index()
                .rename(
                    columns={
                        "technique_id": "technique_ids",
                        "ts_or_st_pretty": "ts_or_sts_pretty",
                    }
                )
            )

            # No insights for classified data
            insights_data = None  # pylint: disable=invalid-name

    except FileNotFoundError as e:
        st.error(
            "Data file not found. Set "
            "`--classified-output-file-path` or Streamlit secret "
            "`classified_output_file_path` to a valid file."
            f"Error: {e}"
        )
        st.stop()
    except Exception as e:  # pylint: disable=broad-exception-caught
        st.error(f"Error loading data: {e}")
        st.stop()

    # Display demo data notice if using demo data
    if using_demo_data:
        st.info(
            "ℹ️ **Viewing Demo Data** - You're currently viewing sample detection rules. "
            "To analyze your own rules, run the aggregation pipeline: "
            "`python -m aggregation.pipeline --config aggregation/config_aggregation.json`. "
            "See the [README](https://github.com/cisco-foundation-ai/detection-rule-classifier/blob/main/README.md) for details."
        )

    # AI-Generated Content Start Marker
    if insights_data and "executive_summary" in insights_data.get("insights", {}):
        st.info("🤖 **AI-Powered Insights**")

    # Display Executive Summary if available (most prominent placement)
    if insights_data and "executive_summary" in insights_data.get("insights", {}):
        exec_summary = insights_data["insights"]["executive_summary"]

        st.markdown("# 📊 Executive Summary")

        # Display summary paragraph from LLM (2-3 sentences max)
        summary_text = exec_summary.get("summary_paragraph", "")
        if summary_text:
            st.markdown(summary_text)
        else:
            st.markdown("*Analysis of your detection coverage and recommendations*")

        st.markdown("")  # Spacing

    # === PRIORITY ACTIONS SECTION ===
    # Display immediately after Executive Summary for strategic visibility
    if insights_data and "executive_summary" in insights_data.get("insights", {}):
        exec_summary = insights_data["insights"]["executive_summary"]

        # Check if we have any actions
        has_actions = (
            exec_summary.get("priority_actions")
            and len(exec_summary["priority_actions"]) > 0
        )

        # Section description (flows directly from executive summary)
        st.markdown("")
        st.markdown(
            "*Recommended actions based on comprehensive analysis of all detection panels, sorted by priority*"
        )
        st.markdown("")

        # Priority Actions Section
        if has_actions:
            # Get all actions (no limit)
            all_actions = exec_summary["priority_actions"]

            # Define priority order for sorting
            priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

            # Sort actions by priority
            sorted_actions = sorted(
                all_actions,
                key=lambda x: priority_order.get(
                    x.get("priority", "medium").lower(), 2
                ),
            )

            # Create DataFrame with new column structure
            actions_data = []
            for action in sorted_actions:
                priority = action.get("priority", "medium").lower()
                priority_display = (
                    priority.upper()
                )  # Just show CRITICAL, HIGH, MEDIUM, LOW

                effort = action.get("estimated_effort", "medium").lower()
                effort_display = effort.title()  # Just show Low, Medium, High

                actions_data.append(
                    {
                        "Priority": priority_display,
                        "Action": action.get("action", "N/A"),
                        "Rationale": action.get("rationale", "N/A"),
                        "Effort": effort_display,
                        "Expected Impact": action.get("expected_impact", "N/A"),
                    }
                )

            # Create Plotly table with proper formatting
            import plotly.graph_objects as go

            # Prepare data for Plotly table (with bold formatting)
            priorities = [f"<b>{action['Priority']}</b>" for action in actions_data]
            actions = [f"<b>{action['Action']}</b>" for action in actions_data]
            rationales = [f"<b>{action['Rationale']}</b>" for action in actions_data]
            efforts = [f"<b>{action['Effort']}</b>" for action in actions_data]
            impacts = [f"<b>{action['Expected Impact']}</b>" for action in actions_data]

            # Define colors for each priority level
            # (0.9 opacity for white text readability in both modes)
            fill_colors = []
            for action in actions_data:
                priority = action["Priority"]
                if priority == "CRITICAL":
                    fill_colors.append("rgba(220, 38, 38, 0.9)")
                elif priority == "HIGH":
                    fill_colors.append("rgba(234, 88, 12, 0.9)")
                elif priority == "MEDIUM":
                    fill_colors.append("rgba(234, 179, 8, 0.9)")
                elif priority == "LOW":
                    fill_colors.append("rgba(34, 197, 94, 0.9)")
                else:
                    fill_colors.append("rgba(128, 128, 128, 0.9)")

            fig = go.Figure(
                data=[
                    go.Table(
                        columnwidth=[
                            80,
                            250,
                            280,
                            70,
                            180,
                        ],  # Fixed widths for Priority and Effort
                        header={
                            "values": [
                                "<b>Priority</b>",
                                "<b>Action</b>",
                                "<b>Rationale</b>",
                                "<b>Effort</b>",
                                "<b>Expected Impact</b>",
                            ],
                            # Distinct medium gray header
                            "fill_color": "rgba(100, 100, 100, 1.0)",
                            "align": ["left", "left", "left", "center", "left"],
                            "font": {
                                "size": 14,
                                "color": "white",
                            },  # White text for better contrast on gray header
                            "height": 40,
                        },
                        cells={
                            "values": [
                                priorities,
                                actions,
                                rationales,
                                efforts,
                                impacts,
                            ],
                            "fill_color": [fill_colors],
                            "align": ["left", "left", "left", "center", "left"],
                            "font": {
                                "size": 13,
                                "color": "#333333",
                            },  # Light gray for both modes
                            "height": 35,
                        },
                    )
                ]
            )

            fig.update_layout(
                margin={"l": 0, "r": 0, "t": 0, "b": 0},
                paper_bgcolor="rgba(0,0,0,0)",
                height=max(
                    300, len(actions_data) * 60 + 50
                ),  # Dynamic height based on rows
            )

            st.plotly_chart(fig, use_container_width=True)

            # AI-Generated Content End Marker
            st.markdown("---")
        else:
            st.info(
                "✅ Current detection coverage is comprehensive. "
                "Continue monitoring emerging threats and consider optimizing existing rules for performance."
            )

            # AI-Generated Content End Marker
            st.markdown("---")

    # Display other insights if available (legacy insights from previous implementation)
    if insights_data:
        insights = insights_data.get("insights", {})

        # Coverage Gaps Section
        if "coverage_gaps" in insights and insights["coverage_gaps"].get("details"):
            with st.expander("⚠️ Coverage Gaps", expanded=True):
                gaps = insights["coverage_gaps"]
                st.markdown(f"**Summary:** {gaps.get('summary', 'N/A')}")

                if gaps.get("details"):
                    st.markdown("**Gap Details:**")
                    for gap in gaps["details"][:5]:  # Show top 5
                        severity_emoji = {
                            "high": "🔴",
                            "medium": "🟡",
                            "low": "🟢",
                        }.get(gap.get("severity", "medium"), "⚪")

                        st.markdown(
                            f"{severity_emoji} **{gap.get('name', 'Unknown')}** "
                            f"({gap.get('type', 'unknown').replace('_', ' ').title()})"
                        )
                        st.markdown(f"- Rules: {gap.get('rule_count', 0)}")
                        st.markdown(
                            f"- Recommendation: {gap.get('recommendation', 'N/A')}"
                        )
                        st.markdown("---")

        # Recommendations Section
        if "recommendations" in insights and insights["recommendations"]:
            with st.expander("💡 Recommendations", expanded=False):
                recs = insights["recommendations"]
                if recs:
                    st.markdown("**Top Priority Techniques to Implement:**")
                    for i, rec in enumerate(recs[:10], 1):  # Show top 10
                        priority_emoji = {
                            "high": "🔴",
                            "medium": "🟡",
                            "low": "🟢",
                        }.get(rec.get("priority", "medium"), "⚪")

                        st.markdown(
                            f"{i}. {priority_emoji} **{rec.get('technique_name', 'Unknown')}** "
                            f"({rec.get('technique_id', 'N/A')})"
                        )
                        st.markdown(f"   - Tactic: {rec.get('tactic', 'N/A')}")
                        st.markdown(
                            f"   - Current Coverage: {rec.get('current_coverage', 0)} rules"
                        )
                        st.markdown(f"   - Rationale: {rec.get('rationale', 'N/A')}")
                else:
                    st.info("No recommendations available.")

        # Anomalies Section
        if "anomalies" in insights and insights["anomalies"].get("anomalies"):
            with st.expander("🔎 Anomalies Detected", expanded=False):
                anomalies_data = insights["anomalies"]
                st.markdown(f"**Summary:** {anomalies_data.get('summary', 'N/A')}")

                if anomalies_data.get("anomalies"):
                    st.markdown("**Detected Anomalies:**")
                    for anomaly in anomalies_data["anomalies"][:5]:  # Show top 5
                        severity_emoji = {
                            "high": "🔴",
                            "medium": "🟡",
                            "low": "🟢",
                        }.get(anomaly.get("severity", "medium"), "⚪")

                        st.markdown(
                            f"{severity_emoji} **{anomaly.get('type', 'unknown').replace('_', ' ').title()}**"
                        )
                        st.markdown(f"   - {anomaly.get('description', 'N/A')}")
                        st.markdown(f"   - Impact: {anomaly.get('impact', 'N/A')}")
                        st.markdown(
                            f"   - Action: {anomaly.get('recommendation', 'N/A')}"
                        )
                        st.markdown("---")

                # Show statistics if available
                if anomalies_data.get("statistics"):
                    stats = anomalies_data["statistics"]
                    st.markdown("**Statistics:**")
                    cols = st.columns(3)
                    if "avg_techniques_per_rule" in stats:
                        cols[0].metric(
                            "Avg Techniques/Rule",
                            f"{stats['avg_techniques_per_rule']:.1f}",
                        )
                    if "rules_with_zero_techniques" in stats:
                        cols[1].metric(
                            "Rules w/ Zero Techniques",
                            stats["rules_with_zero_techniques"],
                        )
                    if "rules_with_many_techniques" in stats:
                        cols[2].metric(
                            "Rules w/ Many Techniques",
                            stats["rules_with_many_techniques"],
                        )

    # Create Tactic Coverage chart - Horizontal Stacked by Technique
    st.subheader("Tactic Coverage")
    st.markdown(
        "The Tactic Coverage chart shows how many detection rules map to each MITRE ATT&CK tactic, "
        "representing adversary goals at specific stages of their attack lifecycle. Colored segments "
        "highlight the top 20 techniques by rule count, which helps identify well-covered areas and gaps. "
        "Hovering reveals details about the specific techniques and the number of rules mapped to them."
    )

    # Prepare data for tactic coverage chart
    tactic_technique_df = rule_tactics_df.copy()
    tactic_technique_counts = (
        tactic_technique_df.groupby(["tactic_pretty", "ts_or_st_pretty"])
        .size()
        .reset_index(name="rule_mappings")
    )
    tactic_technique_counts["tactic_name"] = tactic_technique_counts[
        "tactic_pretty"
    ].str.replace(r"^\[.*?\]\s*", "", regex=True)

    # Use all 14 MITRE ATT&CK tactics in canonical order (even those with 0 rules)
    tactic_order = canonical_tactic_order

    # Calculate top 20 most common techniques across all tactics for color coding
    top_20_techniques = (
        rule_tactics_df.groupby("ts_or_st_pretty")
        .size()
        .sort_values(ascending=False)
        .head(20)
        .index.tolist()
    )
    technique_counts_all = (
        rule_techniques_df.groupby("ts_or_st_pretty")["rule_id"]
        .nunique()
        .sort_values(ascending=False)
    )
    technique_order_all = technique_counts_all.index.tolist()

    # Create and display tactic coverage chart
    tactic_chart = create_tactic_coverage_chart(
        rule_tactics_df, top_20_techniques, tactic_order
    )
    st.altair_chart(tactic_chart, width="stretch")

    # Display insights for this visualization
    display_visualization_insights("tactic_coverage", insights_data)

    # Create Kill Chain Coverage chart - Horizontal Stacked by Technique
    st.subheader("Kill Chain Coverage")
    st.markdown(
        "The Kill Chain Coverage chart displays the number of detection rules mapped to each phase of the "
        "Lockheed Martin Cyber Kill Chain, illustrating adversary actions at distinct stages of their attack "
        "process. Colored segments highlight the top techniques within each phase, while hovering reveals "
        "specific techniques and their detection counts. This visualization helps identify strengths and gaps "
        "in detection coverage across the attack lifecycle."
    )

    # Prepare data for kill chain coverage chart
    kill_chain_technique_df = rule_kill_chains_df.copy()

    # Use all 7 Cyber Kill Chain phases in order (even those with 0 rules)
    all_kill_chain_phases = [
        "[1] Reconnaissance",
        "[2] Weaponization",
        "[3] Delivery",
        "[4] Exploitation",
        "[5] Installation",
        "[6] Command and Control",
        "[7] Actions on Objectives",
    ]
    kill_chain_order = all_kill_chain_phases

    # Create and display kill chain coverage chart (using same top
    # techniques as tactic chart)
    kill_chain_chart = create_kill_chain_coverage_chart(
        rule_kill_chains_df, top_20_techniques, kill_chain_order
    )
    st.altair_chart(kill_chain_chart, width="stretch")

    # Display insights for this visualization
    display_visualization_insights("kill_chain_coverage", insights_data)

    # Create bar chart of top techniques
    st.subheader("Top Techniques by Rule Count")
    st.markdown(
        "[Techniques](https://attack.mitre.org/techniques/enterprise/) are specific methods "
        "adversaries use to accomplish their objectives at each stage of an attack."
    )
    st.markdown(
        "This ranking highlights the most frequently mapped techniques across "
        "your rules, helping you understand where you have high detection "
        "concentration."
    )
    st.caption(
        "💡 The top 20 most common techniques/subtechniques are color-coded with unique colors "
        "that remain consistent across all three visualizations (Tactic Coverage, Kill Chain Coverage, "
        "and Top Techniques). Other techniques appear in grayscale. Each bar represents a parent "
        "technique with its subtechniques stacked horizontally—hover over segments to see details."
    )

    # Prepare data for top 20 techniques chart with stacked subtechniques
    # Extract parent technique ID from technique_id (e.g., T1078 from T1078.001)
    techniques_with_parent = rule_techniques_df.copy()
    techniques_with_parent["parent_technique_id"] = techniques_with_parent[
        "technique_id"
    ].str.extract(r"^(T\d+)", expand=False)

    # Get parent technique names - need to look them up or construct properly
    # For subtechniques like "[T1078.002] Valid Accounts > Domain Accounts",
    # we need "[T1078] Valid Accounts"
    def get_parent_technique_name(row):  # pylint: disable=missing-function-docstring
        parent_id = row["parent_technique_id"]
        technique_id = row["technique_id"]
        pretty_name = row["ts_or_st_pretty"]

        # If this IS the parent technique (no dot in ID), use as-is
        if "." not in technique_id:
            return pretty_name

        # For subtechniques, get the part before " > " and replace the ID
        base_name = pretty_name.split(" > ")[0]
        # Replace [T####.###] with [T####]
        parent_name = base_name.replace(f"[{technique_id}]", f"[{parent_id}]")
        return parent_name

    techniques_with_parent["parent_technique_name"] = techniques_with_parent.apply(
        get_parent_technique_name, axis=1
    )

    # Count rules for each technique/subtechnique
    technique_counts_detailed = (
        techniques_with_parent.groupby(
            [
                "parent_technique_id",
                "parent_technique_name",
                "technique_id",
                "ts_or_st_pretty",
            ]
        )["rule_id"]
        .nunique()
        .reset_index(name="rule_count")
    )

    # Calculate total rules per parent technique
    parent_totals = (
        technique_counts_detailed.groupby("parent_technique_id")["rule_count"]
        .sum()
        .reset_index(name="total_count")
    )

    # Get top 20 parent techniques by total rule count
    top_20_parents = (
        parent_totals.sort_values("total_count", ascending=False)
        .head(20)["parent_technique_id"]
        .tolist()
    )

    # Filter to only include subtechniques from top 20 parents
    top_20_data = technique_counts_detailed[
        technique_counts_detailed["parent_technique_id"].isin(top_20_parents)
    ].copy()

    # Create and display top techniques chart
    # (with same colors as tactic/kill chain charts)
    chart = create_top_techniques_chart(top_20_data, top_20_techniques)
    st.altair_chart(chart, width="stretch")

    # Display insights for this visualization
    display_visualization_insights("top_techniques", insights_data)

    # === SANKEY FLOW SECTION ===
    st.subheader("Detection Flow Explorer")
    st.markdown(
        "This [Sankey diagram](https://en.wikipedia.org/wiki/Sankey_diagram) visualizes how detection rules relate to the MITRE ATT&CK framework's Tactics "
        "and Techniques, and Cyber Kill Chain phases. You can choose different orders for the mappings to "
        "explore relationships and better understand detection coverage from various perspectives. The diagram "
        "highlights the flow and volume of rules connecting these elements, helping identify strengths and gaps "
        "in your cybersecurity defenses."
    )
    sankey_options = {
        "Tactic → Technique → Kill Chain": [
            "tactic_pretty",
            "ts_or_st_pretty",
            "kill_chain_pretty",
        ],
        "Tactic → Kill Chain → Technique": [
            "tactic_pretty",
            "kill_chain_pretty",
            "ts_or_st_pretty",
        ],
        "Kill Chain → Technique → Tactic": [
            "kill_chain_pretty",
            "ts_or_st_pretty",
            "tactic_pretty",
        ],
        "Technique → Tactic → Kill Chain": [
            "ts_or_st_pretty",
            "tactic_pretty",
            "kill_chain_pretty",
        ],
    }
    selected_flow = st.selectbox(
        "Sankey ordering",
        list(sankey_options.keys()),
        index=0,
        key="sankey_flow_order",
    )
    sankey_order = sankey_options[selected_flow]
    show_labels = st.checkbox(
        "Show node labels",
        value=True,  # Default ON to display node labels
        key="sankey_show_labels",
        help="Check to show node labels. Uncheck for a cleaner view. Hover over nodes to see details.",
    )
    sankey_top_n = st.slider(
        "Techniques to include",
        min_value=1,
        max_value=max(1, len(technique_order_all)),
        value=20,
        step=1,
        key="sankey_top_n",
    )
    sankey_techniques = technique_order_all[:sankey_top_n]
    sankey_df = rule_kill_chains_df[
        rule_kill_chains_df["ts_or_st_pretty"].isin(sankey_techniques)
    ].copy()
    sankey_kill_chain_counts = (
        sankey_df.groupby("kill_chain_pretty")["ts_or_st_pretty"].nunique().to_dict()
    )
    sankey_tactic_counts = (
        sankey_df.groupby("tactic_pretty")["ts_or_st_pretty"].nunique().to_dict()
    )
    sankey_figure = create_sankey_chart(
        sankey_df,
        sankey_order,
        node_counts={
            "ts_or_st_pretty": technique_counts_all.to_dict(),
            "kill_chain_pretty": sankey_kill_chain_counts,
            "tactic_pretty": sankey_tactic_counts,
        },
        show_labels=show_labels,
    )
    st.plotly_chart(sankey_figure, width="stretch")

    # === TRENDING ATTACKS COVERAGE SECTION ===
    st.subheader("Trending Attacks Coverage")
    st.markdown(
        "The table shows the most observed MITRE ATT&CK techniques 'in the wild' based on frequency data "
        "compiled annually by the SURGe security research team from publicly available reporting. You can read "
        "more details about this work in the "
        "[SURGe Macro-ATT&CK research blog]"
        "(https://www.splunk.com/en_us/blog/security/macro-att-ck-2024-a-five-year-perspective.html)."
    )

    # Initialize session state for selected technique
    if "selected_trending_technique" not in st.session_state:
        st.session_state.selected_trending_technique = None

    # Load and enrich trending techniques
    trending_df = load_trending_techniques()
    trending_enriched_df = enrich_trending_techniques(trending_df, rule_techniques_df)

    # Trending Techniques table (full width)
    st.markdown("**Trending Techniques**")

    # Prepare display dataframe
    display_df = trending_enriched_df[
        ["technique_pretty", "mentions_in_incidents_percent", "rule_count"]
    ].copy()
    display_df["mentions_in_incidents_percent"] = (
        display_df["mentions_in_incidents_percent"].round().astype(int)
    )
    display_df.columns = ["Technique", "Frequency in Incidents (%)", "# Rules"]

    # Apply gradient styling to # Rules column
    styled_df = style_rule_count_column(display_df, "# Rules")

    # Display with row selection
    selection = st.dataframe(
        styled_df,
        on_select="rerun",
        selection_mode="single-row",
        width="stretch",
        hide_index=True,
        key="trending_table",
    )

    # Update session state based on selection
    if selection.selection.rows:  # type: ignore[attr-defined]
        selected_idx = selection.selection.rows[0]  # type: ignore[attr-defined]
        st.session_state.selected_trending_technique = trending_enriched_df.iloc[
            selected_idx
        ]["technique_id"]
    else:
        st.session_state.selected_trending_technique = None

    # Matching Detection Rules (indented below, shown when a technique is selected)
    if st.session_state.selected_trending_technique:
        # Get the selected technique name for display
        selected_technique_name = trending_enriched_df[
            trending_enriched_df["technique_id"]
            == st.session_state.selected_trending_technique
        ]["technique_pretty"].iloc[0]

        # Indented container using columns for visual nesting
        _, indented_col = st.columns([0.05, 0.95])
        with indented_col:
            st.markdown(f"**↳ Matching Detection Rules for {selected_technique_name}**")

            # Get and display matching rules
            matching_rules_df = get_matching_rules(
                st.session_state.selected_trending_technique,
                rule_techniques_df,
                rules_pretty_df,
            )

            if len(matching_rules_df) > 0:
                st.dataframe(matching_rules_df, width="stretch", hide_index=True)
            else:
                st.warning(
                    "No detection rules currently cover this trending technique. "
                    "This represents a gap in your detection coverage for a commonly "
                    "observed attack technique - consider prioritizing rule development "
                    "for this area."
                )

    # Display insights for trending coverage visualization
    display_visualization_insights("trending_coverage", insights_data)

    # === DETECTION RULES REFERENCE TABLE ===
    st.subheader("Detection Rules Reference")
    st.markdown(
        "This table provides a complete reference of all detection rules analyzed in "
        "this report, showing the techniques, tactics, and kill chain phases mapped to "
        "each rule. Use this to drill down into specific rules and their coverage."
    )

    # Convert tuple columns to strings for display to avoid TypeError with data grid
    rules_display_df = rules_pretty_df.copy()
    for col in rules_display_df.columns:
        if rules_display_df[col].apply(lambda x: isinstance(x, (tuple, list))).any():
            rules_display_df[col] = rules_display_df[col].apply(
                lambda x: ", ".join(x) if isinstance(x, (tuple, list)) else x
            )

    st.dataframe(rules_display_df, hide_index=True, width="stretch")
