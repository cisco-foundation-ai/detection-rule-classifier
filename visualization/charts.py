# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Chart creation functions for the detection rules visualization app."""

from typing import Dict, List

import altair as alt
import pandas as pd
import plotly.graph_objects as go


def _get_technique_color_scale(
    top_techniques: List[str],
) -> tuple[List[str], List[str]]:
    """Return color scale domain and range for technique highlighting."""
    distinct_colors = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
        "#e377c2",
        "#7f7f7f",
        "#bcbd22",
        "#17becf",
        "#aec7e8",
        "#ffbb78",
        "#98df8a",
        "#ff9896",
        "#c5b0d5",
        "#c49c94",
        "#f7b6d2",
        "#c7c7c7",
        "#dbdb8d",
        "#9edae5",
    ]
    muted_colors = [
        "#a0a0a0",
        "#b8b8b8",
        "#d0d0d0",
        "#888888",
        "#c8c8c8",
        "#909090",
        "#b0b0b0",
        "#d8d8d8",
        "#989898",
        "#c0c0c0",
    ]
    color_domain = top_techniques + [f"muted_{i}" for i in range(len(muted_colors))]
    color_range = distinct_colors[: len(top_techniques)] + muted_colors
    return color_domain, color_range


def _assign_technique_color_category(
    technique_name: str, top_techniques: List[str]
) -> str:
    """Map technique names to color categories."""
    if technique_name in top_techniques:
        return technique_name
    muted_colors = [
        "#a0a0a0",
        "#b8b8b8",
        "#d0d0d0",
        "#888888",
        "#c8c8c8",
        "#909090",
        "#b0b0b0",
        "#d8d8d8",
        "#989898",
        "#c0c0c0",
    ]
    hash_value = hash(technique_name) % len(muted_colors)
    return f"muted_{hash_value}"


def create_tactic_coverage_chart(
    rule_tactics_df: pd.DataFrame, top_techniques: List[str], tactic_order: List[str]
) -> alt.Chart:
    """Create horizontal stacked bar chart for tactic coverage.

    Tactics are sorted by canonical MITRE order. Techniques within each bar are sorted
    by size (largest on left). Top techniques get distinct colors, others get varied
    muted colors. No legend is displayed.

    Args:
        rule_tactics_df: DataFrame with columns: tactic_pretty, ts_or_st_pretty
        top_techniques: List of top N technique names to highlight with unique colors
        tactic_order: List of tactics in canonical order

    Returns:
        Altair Chart object for tactic coverage
    """
    # Count rule mappings for each tactic-technique pair
    tactic_technique_counts = (
        rule_tactics_df.groupby(["tactic_pretty", "ts_or_st_pretty"])
        .size()
        .reset_index(name="rule_mappings")
    )

    # Extract tactic name only (remove the ID prefix like "[TA0003] ")
    tactic_technique_counts["tactic_name"] = tactic_technique_counts[
        "tactic_pretty"
    ].str.replace(r"^\[.*?\]\s*", "", regex=True)

    # Sort techniques within each tactic by size (descending)
    # This ensures the largest technique segment appears on the left of each bar
    tactic_technique_counts = tactic_technique_counts.sort_values(
        ["tactic_name", "rule_mappings"], ascending=[True, False]
    )

    tactic_technique_counts["color_category"] = tactic_technique_counts[
        "ts_or_st_pretty"
    ].apply(lambda name: _assign_technique_color_category(name, top_techniques))

    color_domain, color_range = _get_technique_color_scale(top_techniques)

    chart = _build_coverage_chart(
        tactic_technique_counts,
        y_field="tactic_name:N",
        y_title="Tactic",
        y_sort=tactic_order,
        tooltip_field="tactic_name:N",
        tooltip_title="Tactic",
        color_domain=color_domain,
        color_range=color_range,
    )

    return chart


def create_kill_chain_coverage_chart(
    rule_kill_chains_df: pd.DataFrame,
    top_techniques: List[str],
    kill_chain_order: List[str],
) -> alt.Chart:
    """Create horizontal stacked bar chart for kill chain coverage.

    Kill chain stages are sorted by step order. Techniques within each bar are sorted
    by size (largest on left). Top techniques get distinct colors, others get varied
    muted colors. No legend is displayed.

    Args:
        rule_kill_chains_df: DataFrame with columns: kill_chain_pretty, ts_or_st_pretty
        top_techniques: List of top N technique names to highlight with unique colors
        kill_chain_order: List of kill chain stages in step order

    Returns:
        Altair Chart object for kill chain coverage
    """
    # Count rule mappings for each kill_chain-technique pair
    kill_chain_technique_counts = (
        rule_kill_chains_df.groupby(["kill_chain_pretty", "ts_or_st_pretty"])
        .size()
        .reset_index(name="rule_mappings")
    )

    # Sort techniques within each kill chain stage by size (descending)
    # This ensures the largest technique segment appears on the left of each bar
    kill_chain_technique_counts = kill_chain_technique_counts.sort_values(
        ["kill_chain_pretty", "rule_mappings"], ascending=[True, False]
    )

    kill_chain_technique_counts["color_category"] = kill_chain_technique_counts[
        "ts_or_st_pretty"
    ].apply(lambda name: _assign_technique_color_category(name, top_techniques))

    color_domain, color_range = _get_technique_color_scale(top_techniques)

    chart = _build_coverage_chart(
        kill_chain_technique_counts,
        y_field="kill_chain_pretty:N",
        y_title="Kill Chain Stage",
        y_sort=kill_chain_order,
        tooltip_field="kill_chain_pretty:N",
        tooltip_title="Kill Chain Stage",
        color_domain=color_domain,
        color_range=color_range,
    )

    return chart


def _build_coverage_chart(
    df: pd.DataFrame,
    y_field: str,
    y_title: str,
    y_sort: List[str],
    tooltip_field: str,
    tooltip_title: str,
    color_domain: List[str],
    color_range: List[str],
) -> alt.Chart:
    return (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X(
                "sum(rule_mappings):Q",
                title="Total rule mappings",
                axis=alt.Axis(format="d"),
            ),
            y=alt.Y(
                y_field,
                title=y_title,
                sort=y_sort,
                scale=alt.Scale(domain=y_sort),  # Force all items to appear on Y-axis
                axis=alt.Axis(labelLimit=200),
            ),
            color=alt.Color(
                "color_category:N",
                title="Technique",
                scale=alt.Scale(domain=color_domain, range=color_range),
                legend=None,
            ),
            order=alt.Order("rule_mappings:Q", sort="descending"),
            tooltip=[
                alt.Tooltip(tooltip_field, title=tooltip_title),
                alt.Tooltip("ts_or_st_pretty:N", title="Technique"),
                alt.Tooltip("rule_mappings:Q", title="Rule mappings"),
            ],
        )
        .properties(height=400)
    )


def create_tactic_killchain_heatmap(
    tactic_kc_counts: pd.DataFrame,
    tactic_sort_order: List[str],
    kc_sort_order: List[str],
) -> alt.Chart:
    """Create heatmap showing tactic vs kill-chain coverage.

    Args:
        tactic_kc_counts: DataFrame with columns: tactic_name, kill_chain_name,
                         kill_chain_step_num, rule_count
        tactic_sort_order: List of tactics in canonical order
        kc_sort_order: List of kill chain stages in step order

    Returns:
        Altair Chart object for tactic/kill-chain heatmap
    """
    # Create heatmap
    heatmap = (
        alt.Chart(tactic_kc_counts)
        .mark_rect()
        .encode(
            x=alt.X(
                "kill_chain_name:N",
                title="Kill-Chain Step",
                sort=kc_sort_order,
                axis=alt.Axis(labelAngle=-45, labelLimit=200),
            ),
            y=alt.Y(
                "tactic_name:N",
                title="Tactic",
                sort=tactic_sort_order,
                scale=alt.Scale(
                    domain=tactic_sort_order
                ),  # Force all tactics to appear on axis
                axis=alt.Axis(labelLimit=300, labelOverlap=False),
            ),
            color=alt.Color(
                "rule_count:Q",
                title="Number of Rules",
                scale=alt.Scale(scheme="greens"),
            ),
            tooltip=[
                alt.Tooltip("tactic_name:N", title="Tactic"),
                alt.Tooltip("kill_chain_name:N", title="Kill-Chain Step"),
                alt.Tooltip("rule_count:Q", title="Number of Rules"),
            ],
        )
        .properties(height=600, width=800)
    )

    return heatmap


def create_top_techniques_chart(
    technique_df: pd.DataFrame, top_techniques: List[str]
) -> alt.Chart:
    """Create horizontal stacked bar chart for top 20 techniques with subtechniques.

    Args:
        technique_df: DataFrame with columns:
                     - parent_technique_name: Parent technique name
                     - ts_or_st_pretty: Full technique/subtechnique name
                     - rule_count: Number of rules
                     Should already be filtered to top 20 parent techniques
        top_techniques: List of top N technique names to highlight with unique colors
                       (same list used in tactic and kill chain coverage charts)

    Returns:
        Altair Chart object for top techniques with consistent color scheme
    """
    # Assign color categories based on the top_techniques list
    df = technique_df.copy()
    df["color_category"] = df["ts_or_st_pretty"].apply(
        lambda name: _assign_technique_color_category(name, top_techniques)
    )

    # Get the same color scale used in tactic and kill chain charts
    color_domain, color_range = _get_technique_color_scale(top_techniques)

    # Calculate parent totals for sorting (highest at top)
    parent_totals = df.groupby("parent_technique_name")["rule_count"].sum()
    parent_order = parent_totals.sort_values(ascending=False).index.tolist()

    # Create horizontal stacked bar chart with Altair
    chart = (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("sum(rule_count):Q", title="Number of Rules"),
            y=alt.Y(
                "parent_technique_name:N",
                sort=parent_order,
                title="",
                axis=alt.Axis(labelLimit=300),
            ),
            color=alt.Color(
                "color_category:N",
                scale=alt.Scale(domain=color_domain, range=color_range),
                legend=None,
            ),
            order=alt.Order("rule_count:Q", sort="descending"),
            tooltip=[
                alt.Tooltip("parent_technique_name:N", title="Parent Technique"),
                alt.Tooltip("ts_or_st_pretty:N", title="Technique/Subtechnique"),
                alt.Tooltip("rule_count:Q", title="Number of Rules"),
            ],
        )
        .properties(height=500)
    )

    return chart


def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _format_rules_for_hover(rules: List[str], max_rules: int = 10) -> str:
    """Format rules for hover tooltip with readability limit.

    Args:
        rules: List of rule IDs
        max_rules: Maximum number of rules to show before summarizing

    Returns:
        Formatted string for tooltip
    """
    if not rules:
        return ""

    rule_count = len(rules)

    # For many rules, just show the count
    if rule_count > max_rules:
        return f"{rule_count} detection rules"

    # For few rules, show them (one per line for readability)
    return (
        f"{rule_count} detection rule{'s' if rule_count > 1 else ''}:<br>"
        + "<br>".join(f"  • {rule}" for rule in rules[:max_rules])
    )


# pylint: disable=too-many-locals,too-many-statements
def _build_sankey_nodes(
    df: pd.DataFrame,
    order: List[str],
    label_map: Dict[str, str],
    node_counts: Dict[str, Dict[str, int]] | None,
) -> tuple[
    Dict[str, int],
    List[str],
    List[str],
    List[str],
    Dict[str, str],
    Dict[str, List[str]],
]:
    node_index: Dict[str, int] = {}
    node_labels: List[str] = []
    node_colors: List[str] = []
    node_customdata: List[str] = []
    node_palette = [
        "#1b4f72",
        "#6c3483",
        "#196f3d",
        "#7d6608",
        "#922b21",
        "#154360",
        "#4a235a",
        "#145a32",
        "#7e5109",
        "#641e16",
        "#2e4053",
        "#7b241c",
        "#21618c",
        "#633974",
        "#1e8449",
        "#9a7d0a",
        "#b03a2e",
        "#7d3c98",
        "#117864",
        "#b9770e",
    ]
    node_color_map: Dict[str, str] = {}
    palette_index = 0

    def assign_node_color(node_id: str) -> str:
        nonlocal palette_index
        if node_id not in node_color_map:
            node_color_map[node_id] = node_palette[palette_index % len(node_palette)]
            palette_index += 1
        return node_color_map[node_id]

    technique_rules = {
        tech: sorted(set(rules))
        for tech, rules in df.groupby("ts_or_st_pretty")["rule_id"]
    }

    def count_suffix(node_type: str, value: str) -> str:
        if not node_counts or node_type not in node_counts:
            return ""
        count = node_counts[node_type].get(value)
        if count is None:
            return ""
        if node_type == "ts_or_st_pretty":
            return f" ({count} detections)"
        if node_type in ("kill_chain_pretty", "tactic_pretty"):
            return f" ({count} techniques)"
        return ""

    def add_node(node_type: str, value: str) -> None:
        node_id = f"{node_type}:{value}"
        if node_id in node_index:
            return
        node_index[node_id] = len(node_labels)
        label_prefix = label_map.get(node_type, node_type)
        suffix = count_suffix(node_type, value)
        node_labels.append(f"{label_prefix}: {value}{suffix}")
        node_colors.append(_hex_to_rgba(assign_node_color(node_id), 0.35))

        # Add custom hover data
        if node_type == "ts_or_st_pretty":
            # For techniques, show rule details
            rules = technique_rules.get(value, [])
            node_customdata.append(_format_rules_for_hover(rules))
        elif suffix:
            # For tactics/kill chains with counts, show the count info
            node_customdata.append(suffix.strip(" ()"))
        else:
            # No additional data
            node_customdata.append("")

    for node_type in order:
        for value in df[node_type].astype(str).unique():
            add_node(node_type, value)

    return (
        node_index,
        node_labels,
        node_colors,
        node_customdata,
        node_color_map,
        technique_rules,
    )


def _build_sankey_links(
    df: pd.DataFrame,
    order: List[str],
    node_index: Dict[str, int],
    node_color_map: Dict[str, str],
) -> tuple[List[int], List[int], List[int], List[str]]:
    sources: List[int] = []
    targets: List[int] = []
    values: List[int] = []
    link_colors: List[str] = []

    for left_key, right_key in zip(order, order[1:]):
        link_counts = df.groupby([left_key, right_key]).size().reset_index(name="value")
        for _, row in link_counts.iterrows():
            source_id = f"{left_key}:{row[left_key]}"
            target_id = f"{right_key}:{row[right_key]}"
            sources.append(node_index[source_id])
            targets.append(node_index[target_id])
            values.append(int(row["value"]))
            link_colors.append(_hex_to_rgba(node_color_map[source_id], 0.55))

    return sources, targets, values, link_colors


# pylint: disable=too-many-locals
def create_sankey_chart(
    rule_kill_chains_df: pd.DataFrame,
    order: List[str],
    label_map: Dict[str, str] | None = None,
    node_counts: Dict[str, Dict[str, int]] | None = None,
    show_labels: bool = True,
) -> go.Figure:
    """Create a Sankey chart for ordered flow across rule attributes.

    Args:
        rule_kill_chains_df: DataFrame with rule mappings
        order: List of column names defining the flow order
        label_map: Optional mapping of column names to display labels
        node_counts: Optional dict of counts per node category
        show_labels: Whether to display node labels (default True)

    Returns:
        Plotly Figure object with Sankey diagram
    """
    default_label_map = {
        "kill_chain_pretty": "Kill Chain",
        "rule_id": "Rule",
        "ts_or_st_pretty": "Technique",
        "tactic_pretty": "Tactic",
    }
    label_map = label_map or default_label_map

    df = rule_kill_chains_df.dropna(subset=order).copy()
    (
        node_index,
        node_labels,
        node_colors,
        node_customdata,
        node_color_map,
        _,
    ) = _build_sankey_nodes(df, order, label_map, node_counts)
    sources, targets, values, link_colors = _build_sankey_links(
        df, order, node_index, node_color_map
    )

    # Build node dictionary - always include labels for hover to work
    # Create more readable hover template
    # %{label} shows the node name, %{customdata} shows additional info (rules)
    node_dict = {
        "label": node_labels,  # Always needed for hover tooltips
        "color": node_colors,
        "customdata": node_customdata,
        "hovertemplate": "<b>%{label}</b><br>%{customdata}<extra></extra>",
        "pad": 25,
        "thickness": 20,
        "line": {"color": "white", "width": 2},
    }

    # Configure text visibility based on show_labels
    # When labels are hidden, use tiny font and transparent color
    # (labels still exist for hover tooltips, but invisible on display)
    if show_labels:
        textfont = {"size": 11, "color": "black", "family": "Arial, sans-serif"}
    else:
        textfont = {"size": 1, "color": "rgba(0,0,0,0)", "family": "Arial, sans-serif"}

    figure = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=node_dict,
                link={
                    "source": sources,
                    "target": targets,
                    "value": values,
                    "color": link_colors,
                },
                textfont=textfont,
            )
        ]
    )
    figure.update_layout(
        height=650,
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
        font={"color": "black", "size": 11},
        plot_bgcolor="#ffffff",
        paper_bgcolor="#ffffff",
    )

    return figure
