# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for prompt templates."""

import pytest

from aggregation.prompts import format_prompt, get_prompt_template


def test_get_prompt_template_coverage_gaps():
    """Test retrieving coverage gaps prompt template."""
    template = get_prompt_template("coverage_gaps")

    assert "coverage gaps" in template.lower()
    assert "{aggregated_data}" in template
    assert "{threshold}" in template


def test_get_prompt_template_recommendations():
    """Test retrieving recommendations prompt template."""
    template = get_prompt_template("recommendations")

    assert "recommendations" in template.lower()
    assert "{aggregated_data}" in template
    assert "{trending_data}" in template


def test_get_prompt_template_trends_analysis():
    """Test retrieving trends analysis prompt template."""
    template = get_prompt_template("trends_analysis")

    assert "trending" in template.lower()
    assert "{aggregated_data}" in template
    assert "{trending_data}" in template


def test_get_prompt_template_anomalies():
    """Test retrieving anomalies prompt template."""
    template = get_prompt_template("anomalies")

    assert "anomalies" in template.lower()
    assert "{aggregated_data}" in template


def test_get_prompt_template_invalid_type():
    """Test retrieving prompt template with invalid type."""
    with pytest.raises(ValueError) as exc_info:
        get_prompt_template("invalid_type")

    assert "Unknown insight type" in str(exc_info.value)


def test_format_prompt_coverage_gaps():
    """Test formatting coverage gaps prompt."""
    aggregated_data = '{"metadata": {"total_rules": 10}}'
    formatted = format_prompt("coverage_gaps", aggregated_data, threshold=5)

    assert aggregated_data in formatted
    assert "5" in formatted
    assert "{aggregated_data}" not in formatted  # Should be replaced
    assert "{threshold}" not in formatted  # Should be replaced


def test_format_prompt_recommendations():
    """Test formatting recommendations prompt."""
    aggregated_data = '{"metadata": {"total_rules": 10}}'
    trending_data = '{"T1234": {"mentions": 50}}'
    formatted = format_prompt("recommendations", aggregated_data, trending_data)

    assert aggregated_data in formatted
    assert trending_data in formatted
    assert "{aggregated_data}" not in formatted
    assert "{trending_data}" not in formatted


def test_get_prompt_template_executive_summary():
    """Test retrieving executive summary prompt template."""
    template = get_prompt_template("executive_summary")

    assert "executive summary" in template.lower()
    assert "{aggregated_data}" in template
    assert "{visualization_insights}" in template
    assert "synthesize" in template.lower() or "synthesizing" in template.lower()


def test_get_prompt_template_per_visualization():
    """Test retrieving per-visualization prompt template."""
    template = get_prompt_template("per_visualization")

    assert "visualization" in template.lower()
    assert "{chart_type}" in template
    assert "{chart_title}" in template
    assert "{chart_data}" in template


def test_format_prompt_executive_summary():
    """Test formatting executive summary prompt."""
    aggregated_data = '{"total_rules": 100, "total_techniques": 50}'
    viz_insights = '{"tactic_coverage": {"description": "...", "insights": []}}'
    formatted = format_prompt(
        "executive_summary",
        aggregated_data=aggregated_data,
        visualization_insights=viz_insights,
    )

    assert aggregated_data in formatted
    assert viz_insights in formatted
    assert "{aggregated_data}" not in formatted
    assert "{visualization_insights}" not in formatted


def test_format_prompt_per_visualization():
    """Test formatting per-visualization prompt."""
    chart_data = '{"tactic": "Execution", "rules": 50}'
    formatted = format_prompt(
        "per_visualization",
        chart_type="horizontal_bar",
        chart_title="Tactic Coverage",
        chart_description="Detection rules by tactic",
        chart_data=chart_data,
    )

    assert "horizontal_bar" in formatted
    assert "Tactic Coverage" in formatted
    assert chart_data in formatted
    assert "{chart_type}" not in formatted
    assert "{chart_data}" not in formatted


def test_format_prompt_all_types():
    """Test formatting all prompt types."""
    aggregated_data = '{"test": "data"}'
    trending_data = '{"trend": "data"}'

    for insight_type in [
        "coverage_gaps",
        "recommendations",
        "trends_analysis",
        "anomalies",
    ]:
        formatted = format_prompt(insight_type, aggregated_data, trending_data)
        assert isinstance(formatted, str)
        assert len(formatted) > 0
        # Ensure placeholders were replaced
        assert "{aggregated_data}" not in formatted
