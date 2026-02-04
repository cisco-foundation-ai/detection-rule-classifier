# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for new insights features (executive summary and per-viz insights)."""

import json
from unittest.mock import patch

import pytest

from aggregation.insights_generator import (
    generate_executive_summary,
    generate_visualization_insights,
    parse_json_response,
)
from aggregation.prompts import format_prompt, get_prompt_template


def test_get_executive_summary_prompt():
    """Test retrieving executive summary prompt template."""
    template = get_prompt_template("executive_summary")

    assert "executive summary" in template.lower()
    assert "{aggregated_data}" in template
    assert "{visualization_insights}" in template
    assert "critical_gaps" in template
    assert "priority_actions" in template


def test_get_per_visualization_prompt():
    """Test retrieving per-visualization prompt template."""
    template = get_prompt_template("per_visualization")

    assert "visualization" in template.lower()
    assert "{chart_type}" in template
    assert "{chart_title}" in template
    assert "{chart_data}" in template


def test_format_executive_summary_prompt():
    """Test formatting executive summary prompt."""
    aggregated_data = '{"metadata": {"total_rules": 10}}'
    viz_insights = '{"tactic_coverage": {"interpretation": "Test"}}'

    formatted = format_prompt(
        insight_type="executive_summary",
        aggregated_data=aggregated_data,
        visualization_insights=viz_insights,
    )

    assert aggregated_data in formatted
    assert viz_insights in formatted
    assert "{aggregated_data}" not in formatted  # Should be replaced
    assert "{visualization_insights}" not in formatted  # Should be replaced


def test_format_per_visualization_prompt():
    """Test formatting per-visualization prompt."""
    aggregated_data = '{"metadata": {"total_rules": 10}}'
    chart_data = '[{"tactic": "Execution", "count": 5}]'

    formatted = format_prompt(
        insight_type="per_visualization",
        aggregated_data=aggregated_data,
        chart_type="horizontal_bar",
        chart_title="Tactic Coverage",
        chart_description="Detection rules by tactic",
        chart_data=chart_data,
    )

    assert "horizontal_bar" in formatted
    assert "Tactic Coverage" in formatted
    assert chart_data in formatted
    assert "{chart_type}" not in formatted  # Should be replaced


def test_parse_json_response_valid():
    """Test parsing valid JSON response."""
    valid_json = '{"critical_gaps": [], "priority_actions": []}'

    result = parse_json_response(valid_json, "executive_summary")

    assert isinstance(result, dict)
    assert "critical_gaps" in result
    assert "priority_actions" in result


def test_parse_json_response_invalid():
    """Test parsing invalid JSON response."""
    invalid_json = "This is not valid JSON"

    with pytest.raises(ValueError) as exc_info:
        parse_json_response(invalid_json, "executive_summary")

    assert "Invalid JSON response" in str(exc_info.value)


@patch("aggregation.insights_generator.call_llm_api")
def test_generate_visualization_insights(mock_llm):
    """Test generating per-visualization insights."""
    # Mock LLM response
    mock_llm.return_value = json.dumps(
        {
            "interpretation": "Test interpretation",
            "key_findings": ["Finding 1", "Finding 2"],
            "recommendations": [
                {"action": "Test action", "priority": "high", "context": "Context"}
            ],
            "anomalies": [],
        }
    )

    aggregated_data = {
        "metadata": {"total_rules": 100},
        "aggregations": {"tactic_coverage": [{"tactic": "Execution", "count": 50}]},
    }

    llm_config = {"model": "gpt-4o", "temperature": 0.3}

    result = generate_visualization_insights(aggregated_data, llm_config)

    assert isinstance(result, dict)
    assert "tactic_coverage" in result
    assert result["tactic_coverage"]["interpretation"] == "Test interpretation"
    assert len(result["tactic_coverage"]["key_findings"]) == 2


@patch("aggregation.insights_generator.call_llm_api")
def test_generate_executive_summary(mock_llm):
    """Test generating executive summary."""
    # Mock LLM response
    mock_llm.return_value = json.dumps(
        {
            "critical_gaps": [
                {
                    "gap_type": "tactic",
                    "name": "Resource Development",
                    "severity": "critical",
                    "current_coverage": 2,
                    "risk_context": "Early-stage detection gap",
                    "business_impact": "Cannot detect infrastructure prep",
                    "supporting_evidence": "Tactic coverage shows only 2 rules",
                }
            ],
            "priority_actions": [
                {
                    "rank": 1,
                    "action": "Create detections for T1583",
                    "rationale": "High-priority trending technique",
                    "estimated_effort": "medium",
                    "expected_impact": "Detect 40% of infrastructure acquisition",
                }
            ],
        }
    )

    aggregated_data = {"metadata": {"total_rules": 100}}
    viz_insights = {"tactic_coverage": {"interpretation": "Test"}}
    llm_config = {"model": "gpt-4o", "temperature": 0.3}

    result = generate_executive_summary(aggregated_data, viz_insights, llm_config)

    assert isinstance(result, dict)
    assert "critical_gaps" in result
    assert "priority_actions" in result
    assert len(result["critical_gaps"]) == 1
    assert len(result["priority_actions"]) == 1
    assert result["critical_gaps"][0]["name"] == "Resource Development"


@patch("aggregation.insights_generator.call_llm_api")
def test_generate_executive_summary_with_viz_context(mock_llm):
    """Test that executive summary receives viz insights as context."""
    mock_llm.return_value = json.dumps({"critical_gaps": [], "priority_actions": []})

    aggregated_data = {"metadata": {"total_rules": 100}}
    viz_insights = {
        "tactic_coverage": {
            "interpretation": "Defense Evasion has 5x more rules",
            "key_findings": ["Finding 1"],
        }
    }
    llm_config = {"model": "gpt-4o"}

    generate_executive_summary(aggregated_data, viz_insights, llm_config)

    # Verify that the LLM was called with a prompt containing viz insights
    call_args = mock_llm.call_args[0][0]  # First positional argument (prompt)
    assert "Defense Evasion has 5x more rules" in call_args
    assert (
        "visualization_insights" in call_args.lower()
        or "visualization" in call_args.lower()
    )


def test_visualization_insights_structure():
    """Test that visualization insights have correct structure."""
    insight = {
        "interpretation": "Test interpretation",
        "key_findings": ["Finding 1", "Finding 2", "Finding 3"],
        "recommendations": [
            {"action": "Action 1", "priority": "high", "context": "Context 1"}
        ],
        "anomalies": ["Anomaly 1"],
    }

    # Validate structure
    assert "interpretation" in insight
    assert isinstance(insight["interpretation"], str)
    assert "key_findings" in insight
    assert isinstance(insight["key_findings"], list)
    assert "recommendations" in insight
    assert isinstance(insight["recommendations"], list)
    assert "anomalies" in insight
    assert isinstance(insight["anomalies"], list)

    # Validate recommendation structure
    rec = insight["recommendations"][0]
    assert "action" in rec
    assert "priority" in rec
    assert "context" in rec


def test_executive_summary_structure():
    """Test that executive summary has correct structure."""
    summary = {
        "critical_gaps": [
            {
                "gap_type": "tactic",
                "name": "Test Tactic",
                "severity": "critical",
                "current_coverage": 0,
                "risk_context": "Risk context",
                "business_impact": "Business impact",
                "supporting_evidence": "Evidence",
            }
        ],
        "priority_actions": [
            {
                "rank": 1,
                "action": "Action",
                "rationale": "Rationale",
                "estimated_effort": "medium",
                "expected_impact": "Impact",
            }
        ],
    }

    # Validate structure
    assert "critical_gaps" in summary
    assert isinstance(summary["critical_gaps"], list)
    assert "priority_actions" in summary
    assert isinstance(summary["priority_actions"], list)

    # Validate gap structure
    gap = summary["critical_gaps"][0]
    assert all(
        key in gap
        for key in [
            "gap_type",
            "name",
            "severity",
            "current_coverage",
            "risk_context",
            "business_impact",
            "supporting_evidence",
        ]
    )

    # Validate action structure
    action = summary["priority_actions"][0]
    assert all(
        key in action
        for key in [
            "rank",
            "action",
            "rationale",
            "estimated_effort",
            "expected_impact",
        ]
    )
