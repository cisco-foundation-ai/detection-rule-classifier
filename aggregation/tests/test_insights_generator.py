# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for insights generator."""

import json


from aggregation.config_utils import load_config
from aggregation.insights_generator import (
    generate_empty_insights,
    load_aggregated_data,
    run_insights_generator,
    save_insights,
)


def test_generate_empty_insights_all_types():
    """Test generating empty insights structure with all types."""
    enabled_types = ["coverage_gaps", "recommendations", "trends_analysis", "anomalies"]
    insights = generate_empty_insights(enabled_types)

    assert "coverage_gaps" in insights
    assert "recommendations" in insights
    assert "trends_analysis" in insights
    assert "anomalies" in insights

    assert isinstance(insights["coverage_gaps"], dict)
    assert isinstance(insights["recommendations"], list)
    assert isinstance(insights["trends_analysis"], dict)
    assert isinstance(insights["anomalies"], dict)


def test_generate_empty_insights_subset():
    """Test generating empty insights structure with subset of types."""
    enabled_types = ["coverage_gaps", "recommendations"]
    insights = generate_empty_insights(enabled_types)

    assert "coverage_gaps" in insights
    assert "recommendations" in insights
    assert "trends_analysis" not in insights
    assert "anomalies" not in insights


def test_load_config(tmp_path):
    """Test loading configuration from JSON file."""
    config_data = {
        "llm": {"model": "gpt-4o", "temperature": 0.7},
        "insights": {"enabled_types": ["coverage_gaps"]},
    }

    config_file = tmp_path / "config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f)

    config = load_config(config_file)

    assert config["llm"]["model"] == "gpt-4o"
    assert config["insights"]["enabled_types"] == ["coverage_gaps"]


def test_load_aggregated_data(tmp_path):
    """Test loading aggregated data from JSON file."""
    test_data = {
        "metadata": {"total_rules": 10},
        "aggregations": {"technique_counts": []},
        "dataframes": {},
    }

    data_file = tmp_path / "aggregated.json"
    with open(data_file, "w", encoding="utf-8") as f:
        json.dump(test_data, f)

    data = load_aggregated_data(data_file)

    assert data["metadata"]["total_rules"] == 10


def test_save_insights(tmp_path):
    """Test saving insights to JSON file."""
    insights_data = {
        "insights": {"coverage_gaps": {"summary": "Test summary"}},
        "generated_at": "2025-01-14T00:00:00",
    }

    output_file = tmp_path / "insights.json"
    save_insights(insights_data, output_file)

    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        loaded_data = json.load(f)

    assert loaded_data["insights"]["coverage_gaps"]["summary"] == "Test summary"


def test_run_insights_generator(tmp_path):
    """Test running the insights generator."""
    # Create test aggregated data file
    aggregated_data = {
        "metadata": {"total_rules": 5},
        "aggregations": {},
        "dataframes": {},
    }

    input_file = tmp_path / "aggregated.json"
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(aggregated_data, f)

    output_file = tmp_path / "insights.json"

    # Run the generator
    run_insights_generator(
        input_file=str(input_file),
        output_file=str(output_file),
        enabled_types=["coverage_gaps", "recommendations"],
        llm_config={"model": "gpt-4o", "temperature": 0.7},
        coverage_gap_threshold=5,
    )

    # Verify output was created
    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        insights = json.load(f)

    assert "insights" in insights
    assert "generated_at" in insights
    assert "llm_config" in insights
    assert insights["metadata"]["implementation_status"] == "empty_structure_no_api_key"
