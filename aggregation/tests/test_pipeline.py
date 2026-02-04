# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for aggregation pipeline."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from aggregation.config_utils import load_config
from aggregation.pipeline import run_aggregation_pipeline, save_aggregated_data


def test_load_config(tmp_path):
    """Test loading configuration from JSON file."""
    config_data = {
        "input": {"classified_output": "test.json"},
        "output": {"aggregated_data": "output.json"},
    }

    config_file = tmp_path / "config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f)

    config = load_config(config_file)

    assert config["input"]["classified_output"] == "test.json"
    assert config["output"]["aggregated_data"] == "output.json"


def test_load_config_file_not_found():
    """Test loading config with non-existent file."""
    with pytest.raises(FileNotFoundError):
        load_config(Path("nonexistent_config.json"))


def test_save_aggregated_data(tmp_path):
    """Test saving aggregated data to JSON file."""
    test_data = {
        "metadata": {"total_rules": 10},
        "aggregations": {"technique_counts": []},
    }

    output_file = tmp_path / "aggregated.json"
    save_aggregated_data(test_data, output_file)

    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        loaded_data = json.load(f)

    assert loaded_data["metadata"]["total_rules"] == 10


@patch("aggregation.pipeline.process_classified_rules")
def test_run_aggregation_pipeline(mock_process, tmp_path):
    """Test running the complete aggregation pipeline."""
    # Mock the process_classified_rules function
    mock_aggregated_data = {
        "metadata": {
            "total_rules": 5,
            "total_techniques": 10,
            "total_tactics": 3,
            "total_kill_chains": 2,
        },
        "aggregations": {},
        "dataframes": {},
    }
    mock_process.return_value = mock_aggregated_data

    # Create temporary input file
    input_file = tmp_path / "classified.json"
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump([{"id": "rule1", "relevant_techniques": ["T1234"]}], f)

    output_dir = tmp_path / "output"
    trending_file = tmp_path / "trending.csv"
    trending_file.write_text("technique_id,mentions_in_incidents_percent\nT1234,10\n")

    # Run the pipeline
    run_aggregation_pipeline(
        input_file=str(input_file),
        output_dir=str(output_dir),
        trending_techniques_source=str(trending_file),
        save_config_snapshot_flag=False,
    )

    # Verify output was created
    output_file = output_dir / "aggregated_data.json"
    assert output_file.exists()

    # Verify the mock was called correctly
    mock_process.assert_called_once_with(str(input_file), str(trending_file))
