# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for data_processor module."""

import json
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from aggregation.data_processor import load_classified_rules
from aggregation.enrichment import (
    enrich_kill_chain_data,
    enrich_tactic_data,
    enrich_technique_data,
    sort_tactics,
)


def test_sort_tactics():
    """Test tactic sorting by canonical order."""
    unsorted = ["Impact", "Execution", "Reconnaissance", "Collection"]
    sorted_tactics = sort_tactics(unsorted)

    assert sorted_tactics == [
        "Reconnaissance",
        "Execution",
        "Collection",
        "Impact",
    ]


def test_sort_tactics_with_subset():
    """Test tactic sorting with only a subset of tactics."""
    subset = ["Impact", "Execution"]
    sorted_tactics = sort_tactics(subset)

    assert sorted_tactics == ["Execution", "Impact"]


def test_enrich_technique_data_with_technique():
    """Test enrichment of technique data for a regular technique."""
    mock_tech = MagicMock()
    mock_tech.id = "T1234"
    mock_tech.name = "Test Technique"
    mock_tech.tactics = ["tactic1", "tactic2"]

    with patch("aggregation.enrichment.get_mapper") as mock_mapper:
        mock_mapper.return_value.get_technique.return_value = mock_tech
        mock_mapper.return_value.get_sub_technique.return_value = None

        row = pd.Series({"technique_id": "T1234"})
        result = enrich_technique_data(row)

        assert result["ts_or_st_pretty"] == "[T1234] Test Technique"
        assert result["tactics"] == ["tactic1", "tactic2"]


def test_enrich_technique_data_with_subtechnique():
    """Test enrichment of technique data for a sub-technique."""
    mock_parent_tech = MagicMock()
    mock_parent_tech.name = "Parent Technique"
    mock_parent_tech.tactics = ["tactic1"]

    mock_sub_tech = MagicMock()
    mock_sub_tech.id = "T1234.001"
    mock_sub_tech.name = "Sub Technique"
    mock_sub_tech.technique = mock_parent_tech

    with patch("aggregation.enrichment.get_mapper") as mock_mapper:
        mock_mapper.return_value.get_sub_technique.return_value = mock_sub_tech

        row = pd.Series({"technique_id": "T1234.001"})
        result = enrich_technique_data(row)

        assert (
            result["ts_or_st_pretty"] == "[T1234.001] Parent Technique > Sub Technique"
        )
        assert result["tactics"] == ["tactic1"]


def test_enrich_tactic_data():
    """Test enrichment of tactic data."""
    mock_tactic = MagicMock()
    mock_tactic.id = "TA0001"
    mock_tactic.name = "Initial Access"
    mock_tactic.kill_chain_stages = ["stage1", "stage2"]

    row = pd.Series({"tactic": mock_tactic})
    result = enrich_tactic_data(row)

    assert result["tactic_id"] == "TA0001"
    assert result["tactic_pretty"] == "[TA0001] Initial Access"
    assert result["kill_chain_stages"] == ["stage1", "stage2"]


def test_enrich_kill_chain_data():
    """Test enrichment of kill chain data."""
    mock_kc_stage = MagicMock()
    mock_kc_stage.kill_chain_step_number = 1
    mock_kc_stage.name = "Reconnaissance"

    row = pd.Series({"kill_chain_stage": mock_kc_stage})
    result = enrich_kill_chain_data(row)

    assert result["kill_chain_id"] == 1
    assert result["kill_chain_pretty"] == "[1] Reconnaissance"


def test_load_classified_rules(tmp_path):
    """Test loading classified rules from JSON."""
    # Create a test JSON file
    test_data = [
        {
            "id": "rule1",
            "relevant_techniques": ["T1234", "T5678"],
        },
        {
            "id": "rule2",
            "relevant_techniques": ["T9999"],
        },
    ]

    test_file = tmp_path / "test_classified.json"
    with open(test_file, "w", encoding="utf-8") as f:
        json.dump(test_data, f)

    # Load the rules
    df = load_classified_rules(str(test_file))

    assert len(df) == 2
    assert "rule_id" in df.columns
    assert "technique_ids" in df.columns
    assert df.iloc[0]["rule_id"] == "rule1"
    assert df.iloc[0]["technique_ids"] == ["T1234", "T5678"]


def test_load_classified_rules_file_not_found():
    """Test loading classified rules with non-existent file."""
    with pytest.raises(FileNotFoundError):
        load_classified_rules("nonexistent_file.json")
