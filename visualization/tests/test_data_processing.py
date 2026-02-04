# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for data processing functions in visualization/app.py."""

import pandas as pd
import pytest

from aggregation.enrichment import (
    canonical_tactic_order,
    enrich_kill_chain_data,
    enrich_tactic_data,
    enrich_technique_data,
    sort_tactics,
)
from visualization.app import load_detection_rules, parse_args

# ===== Test sort_tactics() =====


class TestSortTactics:
    """Test the sort_tactics function."""

    @pytest.mark.unit
    def test_canonical_order(self):
        """Test tactics are sorted in canonical MITRE order."""
        input_tactics = [
            "Impact",
            "Reconnaissance",
            "Execution",
            "Defense Evasion",
            "Persistence",
        ]
        result = sort_tactics(input_tactics)

        # Verify order:
        # Reconnaissance < Execution < Persistence < Defense Evasion < Impact
        assert result.index("Reconnaissance") < result.index("Execution")
        assert result.index("Execution") < result.index("Persistence")
        assert result.index("Persistence") < result.index("Defense Evasion")
        assert result.index("Defense Evasion") < result.index("Impact")

    @pytest.mark.unit
    def test_filters_unknown_tactics(self):
        """Test unknown tactics are filtered out."""
        input_tactics = ["Execution", "UnknownTactic", "Impact", "FakeTactic"]
        result = sort_tactics(input_tactics)

        assert "UnknownTactic" not in result
        assert "FakeTactic" not in result
        assert "Execution" in result
        assert "Impact" in result
        assert len(result) == 2

    @pytest.mark.unit
    def test_empty_list(self):
        """Test handling of empty list."""
        assert sort_tactics([]) == []

    @pytest.mark.unit
    def test_set_input(self):
        """Test function works with set input."""
        input_tactics = {"Impact", "Execution", "Reconnaissance"}
        result = sort_tactics(input_tactics)

        assert isinstance(result, list)
        assert len(result) == 3
        assert "Execution" in result
        assert "Impact" in result
        assert "Reconnaissance" in result

    @pytest.mark.unit
    def test_preserves_only_valid_tactics(self):
        """Test that only valid tactics from input are preserved."""
        # Include all 14 canonical tactics plus some invalid ones
        all_tactics = canonical_tactic_order + ["InvalidTactic1", "InvalidTactic2"]
        result = sort_tactics(all_tactics)

        # Should have exactly 14 tactics (all valid ones)
        assert len(result) == 14
        assert "InvalidTactic1" not in result
        assert "InvalidTactic2" not in result


# ===== Test load_detection_rules() =====


class TestLoadDetectionRules:
    """Test the load_detection_rules function."""

    @pytest.mark.unit
    def test_load_from_local_file(self, sample_classified_output):
        """Test loading from local JSON file."""
        df = load_detection_rules(sample_classified_output)

        assert isinstance(df, pd.DataFrame)
        assert "rule_id" in df.columns
        assert "technique_ids" in df.columns
        assert len(df) == 4  # Based on SAMPLE_CLASSIFICATION_DATA
        assert df.iloc[0]["rule_id"] == "test_rule_1.yml"

    @pytest.mark.unit
    def test_column_renaming(self, sample_classified_output):
        """Test that columns are renamed correctly."""
        df = load_detection_rules(sample_classified_output)

        # Original columns should not exist
        assert "id" not in df.columns
        assert "relevant_techniques" not in df.columns

        # Renamed columns should exist
        assert "rule_id" in df.columns
        assert "technique_ids" in df.columns

    @pytest.mark.unit
    def test_dataframe_structure(self, sample_classified_output):
        """Test DataFrame structure validation."""
        df = load_detection_rules(sample_classified_output)

        # Verify technique_ids are lists
        assert all(isinstance(row, list) for row in df["technique_ids"])

        # Verify sorting by rule_id
        assert df["rule_id"].is_monotonic_increasing

    @pytest.mark.unit
    def test_handles_missing_file(self):
        """Test error handling for missing file."""
        with pytest.raises(FileNotFoundError):
            load_detection_rules("nonexistent_file.json")


# ===== Test enrich_technique_data() =====


class TestEnrichTechniqueData:
    """Test the enrich_technique_data function."""

    @pytest.mark.unit
    def test_enrich_regular_technique(self):
        """Test enrichment of regular technique (T1059)."""
        row = pd.Series({"rule_id": "test_rule", "technique_id": "T1059"})

        result = enrich_technique_data(row)

        assert result["ts_or_st_pretty"] == "[T1059] Command and Scripting Interpreter"
        assert isinstance(result["tactics"], list)
        assert len(result["tactics"]) > 0

    @pytest.mark.unit
    def test_enrich_sub_technique(self):
        """Test enrichment of sub-technique (T1059.001)."""
        row = pd.Series({"rule_id": "test_rule", "technique_id": "T1059.001"})

        result = enrich_technique_data(row)

        expected = "[T1059.001] Command and Scripting Interpreter > PowerShell"
        assert result["ts_or_st_pretty"] == expected
        assert isinstance(result["tactics"], list)

    @pytest.mark.unit
    def test_pretty_format_technique(self):
        """Test format for technique: [T1059] Name."""
        row = pd.Series({"rule_id": "test_rule", "technique_id": "T1027"})

        result = enrich_technique_data(row)

        assert result["ts_or_st_pretty"].startswith("[T1027]")
        assert "Obfuscated Files or Information" in result["ts_or_st_pretty"]

    @pytest.mark.unit
    def test_tactics_list_extraction(self):
        """Test tactics list is extracted from technique."""
        row = pd.Series({"rule_id": "test_rule", "technique_id": "T1059"})

        result = enrich_technique_data(row)

        assert "tactics" in result
        assert isinstance(result["tactics"], list)
        # T1059 should have Execution tactic
        if len(result["tactics"]) > 0:
            assert hasattr(result["tactics"][0], "name")

    @pytest.mark.unit
    def test_unknown_technique_id(self):
        """Test handling of unknown technique ID returns None and empty list."""
        row = pd.Series({"rule_id": "test_rule", "technique_id": "T9999"})

        result = enrich_technique_data(row)

        assert result["ts_or_st_pretty"] is None
        assert result["tactics"] == []

    @pytest.mark.unit
    def test_empty_technique_id(self):
        """Test handling of empty technique ID."""
        row = pd.Series({"rule_id": "test_rule", "technique_id": ""})

        result = enrich_technique_data(row)

        assert result["ts_or_st_pretty"] is None
        assert result["tactics"] == []


# ===== Test enrich_tactic_data() =====


class TestEnrichTacticData:
    """Test the enrich_tactic_data function."""

    @pytest.mark.unit
    def test_enrich_with_valid_tactic(self, mock_tactic):
        """Test enrichment with valid Tactic object."""
        row = pd.Series({"rule_id": "test_rule", "tactic": mock_tactic})

        result = enrich_tactic_data(row)

        assert result["tactic_id"] == "TA0002"
        assert result["tactic_pretty"] == "[TA0002] Execution"
        assert isinstance(result["kill_chain_stages"], list)
        assert len(result["kill_chain_stages"]) > 0

    @pytest.mark.unit
    def test_pretty_format(self, mock_tactic):
        """Test pretty format: [TA0002] Execution."""
        row = pd.Series({"rule_id": "test_rule", "tactic": mock_tactic})

        result = enrich_tactic_data(row)

        assert result["tactic_pretty"].startswith("[TA0002]")
        assert "Execution" in result["tactic_pretty"]

    @pytest.mark.unit
    def test_kill_chain_stages_extraction(self, mock_tactic):
        """Test kill chain stages are extracted from tactic."""
        row = pd.Series({"rule_id": "test_rule", "tactic": mock_tactic})

        result = enrich_tactic_data(row)

        assert "kill_chain_stages" in result
        assert isinstance(result["kill_chain_stages"], list)

    @pytest.mark.unit
    def test_enrich_with_none_tactic(self):
        """Test handling of None tactic."""
        row = pd.Series({"rule_id": "test_rule", "tactic": None})

        result = enrich_tactic_data(row)

        assert result["tactic_id"] is None
        assert result["tactic_pretty"] is None
        assert result["kill_chain_stages"] == []


# ===== Test enrich_kill_chain_data() =====


class TestEnrichKillChainData:
    """Test the enrich_kill_chain_data function."""

    @pytest.mark.unit
    def test_enrich_with_valid_kill_chain(self, mock_kill_chain_stage):
        """Test enrichment with valid CyberKillChainStage object."""
        row = pd.Series(
            {"rule_id": "test_rule", "kill_chain_stage": mock_kill_chain_stage}
        )

        result = enrich_kill_chain_data(row)

        assert result["kill_chain_id"] == 4
        assert result["kill_chain_pretty"] == "[4] Exploitation"

    @pytest.mark.unit
    def test_pretty_format(self, mock_kill_chain_stage):
        """Test pretty format: [4] Exploitation."""
        row = pd.Series(
            {"rule_id": "test_rule", "kill_chain_stage": mock_kill_chain_stage}
        )

        result = enrich_kill_chain_data(row)

        assert result["kill_chain_pretty"].startswith("[4]")
        assert "Exploitation" in result["kill_chain_pretty"]

    @pytest.mark.unit
    def test_enrich_with_none_kill_chain(self):
        """Test handling of None kill chain stage."""
        row = pd.Series({"rule_id": "test_rule", "kill_chain_stage": None})

        result = enrich_kill_chain_data(row)

        assert result["kill_chain_id"] is None
        assert result["kill_chain_pretty"] is None


# ===== Test Data Pipeline Integration =====


class TestDataPipeline:
    """Test the complete data processing pipeline."""

    @pytest.mark.integration
    def test_stage_1_explode_techniques(self, sample_classified_output):
        """Test Stage 1: Explode technique_ids correctly."""
        input_df = load_detection_rules(sample_classified_output)
        original_count = len(input_df)

        # Stage 1: Explode techniques
        rule_techniques_df = input_df.explode("technique_ids").rename(
            columns={"technique_ids": "technique_id"}
        )

        # Should have more rows after exploding (since each rule has multiple
        # techniques)
        assert len(rule_techniques_df) >= original_count
        assert "technique_id" in rule_techniques_df.columns

    @pytest.mark.integration
    def test_stage_2_enrich_techniques_preserves_rows(self, sample_classified_output):
        """Test Stage 2: Enrich techniques preserves row count."""
        input_df = load_detection_rules(sample_classified_output)

        # Stage 1: Explode
        rule_techniques_df = input_df.explode("technique_ids").rename(
            columns={"technique_ids": "technique_id"}
        )
        count_before_enrich = len(rule_techniques_df)

        # Stage 2: Enrich
        rule_techniques_df = rule_techniques_df.apply(enrich_technique_data, axis=1)

        # Row count should be preserved
        assert len(rule_techniques_df) == count_before_enrich
        assert "ts_or_st_pretty" in rule_techniques_df.columns
        assert "tactics" in rule_techniques_df.columns

    @pytest.mark.integration
    def test_stage_3_explode_tactics_increases_rows(self, sample_rule_techniques_df):
        """Test Stage 3: Explode tactics increases rows correctly."""
        original_count = len(sample_rule_techniques_df)

        # Stage 3: Explode tactics
        rule_tactics_df = sample_rule_techniques_df.explode("tactics").rename(
            columns={"tactics": "tactic"}
        )

        # Should have same or more rows (techniques can have multiple tactics)
        assert len(rule_tactics_df) >= original_count
        assert "tactic" in rule_tactics_df.columns

    @pytest.mark.integration
    def test_stage_4_enrich_tactics_adds_columns(self, sample_rule_techniques_df):
        """Test Stage 4: Enrich tactics adds correct columns."""
        # Stage 3: Explode tactics
        rule_tactics_df = sample_rule_techniques_df.explode("tactics").rename(
            columns={"tactics": "tactic"}
        )

        # Stage 4: Enrich tactics
        rule_tactics_df = rule_tactics_df.apply(enrich_tactic_data, axis=1)

        # Verify new columns added
        assert "tactic_id" in rule_tactics_df.columns
        assert "tactic_pretty" in rule_tactics_df.columns
        assert "kill_chain_stages" in rule_tactics_df.columns

    @pytest.mark.integration
    def test_stage_5_explode_kill_chains_creates_full_disaggregation(
        self, sample_rule_tactics_df
    ):
        """Test Stage 5: Explode kill chains creates full disaggregation."""
        # Stage 5: Explode kill chain stages
        rule_kill_chains_df = sample_rule_tactics_df.explode(
            "kill_chain_stages"
        ).rename(columns={"kill_chain_stages": "kill_chain_stage"})

        # Verify kill_chain_stage column exists
        assert "kill_chain_stage" in rule_kill_chains_df.columns

        # Verify we have fully disaggregated data
        # (one row per rule-technique-tactic-killchain)
        assert len(rule_kill_chains_df) >= len(sample_rule_tactics_df)

    @pytest.mark.integration
    def test_stage_6_enrich_kill_chains_completes_pipeline(
        self, sample_rule_tactics_df
    ):
        """Test Stage 6: Enrich kill chains completes the pipeline."""
        # Stage 5: Explode
        rule_kill_chains_df = sample_rule_tactics_df.explode(
            "kill_chain_stages"
        ).rename(columns={"kill_chain_stages": "kill_chain_stage"})

        # Stage 6: Enrich
        rule_kill_chains_df = rule_kill_chains_df.apply(enrich_kill_chain_data, axis=1)

        # Verify final columns exist
        assert "kill_chain_id" in rule_kill_chains_df.columns
        assert "kill_chain_pretty" in rule_kill_chains_df.columns

        # Verify we have complete data
        assert len(rule_kill_chains_df) > 0


# ===== Test Aggregation Correctness (HIGH PRIORITY) =====


class TestAggregationCorrectness:
    """Test data aggregation correctness - ensuring uniqueness, completeness, and correctness."""

    aggregations = {
        "ts_or_st_pretty": lambda x: tuple(set(x)),
        "tactic_pretty": lambda x: tuple(set(x)),
        "kill_chain_pretty": lambda x: tuple(set(x)),
    }

    def verify_no_duplicates(self, result):
        """Verify no duplicates in tuples."""
        for _, row in result.iterrows():
            assert len(row["ts_or_st_pretty"]) == len(set(row["ts_or_st_pretty"]))
            assert len(row["tactic_pretty"]) == len(set(row["tactic_pretty"]))
            assert len(row["kill_chain_pretty"]) == len(set(row["kill_chain_pretty"]))

    @pytest.mark.unit
    def test_rule_tactics_pretty_df_groupby(self, sample_rule_kill_chains_df):
        """Test groupby(rule_id, technique_id, tactic_id) for rule_tactics_pretty_df."""
        # Aggregate by rule_id, technique_id, tactic_id
        result = (
            sample_rule_kill_chains_df.groupby(["rule_id", "technique_id", "tactic_id"])
            .agg(self.aggregations)
            .reset_index()
        )

        # Verify no duplicates in tuples
        self.verify_no_duplicates(result)

    @pytest.mark.unit
    def test_unique_technique_values_per_group(self, sample_rule_kill_chains_df):
        """Test that technique values are unique within each group."""
        result = (
            sample_rule_kill_chains_df.groupby(["rule_id", "technique_id", "tactic_id"])
            .agg({"ts_or_st_pretty": lambda x: tuple(set(x))})
            .reset_index()
        )

        # Each group should have exactly 1 unique technique pretty string
        for _, row in result.iterrows():
            assert len(row["ts_or_st_pretty"]) == 1

    @pytest.mark.unit
    def test_unique_tactic_values_per_group(self, sample_rule_kill_chains_df):
        """Test that tactic values are unique within each group."""
        result = (
            sample_rule_kill_chains_df.groupby(["rule_id", "technique_id", "tactic_id"])
            .agg({"tactic_pretty": lambda x: tuple(set(x))})
            .reset_index()
        )

        # Each group should have exactly 1 unique tactic pretty string
        for _, row in result.iterrows():
            assert len(row["tactic_pretty"]) == 1

    @pytest.mark.unit
    def test_rule_techniques_pretty_df_aggregation(self, sample_rule_kill_chains_df):
        """Test groupby(rule_id, technique_id) for rule_techniques_pretty_df."""
        result = (
            sample_rule_kill_chains_df.groupby(["rule_id", "technique_id"])
            .agg(self.aggregations)
            .reset_index()
        )

        # Verify aggregation worked
        assert len(result) > 0

        # Verify no data loss - each rule_id should appear at least once
        rule_ids_in_result = set(result["rule_id"].unique())
        rule_ids_in_original = set(sample_rule_kill_chains_df["rule_id"].unique())
        assert rule_ids_in_result == rule_ids_in_original

    @pytest.mark.unit
    def test_no_duplicate_techniques_per_rule(self, sample_rule_kill_chains_df):
        """Test that rule_techniques_pretty_df has no duplicate techniques per rule."""
        result = (
            sample_rule_kill_chains_df.groupby(["rule_id", "technique_id"])
            .agg({"ts_or_st_pretty": lambda x: tuple(set(x))})
            .reset_index()
        )

        # Check no duplicates within each rule
        for rule_id in result["rule_id"].unique():
            rule_data = result[result["rule_id"] == rule_id]
            technique_ids = rule_data["technique_id"].tolist()
            assert len(technique_ids) == len(set(technique_ids))

    @pytest.mark.unit
    def test_rules_pretty_df_aggregation(self, sample_rule_kill_chains_df):
        """Test groupby(rule_id) for rules_pretty_df aggregates all data correctly."""
        result = (
            sample_rule_kill_chains_df.groupby("rule_id")
            .agg(self.aggregations)
            .reset_index()
        )

        # Each rule should appear exactly once
        assert len(result) == len(sample_rule_kill_chains_df["rule_id"].unique())

        # Verify tuples contain unique values
        self.verify_no_duplicates(result)

    @pytest.mark.unit
    def test_all_techniques_aggregated_correctly(self, sample_rule_kill_chains_df):
        """Test that all techniques are preserved during aggregation."""
        # Get unique techniques from original data
        original_techniques = set(sample_rule_kill_chains_df["technique_id"].unique())

        # Aggregate by rule_id
        result = (
            sample_rule_kill_chains_df.groupby("rule_id")
            .agg({"technique_id": lambda x: list(set(x))})
            .reset_index()
        )

        # Collect all techniques from aggregated data
        aggregated_techniques = set()
        for _, row in result.iterrows():
            aggregated_techniques.update(row["technique_id"])

        # No techniques should be lost
        assert original_techniques == aggregated_techniques

    @pytest.mark.unit
    def test_all_tactics_aggregated_correctly(self, sample_rule_kill_chains_df):
        """Test that all tactics are preserved during aggregation."""
        # Get unique tactics from original data
        original_tactics = set(
            sample_rule_kill_chains_df["tactic_id"].dropna().unique()
        )

        # Aggregate by rule_id
        result = (
            sample_rule_kill_chains_df.groupby("rule_id")
            .agg({"tactic_id": lambda x: list(set(x.dropna()))})
            .reset_index()
        )

        # Collect all tactics from aggregated data
        aggregated_tactics = set()
        for _, row in result.iterrows():
            aggregated_tactics.update(row["tactic_id"])

        # No tactics should be lost
        assert original_tactics == aggregated_tactics


# ===== Test parse_args() =====


class TestParseArgs:
    """Test CLI argument parsing."""

    @pytest.mark.unit
    def test_default_arguments(self):
        """Test default argument values."""
        args = parse_args([])
        assert (
            args.classified_output_file_path
            == "output/aggregation/aggregated_data.json"
        )

    @pytest.mark.unit
    def test_custom_file_path(self):
        """Test custom file path argument."""
        custom_path = "/custom/path/to/output.json"
        args = parse_args(["--classified-output-file-path", custom_path])
        assert args.classified_output_file_path == custom_path

    @pytest.mark.unit
    def test_url_path(self):
        """Test URL as file path."""
        url = "https://example.com/data.json"
        args = parse_args(["--classified-output-file-path", url])
        assert args.classified_output_file_path == url
