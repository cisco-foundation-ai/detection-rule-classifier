# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for chart creation functions in visualization/charts.py."""

import altair as alt
import pytest
from visualization.charts import (
    create_kill_chain_coverage_chart,
    create_sankey_chart,
    create_tactic_coverage_chart,
    create_top_techniques_chart,
)

# ===== Test Tactic Coverage Chart =====


class TestTacticCoverageChart:
    """Test the create_tactic_coverage_chart function."""

    @pytest.mark.unit
    def test_creates_valid_altair_chart(self, sample_rule_tactics_df):
        """Test that function returns a valid Altair Chart object."""
        top_techniques = [
            "[T1059] Command and Scripting Interpreter",
            "[T1027] Obfuscated Files or Information",
        ]
        tactic_order = ["Execution", "Defense Evasion", "Persistence"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        assert isinstance(chart, alt.Chart)

    @pytest.mark.unit
    def test_chart_has_bar_mark(self, sample_rule_tactics_df):
        """Test that chart uses bar mark."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        tactic_order = ["Execution", "Defense Evasion"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        assert chart.mark == "bar"

    @pytest.mark.unit
    def test_x_encoding_is_quantitative(self, sample_rule_tactics_df):
        """Test that X-axis encoding is quantitative (sum of rule mappings)."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        tactic_order = ["Execution"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        spec = chart.to_dict()
        assert "encoding" in spec
        assert "x" in spec["encoding"]
        # X should aggregate rule_mappings with sum
        x_spec = spec["encoding"]["x"]
        assert x_spec.get("aggregate") == "sum"
        assert x_spec.get("field") == "rule_mappings"
        assert x_spec.get("type") == "quantitative"

    @pytest.mark.unit
    def test_y_encoding_uses_tactic_order(self, sample_rule_tactics_df):
        """Test that Y-axis encoding uses provided tactic order."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        tactic_order = ["Execution", "Defense Evasion", "Persistence"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        spec = chart.to_dict()
        assert "y" in spec["encoding"]
        # Y-axis should have tactic_name field
        assert "tactic_name" in str(spec["encoding"]["y"])

    @pytest.mark.unit
    def test_color_encoding_by_technique(self, sample_rule_tactics_df):
        """Test that color encodes technique category."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        tactic_order = ["Execution"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        spec = chart.to_dict()
        assert "color" in spec["encoding"]
        # Color should encode color_category
        assert "color_category" in str(spec["encoding"]["color"])

    @pytest.mark.unit
    def test_chart_height_set(self, sample_rule_tactics_df):
        """Test that chart height is set to 400."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        tactic_order = ["Execution"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        assert chart.height == 400

    @pytest.mark.unit
    def test_has_order_encoding(self, sample_rule_tactics_df):
        """Test that chart has order encoding to sort techniques by size."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        tactic_order = ["Execution"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        spec = chart.to_dict()
        _assert_order_encoding(spec)

    @pytest.mark.unit
    def test_color_uses_custom_scale(self, sample_rule_tactics_df):
        """Test that color encoding uses custom scale with domain and range."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        tactic_order = ["Execution"]
        chart = create_tactic_coverage_chart(
            sample_rule_tactics_df, top_techniques, tactic_order
        )

        spec = chart.to_dict()
        _assert_color_scale(spec)


# ===== Test Kill Chain Coverage Chart =====


class TestKillChainCoverageChart:
    """Test the create_kill_chain_coverage_chart function."""

    @pytest.mark.unit
    def test_creates_valid_altair_chart(self, sample_rule_kill_chains_df):
        """Test that function returns a valid Altair Chart object."""
        top_techniques = [
            "[T1059] Command and Scripting Interpreter",
            "[T1027] Obfuscated Files or Information",
        ]
        kill_chain_order = ["[4] Exploitation", "[5] Installation"]
        chart = create_kill_chain_coverage_chart(
            sample_rule_kill_chains_df, top_techniques, kill_chain_order
        )

        assert isinstance(chart, alt.Chart)

    @pytest.mark.unit
    def test_chart_has_bar_mark(self, sample_rule_kill_chains_df):
        """Test that chart uses bar mark."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        kill_chain_order = ["[4] Exploitation"]
        chart = create_kill_chain_coverage_chart(
            sample_rule_kill_chains_df, top_techniques, kill_chain_order
        )

        assert chart.mark == "bar"

    @pytest.mark.unit
    def test_y_encoding_uses_kill_chain_order(self, sample_rule_kill_chains_df):
        """Test that Y-axis encoding uses provided kill chain order."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        kill_chain_order = ["[4] Exploitation", "[5] Installation", "[7] Actions"]
        chart = create_kill_chain_coverage_chart(
            sample_rule_kill_chains_df, top_techniques, kill_chain_order
        )

        spec = chart.to_dict()
        assert "y" in spec["encoding"]
        # Y-axis should have kill_chain_pretty field
        assert "kill_chain_pretty" in str(spec["encoding"]["y"])

    @pytest.mark.unit
    def test_chart_height_set(self, sample_rule_kill_chains_df):
        """Test that chart height is set to 400."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        kill_chain_order = ["[4] Exploitation"]
        chart = create_kill_chain_coverage_chart(
            sample_rule_kill_chains_df, top_techniques, kill_chain_order
        )

        assert chart.height == 400

    @pytest.mark.unit
    def test_has_order_encoding(self, sample_rule_kill_chains_df):
        """Test that chart has order encoding to sort techniques by size."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        kill_chain_order = ["[4] Exploitation"]
        chart = create_kill_chain_coverage_chart(
            sample_rule_kill_chains_df, top_techniques, kill_chain_order
        )

        spec = chart.to_dict()
        _assert_order_encoding(spec)

    @pytest.mark.unit
    def test_color_uses_custom_scale(self, sample_rule_kill_chains_df):
        """Test that color encoding uses custom scale with domain and range."""
        top_techniques = ["[T1059] Command and Scripting Interpreter"]
        kill_chain_order = ["[4] Exploitation"]
        chart = create_kill_chain_coverage_chart(
            sample_rule_kill_chains_df, top_techniques, kill_chain_order
        )

        spec = chart.to_dict()
        _assert_color_scale(spec)


# ===== Test Tactic/Kill-Chain Heatmap =====


# ===== Test Top Techniques Chart =====


class TestTopTechniquesChart:
    """Test the create_top_techniques_chart function."""

    @pytest.mark.unit
    def test_creates_valid_altair_chart(self, technique_counts_fixture):
        """Test that function returns a valid Altair Chart object."""
        top_techniques = ["[T0001] Technique 1", "[T0002] Technique 2"]
        chart = create_top_techniques_chart(technique_counts_fixture, top_techniques)

        assert isinstance(chart, alt.Chart)

    @pytest.mark.unit
    def test_chart_has_bar_mark(self, technique_counts_fixture):
        """Test that chart uses bar mark."""
        top_techniques = ["[T0001] Technique 1"]
        chart = create_top_techniques_chart(technique_counts_fixture, top_techniques)

        assert chart.mark == "bar"

    @pytest.mark.unit
    def test_y_encoding_sorted_descending(self, technique_counts_fixture):
        """Test that Y-axis encoding has parent technique names."""
        top_techniques = ["[T0001] Technique 1"]
        chart = create_top_techniques_chart(technique_counts_fixture, top_techniques)

        spec = chart.to_dict()
        assert "y" in spec["encoding"]
        # Y-axis should have parent_technique_name field
        y_spec = str(spec["encoding"]["y"])
        assert "parent_technique_name" in y_spec

    @pytest.mark.unit
    def test_chart_height_set(self, technique_counts_fixture):
        """Test that chart height is set to 500."""
        top_techniques = ["[T0001] Technique 1"]
        chart = create_top_techniques_chart(technique_counts_fixture, top_techniques)

        assert chart.height == 500


class TestSankeyChart:
    """Test the create_sankey_chart function."""

    @pytest.mark.unit
    def test_creates_plotly_sankey(self, sample_rule_kill_chains_df):
        chart = create_sankey_chart(
            sample_rule_kill_chains_df,
            ["kill_chain_pretty", "ts_or_st_pretty", "tactic_pretty"],
        )

        assert chart.to_dict()["data"][0]["type"] == "sankey"


def _assert_color_scale(spec):
    assert "color" in spec["encoding"]
    color_spec = spec["encoding"]["color"]
    assert "scale" in color_spec
    scale = color_spec["scale"]
    assert "domain" in scale
    assert "range" in scale
    assert len(scale["domain"]) > 0


def _assert_order_encoding(spec):
    assert "order" in spec["encoding"]
    order_spec = spec["encoding"]["order"]
    assert order_spec.get("field") == "rule_mappings"
    assert order_spec.get("sort") == "descending"
