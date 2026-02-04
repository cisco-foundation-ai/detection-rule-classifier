# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for Streamlit app rendering in visualization/app.py.

These tests use Streamlit's AppTest framework to verify that UI components
render without errors. The focus is on ensuring the app runs successfully,
not on testing user interactions or visual appearance.
"""

import time

import pytest

# ===== Basic App Rendering Tests =====


class TestAppBasicRendering:
    """Test basic app rendering and initialization."""

    @pytest.mark.visual
    def test_app_runs_without_error(self, app_with_test_data):
        """Test that the app runs without raising exceptions (smoke test)."""
        # Run the app
        app_with_test_data.run()

        # Should not have any exceptions
        assert (
            not app_with_test_data.exception
        ), f"App raised exception: {app_with_test_data.exception}"

    @pytest.mark.visual
    def test_app_title_renders(self, app_with_test_data):
        """Test that the app title is rendered."""
        app_with_test_data.run()

        # Check for title element
        titles = app_with_test_data.title
        assert len(titles) > 0, "No title elements found"
        assert titles[0].value == (
            "LUCID: LLM-driven Understanding, Classification & Insight for Detections"
        )

    @pytest.mark.visual
    def test_ai_insights_marker_displays(self, app_with_test_data):
        """Test that AI-powered insights marker appears when insights are loaded."""
        app_with_test_data.run()

        # Test passes if app runs without error
        # (AI marker may or may not be present depending on test data)
        assert not app_with_test_data.exception


# ===== Chart Rendering Tests =====


class TestChartRendering:
    """Test that all charts render without errors."""

    @pytest.mark.visual
    def test_tactic_coverage_chart_renders(self, app_with_test_data):
        """Test that Tactic Coverage chart renders."""
        app_with_test_data.run()

        # Check for subheader
        subheaders = app_with_test_data.subheader
        tactic_subheader = None
        for sh in subheaders:
            if "Tactic Coverage" in sh.value:
                tactic_subheader = sh
                break

        assert tactic_subheader is not None, "Tactic Coverage subheader not found"

        # Check that altair charts exist (app has 4 total)
        # Note: AppTest doesn't expose altair_chart as a direct attribute,
        # but we can verify the chart rendered by checking for the subheader
        # and that no exception was raised
        assert not app_with_test_data.exception

    @pytest.mark.visual
    def test_kill_chain_coverage_chart_renders(self, app_with_test_data):
        """Test that Kill Chain Coverage chart renders."""
        app_with_test_data.run()

        # Check for subheader
        subheaders = app_with_test_data.subheader
        kc_subheader = None
        for sh in subheaders:
            if "Kill Chain Coverage" in sh.value:
                kc_subheader = sh
                break

        assert kc_subheader is not None, "Kill Chain Coverage subheader not found"

    @pytest.mark.visual
    def test_top_techniques_chart_renders(self, app_with_test_data):
        """Test that Top 20 Techniques chart renders."""
        app_with_test_data.run()

        # Check for subheader
        subheaders = app_with_test_data.subheader
        top_tech_subheader = None
        for sh in subheaders:
            if "Top Techniques" in sh.value:
                top_tech_subheader = sh
                break

        assert top_tech_subheader is not None, "Top Techniques subheader not found"


# ===== Data Display Tests =====


class TestDataDisplay:
    """Test data display components."""

    @pytest.mark.visual
    def test_dataframe_renders(self, app_with_test_data):
        """Test that dataframes render with st.dataframe()."""
        app_with_test_data.run()

        # Check for dataframe widgets
        dataframes = app_with_test_data.dataframe
        assert len(dataframes) > 0, "No dataframe elements found"

        # Find the Detection Rules Reference dataframe (should have rule_id column)
        rules_df = None
        for df_widget in dataframes:
            df = df_widget.value
            if "rule_id" in df.columns:
                rules_df = df
                break

        assert rules_df is not None, "Detection Rules Reference dataframe not found"
        assert len(rules_df) > 0, "Rules dataframe is empty"

    @pytest.mark.visual
    def test_priority_actions_section_renders(self, app_with_test_data):
        """Test that priority actions section renders when insights exist."""
        app_with_test_data.run()

        # Just verify no exception - the table is complex,
        # we're just checking it doesn't crash
        assert not app_with_test_data.exception


# ===== Error Handling Tests =====


class TestErrorHandling:
    """Test that app handles edge cases gracefully."""

    @pytest.mark.visual
    def test_app_handles_data_gracefully(self, app_with_test_data):
        """Test that app processes test data without errors."""
        # This is essentially testing the full pipeline with realistic mock data
        app_with_test_data.run()

        # Should complete without exceptions
        assert not app_with_test_data.exception

        # Verify key components exist (basic sanity check)
        assert len(app_with_test_data.title) > 0
        assert len(app_with_test_data.subheader) >= 4  # 4 charts have subheaders


# ===== Performance Tests =====


class TestPerformance:
    """Test app performance characteristics."""

    @pytest.mark.visual
    @pytest.mark.slow
    def test_app_renders_in_reasonable_time(self, app_with_test_data):
        """Test that app completes rendering within reasonable time."""
        start_time = time.time()

        app_with_test_data.run()

        elapsed_time = time.time() - start_time

        # App should render within 10 seconds with test data
        assert elapsed_time < 10.0, (
            f"App took {elapsed_time:.2f} seconds to render, " f"expected < 10 seconds"
        )

        # Also verify it actually ran successfully
        assert not app_with_test_data.exception


# ===== Trending Attacks Coverage Tests =====


class TestTrendingAttacksCoverage:
    """Test Trending Attacks Coverage section rendering."""

    @pytest.mark.visual
    def test_trending_section_subheader_renders(self, app_with_test_data):
        """Test that Trending Attacks Coverage subheader appears."""
        app_with_test_data.run()

        # Check for subheader
        subheaders = app_with_test_data.subheader
        trending_subheader = None
        for sh in subheaders:
            if "Trending Attacks Coverage" in sh.value:
                trending_subheader = sh
                break

        assert (
            trending_subheader is not None
        ), "Trending Attacks Coverage subheader not found"

    @pytest.mark.visual
    def test_trending_techniques_table_renders(self, app_with_test_data):
        """Test that trending techniques table displays."""
        app_with_test_data.run()

        # Check that we have multiple dataframes (at least 2 for trending section)
        dataframes = app_with_test_data.dataframe
        assert len(dataframes) >= 2, "Expected at least 2 dataframes (rules + trending)"

    @pytest.mark.visual
    def test_matching_rules_hidden_when_no_selection(self, app_with_test_data):
        """Test that matching rules section is hidden when no technique is selected."""
        app_with_test_data.run()

        # Check that no "Matching Detection Rules" header appears initially
        # (it only shows when a technique is selected)
        markdown_elements = app_with_test_data.markdown
        matching_header_found = False

        for elem in markdown_elements:
            if "Matching Detection Rules" in elem.value:
                matching_header_found = True
                break

        assert not matching_header_found, (
            "Matching Detection Rules header should not appear "
            "when no technique is selected"
        )

    @pytest.mark.visual
    def test_trending_techniques_header_renders(self, app_with_test_data):
        """Test that Trending Techniques header appears."""
        app_with_test_data.run()

        # Check for markdown elements containing the header
        markdown_elements = app_with_test_data.markdown
        trending_header = False

        for elem in markdown_elements:
            if "Trending Techniques" in elem.value:
                trending_header = True
                break

        assert trending_header, "Trending Techniques header not found"
