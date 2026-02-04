# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared pytest fixtures for visualization tests."""

# pylint: disable=redefined-outer-name,unused-argument,import-outside-toplevel
# pylint: disable=broad-exception-caught

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from visualization.tests.fixtures.sample_data import (
    KILL_CHAIN_EXPLOITATION,
    SAMPLE_CLASSIFICATION_DATA,
    SUB_TECHNIQUE_T1059_001,
    TACTIC_CREDENTIAL_ACCESS,
    TACTIC_DEFENSE_EVASION,
    TACTIC_EXECUTION,
    TACTIC_PERSISTENCE,
    TECHNIQUE_T1059,
    get_mock_sub_technique_by_id,
    get_mock_technique_by_id,
)

# ===== Mock MITRE Mapper Fixtures =====


@pytest.fixture
def mock_kill_chain_stage():
    """Return a mock CyberKillChainStage object."""
    return KILL_CHAIN_EXPLOITATION


@pytest.fixture
def mock_tactic(mock_kill_chain_stage):
    """Return a mock Tactic object."""
    return TACTIC_EXECUTION


@pytest.fixture
def mock_technique(mock_tactic):
    """Return a mock Technique object."""
    return TECHNIQUE_T1059


@pytest.fixture
def mock_sub_technique(mock_technique):
    """Return a mock SubTechnique object."""
    return SUB_TECHNIQUE_T1059_001


@pytest.fixture
def mock_mapper():
    """Mock the MITRE ATT&CK mapper with comprehensive test data."""
    mapper = MagicMock()

    # Configure get_technique to return mock techniques
    def get_technique_side_effect(technique_id):
        return get_mock_technique_by_id(technique_id)

    mapper.get_technique.side_effect = get_technique_side_effect

    # Configure get_sub_technique to return mock sub-techniques
    def get_sub_technique_side_effect(sub_technique_id):
        return get_mock_sub_technique_by_id(sub_technique_id)

    mapper.get_sub_technique.side_effect = get_sub_technique_side_effect

    return mapper


@pytest.fixture
def patch_mapper(mock_mapper):
    """Patch get_mapper() to return mock throughout test."""
    # Patch both the module import and the direct import in app.py
    with patch(
        "mitre_mapping.mitre_attack_mapper.get_mapper", return_value=mock_mapper
    ):
        with patch("visualization.app.get_mapper", return_value=mock_mapper):
            yield mock_mapper


# ===== Sample Data Fixtures =====


@pytest.fixture
def sample_classified_output(tmp_path):
    """Create a temporary JSON file with sample classified output."""
    file_path = tmp_path / "classified_output.json"
    file_path.write_text(json.dumps(SAMPLE_CLASSIFICATION_DATA))
    return str(file_path)


@pytest.fixture
def sample_classification_data():
    """Return sample classification data as Python list."""
    return SAMPLE_CLASSIFICATION_DATA


# ===== Streamlit-Specific Fixtures =====


@pytest.fixture
def disable_streamlit_cache():
    """Disable Streamlit caching for tests."""
    # Patch the cache_data decorator to be a no-op
    with patch("streamlit.cache_data", lambda func: func):
        yield


@pytest.fixture(autouse=True)
def reset_streamlit_state():
    """Reset Streamlit state between tests."""
    yield
    # Clear any cached data after each test
    try:
        import streamlit as st

        st.cache_data.clear()
    except Exception:
        # Ignore errors if Streamlit isn't fully initialized
        pass


# ===== DataFrame Fixtures for Aggregation Tests =====


@pytest.fixture
def sample_rule_techniques_df(patch_mapper):
    """Create a sample rule_techniques_df for testing aggregations."""
    data = {
        "rule_id": [
            "test_rule_1.yml",
            "test_rule_1.yml",
            "test_rule_2.yml",
            "test_rule_3.yml",
            "test_rule_3.yml",
        ],
        "technique_id": [
            "T1059.001",
            "T1027",
            "T1558.003",
            "T1059",
            "T1098.001",
        ],
        "ts_or_st_pretty": [
            "[T1059.001] Command and Scripting Interpreter > PowerShell",
            "[T1027] Obfuscated Files or Information",
            "[T1558.003] Steal or Forge Kerberos Tickets > Kerberoasting",
            "[T1059] Command and Scripting Interpreter",
            "[T1098.001] Account Manipulation > Additional Cloud Credentials",
        ],
        "tactics": [
            [TACTIC_EXECUTION],
            [TACTIC_DEFENSE_EVASION],
            [TACTIC_CREDENTIAL_ACCESS],
            [TACTIC_EXECUTION],
            [TACTIC_PERSISTENCE],
        ],
    }
    return pd.DataFrame(data)


@pytest.fixture
def sample_rule_tactics_df(sample_rule_techniques_df):
    """Create a sample rule_tactics_df by exploding tactics."""
    df = sample_rule_techniques_df.explode("tactics").rename(
        columns={"tactics": "tactic"}
    )

    # Add tactic enrichment columns
    df["tactic_id"] = df["tactic"].apply(lambda t: t.id if t else None)
    df["tactic_pretty"] = df["tactic"].apply(
        lambda t: f"[{t.id}] {t.name}" if t else None
    )
    df["kill_chain_stages"] = df["tactic"].apply(
        lambda t: t.kill_chain_stages if t else []
    )
    df["tactic_name"] = df["tactic"].apply(lambda t: t.name if t else None)

    return df


@pytest.fixture
def sample_rule_kill_chains_df(sample_rule_tactics_df):
    """Create a sample rule_kill_chains_df by exploding kill chain stages."""
    df = sample_rule_tactics_df.explode("kill_chain_stages").rename(
        columns={"kill_chain_stages": "kill_chain_stage"}
    )

    # Add kill chain enrichment columns
    df["kill_chain_id"] = df["kill_chain_stage"].apply(
        lambda kc: kc.kill_chain_step_number if kc else None
    )
    df["kill_chain_pretty"] = df["kill_chain_stage"].apply(
        lambda kc: f"[{kc.kill_chain_step_number}] {kc.name}" if kc else None
    )
    df["kill_chain_name"] = df["kill_chain_stage"].apply(
        lambda kc: kc.name if kc else None
    )

    return df


# ===== Chart Data Fixtures =====


@pytest.fixture
def technique_counts_fixture():
    """Sample data for top techniques chart with stacked subtechniques."""
    # Create sample data with parent techniques and subtechniques
    data = []
    for i in range(1, 11):  # 10 parent techniques
        parent_id = f"T{i:04d}"
        parent_name = f"[{parent_id}] Technique {i}"

        # Add parent technique (without subtechnique)
        data.append(
            {
                "parent_technique_id": parent_id,
                "parent_technique_name": parent_name,
                "technique_id": parent_id,
                "ts_or_st_pretty": parent_name,
                "rule_count": 20 - (i * 2),
            }
        )

        # Add 2 subtechniques for some techniques
        if i <= 5:
            for j in range(1, 3):
                sub_id = f"{parent_id}.{j:03d}"
                sub_name = f"{parent_name} > Subtechnique {j}"
                data.append(
                    {
                        "parent_technique_id": parent_id,
                        "parent_technique_name": parent_name,
                        "technique_id": sub_id,
                        "ts_or_st_pretty": sub_name,
                        "rule_count": 5 - j,
                    }
                )

    return pd.DataFrame(data)


# ===== Trending Techniques Fixtures =====


@pytest.fixture
def sample_trending_techniques():
    """Sample trending techniques data for testing."""
    return pd.DataFrame(
        {
            "technique_id": ["T1059.001", "T1027", "T1558.003", "T1999"],
            "mentions_in_incidents_percent": [29.8, 26.6, 21.7, 15.0],
        }
    )


@pytest.fixture
def sample_trending_enriched_df(sample_trending_techniques, sample_rule_techniques_df):
    """Sample enriched trending techniques with rule counts."""
    # This simulates the output of enrich_trending_techniques()
    return pd.DataFrame(
        {
            "technique_id": ["T1059.001", "T1027", "T1558.003", "T1999"],
            "technique_pretty": [
                "[T1059.001] Command and Scripting Interpreter > PowerShell",
                "[T1027] Obfuscated Files or Information",
                "[T1558.003] Steal or Forge Kerberos Tickets > Kerberoasting",
                "[T1999] Unknown",
            ],
            "mentions_in_incidents_percent": [29.8, 26.6, 21.7, 15.0],
            "rule_count": [1, 1, 1, 0],  # Based on sample_rule_techniques_df
        }
    )


@pytest.fixture
def sample_rules_pretty_df():
    """Sample rules_pretty_df for testing get_matching_rules."""
    return pd.DataFrame(
        {
            "rule_id": ["test_rule_1.yml", "test_rule_2.yml", "test_rule_3.yml"],
            "technique": [
                ("[T1059.001] PowerShell", "[T1027] Obfuscation"),
                ("[T1558.003] Kerberoasting",),
                ("[T1059] Command Interpreter", "[T1098.001] Cloud Credentials"),
            ],
            "tactic": [
                ("[TA0002] Execution", "[TA0005] Defense Evasion"),
                ("[TA0006] Credential Access",),
                ("[TA0002] Execution", "[TA0003] Persistence"),
            ],
            "kill_chain": [
                ("[4] Exploitation",),
                ("[7] Actions on Objectives",),
                ("[4] Exploitation", "[5] Installation"),
            ],
        }
    )


# ===== AppTest Fixtures for Visual/UI Testing =====


@pytest.fixture
def app_with_test_data(sample_classified_output, patch_mapper, disable_streamlit_cache):
    """Create AppTest instance configured with test data.

    This fixture sets up a Streamlit AppTest with:
    - Mock MITRE mapper (via patch_mapper)
    - Test classification data (via sample_classified_output)
    - Disabled caching (via disable_streamlit_cache)

    Returns:
        AppTest: Configured Streamlit AppTest instance ready to run
    """
    from streamlit.testing.v1 import AppTest

    # Get absolute path to app.py
    app_path = Path(__file__).parent.parent / "app.py"

    # Create AppTest instance with extended timeout for data processing
    at = AppTest.from_file(str(app_path), default_timeout=15.0)

    # Configure secrets to point to test data file
    at.secrets["classified_output_file_path"] = sample_classified_output

    return at
