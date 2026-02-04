# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared enrichment functions for MITRE ATT&CK data.

This module provides enrichment functions used by both the aggregation pipeline
and visualization layer. By centralizing these functions, we ensure consistency
and reduce code duplication.

The enrichment functions add human-readable formatting and cross-references
between MITRE ATT&CK entities (techniques, tactics, kill-chain stages).
"""

from typing import List, Union

import pandas as pd

from mitre_mapping.mitre_attack_mapper import get_mapper

# Canonical MITRE ATT&CK Enterprise tactic order.
# Reference: https://attack.mitre.org/tactics/enterprise/
canonical_tactic_order = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def sort_tactics(tactics_to_sort: Union[List[str], set]) -> List[str]:
    """
    Filter and sort tactics based on canonical MITRE ATT&CK Enterprise order.

    Args:
        tactics_to_sort: Tactic names to sort (list or set)

    Returns:
        List of tactics sorted by canonical order, containing only tactics
        that are present in the input

    Example:
        >>> sort_tactics(["Impact", "Execution", "Unknown Tactic"])
        ["Execution", "Impact"]
    """
    return [tactic for tactic in canonical_tactic_order if tactic in tactics_to_sort]


def enrich_technique_data(row: pd.Series) -> pd.Series:
    """
    Enrich a row with technique/subtechnique data from MITRE ATT&CK.

    This function adds the following columns to the row:
    - ts_or_st_pretty: Pretty formatted technique or subtechnique string
      Format for techniques: "[T1234] Technique Name"
      Format for sub-techniques: "[T1234.001] Parent Technique > Sub-technique Name"
    - tactics: List of tactic objects associated with this technique

    Args:
        row: DataFrame row containing a 'technique_id' column

    Returns:
        The same row with added enrichment columns

    Example:
        >>> row = pd.Series({"technique_id": "T1059"})
        >>> enriched = enrich_technique_data(row)
        >>> enriched["ts_or_st_pretty"]
        "[T1059] Command and Scripting Interpreter"
    """
    mapper = get_mapper()
    technique_id = row["technique_id"]

    if not technique_id:
        row["ts_or_st_pretty"] = None
        row["tactics"] = []
        return row

    if "." in technique_id:
        # It's a sub-technique
        sub_tech = mapper.get_sub_technique(technique_id)
        if sub_tech:
            # Format: "[T1098.001] Account Manipulation > Additional Cloud Credentials"
            row["ts_or_st_pretty"] = (
                f"[{sub_tech.id}] {sub_tech.technique.name} > {sub_tech.name}"
            )
            # Get tactics from parent technique
            row["tactics"] = sub_tech.technique.tactics
        else:
            row["ts_or_st_pretty"] = None
            row["tactics"] = []
    else:
        # It's a technique
        tech = mapper.get_technique(technique_id)
        if tech:
            # Format: "[T1234] Foo"
            row["ts_or_st_pretty"] = f"[{tech.id}] {tech.name}"
            row["tactics"] = tech.tactics
        else:
            row["ts_or_st_pretty"] = None
            row["tactics"] = []

    return row


def enrich_tactic_data(row: pd.Series) -> pd.Series:
    """
    Enrich a row with tactic data from MITRE ATT&CK.

    This function adds the following columns to the row:
    - tactic_id: Tactic ID (e.g., TA0005)
    - tactic_pretty: Pretty formatted tactic string (e.g., "[TA0005] Defense Evasion")
    - kill_chain_stages: List of kill chain stage objects for this tactic

    Args:
        row: DataFrame row containing a 'tactic' column with a tactic object

    Returns:
        The same row with added enrichment columns

    Example:
        >>> # Assuming row has a tactic object
        >>> enriched = enrich_tactic_data(row)
        >>> enriched["tactic_pretty"]
        "[TA0005] Defense Evasion"
    """
    tactic = row["tactic"]

    # Check if tactic is not NaN/None and has the expected attributes
    if tactic is not None and not pd.isna(tactic) and hasattr(tactic, "id"):
        row["tactic_id"] = tactic.id
        row["tactic_pretty"] = f"[{tactic.id}] {tactic.name}"
        row["kill_chain_stages"] = tactic.kill_chain_stages
    else:
        row["tactic_id"] = None
        row["tactic_pretty"] = None
        row["kill_chain_stages"] = []

    return row


def enrich_kill_chain_data(row: pd.Series) -> pd.Series:
    """
    Enrich a row with kill chain stage data.

    This function adds the following columns to the row:
    - kill_chain_id: Kill chain step number (e.g., 3 for "Exploitation")
    - kill_chain_pretty: Pretty formatted string (e.g., "[3] Exploitation")

    Args:
        row: DataFrame row containing a 'kill_chain_stage' column with a stage object

    Returns:
        The same row with added enrichment columns

    Example:
        >>> # Assuming row has a kill_chain_stage object
        >>> enriched = enrich_kill_chain_data(row)
        >>> enriched["kill_chain_pretty"]
        "[3] Exploitation"
    """
    kc_stage = row["kill_chain_stage"]

    # Check if kc_stage is not NaN/None and has the expected attributes
    if (
        kc_stage is not None
        and not pd.isna(kc_stage)
        and hasattr(kc_stage, "kill_chain_step_number")
    ):
        row["kill_chain_id"] = kc_stage.kill_chain_step_number
        row["kill_chain_pretty"] = (
            f"[{kc_stage.kill_chain_step_number}] {kc_stage.name}"
        )
    else:
        row["kill_chain_id"] = None
        row["kill_chain_pretty"] = None

    return row
