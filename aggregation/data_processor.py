# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Data processor for aggregating classified detection rules.

This module extracts all data transformation logic from the visualization layer,
performing technique enrichment, tactic/kill-chain explosions, and statistical
aggregations.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from aggregation.enrichment import (
    enrich_kill_chain_data,
    enrich_tactic_data,
    enrich_technique_data,
)
from mitre_mapping.mitre_attack_mapper import get_mapper

logger = logging.getLogger(__name__)


def load_classified_rules(classified_output_file: str) -> pd.DataFrame:
    """
    Load classified detection rules from a JSON file.

    Args:
        classified_output_file: Path to local file

    Returns:
        DataFrame containing the detection rules
    """
    classified_path = Path(classified_output_file)
    if not classified_path.is_absolute():
        classified_path = Path(__file__).parent.parent / classified_path

    if not classified_path.exists():
        raise FileNotFoundError(f"Classified output file not found: {classified_path}")

    with classified_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    loaded_rules_df = pd.DataFrame(data)
    loaded_rules_df = loaded_rules_df.rename(
        columns={"id": "rule_id", "relevant_techniques": "technique_ids"}
    )

    return loaded_rules_df


def load_trending_techniques(trending_file_path: str) -> pd.DataFrame:
    """
    Load trending techniques from CSV file.

    Args:
        trending_file_path: Path to trending techniques CSV

    Returns:
        DataFrame with columns: technique_id, mentions_in_incidents_percent
    """
    trending_path = Path(trending_file_path)
    if not trending_path.is_absolute():
        trending_path = Path(__file__).parent.parent / trending_path

    if not trending_path.exists():
        logger.warning("Trending techniques file not found: %s", trending_path)
        return pd.DataFrame(columns=["technique_id", "mentions_in_incidents_percent"])

    return pd.read_csv(trending_path)


def enrich_trending_techniques(
    trending_data_df: pd.DataFrame, techniques_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Enrich trending techniques with pretty names and rule counts.

    Args:
        trending_data_df: DataFrame with technique_id and mentions percentage
        techniques_df: DataFrame with rule-technique mappings

    Returns:
        DataFrame with columns:
        - technique_id: Raw technique ID (e.g., T1190)
        - technique_pretty: Pretty formatted (e.g.,
          [T1190] Exploit Public-Facing Application)
        - mentions_in_incidents_percent: Percentage value
        - rule_count: Number of rules matching this technique
    """
    mapper = get_mapper()
    result_rows = []

    for _, row in trending_data_df.iterrows():
        technique_id = row["technique_id"]

        # Look up pretty name
        if "." in technique_id:
            sub_tech = mapper.get_sub_technique(technique_id)
            if sub_tech:
                technique_pretty = (
                    f"[{sub_tech.id}] {sub_tech.technique.name} > {sub_tech.name}"
                )
            else:
                technique_pretty = f"[{technique_id}] Unknown"
        else:
            tech = mapper.get_technique(technique_id)
            if tech:
                technique_pretty = f"[{tech.id}] {tech.name}"
            else:
                technique_pretty = f"[{technique_id}] Unknown"

        # Count matching rules
        rule_count = techniques_df[techniques_df["technique_id"] == technique_id][
            "rule_id"
        ].nunique()

        result_rows.append(
            {
                "technique_id": technique_id,
                "technique_pretty": technique_pretty,
                "mentions_in_incidents_percent": row["mentions_in_incidents_percent"],
                "rule_count": rule_count,
            }
        )

    return pd.DataFrame(result_rows)


def _explode_and_enrich_techniques(rules_df: pd.DataFrame) -> pd.DataFrame:
    """
    Explode techniques and enrich with MITRE data.

    Args:
        rules_df: DataFrame with rule_id and technique_ids columns

    Returns:
        DataFrame with one row per (rule_id, technique_id), enriched with
        technique names and tactics
    """
    logger.info("Exploding techniques...")
    rule_techniques_df = rules_df.explode("technique_ids").rename(
        columns={"technique_ids": "technique_id"}
    )
    # Enrich with technique-level data (ts_or_st_pretty, tactics list)
    rule_techniques_df = rule_techniques_df.apply(enrich_technique_data, axis=1)
    return rule_techniques_df


def _explode_and_enrich_tactics(rule_techniques_df: pd.DataFrame) -> pd.DataFrame:
    """
    Explode tactics and enrich with MITRE data.

    Args:
        rule_techniques_df: DataFrame from _explode_and_enrich_techniques()

    Returns:
        DataFrame with one row per (rule_id, technique_id, tactic_id),
        enriched with tactic names and kill chain stages
    """
    logger.info("Exploding tactics...")
    rule_tactics_df = (
        rule_techniques_df.explode("tactics")
        .rename(columns={"tactics": "tactic"})
        .copy()
    )
    # Enrich with tactic-level data (tactic_id, tactic_pretty, kill_chain_stages list)
    rule_tactics_df = rule_tactics_df.apply(enrich_tactic_data, axis=1)
    return rule_tactics_df


def _explode_and_enrich_kill_chains(rule_tactics_df: pd.DataFrame) -> pd.DataFrame:
    """
    Explode kill chains and enrich with MITRE data.

    Args:
        rule_tactics_df: DataFrame from _explode_and_enrich_tactics()

    Returns:
        DataFrame with one row per (rule_id, technique_id, tactic_id, kill_chain_id),
        fully disaggregated and enriched
    """
    logger.info("Exploding kill chains...")
    rule_kill_chains_df = (
        rule_tactics_df.explode("kill_chain_stages")
        .rename(columns={"kill_chain_stages": "kill_chain_stage"})
        .copy()
    )
    # Enrich with kill_chain-level data (kill_chain_id, kill_chain_pretty)
    rule_kill_chains_df = rule_kill_chains_df.apply(enrich_kill_chain_data, axis=1)
    return rule_kill_chains_df


def _clean_enriched_dataframes(
    rule_techniques_df: pd.DataFrame,
    rule_tactics_df: pd.DataFrame,
    rule_kill_chains_df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Remove rows with missing enrichment data.

    Args:
        rule_techniques_df: Enriched techniques dataframe
        rule_tactics_df: Enriched tactics dataframe
        rule_kill_chains_df: Enriched kill chains dataframe

    Returns:
        Tuple of (cleaned_techniques, cleaned_tactics, cleaned_kill_chains)
    """
    logger.info("Cleaning up NaN values...")
    rule_kill_chains_df = rule_kill_chains_df.dropna(subset=["kill_chain_pretty"])
    rule_tactics_df = rule_tactics_df.dropna(subset=["tactic_pretty"])
    rule_techniques_df = rule_techniques_df.dropna(subset=["ts_or_st_pretty"])
    return rule_techniques_df, rule_tactics_df, rule_kill_chains_df


def _create_pretty_dataframes(
    rule_kill_chains_df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Create aggregated, pretty-formatted dataframes for display.

    Args:
        rule_kill_chains_df: Fully enriched and cleaned kill chains dataframe

    Returns:
        Tuple of (rule_tactics_pretty, rule_techniques_pretty, rules_pretty)
    """
    logger.info("Creating aggregated dataframes...")

    # Aggregate by (rule_id, technique_id, tactic_id)
    rule_tactics_pretty_df = (
        rule_kill_chains_df.groupby(["rule_id", "technique_id", "tactic_id"])
        .agg(
            {
                "ts_or_st_pretty": "first",
                "tactic_pretty": "first",
                "kill_chain_pretty": lambda x: tuple(sorted(set(x))),
            }
        )
        .reset_index()
        .rename(
            columns={
                "ts_or_st_pretty": "technique",
                "tactic_pretty": "tactic",
                "kill_chain_pretty": "kill_chain",
            }
        )
    )

    # Aggregate by (rule_id, technique_id)
    rule_techniques_pretty_df = (
        rule_tactics_pretty_df.groupby(["rule_id", "technique_id"])
        .agg(
            {
                "technique": "first",
                "tactic": lambda x: tuple(sorted(set(x))),
                "kill_chain": lambda x: tuple(
                    sorted(set(item for tup in x for item in tup))
                ),
            }
        )
        .reset_index()
    )

    # Aggregate by rule_id
    rules_pretty_df = (
        rule_techniques_pretty_df.groupby("rule_id")
        .agg(
            {
                "technique": lambda x: tuple(sorted(set(x))),
                "tactic": lambda x: tuple(
                    sorted(set(item for tup in x for item in tup))
                ),
                "kill_chain": lambda x: tuple(
                    sorted(set(item for tup in x for item in tup))
                ),
            }
        )
        .reset_index()
    )

    return rule_tactics_pretty_df, rule_techniques_pretty_df, rules_pretty_df


def _compute_technique_counts(rule_techniques_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute technique counts (number of rules per technique).

    Args:
        rule_techniques_df: Enriched techniques dataframe

    Returns:
        DataFrame with columns: Technique, Count
    """
    technique_counts = (
        rule_techniques_df.groupby("ts_or_st_pretty")["rule_id"]
        .nunique()
        .reset_index(name="Count")
        .rename(columns={"ts_or_st_pretty": "Technique"})
    )
    return technique_counts.sort_values("Count", ascending=False)


def _compute_tactic_coverage(rule_tactics_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute tactic coverage (technique-tactic mappings).

    Args:
        rule_tactics_df: Enriched tactics dataframe

    Returns:
        DataFrame with columns: tactic_pretty, ts_or_st_pretty,
        rule_mappings, tactic_name
    """
    tactic_technique_counts = (
        rule_tactics_df.groupby(["tactic_pretty", "ts_or_st_pretty"])
        .size()
        .reset_index(name="rule_mappings")
    )
    tactic_technique_counts["tactic_name"] = tactic_technique_counts[
        "tactic_pretty"
    ].str.replace(r"^\[.*?\]\s*", "", regex=True)
    return tactic_technique_counts


def _compute_kill_chain_coverage(rule_kill_chains_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute kill chain coverage (technique-kill-chain mappings).

    Args:
        rule_kill_chains_df: Enriched kill chains dataframe

    Returns:
        DataFrame with columns: kill_chain_pretty, ts_or_st_pretty,
        rule_mappings, kill_chain_step
    """
    # Create kill chain ID mapping
    kill_chain_with_step = (
        rule_kill_chains_df[["kill_chain_pretty", "kill_chain_id"]]
        .drop_duplicates()
        .set_index("kill_chain_pretty")["kill_chain_id"]
        .to_dict()
    )

    kill_chain_technique_counts = (
        rule_kill_chains_df.groupby(["kill_chain_pretty", "ts_or_st_pretty"])
        .size()
        .reset_index(name="rule_mappings")
    )
    kill_chain_technique_counts["kill_chain_step"] = kill_chain_technique_counts[
        "kill_chain_pretty"
    ].map(kill_chain_with_step)

    return kill_chain_technique_counts


def _compute_tactic_killchain_matrix(rule_kill_chains_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute tactic × kill-chain matrix for heatmap visualization.

    Args:
        rule_kill_chains_df: Enriched kill chains dataframe

    Returns:
        DataFrame with columns: tactic_name, kill_chain_name,
        kill_chain_step_num, rule_count
    """
    tactic_kc_df = rule_kill_chains_df.copy()
    tactic_kc_df["tactic_name"] = tactic_kc_df["tactic_pretty"].str.replace(
        r"^\[.*?\]\s*", "", regex=True
    )
    tactic_kc_df["kill_chain_name"] = tactic_kc_df["kill_chain_pretty"]
    tactic_kc_df["kill_chain_step_num"] = tactic_kc_df["kill_chain_id"]

    tactic_kc_counts = (
        tactic_kc_df.groupby(["tactic_name", "kill_chain_name", "kill_chain_step_num"])
        .agg({"rule_id": "nunique"})
        .reset_index()
        .rename(columns={"rule_id": "rule_count"})
    )

    return tactic_kc_counts


def _process_trending_analysis(
    trending_techniques_source: str, rule_techniques_df: pd.DataFrame
) -> pd.DataFrame:
    """
    Process trending techniques analysis.

    Args:
        trending_techniques_source: Path to trending techniques CSV
        rule_techniques_df: Enriched techniques dataframe

    Returns:
        DataFrame with trending techniques enriched with rule counts
    """
    logger.info("Enriching trending techniques...")
    trending_df = load_trending_techniques(trending_techniques_source)
    return enrich_trending_techniques(trending_df, rule_techniques_df)


def _compute_all_aggregations(
    rule_techniques_df: pd.DataFrame,
    rule_tactics_df: pd.DataFrame,
    rule_kill_chains_df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Compute all statistical aggregations.

    Args:
        rule_techniques_df: Enriched techniques dataframe
        rule_tactics_df: Enriched tactics dataframe
        rule_kill_chains_df: Enriched kill chains dataframe

    Returns:
        Tuple of (technique_counts, tactic_coverage, kill_chain_coverage,
                 tactic_kc_matrix)
    """
    logger.info("Computing statistical aggregations...")
    technique_counts = _compute_technique_counts(rule_techniques_df)
    tactic_technique_counts = _compute_tactic_coverage(rule_tactics_df)
    kill_chain_technique_counts = _compute_kill_chain_coverage(rule_kill_chains_df)
    tactic_kc_counts = _compute_tactic_killchain_matrix(rule_kill_chains_df)
    return (
        technique_counts,
        tactic_technique_counts,
        kill_chain_technique_counts,
        tactic_kc_counts,
    )


def _compute_totals_for_insights(
    tactic_technique_counts: pd.DataFrame, kill_chain_technique_counts: pd.DataFrame
) -> tuple[Dict[str, int], Dict[str, int]]:
    """
    Compute tactic and kill-chain totals for insights generator.

    Args:
        tactic_technique_counts: Tactic coverage dataframe
        kill_chain_technique_counts: Kill chain coverage dataframe

    Returns:
        Tuple of (tactic_totals, kill_chain_totals) dictionaries
    """
    logger.info("Computing tactic and kill-chain totals...")
    tactic_totals: Dict[str, int] = {}
    for item in tactic_technique_counts.to_dict(orient="records"):
        tactic = item.get("tactic_name", "")
        if tactic:
            tactic_totals[tactic] = tactic_totals.get(tactic, 0) + item.get(
                "rule_mappings", 0
            )

    kill_chain_totals: Dict[str, int] = {}
    for item in kill_chain_technique_counts.to_dict(orient="records"):
        kc = item.get("kill_chain_pretty", "")
        if kc:
            kill_chain_totals[kc] = kill_chain_totals.get(kc, 0) + item.get(
                "rule_mappings", 0
            )

    return tactic_totals, kill_chain_totals


def _build_output_structure(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    input_rule_classification_df: pd.DataFrame,
    rule_techniques_df: pd.DataFrame,
    rule_tactics_df: pd.DataFrame,
    rule_kill_chains_df: pd.DataFrame,
    rules_pretty_df: pd.DataFrame,
    rule_techniques_pretty_df: pd.DataFrame,
    rule_tactics_pretty_df: pd.DataFrame,
    technique_counts: pd.DataFrame,
    tactic_technique_counts: pd.DataFrame,
    kill_chain_technique_counts: pd.DataFrame,
    tactic_kc_counts: pd.DataFrame,
    trending_enriched_df: pd.DataFrame,
    tactic_totals: Dict[str, int],
    kill_chain_totals: Dict[str, int],
) -> Dict[str, Any]:
    """
    Build the final output structure.

    Args:
        All processed and aggregated dataframes

    Returns:
        Dictionary containing metadata, aggregations, and dataframes
    """
    logger.info("Building output structure...")
    return {
        "metadata": {
            "total_rules": len(input_rule_classification_df),
            "total_techniques": rule_techniques_df["technique_id"].nunique(),
            "total_tactics": rule_tactics_df["tactic_id"].nunique(),
            "total_kill_chains": rule_kill_chains_df["kill_chain_id"].nunique(),
            "generated_at": datetime.utcnow().isoformat(),
        },
        "aggregations": {
            "technique_counts": technique_counts.to_dict(orient="records"),
            "tactic_coverage": tactic_technique_counts.to_dict(orient="records"),
            "kill_chain_coverage": kill_chain_technique_counts.to_dict(
                orient="records"
            ),
            "tactic_killchain_matrix": tactic_kc_counts.to_dict(orient="records"),
            "trending_analysis": trending_enriched_df.to_dict(orient="records"),
            # Pre-computed totals for insights generator
            "tactic_totals": tactic_totals,
            "kill_chain_totals": kill_chain_totals,
        },
        "dataframes": {
            "rules_summary": rules_pretty_df.to_dict(orient="records"),
            "rule_techniques": rule_techniques_pretty_df.to_dict(orient="records"),
            "rule_tactics": rule_tactics_pretty_df.to_dict(orient="records"),
            # Store raw dataframes for visualization layer (serializable format)
            "rule_techniques_raw": rule_techniques_df[
                ["rule_id", "technique_id", "ts_or_st_pretty"]
            ].to_dict(orient="records"),
            "rule_tactics_raw": rule_tactics_df[
                [
                    "rule_id",
                    "technique_id",
                    "tactic_id",
                    "ts_or_st_pretty",
                    "tactic_pretty",
                ]
            ].to_dict(orient="records"),
            "rule_kill_chains_raw": rule_kill_chains_df[
                [
                    "rule_id",
                    "technique_id",
                    "tactic_id",
                    "kill_chain_id",
                    "ts_or_st_pretty",
                    "tactic_pretty",
                    "kill_chain_pretty",
                ]
            ].to_dict(orient="records"),
        },
    }


def _process_and_enrich_rules(
    input_rule_classification_df: pd.DataFrame,
) -> tuple[
    pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame
]:
    """
    Process and enrich rules through all transformation stages.

    Args:
        input_rule_classification_df: Raw classified rules dataframe

    Returns:
        Tuple of (rule_techniques_df, rule_tactics_df, rule_kill_chains_df,
                 rule_tactics_pretty_df, rule_techniques_pretty_df, rules_pretty_df)
    """
    # Step 1-3: Explode and enrich (techniques → tactics → kill chains)
    rule_techniques_df = _explode_and_enrich_techniques(input_rule_classification_df)
    rule_tactics_df = _explode_and_enrich_tactics(rule_techniques_df)
    rule_kill_chains_df = _explode_and_enrich_kill_chains(rule_tactics_df)

    # Step 4: Clean up missing data
    rule_techniques_df, rule_tactics_df, rule_kill_chains_df = (
        _clean_enriched_dataframes(
            rule_techniques_df, rule_tactics_df, rule_kill_chains_df
        )
    )

    # Step 5: Create pretty-formatted dataframes for display
    rule_tactics_pretty_df, rule_techniques_pretty_df, rules_pretty_df = (
        _create_pretty_dataframes(rule_kill_chains_df)
    )

    return (
        rule_techniques_df,
        rule_tactics_df,
        rule_kill_chains_df,
        rule_tactics_pretty_df,
        rule_techniques_pretty_df,
        rules_pretty_df,
    )


def process_classified_rules(
    classified_output_file: str, trending_techniques_source: str
) -> Dict[str, Any]:
    """
    Process classified detection rules and generate all aggregations.

    This is the main entry point that orchestrates all data transformations.
    The processing is broken down into logical steps performed by helper functions.

    Args:
        classified_output_file: Path to classified rules JSON
        trending_techniques_source: Path to trending techniques CSV

    Returns:
        Dictionary containing metadata, aggregations, and dataframes
    """
    logger.info("Loading classified rules from: %s", classified_output_file)
    input_rule_classification_df = load_classified_rules(classified_output_file)
    input_rule_classification_df = input_rule_classification_df.sort_values("rule_id")
    logger.info("Loaded %d rules", len(input_rule_classification_df))

    # Process and enrich rules
    (
        rule_techniques_df,
        rule_tactics_df,
        rule_kill_chains_df,
        rule_tactics_pretty_df,
        rule_techniques_pretty_df,
        rules_pretty_df,
    ) = _process_and_enrich_rules(input_rule_classification_df)

    # Compute statistical aggregations
    aggregations = _compute_all_aggregations(
        rule_techniques_df, rule_tactics_df, rule_kill_chains_df
    )

    # Process trending analysis
    trending_enriched_df = _process_trending_analysis(
        trending_techniques_source, rule_techniques_df
    )

    # Compute totals for insights generator
    tactic_totals, kill_chain_totals = _compute_totals_for_insights(
        aggregations[1], aggregations[2]
    )

    # Build output structure
    output = _build_output_structure(
        input_rule_classification_df,
        rule_techniques_df,
        rule_tactics_df,
        rule_kill_chains_df,
        rules_pretty_df,
        rule_techniques_pretty_df,
        rule_tactics_pretty_df,
        aggregations[0],  # technique_counts
        aggregations[1],  # tactic_technique_counts
        aggregations[2],  # kill_chain_technique_counts
        aggregations[3],  # tactic_kc_counts
        trending_enriched_df,
        tactic_totals,
        kill_chain_totals,
    )

    logger.info("Aggregation complete!")
    return output
