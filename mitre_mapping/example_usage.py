# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Example usage of the MITRE ATT&CK Mapper
"""

import logging
from typing import List, Optional

from mitre_mapping.mitre_attack_mapper import (
    CyberKillChainStage,
    SubTechnique,
    Tactic,
    Technique,
    get_mapper,
    get_sub_technique,
    get_sub_techniques,
    get_technique,
    get_techniques,
)

logger = logging.getLogger(__name__)


def format_tactics_names(tactics: List[Tactic]) -> str:
    """Format a list of tactics into a comma-separated string."""
    return ", ".join([t.name for t in tactics])


def display_technique(
    technique: Optional[Technique],
    show_sub_techniques: bool = True,
    max_sub_techniques: int = 3,
) -> None:
    """Display information about a technique."""
    if not technique:
        return

    logger.info("  Technique: %s (%s)", technique.name, technique.id)
    tactics_names = format_tactics_names(technique.tactics)
    logger.info("  Tactics: %s", tactics_names)
    logger.info("  Sub-techniques: %d", len(technique.sub_techniques))

    if show_sub_techniques and technique.sub_techniques:
        for sub in technique.sub_techniques[:max_sub_techniques]:
            logger.info("    - %s (%s)", sub.name, sub.id)


def display_sub_technique(sub_technique: Optional[SubTechnique]) -> None:
    """Display information about a sub-technique."""
    if not sub_technique:
        return

    logger.info("  Sub-technique: %s (%s)", sub_technique.name, sub_technique.id)
    logger.info(
        "  Parent Technique: %s (%s)",
        sub_technique.technique.name,
        sub_technique.technique.id,
    )
    tactics_str = format_tactics_names(sub_technique.technique.tactics)
    logger.info("  Tactics: %s", tactics_str)


def display_tactic_techniques(
    tactic: Optional[Tactic], max_techniques: int = 5
) -> None:
    """Display techniques associated with a tactic."""
    if not tactic:
        return

    logger.info("  Exploring tactic: %s (%s)", tactic.name, tactic.id)
    logger.info("  Number of techniques in this tactic: %d", len(tactic.techniques))
    logger.info("  First %d techniques:", max_techniques)
    for tech in tactic.techniques[:max_techniques]:
        logger.info("    - %s (%s)", tech.name, tech.id)


def display_kill_chain_stages(tactic: Optional[Tactic]) -> None:
    """Display kill chain stages for a tactic."""
    if not tactic or not tactic.kill_chain_stages:
        return

    logger.info("  Tactic: %s (%s)", tactic.name, tactic.id)
    logger.info("  Kill Chain Stages:")
    for stage in tactic.kill_chain_stages:
        logger.info("    - %s: %s", stage.name, stage.description)


def display_kill_chain_stage_details(stage: Optional[CyberKillChainStage]) -> None:
    """Display detailed information about a kill chain stage."""
    if not stage:
        return

    logger.info("  Stage: %s", stage.name)
    logger.info("  Description: %s", stage.description)
    logger.info("  Associated Tactics (%d):", len(stage.tactics))
    for tactic in stage.tactics:
        logger.info("    - %s (%s)", tactic.name, tactic.id)


def example_single_technique() -> None:
    """Example 1: Get a single technique."""
    logger.info("Example 1: Getting a single technique")
    technique = get_technique("T1548")
    display_technique(technique)
    logger.info("")


def example_multiple_techniques() -> None:
    """Example 2: Get multiple techniques."""
    logger.info("Example 2: Getting multiple techniques")
    techniques = get_techniques(["T1548", "T1134", "T1059"])
    for tech in techniques:
        tactics_str = format_tactics_names(tech.tactics)
        logger.info("  %s (%s) -> Tactics: %s", tech.name, tech.id, tactics_str)
    logger.info("")


def example_single_sub_technique() -> None:
    """Example 3: Get a single sub-technique."""
    logger.info("Example 3: Getting a single sub-technique")
    sub_technique = get_sub_technique("T1548.001")
    display_sub_technique(sub_technique)
    logger.info("")


def example_multiple_sub_techniques() -> None:
    """Example 4: Get multiple sub-techniques."""
    logger.info("Example 4: Getting multiple sub-techniques")
    sub_techniques = get_sub_techniques(["T1548.001", "T1548.002", "T1134.001"])
    for sub in sub_techniques:
        logger.info("  %s (%s) -> %s", sub.name, sub.id, sub.technique.name)
    logger.info("")


def example_tactic_techniques() -> None:
    """Example 5: Exploring a tactic's techniques."""
    logger.info("Example 5: Exploring a tactic's techniques")
    technique = get_technique("T1059")
    if technique and technique.tactics:
        display_tactic_techniques(technique.tactics[0])
    logger.info("")


def example_kill_chain_mappings() -> None:
    """Example 6: Cyber Kill Chain stage mappings."""
    logger.info("Example 6: Cyber Kill Chain stage mappings")
    mapper = get_mapper()
    technique = mapper.get_technique("T1566")  # Phishing
    if technique and technique.tactics:
        display_kill_chain_stages(technique.tactics[0])
    logger.info("")


def example_kill_chain_stages() -> None:
    """Example 7: Exploring kill chain stages."""
    logger.info("Example 7: Exploring kill chain stages")
    kill_chain_stages = get_mapper().get_kill_chain_stages()
    if kill_chain_stages:
        exploitation_stage = kill_chain_stages.get("exploitation")
        display_kill_chain_stage_details(exploitation_stage)
    logger.info("")


def main() -> None:
    """Main function to demonstrate the usage of the MITRE ATT&CK Mapper."""
    logger.info("Loading MITRE ATT&CK data...")
    logger.info("(This will use the cache if available, or fetch fresh data if not)")
    logger.info("")

    example_single_technique()
    example_multiple_techniques()
    example_single_sub_technique()
    example_multiple_sub_techniques()
    example_tactic_techniques()
    example_kill_chain_mappings()
    example_kill_chain_stages()


if __name__ == "__main__":
    main()
