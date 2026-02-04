# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Merge original MITRE technique labels from detection rules with classifier output.

This script extracts MITRE ATT&CK technique IDs from Splunk YAML rule files and merges
them with the classifier's predictions using set union on the relevant_techniques field.

Note: This script is designed for Splunk security content YAML format. Other formats
(e.g., Sigma rules) would require different parsing logic.
"""

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Dict, List

import yaml

# Set up module-level logger
logger = logging.getLogger(__name__)


def load_classifier_output(classifier_output_path: Path) -> List[Dict]:
    """
    Load classifier output from JSON file.

    Args:
        classifier_output_path: Path to classifier output JSON file

    Returns:
        List of classification results, where each dict contains:
            - "id": Rule identifier (filename)
            - "relevant_techniques": List of MITRE technique IDs
            - (optional) "plausible_techniques": List from two-step classification
    """
    try:
        with open(classifier_output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug("Loaded %d rules from classifier output", len(data))
        return data
    except (IOError, json.JSONDecodeError) as e:
        logger.error("Error loading classifier output: %s", e)
        raise


def extract_mitre_ids_from_yaml_rule(yaml_rule_path: Path) -> List[str]:
    """
    Extract MITRE technique IDs from a Splunk YAML rule file.

    This function reads the tags.mitre_attack_id field from Splunk security
    content YAML files. Other rule formats (e.g., Sigma) have different structures.

    Args:
        yaml_rule_path: Path to Splunk YAML rule file

    Returns:
        List of technique IDs (e.g., ["T1090.003", "T1071.001"])
    """
    try:
        with open(yaml_rule_path, "r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        if not rule_data:
            return []

        # Extract mitre_attack_id from tags field (Splunk format)
        tags = rule_data.get("tags", {})
        if isinstance(tags, dict):
            mitre_ids = tags.get("mitre_attack_id", [])
            return (
                mitre_ids
                if isinstance(mitre_ids, list)
                else [mitre_ids] if mitre_ids else []
            )

        return []
    except (IOError, yaml.YAMLError) as e:
        logger.debug("Error parsing %s: %s", yaml_rule_path.name, e)
        return []


def build_original_labels_mapping(
    original_rules_folder: Path, rule_ids: List[str]
) -> Dict[str, List[str]]:
    """
    Build a mapping from rule filename to original MITRE technique IDs.

    Iterates through all YAML files in the folder and matches them against the
    provided rule IDs by filename.

    Note: This assumes that rule_id in the classifier output matches the filename
    of the original YAML rule file (including extension). This is typically true
    when rules are processed through the standard pipeline.

    Args:
        original_rules_folder: Path to folder containing original YAML rule files
        rule_ids: List of rule IDs from classifier output to match

    Returns:
        Dictionary mapping rule IDs (filenames) to lists of technique IDs
    """
    mapping = {}
    rule_id_set = set(rule_ids)
    matched_count = 0

    logger.debug("Looking for %d rules in folder", len(rule_ids))

    # Iterate over all files and match by filename
    for yaml_file in original_rules_folder.iterdir():
        if yaml_file.suffix in {".yml", ".yaml"} and yaml_file.name in rule_id_set:
            mitre_ids = extract_mitre_ids_from_yaml_rule(yaml_file)
            if mitre_ids:
                mapping[yaml_file.name] = mitre_ids
                logger.debug("  %s: %s", yaml_file.name, mitre_ids)
            else:
                logger.debug("  %s: No MITRE IDs found", yaml_file.name)
            matched_count += 1

    not_found_count = len(rule_ids) - matched_count
    logger.debug(
        "Built original labels mapping: %d matched, %d not found",
        matched_count,
        not_found_count,
    )
    return mapping


def augment_with_original_labels(
    classifier_data: List[Dict], original_labels: Dict[str, List[str]]
) -> None:
    """
    Augment classifier predictions with original labels using set union.

    Modifies the classifier_data in place by merging original technique IDs
    with predicted techniques in the relevant_techniques field.

    Args:
        classifier_data: List of classifier results (modified in place)
        original_labels: Mapping from filename to original technique IDs
    """
    matched_count = 0
    unmatched_count = 0
    skipped_count = 0

    for item in classifier_data:
        rule_id = item.get("id")

        # Skip items with missing or empty rule_id
        if not rule_id:
            logger.debug("Skipping item with missing or empty rule_id")
            skipped_count += 1
            continue

        relevant = item.get("relevant_techniques", [])

        # Look up original labels by exact filename match
        if rule_id in original_labels:
            original_techniques = original_labels[rule_id]
            # Merge using set union
            merged_relevant = sorted(set(relevant) | set(original_techniques))
            item["relevant_techniques"] = merged_relevant

            logger.debug(
                "  %s: merged %d + %d = %d techniques",
                rule_id,
                len(relevant),
                len(original_techniques),
                len(merged_relevant),
            )
            matched_count += 1
        else:
            logger.debug("  %s: no original labels found, keeping original", rule_id)
            unmatched_count += 1

    logger.info(
        "Augmented with original labels: %d matched, %d unmatched, %d skipped",
        matched_count,
        unmatched_count,
        skipped_count,
    )


def save_enhanced_output(data: List[Dict], output_path: Path) -> None:
    """
    Save enhanced classifier output to JSON file.

    Args:
        data: Enhanced classifier data
        output_path: Path to output JSON file
    """
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Saved enhanced output to %s", output_path)
    except (IOError, OSError) as e:
        logger.error("Error saving output: %s", e)
        raise


def main() -> int:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Merge original MITRE labels with classifier output"
    )
    parser.add_argument(
        "--classifier-output",
        type=str,
        default="output/classification/classified_output.json",
        help="Path to classifier output JSON file (default: output/classification/classified_output.json)",
    )
    parser.add_argument(
        "--original-rules-folder",
        type=str,
        default="output/rules/original",
        help="Path to folder containing original YAML rule files (default: output/rules/original)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output/classification/classified_output_with_original_labels.json",
        help="Path to output JSON file with merged original labels (default: output/classification/classified_output_with_original_labels.json)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debug messages",
    )

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    # Convert paths
    classifier_output_path = Path(args.classifier_output)
    original_rules_folder_path = Path(args.original_rules_folder)
    output_path = Path(args.output)

    # Validate inputs
    if not classifier_output_path.exists():
        logger.error("Classifier output file not found: %s", classifier_output_path)
        return 1

    if not original_rules_folder_path.exists():
        logger.error("Rules folder not found: %s", original_rules_folder_path)
        return 1

    # Load classifier output
    classifier_data = load_classifier_output(classifier_output_path)

    # Extract rule IDs from classifier output
    rule_ids: List[str] = [
        rule_id for item in classifier_data if (rule_id := item.get("id")) is not None
    ]
    logger.debug("Found %d rules in classifier output", len(rule_ids))

    # Build original labels mapping (only for rules in classifier output)
    original_labels = build_original_labels_mapping(
        original_rules_folder_path, rule_ids
    )

    # Augment with original labels (modifies classifier_data in place)
    logger.debug("Augmenting classifier predictions with original labels...")
    augment_with_original_labels(classifier_data, original_labels)

    # Save augmented output
    save_enhanced_output(classifier_data, output_path)

    logger.info("Successfully processed %d rules", len(classifier_data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
