# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
MITRE ATT&CK Mapper

A mapping from MITRE ATT&CK's techniques to tactics and sub-techniques.
Uses the mitreattack-python library to fetch and organize the data.
"""

from dataclasses import dataclass, field
import gc
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import urllib.request

from mitreattack.stix20 import MitreAttackData

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class CyberKillChainStage:
    """Represents a Cyber Kill Chain Stage"""

    id: str
    name: str
    description: str
    kill_chain_step_number: int
    tactics: List["Tactic"] = field(default_factory=list, repr=False)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, CyberKillChainStage):
            return self.id == other.id
        return False

    def __repr__(self):
        return (
            f"CyberKillChainStage(id='{self.id}', name='{self.name}', "
            f"description='{self.description}', "
            f"kill_chain_step_number='{self.kill_chain_step_number}', "
            f"tactics={len(self.tactics)} items)"
        )


@dataclass
class Tactic:
    """Represents a MITRE ATT&CK Tactic"""

    name: str
    description: str
    id: str
    url: str
    techniques: List["Technique"] = field(default_factory=list, repr=False)
    kill_chain_stages: List[CyberKillChainStage] = field(
        default_factory=list, repr=False
    )

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, Tactic):
            return self.id == other.id
        return False

    def __repr__(self):
        kc_stages = (
            ", ".join([s.id for s in self.kill_chain_stages])
            if self.kill_chain_stages
            else "none"
        )
        return (
            f"Tactic(name='{self.name}', description='{self.description}', "
            f"id='{self.id}', url='{self.url}', techniques={len(self.techniques)} items, "
            f"kill_chain_stages=[{kc_stages}])"
        )


@dataclass
class Technique:
    """Represents a MITRE ATT&CK Technique"""

    name: str
    id: str
    description: str
    url: str
    tactics: List[Tactic] = field(default_factory=list, repr=False)
    sub_techniques: List["SubTechnique"] = field(default_factory=list, repr=False)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, Technique):
            return self.id == other.id
        return False

    def __repr__(self):
        tactics_str = ", ".join([t.id for t in self.tactics])
        return (
            f"Technique(name='{self.name}', description='{self.description}', "
            f"id='{self.id}', url='{self.url}', tactics=[{tactics_str}], "
            f"sub_techniques={len(self.sub_techniques)} items)"
        )


@dataclass
class SubTechnique:
    """Represents a MITRE ATT&CK Sub-Technique"""

    name: str
    description: str
    id: str
    url: str
    technique: Technique = field(repr=False)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, SubTechnique):
            return self.id == other.id
        return False

    def __repr__(self):
        return (
            f"SubTechnique(name='{self.name}', "
            f"description='{self.description}', id='{self.id}', "
            f"url='{self.url}', technique='{self.technique.id}')"
        )


@dataclass
class MappingData:
    """Container for all MITRE ATT&CK mapping data"""

    tactics: Dict[str, Tactic]
    techniques: Dict[str, Technique]
    sub_techniques: Dict[str, SubTechnique]
    kill_chain_stages: Dict[str, CyberKillChainStage]


class MappingFetcher:
    """
    Fetches and builds MITRE ATT&CK mapping data from cache or remote source.
    Handles downloading, parsing, caching, and loading of MITRE ATT&CK data.
    """

    # Base URL for MITRE ATT&CK STIX data
    ENTERPRISE_ATTACK_URL_TEMPLATE = (
        "https://raw.githubusercontent.com/mitre/cti/{version}/"
        "enterprise-attack/enterprise-attack.json"
    )
    # Use 'master' for latest, or 'ATT&CK-v15.1' for a specific version
    DEFAULT_VERSION = "master"

    def __init__(self, cache_file: Optional[str] = None, version: Optional[str] = None):
        """
        Initialize the fetcher.

        Args:
            cache_file: Path to JSON cache file. If None, defaults to
                       'mitre_attack_cache.json' in the same directory as this module.
            version: MITRE ATT&CK version to use. If None, defaults to 'master'
                    (latest). Examples: 'master', 'ATT&CK-v15.1', 'ATT&CK-v14.1'
        """
        # Set version
        self.version = version or self.DEFAULT_VERSION

        # Set up cache file path
        if cache_file is None:
            module_dir = Path(__file__).parent
            self.cache_file = module_dir / "mitre_attack_cache.json"
        else:
            self.cache_file = Path(cache_file)

        # Set up STIX data file path
        # Include version in filename for multiple versions
        version_safe = self.version.replace("/", "_").replace("&", "and")
        self.stix_file = (
            self.cache_file.parent / f"enterprise-attack-{version_safe}.json"
        )

        # Set up Cyber Kill Chain mapping file path
        module_dir = Path(__file__).parent
        self.kill_chain_mapping_file = module_dir / "cyber_kill_chain_mapping.json"

    def fetch_and_build_data(self) -> MappingData:
        """
        Fetch and build MITRE ATT&CK mapping data (from cache if available).

        Returns:
            MappingData object containing all tactics, techniques,
            sub-techniques, and kill chain stages
        """
        logger.debug("=" * 60)
        logger.debug("Fetching MITRE ATT&CK mapping data...")
        logger.debug("ATT&CK version: %s", self.version)
        logger.debug("Cache file: %s", self.cache_file)
        logger.debug("STIX data file: %s", self.stix_file)
        logger.debug("Kill Chain mapping file: %s", self.kill_chain_mapping_file)

        logger.debug("Loading MITRE ATT&CK data...")

        # Try to load from cache first
        if self.cache_file.exists():
            logger.debug("Cache file found: %s", self.cache_file)
            try:
                tactics, techniques, sub_techniques = self._load_from_cache()
                logger.debug("Successfully loaded from cache")
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.info("Failed to load from cache (%s). Fetching fresh data...", e)
                tactics, techniques, sub_techniques = self._fetch_and_build_data()
        else:
            logger.debug("No cache file found. Will fetch fresh data.")
            tactics, techniques, sub_techniques = self._fetch_and_build_data()

        # Load kill chain mapping and connect to tactics
        kill_chain_stages: Dict[str, CyberKillChainStage] = {}
        self._load_kill_chain_mapping(tactics, kill_chain_stages)

        # Save to cache for next time
        try:
            logger.debug("Saving to cache...")
            self._save_to_cache(tactics, techniques, sub_techniques)
            logger.debug("Successfully saved cache to %s", self.cache_file)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("Failed to save cache (%s). Data still loaded in memory.", e)

        logger.debug("=" * 60)
        return MappingData(
            tactics=tactics,
            techniques=techniques,
            sub_techniques=sub_techniques,
            kill_chain_stages=kill_chain_stages,
        )

    def _download_stix_data(self):
        """Download the MITRE ATT&CK STIX data for the specified version"""
        download_url = self.ENTERPRISE_ATTACK_URL_TEMPLATE.format(version=self.version)
        logger.debug("Downloading MITRE ATT&CK data (version: %s)...", self.version)
        logger.debug("URL: %s", download_url)

        try:
            # Download with progress tracking
            with urllib.request.urlopen(download_url) as response:
                total_size = int(response.headers.get("Content-Length", 0))
                logger.debug("Download size: %.2f MB", total_size / 1024 / 1024)

                data = response.read()
                logger.debug("Downloaded %.2f MB", len(data) / 1024 / 1024)

            # Save to file
            self.stix_file.parent.mkdir(parents=True, exist_ok=True)
            logger.debug("Writing to %s...", self.stix_file)
            with open(self.stix_file, "wb") as f:
                f.write(data)

            file_size_mb = self.stix_file.stat().st_size / 1024 / 1024
            logger.debug(
                "Successfully saved %.2f MB to %s", file_size_mb, self.stix_file
            )

            # Clear downloaded data from memory
            del data
            gc.collect()

        except Exception as e:
            logger.error("Failed to download MITRE ATT&CK data: %s", e)
            raise RuntimeError("Failed to download MITRE ATT&CK data") from e

    def _fetch_and_build_data(
        self,
    ) -> tuple[Dict[str, Tactic], Dict[str, Technique], Dict[str, SubTechnique]]:
        """Fetch data from MITRE ATT&CK and build data structures."""
        # Download the STIX data if it doesn't exist
        if not self.stix_file.exists():
            self._download_stix_data()
        else:
            file_size_mb = self.stix_file.stat().st_size / 1024 / 1024
            logger.debug(
                "Using existing STIX file (%.2f MB): %s",
                file_size_mb,
                self.stix_file,
            )

        # Load the STIX data
        logger.debug("Loading STIX data into MitreAttackData...")
        mitre_data = MitreAttackData(str(self.stix_file))

        # First, load all tactics
        logger.debug("Loading tactics...")
        tactics: Dict[str, Tactic] = {}
        self._load_tactics(mitre_data, tactics)
        logger.debug("Loaded %d tactics", len(tactics))

        # Then load techniques (which reference tactics)
        logger.debug("Loading techniques...")
        techniques: Dict[str, Technique] = {}
        self._load_techniques(mitre_data, tactics, techniques)
        logger.debug("Loaded %d techniques", len(techniques))

        # Finally load sub-techniques (which reference techniques)
        logger.debug("Loading sub-techniques...")
        sub_techniques: Dict[str, SubTechnique] = {}
        self._load_sub_techniques(mitre_data, techniques, sub_techniques)
        logger.debug("Loaded %d sub-techniques", len(sub_techniques))

        return tactics, techniques, sub_techniques

    def _load_tactics(self, mitre_data: MitreAttackData, tactics: Dict[str, Tactic]):
        """Load all tactics from MITRE ATT&CK"""
        tactics_stix = mitre_data.get_tactics(remove_revoked_deprecated=True)

        for tactic_stix in tactics_stix:
            tactic_id = self._get_external_id(tactic_stix)
            if tactic_id:
                description = tactic_stix.description or ""
                tactic_url = self._construct_tactic_url(tactic_id)
                tactic = Tactic(
                    name=tactic_stix.name,
                    description=description,
                    id=tactic_id,
                    url=tactic_url,
                    techniques=[],
                )
                tactics[tactic_id] = tactic

    def _load_techniques(
        self,
        mitre_data: MitreAttackData,
        tactics: Dict[str, Tactic],
        techniques: Dict[str, Technique],
    ):
        """Load all techniques from MITRE ATT&CK"""
        techniques_stix = mitre_data.get_techniques(remove_revoked_deprecated=True)

        for technique_stix in techniques_stix:
            technique_id = self._get_external_id(technique_stix)
            if not technique_id:
                continue

            # Skip sub-techniques (they have dots in their ID, e.g., T1548.001)
            # Sub-techniques are handled separately in _load_sub_techniques()
            if "." in technique_id:
                continue

            # Get the kill chain phases (tactics) for this technique
            kill_chain_phases = getattr(technique_stix, "kill_chain_phases", [])

            # Create or get existing technique
            if technique_id not in techniques:
                technique_url = self._construct_attack_url(technique_id)
                technique = Technique(
                    name=technique_stix.name,
                    description=technique_stix.description or "",
                    id=technique_id,
                    url=technique_url,
                    tactics=[],
                    sub_techniques=[],
                )
                techniques[technique_id] = technique
            else:
                technique = techniques[technique_id]

            # Add all tactics to this technique
            for phase in kill_chain_phases:
                tactic_name = phase.phase_name.replace("-", " ").title()

                # Find the matching tactic
                tactic = self._find_tactic_by_name(tactics, tactic_name)

                if tactic:
                    # Add tactic to technique's tactics list (if not already there)
                    if tactic not in technique.tactics:
                        technique.tactics.append(tactic)

                    # Add technique to tactic's technique list (if not already there)
                    if technique not in tactic.techniques:
                        tactic.techniques.append(technique)

    def _load_sub_techniques(
        self,
        mitre_data: MitreAttackData,
        techniques: Dict[str, Technique],
        sub_techniques: Dict[str, SubTechnique],
    ):
        """Load all sub-techniques from MITRE ATT&CK"""
        sub_techniques_stix = mitre_data.get_subtechniques(
            remove_revoked_deprecated=True
        )

        for sub_technique_stix in sub_techniques_stix:
            sub_technique_id = self._get_external_id(sub_technique_stix)
            if not sub_technique_id:
                continue

            # Extract parent technique ID (e.g., T1548 from T1548.001)
            parent_technique_id = sub_technique_id.split(".")[0]

            # Find parent technique
            parent_technique = techniques.get(parent_technique_id)

            if parent_technique:
                sub_technique_url = self._construct_attack_url(sub_technique_id)
                sub_technique = SubTechnique(
                    name=sub_technique_stix.name,
                    description=sub_technique_stix.description or "",
                    id=sub_technique_id,
                    url=sub_technique_url,
                    technique=parent_technique,
                )

                # Store in our lookup
                sub_techniques[sub_technique_id] = sub_technique

                # Add to parent technique's sub-techniques list
                if sub_technique not in parent_technique.sub_techniques:
                    parent_technique.sub_techniques.append(sub_technique)

    def _get_external_id(self, stix_object) -> Optional[str]:
        """Extract the external ID (e.g., T1548) from a STIX object"""
        external_refs = getattr(stix_object, "external_references", [])
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                return ref["external_id"]
        return None

    def _construct_tactic_url(self, tactic_id: str) -> str:
        """Construct MITRE ATT&CK URL from tactic ID.

        Args:
            tactic_id: Tactic ID (e.g., TA0043)

        Returns:
            URL string (e.g., https://attack.mitre.org/tactics/TA0043/)
        """
        return f"https://attack.mitre.org/tactics/{tactic_id}/"

    def _construct_attack_url(self, technique_id: str) -> str:
        """Construct MITRE ATT&CK URL from technique or sub-technique ID.

        Args:
            technique_id: Technique or sub-technique ID (e.g., T1548 or T1548.001)

        Returns:
            URL string (e.g., https://attack.mitre.org/techniques/T1548 or
            https://attack.mitre.org/techniques/T1548/001)
        """
        if "." in technique_id:
            # Sub-technique: T1548.001 -> T1548/001
            parent_id, sub_id = technique_id.split(".", 1)
            return f"https://attack.mitre.org/techniques/{parent_id}/{sub_id}"

        # Regular technique: T1548 -> T1548
        return f"https://attack.mitre.org/techniques/{technique_id}"

    def _find_tactic_by_name(
        self, tactics: Dict[str, Tactic], name: str
    ) -> Optional[Tactic]:
        """Find a tactic by its name (case-insensitive)"""
        name_lower = name.lower()
        for tactic in tactics.values():
            if tactic.name.lower() == name_lower:
                return tactic
        return None

    def _connect_tactic_to_kc_stage(
        self,
        tactic: Tactic,
        stage: CyberKillChainStage,
    ) -> bool:
        """Connect a tactic to a kill chain stage (bidirectional).

        Returns:
            True if connection was made, False if already connected
        """
        # Add stage to tactic
        if stage not in tactic.kill_chain_stages:
            tactic.kill_chain_stages.append(stage)

        # Add tactic to stage
        if tactic not in stage.tactics:
            stage.tactics.append(tactic)
            return True
        return False

    def _load_kill_chain_stages(
        self,
        mapping_data: dict,
        kill_chain_stages: Dict[str, CyberKillChainStage],
    ):
        """Load kill chain stages from mapping data"""
        for stage_data in mapping_data.get("kill_chain_stages", []):
            stage = CyberKillChainStage(
                id=stage_data["id"],
                name=stage_data["name"],
                description=stage_data["description"],
                kill_chain_step_number=stage_data["kill_chain_step_number"],
                tactics=[],
            )
            kill_chain_stages[stage.id] = stage

    def _connect_tactics_to_kc_stages(
        self,
        mapping_data: dict,
        tactics: Dict[str, Tactic],
        kill_chain_stages: Dict[str, CyberKillChainStage],
    ) -> int:
        """Connect tactics to kill chain stages based on mapping data.

        Returns:
            Number of connections made
        """
        tactic_mappings = mapping_data.get("tactic_mappings", {})
        mapped_count = 0

        for tactic_name, stage_ids in tactic_mappings.items():
            tactic = self._find_tactic_by_name(tactics, tactic_name)
            if not tactic:
                logger.warning(
                    "Tactic '%s' not found in MITRE ATT&CK data",
                    tactic_name,
                )
                continue

            # Connect to kill chain stages
            for stage_id in stage_ids:
                stage = kill_chain_stages.get(stage_id)
                if not stage:
                    continue

                if self._connect_tactic_to_kc_stage(tactic, stage):
                    mapped_count += 1

        return mapped_count

    def _load_kill_chain_mapping(
        self,
        tactics: Dict[str, Tactic],
        kill_chain_stages: Dict[str, CyberKillChainStage],
    ):
        """Load Cyber Kill Chain mapping and connect to tactics"""
        if not self.kill_chain_mapping_file.exists():
            logger.warning(
                "Kill Chain mapping file not found: %s",
                self.kill_chain_mapping_file,
            )
            return

        logger.debug("Loading Cyber Kill Chain mapping...")

        try:
            with open(self.kill_chain_mapping_file, "r", encoding="utf-8") as f:
                mapping_data = json.load(f)

            # First pass: Create all kill chain stages
            self._load_kill_chain_stages(mapping_data, kill_chain_stages)
            logger.debug("Loaded %d kill chain stages", len(kill_chain_stages))

            # Second pass: Connect tactics to kill chain stages
            mapped_count = self._connect_tactics_to_kc_stages(
                mapping_data, tactics, kill_chain_stages
            )
            logger.debug("Connected %d tactic-to-stage mappings", mapped_count)

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to load kill chain mapping: %s", e)
            # Don't fail initialization, just log the error

    def _save_to_cache(
        self,
        tactics: Dict[str, Tactic],
        techniques: Dict[str, Technique],
        sub_techniques: Dict[str, SubTechnique],
    ):
        """Save the current data to the cache file"""
        logger.debug("Building cache data structure...")

        # Create a serializable structure without circular references
        cache_data: Dict[str, Dict[str, Any]] = {
            "tactics": {},
            "techniques": {},
            "sub_techniques": {},
        }

        # Save tactics (without techniques list to avoid circular refs)
        logger.debug("Serializing %d tactics...", len(tactics))
        for tactic_id, tactic in tactics.items():
            cache_data["tactics"][tactic_id] = {
                "name": tactic.name,
                "description": tactic.description,
                "id": tactic.id,
                "url": tactic.url,
            }

        # Save techniques (with tactic IDs references and without
        # sub_techniques)
        logger.debug("Serializing %d techniques...", len(techniques))
        for technique_id, technique in techniques.items():
            cache_data["techniques"][technique_id] = {
                "name": technique.name,
                "description": technique.description,
                "id": technique.id,
                "url": technique.url,
                "tactic_ids": [tactic.id for tactic in technique.tactics],
            }

        # Save sub-techniques (with technique ID reference)
        logger.debug("Serializing %d sub-techniques...", len(sub_techniques))
        for sub_technique_id, sub_technique in sub_techniques.items():
            cache_data["sub_techniques"][sub_technique_id] = {
                "name": sub_technique.name,
                "description": sub_technique.description,
                "id": sub_technique.id,
                "url": sub_technique.url,
                "technique_id": sub_technique.technique.id,
            }

        # Write to file
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        logger.debug("Writing cache to %s...", self.cache_file)
        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)

        cache_size_mb = self.cache_file.stat().st_size / 1024 / 1024
        logger.debug("Cache file size: %.2f MB", cache_size_mb)

    def _load_tactics_from_cache(self, cache_data: dict) -> Dict[str, Tactic]:
        """Load tactics from cache data and return them."""
        logger.debug("Loading %d tactics from cache...", len(cache_data["tactics"]))
        tactics: Dict[str, Tactic] = {}
        for tactic_id, tactic_data in cache_data["tactics"].items():
            # Get URL from cache or construct it
            tactic_url = tactic_data.get("url")
            if not tactic_url:
                tactic_url = self._construct_tactic_url(tactic_id)
            tactic = Tactic(
                name=tactic_data["name"],
                description=tactic_data["description"],
                id=tactic_data["id"],
                url=tactic_url,
                techniques=[],
            )
            tactics[tactic_id] = tactic
        return tactics

    def _get_technique_tactic_ids(self, technique_data: dict) -> List[str]:
        """Extract tactic IDs from technique cache data, handling legacy format."""
        technique_tactics_ids = technique_data.get("tactic_ids", [])
        # Support legacy cache format with single tactic_id
        if "tactic_id" in technique_data and not technique_tactics_ids:
            technique_tactics_ids = [technique_data["tactic_id"]]
        return technique_tactics_ids

    def _find_matching_tactics(
        self, tactic_ids: List[str], tactics: Dict[str, Tactic]
    ) -> tuple[List[Tactic], List[str]]:
        """Find matching tactics and identify missing ones."""
        matching_tactics = [tactics[tid] for tid in tactic_ids if tid in tactics]
        missing_tactic_ids = [tid for tid in tactic_ids if tid not in tactics]
        return matching_tactics, missing_tactic_ids

    def _create_technique_from_cache(
        self, technique_id: str, technique_data: dict, technique_tactics: List[Tactic]
    ) -> Technique:
        """Create a Technique object from cache data."""
        technique_url = technique_data.get("url")
        if not technique_url:
            technique_url = self._construct_attack_url(technique_id)
        return Technique(
            name=technique_data["name"],
            description=technique_data["description"],
            id=technique_data["id"],
            url=technique_url,
            tactics=technique_tactics,
            sub_techniques=[],
        )

    def _log_techniques_without_tactics(self, techniques_without_tactics: List[dict]):
        """Log error messages for techniques that have no tactics."""
        if not techniques_without_tactics:
            return

        logger.error(
            "Found %d technique(s) without tactics:",
            len(techniques_without_tactics),
        )
        for tech_info in techniques_without_tactics:
            logger.error("  - %s: %s", tech_info["id"], tech_info["name"])
            if tech_info["tactic_ids_in_cache"]:
                logger.error(
                    "    Cache had tactic_ids: %s",
                    tech_info["tactic_ids_in_cache"],
                )
                logger.error(
                    "    Missing tactic IDs: %s",
                    tech_info["missing_tactic_ids"],
                )
            else:
                logger.error("    No tactic_ids found in cache data")

    def _load_techniques_from_cache(
        self, cache_data: dict, tactics: Dict[str, Tactic]
    ) -> Dict[str, Technique]:
        """Load techniques from cache data and link to tactics."""
        logger.debug(
            "Loading %d techniques from cache...",
            len(cache_data["techniques"]),
        )
        techniques: Dict[str, Technique] = {}
        techniques_without_tactics = []

        for technique_id, technique_data in cache_data["techniques"].items():
            # Get tactic IDs and find matching tactics
            tactic_ids = self._get_technique_tactic_ids(technique_data)
            technique_tactics, missing_tactic_ids = self._find_matching_tactics(
                tactic_ids, tactics
            )

            # Warn about missing tactic references
            if missing_tactic_ids:
                logger.warning(
                    "Technique %s (%s) references missing tactics: %s",
                    technique_id,
                    technique_data["name"],
                    missing_tactic_ids,
                )

            # Create technique
            technique = self._create_technique_from_cache(
                technique_id, technique_data, technique_tactics
            )
            techniques[technique_id] = technique

            # Track techniques without tactics for error logging
            if not technique_tactics:
                techniques_without_tactics.append(
                    {
                        "id": technique_id,
                        "name": technique_data["name"],
                        "tactic_ids_in_cache": tactic_ids,
                        "missing_tactic_ids": missing_tactic_ids,
                    }
                )

            # Link technique to tactics
            for tactic in technique_tactics:
                if technique not in tactic.techniques:
                    tactic.techniques.append(technique)

        # Log errors for techniques without tactics
        self._log_techniques_without_tactics(techniques_without_tactics)
        return techniques

    def _load_sub_techniques_from_cache(
        self, cache_data: dict, techniques: Dict[str, Technique]
    ) -> Dict[str, SubTechnique]:
        """Load sub-techniques from cache data and link to techniques."""
        logger.debug(
            "Loading %d sub-techniques from cache...",
            len(cache_data["sub_techniques"]),
        )
        sub_techniques: Dict[str, SubTechnique] = {}
        for sub_technique_id, sub_technique_data in cache_data[
            "sub_techniques"
        ].items():
            technique = techniques.get(sub_technique_data["technique_id"])
            if technique:
                # Get URL from cache or construct it
                sub_technique_url = sub_technique_data.get("url")
                if not sub_technique_url:
                    sub_technique_url = self._construct_attack_url(sub_technique_id)

                sub_technique = SubTechnique(
                    name=sub_technique_data["name"],
                    description=sub_technique_data["description"],
                    id=sub_technique_data["id"],
                    url=sub_technique_url,
                    technique=technique,
                )
                sub_techniques[sub_technique_id] = sub_technique

                # Add sub-technique to technique's list
                if sub_technique not in technique.sub_techniques:
                    technique.sub_techniques.append(sub_technique)
        return sub_techniques

    def _load_from_cache(
        self,
    ) -> tuple[Dict[str, Tactic], Dict[str, Technique], Dict[str, SubTechnique]]:
        """Load data from the cache file and return dictionaries."""
        cache_size_mb = self.cache_file.stat().st_size / 1024 / 1024
        logger.debug("Reading cache file (%.2f MB)...", cache_size_mb)

        with open(self.cache_file, "r", encoding="utf-8") as f:
            cache_data = json.load(f)

        # First pass: Create all tactics
        tactics = self._load_tactics_from_cache(cache_data)

        # Second pass: Create all techniques and link to tactics
        techniques = self._load_techniques_from_cache(cache_data, tactics)

        # Third pass: Create all sub-techniques and link to techniques
        sub_techniques = self._load_sub_techniques_from_cache(cache_data, techniques)

        # Clear cache_data to free memory
        del cache_data
        gc.collect()

        return tactics, techniques, sub_techniques

    def refresh_cache(self):
        """
        Force refresh the cache by fetching fresh data from MITRE ATT&CK.
        This will overwrite the existing cache file and re-download the STIX
        data.
        """
        # Re-download STIX data
        self._download_stix_data()

        # Fetch fresh data (this will rebuild and save to cache)
        tactics, techniques, sub_techniques = self._fetch_and_build_data()
        kill_chain_stages: Dict[str, CyberKillChainStage] = {}
        self._load_kill_chain_mapping(tactics, kill_chain_stages)
        self._save_to_cache(tactics, techniques, sub_techniques)


class MitreAttackMapper:
    """
    Maps MITRE ATT&CK techniques to tactics and sub-techniques.
    Provides methods to retrieve technique and sub-technique information.
    """

    def __init__(self, mapping_fetcher: MappingFetcher):
        """
        Initialize the mapper with a MappingFetcher.

        Args:
            mapping_fetcher: MappingFetcher instance that will provide the
                            mapping data
        """
        logger.debug("Initializing MitreAttackMapper")

        # Fetch and store the mapping data
        self._mapping_data = mapping_fetcher.fetch_and_build_data()

        logger.debug("MitreAttackMapper initialized")

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """
        Get a technique by its ID.

        Args:
            technique_id: The technique ID (e.g., "T1548")

        Returns:
            Technique object if found, None otherwise
        """
        return self._mapping_data.techniques.get(technique_id)

    def get_techniques(self, technique_ids: List[str]) -> List[Technique]:
        """
        Get multiple techniques by their IDs.

        Args:
            technique_ids: List of technique IDs (e.g., ["T1548", "T1134"])

        Returns:
            List of Technique objects (skips any not found)
        """
        techniques = []
        for technique_id in technique_ids:
            technique = self.get_technique(technique_id)
            if technique:
                techniques.append(technique)
        return techniques

    def get_sub_technique(self, sub_technique_id: str) -> Optional[SubTechnique]:
        """
        Get a sub-technique by its ID.

        Args:
            sub_technique_id: The sub-technique ID (e.g., "T1548.001")

        Returns:
            SubTechnique object if found, None otherwise
        """
        return self._mapping_data.sub_techniques.get(sub_technique_id)

    def get_sub_techniques(self, sub_technique_ids: List[str]) -> List[SubTechnique]:
        """
        Get multiple sub-techniques by their IDs.

        Args:
            sub_technique_ids: List of sub-technique IDs
                              (e.g., ["T1548.001", "T1134.001"])

        Returns:
            List of SubTechnique objects (skips any not found)
        """
        sub_techniques = []
        for sub_technique_id in sub_technique_ids:
            sub_technique = self.get_sub_technique(sub_technique_id)
            if sub_technique:
                sub_techniques.append(sub_technique)
        return sub_techniques

    def get_all_techniques(self) -> List[Technique]:
        """
        Get all techniques.

        Returns:
            List of all Technique objects
        """
        return list(self._mapping_data.techniques.values())

    def get_all_sub_techniques(self) -> List[SubTechnique]:
        """
        Get all sub-techniques.

        Returns:
            List of all SubTechnique objects
        """
        return list(self._mapping_data.sub_techniques.values())

    def get_all_tactics(self) -> List[Tactic]:
        """
        Get all tactics.

        Returns:
            List of all Tactic objects
        """
        return list(self._mapping_data.tactics.values())

    def get_kill_chain_stages(self) -> Dict[str, CyberKillChainStage]:
        """
        Get all kill chain stages.

        Returns:
            Dict of all CyberKillChainStage objects
        """
        return self._mapping_data.kill_chain_stages


def init_mapper(
    cache_file: Optional[str] = None, version: Optional[str] = None
) -> MitreAttackMapper:
    """
    Get or create the global MitreAttackMapper instance.

    Args:
        cache_file: Path to JSON cache file. Only used when creating a new
                   instance. If an instance already exists, this parameter is
                   ignored.
        version: MITRE ATT&CK version to use. Only used when creating a new
                instance. If an instance already exists, this parameter is
                ignored.

    Returns:
        The global MitreAttackMapper instance
    """
    mapping_fetcher = MappingFetcher(cache_file=cache_file, version=version)
    return MitreAttackMapper(mapping_fetcher=mapping_fetcher)


# Create a global instance for easy access
MAPPER_INSTANCE: MitreAttackMapper = init_mapper()


def get_mapper() -> MitreAttackMapper:
    """Get the global mapper instance"""
    return MAPPER_INSTANCE


# Convenience functions that use the global mapper instance
def get_technique(technique_id: str) -> Optional[Technique]:
    """Get a technique by its ID using the global mapper instance"""
    return get_mapper().get_technique(technique_id)


def get_techniques(technique_ids: List[str]) -> List[Technique]:
    """Get multiple techniques by their IDs using the global mapper instance"""
    return get_mapper().get_techniques(technique_ids)


def get_sub_technique(sub_technique_id: str) -> Optional[SubTechnique]:
    """Get a sub-technique by its ID using the global mapper instance"""
    return get_mapper().get_sub_technique(sub_technique_id)


def get_sub_techniques(
    sub_technique_ids: List[str],
) -> List[SubTechnique]:
    """Get multiple sub-techniques by their IDs using the global mapper
    instance"""
    return get_mapper().get_sub_techniques(sub_technique_ids)


def get_all_techniques() -> List[Technique]:
    """Get all techniques using the global mapper instance"""
    return get_mapper().get_all_techniques()


def get_all_sub_techniques() -> List[SubTechnique]:
    """Get all sub-techniques using the global mapper instance"""
    return get_mapper().get_all_sub_techniques()


def get_all_tactics() -> List[Tactic]:
    """Get all tactics using the global mapper instance"""
    return get_mapper().get_all_tactics()


if __name__ == "__main__":
    mapper = get_mapper()
    print("Got mapper. Fetching technique T1548...")
    tt = mapper.get_technique("T1548")
    if not tt:
        print("No technique found")
        sys.exit(1)

    print("Got technique. Fetching tactics...")
    print(tt)
    tacs = tt.tactics
    print(f"Tactics: {len(tacs)}")
    for tac in tacs:
        kill_chain_names = [
            kill_chain_stage.name for kill_chain_stage in tac.kill_chain_stages
        ]
        print(
            f"For tactic: {tac.name} ({tac.url} - {tac.description}) "
            f"found kill chain stages: {kill_chain_names}"
        )
