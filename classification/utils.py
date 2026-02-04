# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""MITRE ATT&CK Technique Classification using LLMs.

This module provides:
- LLM providers (OpenAI, HuggingFace) for technique classification
- Response parsing to extract technique IDs
- Annotation result handling and JSON output

Classification Terminology:
    - PLAUSIBLE (Step 1): Broad initial filtering from all ~600 techniques
      Returns a manageable subset (e.g., 10) that could plausibly be related.

    - RELEVANT (Step 2): Refined selection from the plausible set
      Returns the 1-3 most specifically detected techniques.

    - SINGLE-STEP MODE: Skip plausible step and directly classify relevant
      from the full technique list (faster but potentially less precise).
"""

from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from openai import OpenAI
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from mitre_mapping.mitre_attack_mapper import (
    SubTechnique,
    Technique,
    get_all_sub_techniques,
    get_all_techniques,
)

logger = logging.getLogger(__name__)

PLAUSIBLE_STEP = "plausible_step"
RELEVANT_STEP = "relevant_step"
required_config_values = [RELEVANT_STEP]


@dataclass
class AnnotationResult:
    """Result of technique classification for a single rule."""

    plausible: List[str] = field(default_factory=list)
    relevant: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary, removing relevant items from plausible."""
        relevant_set = set(self.relevant)
        filtered_plausible = [t for t in self.plausible if t not in relevant_set]
        return {"plausible": filtered_plausible, "relevant": self.relevant}


@dataclass
class StepConfig:
    """Configuration for a classification step."""

    enabled: bool
    provider: str
    model: str
    top_k: int
    prompt: str
    use_short_descriptions: bool


@dataclass
class PipelineConfig:
    """Full pipeline configuration."""

    plausible_step: Optional[StepConfig]
    relevant_step: StepConfig
    config_dict: dict
    num_workers: int = 1
    retries: int = 3


def parse_step_config(step_dict: dict, step_name: str) -> StepConfig:
    """Parse step configuration from dictionary."""
    enabled = step_dict.get("enabled", True)

    if not enabled:
        return StepConfig(
            enabled=False,
            provider="",
            model="",
            top_k=0,
            prompt="",
            use_short_descriptions=False,
        )

    required = ["provider", "model", "prompt"]
    missing = [k for k in required if k not in step_dict]
    if missing:
        raise ValueError(f"{step_name} missing required fields: {missing}")

    return StepConfig(
        enabled=True,
        provider=step_dict["provider"],
        model=step_dict["model"],
        top_k=step_dict.get("top_k", 10 if "plausible" in step_name else 3),
        prompt=step_dict["prompt"],
        use_short_descriptions=step_dict.get("use_short_descriptions", False),
    )


def load_config(config_path: Path) -> PipelineConfig:
    """Load configuration from JSON file."""
    with open(config_path, "r", encoding="utf-8") as f:
        config_dict = json.load(f)

    # Required fields
    missing = [k for k in required_config_values if k not in config_dict]
    if missing:
        raise ValueError(f"Config missing required fields: {missing}")

    # Parse plausible step (optional)
    plausible_step = None
    if PLAUSIBLE_STEP in config_dict:
        plausible_step = parse_step_config(config_dict[PLAUSIBLE_STEP], PLAUSIBLE_STEP)
        if not plausible_step.enabled:
            plausible_step = None

    # Parse relevant step (required)
    relevant_step = parse_step_config(config_dict[RELEVANT_STEP], RELEVANT_STEP)

    # Parse num_workers (optional, defaults to 1)
    num_workers = config_dict.get("num_workers", 1)
    if not isinstance(num_workers, int) or num_workers < 1:
        raise ValueError("num_workers must be a positive integer")

    # Parse retries (optional, defaults to 3)
    retries = config_dict.get("retries", 3)
    if not isinstance(retries, int) or retries < 0:
        raise ValueError("retries must be a non-negative integer")

    return PipelineConfig(
        plausible_step=plausible_step,
        relevant_step=relevant_step,
        config_dict=config_dict,
        num_workers=num_workers,
        retries=retries,
    )


def load_labels() -> List[str]:
    """Load technique IDs from labels file."""
    return [tech.id for tech in get_all_techniques() + get_all_sub_techniques()]


def format_tech_description(
    tech: Union[Technique, SubTechnique], use_short_descriptions: bool = False
) -> str:
    """Format technique or sub-technique description."""
    if use_short_descriptions:
        return f"{tech.id} - {tech.name}"

    return f"{tech.id} - {tech.name}\n{tech.description}"


def get_descriptions(
    use_short_descriptions: bool = False,
) -> Tuple[str, Dict[str, str]]:
    """Get all descriptions and description map."""
    techniques = get_all_techniques()
    sub_techniques = get_all_sub_techniques()

    tech_descriptions = [
        format_tech_description(tech, use_short_descriptions) for tech in techniques
    ]
    sub_tech_descriptions = [
        format_tech_description(sub_tech, use_short_descriptions)
        for sub_tech in sub_techniques
    ]

    sorted_tech_descriptions = sorted(tech_descriptions + sub_tech_descriptions)
    descriptions = "\n\n".join(sorted_tech_descriptions)

    description_map = {tech.id: tech.name for tech in techniques + sub_techniques}
    return descriptions, description_map


def filter_descriptions(
    techniques: List[str], use_short_descriptions: bool = False
) -> str:
    """Get descriptions only for specified techniques."""
    all_techniques = get_all_techniques()
    all_sub_techniques = get_all_sub_techniques()
    technique_lookup = {tech.id: tech for tech in all_techniques + all_sub_techniques}

    lines = []
    for tech_id in sorted(techniques):
        if tech_id in technique_lookup:
            tech_obj = technique_lookup[tech_id]
            lines.append(format_tech_description(tech_obj, use_short_descriptions))

    return "\n\n".join(lines)


def fill_prompt_template(template: str, variables: Dict[str, Any]) -> str:
    """Fill prompt template with variables, using empty string for missing keys."""

    class SafeDict(dict):
        """Safe dictionary for filling prompt template."""

        def __missing__(self, key: str) -> str:
            """Return empty string for missing keys."""
            return ""

    return template.format_map(SafeDict(variables))


def parse_techniques_from_response(
    llm_response: str, known_technique_ids: List[str]
) -> List[str]:
    """Parse LLM response to extract technique IDs in order of appearance.

    Args:
        llm_response: Raw LLM response text
        known_technique_ids: List of all known technique IDs to match against

    Returns:
        List of technique IDs found, ordered by position in response
    """
    found_ordered = []
    for technique_id in known_technique_ids:
        # Match technique ID not followed by more sub-technique digits
        # e.g., T1003 should not match T1003.001
        pattern = r"\b" + re.escape(technique_id) + r"(?!\.\d)"
        match = re.search(pattern, llm_response)
        if match:
            found_ordered.append((match.start(), technique_id))

    found_ordered.sort()
    return [technique_id for _, technique_id in found_ordered]


# pylint: disable=too-few-public-methods
class LLMClassifier:
    """Base classifier interface."""

    def query(self, prompt: str) -> str:
        """Send prompt to LLM and return response."""
        raise NotImplementedError


# pylint: disable=too-few-public-methods
class OpenAIClassifier(LLMClassifier):
    """OpenAI API classifier."""

    def __init__(
        self,
        model: str,
        timeout: int = 120,
        max_retries: int = 3,
        disable_ssl_verify: bool = False,
        step_name: Optional[str] = None,
    ):
        # Create httpx client with SSL verification control
        http_client = httpx.Client(verify=False) if disable_ssl_verify else None

        if disable_ssl_verify:
            logger.warning(
                "SSL verification is DISABLED - use only for development/testing to bypass proxy restrictions"
            )

        self.client = OpenAI(
            timeout=timeout, max_retries=max_retries, http_client=http_client
        )
        self.model = model
        self.uses_completion_tokens = any(
            x in model.lower() for x in ["o1", "o3", "o4"]
        )
        if step_name:
            logger.info("Using OpenAI model for %s: %s", step_name, model)
        else:
            logger.info("Using OpenAI model: %s", model)

    def query(self, prompt: str) -> str:
        params: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }

        if self.uses_completion_tokens:
            params["max_completion_tokens"] = 4000
        else:
            params["temperature"] = 0
            params["max_tokens"] = 2000

        llm_response = self.client.chat.completions.create(**params)
        return llm_response.choices[0].message.content.strip()


# pylint: disable=too-few-public-methods
class HuggingFaceClassifier(LLMClassifier):
    """HuggingFace transformers classifier."""

    def __init__(self, model: str):
        logger.info("Loading HuggingFace model: %s", model)
        self.tokenizer = AutoTokenizer.from_pretrained(model)
        self.model = AutoModelForCausalLM.from_pretrained(
            model,
            torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
            device_map="auto",
            low_cpu_mem_usage=True,
        )
        self.model.eval()

        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        self.device = next(self.model.parameters()).device
        logger.info("Model loaded on device: %s", self.device)

    def query(self, prompt: str) -> str:
        if hasattr(self.tokenizer, "chat_template") and self.tokenizer.chat_template:
            messages = [{"role": "user", "content": prompt}]
            formatted_prompt = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        else:
            formatted_prompt = prompt

        inputs = self.tokenizer(
            formatted_prompt, return_tensors="pt", truncation=True, max_length=16384
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=1500,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
            )
            prompt_length = inputs["input_ids"].shape[1]
            generated_tokens = outputs[0][prompt_length:]
            return self.tokenizer.decode(
                generated_tokens, skip_special_tokens=True
            ).strip()


def create_classifier(
    provider: str,
    model: str,
    disable_ssl_verify: bool = False,
    step_name: Optional[str] = None,
) -> LLMClassifier:
    """Create LLM classifier from provider and model."""
    if provider == "openai":
        return OpenAIClassifier(
            model, disable_ssl_verify=disable_ssl_verify, step_name=step_name
        )
    if provider == "huggingface":
        return HuggingFaceClassifier(model)
    raise ValueError(f"Unknown provider: {provider}. Use 'openai' or 'huggingface'")


class TechniqueClassifier:
    """MITRE ATT&CK Technique Classifier.

    Handles both plausible and relevant classification steps.
    """

    def __init__(
        self,
        config: StepConfig,
        labels: List[str],
        disable_ssl_verify: bool = False,
        step_name: Optional[str] = None,
    ):
        self.config = config
        self.llm = create_classifier(
            config.provider,
            config.model,
            disable_ssl_verify=disable_ssl_verify,
            step_name=step_name,
        )
        self.top_k = config.top_k
        self.prompt_template = config.prompt
        self.descriptions, self.description_map = get_descriptions(
            config.use_short_descriptions
        )
        self.labels = labels

    def query_and_parse_techniques(self, variables: Dict[str, Any]) -> List[str]:
        """Query LLM and parse techniques from response."""
        prompt = fill_prompt_template(self.prompt_template, variables)
        llm_response = self.llm.query(prompt)

        logger.debug("  Response: %s...", llm_response[:200])

        techniques = parse_techniques_from_response(llm_response, self.labels)
        return techniques[: self.top_k]

    def classify_plausible(self, rule_content: str) -> List[str]:
        """Step 1: Classify rule to get PLAUSIBLE techniques.

        This is a broad initial filtering from all techniques (~600).
        Returns a manageable subset (e.g., top 10) that could plausibly be related.

        Args:
            rule_content: The detection rule content to classify

        Returns:
            List of plausible technique IDs, ordered by relevance
        """
        variables = {
            "top_k": self.top_k,
            "rule_content": rule_content,
            "descriptions": self.descriptions or "",
        }

        return self.query_and_parse_techniques(variables)

    def classify_relevant(
        self, rule_content: str, plausible_techniques: Optional[List[str]] = None
    ) -> List[str]:
        """Step 2: Refine plausible techniques to RELEVANT ones.

        Takes the plausible set and narrows it down to the 1-3 most
        specifically detected techniques using more detailed analysis.

        If plausible_techniques is None, classifies directly from all techniques
        (single-step mode).

        Args:
            rule_content: The detection rule content
            plausible_techniques: List of plausible technique IDs from Step 1,
            or None for single-step mode.

        Returns:
            List of most relevant technique IDs, ordered by relevance
        """
        # Build filtered descriptions for plausible techniques
        filtered_desc = ""
        if plausible_techniques:
            filtered_desc = filter_descriptions(
                plausible_techniques, self.config.use_short_descriptions
            )

        variables = {
            "top_k": self.top_k,
            "rule_content": rule_content,
            "plausible_techniques": (
                ", ".join(plausible_techniques) if plausible_techniques else ""
            ),
            "descriptions": (
                filtered_desc if plausible_techniques else (self.descriptions or "")
            ),
            "full_descriptions": self.descriptions or "",
        }

        return self.query_and_parse_techniques(variables)


def save_annotations(
    annotations: Dict[str, AnnotationResult], output_path: Path
) -> None:
    """Save annotations to JSON file."""
    output_list = [
        {
            "id": rule_id,
            "plausible_techniques": result.to_dict()["plausible"],
            "relevant_techniques": result.to_dict()["relevant"],
        }
        for rule_id, result in annotations.items()
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_list, f, indent=2)

    logger.info("Saved %d annotations to %s", len(annotations), output_path)
