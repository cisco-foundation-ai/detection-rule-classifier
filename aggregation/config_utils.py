# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shared configuration utilities for aggregation modules.

This module provides common configuration loading and CLI argument processing
functions used across multiple aggregation tools.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def load_config(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from JSON file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If configuration file doesn't exist
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_config_from_args(
    config_arg: str | None,
) -> Dict[str, Any]:
    """
    Load configuration from CLI argument if provided.

    Args:
        config_arg: Path to config file from CLI argument (or None)

    Returns:
        Configuration dictionary (empty dict if no config provided)
        Returns 1 if config file not found

    Note:
        Logs error and returns non-zero on failure for easy use in main()
    """
    config_dict = {}
    if config_arg:
        config_path = Path(config_arg)
        if not config_path.exists():
            logger.error("Configuration file not found: %s", config_path)
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        config_dict = load_config(config_path)
    return config_dict


def setup_logging(debug: bool = False, module_names: list[str] | None = None) -> None:
    """
    Configure logging for aggregation modules.

    Args:
        debug: Enable debug-level logging
        module_names: Additional module names to set log level for
    """
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Set log level for specified modules
    if module_names:
        for module_name in module_names:
            logging.getLogger(module_name).setLevel(log_level)
