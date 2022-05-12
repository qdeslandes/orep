"""Utilities to help with Orep usage

Attributes:
    CONFIG_NAME (str): name of the configuration file.
    CONFIG_PATH (str): path to the configuration file.
"""
import json
import logging
import os

CONFIG_NAME = ".orep.cfg"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), CONFIG_NAME)


def get_config(logger: logging.Logger = logging) -> dict:
    """Load configuration from the default location.

    Args:
        config_path (str): path to the configuration file to read.

    Returns:
        dict: configuration options as defined in the configuration file.
    """

    if not os.path.exists(CONFIG_PATH):
        logger.info(f"Config file not found: {CONFIG_PATH}")
        return {}

    with open(CONFIG_PATH, "r", encoding="utf-8") as config:
        return json.loads(config.read())
