#!/usr/bin/python3
import argparse
import getpass
import json
import logging
import os
import sys
from orep.orep import OpConnect, HostCredentials

DEFAULT_CONFIG_NAME = ".orep.cfg"
DEFAULT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), DEFAULT_CONFIG_NAME)


def load_config(config_path: str) -> dict:
    """Load configuration from the default location.

    Args:
        config_path (str): path to the configuration file to read.

    Returns:
        dict: configuration options as defined in the configuration file.
    """

    if not os.path.exists(config_path):
        logger.info(f"Config file not found: {config_path}")
        return {}

    with open(config_path, "r", encoding="utf-8") as config:
        return json.loads(config.read())


def parse_arguments(config: dict = {}) -> argparse.Namespace:
    """Create argument parser and parse arguments.

    Args:
        config: configuration, read from the configuration file (if any).

    Returns:
        argparse.Namespace: parsed arguments.
    """

    parser = argparse.ArgumentParser(description="Create and edit hosts credentials.")

    # Generic arguments
    parser.add_argument(
        "--op_host",
        default=config["op_host"] if "op_host" in config else None,
        required=False if "op_host" in config else True,
        help="1Password Connect host URL.",
    )
    parser.add_argument(
        "--op_api_key",
        default=config["op_api_key"] if "op_api_key" in config else None,
        required=False if "op_api_key" in config else True,
        help="1Password Connect API key.",
    )
    parser.add_argument(
        "--vault",
        default=config["vault"] if "vault" in config else None,
        required=False if "vault" in config else True,
        help="Vault to fetch credentials from",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=config["debug"] if "debug" in config else False,
        help="If set, enable debug logging.",
    )

    subparsers = parser.add_subparsers(dest="command")

    # Create credentials command
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--hostname", required=True, help="Remote host's hostname")
    create_parser.add_argument("--username", required=True, help="Remote host's username")
    create_parser.add_argument(
        "--force", action="store_true", help="Force credentials change even if host already exists"
    )

    # Renew credentials command
    connect_parser = subparsers.add_parser("renew")
    connect_parser.add_argument("hostname", help="Host to connect to")

    # Connect command
    connect_parser = subparsers.add_parser("connect")
    connect_parser.add_argument("hostname", help="Host to connect to")

    return parser.parse_args()


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure logging facility.

    Args:
        level (int): log level to use.

    Returns:
        logging.Logger: logger object.
    """

    # Create logger
    logger = logging.getLogger("orep")
    logger.setLevel(level)

    # Create console handler and set level to debug
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter("%(asctime)s :: %(levelname)8s - %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    logger.addHandler(handler)

    return logger


if __name__ == "__main__":
    args = parse_arguments(load_config(DEFAULT_CONFIG_PATH))
    logger = setup_logging(logging.DEBUG if args.debug else logging.INFO)

    op = OpConnect(args.op_host, args.op_api_key, logger)
    host = HostCredentials(args.hostname, op, op.get_vault_by_name(args.vault), logger)

    if args.command == "create":
        if host.exists:
            if not args.force:
                logger.info("Credentials already exists. Pass --force to force override.")
                sys.exit(-1)
            else:
                logger.warning("CREDENTIALS ALREADY EXIST. FORCING OVERRIDE!")

        logger.info("Please, provide current host's password")
        password = getpass.getpass("Password: ")
        host.create(args.username, password, args.force)
    elif args.command == "renew":
        if not host.exists:
            logger.error("Credentials doesn't exist. Can't renew!")
            sys.exit(-1)
        host.renew()
    elif args.command == "connect":
        host.connect()
