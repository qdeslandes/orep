#!/usr/bin/python3
import argparse
import getpass
import logging
from orep.orep import OpConnect, HostCredentials, set_logger
from orep.utils import get_config


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
        "--ask-pass",
        action="store_true",
        help="Ask for new user's password instead of generating a new one",
    )

    # Renew credentials command
    renew_parser = subparsers.add_parser("renew")
    renew_parser.add_argument("--hostname", required=True, help="Host to renew credentials for")
    renew_parser.add_argument("--username", required=True, help="User to change credentials for")
    renew_parser.add_argument(
        "--ask-pass",
        action="store_true",
        help="Ask for new user's password instead of generating a new one",
    )

    # Set default credentials command
    default_parser = subparsers.add_parser("default")
    default_parser.add_argument(
        "--hostname", required=True, help="Host to change the default user for"
    )
    default_parser.add_argument("--username", required=True, help="New default user")

    # Connect command
    connect_parser = subparsers.add_parser("connect")
    connect_parser.add_argument("--username", default=None, help="Username to connect with")
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
    args = parse_arguments(get_config())
    logger = setup_logging(logging.DEBUG if args.debug else logging.INFO)
    set_logger(logger)

    op = OpConnect(args.op_host, args.op_api_key, logger)
    host = HostCredentials(args.hostname, op, op.get_vault_by_name(args.vault), logger)

    if args.command == "create":
        logger.info(f"Please, provide current host's password for {args.username}")
        host.create(
            args.username,
            getpass.getpass("Password: "),
            ask_pass=args.ask_pass,
            force=False,
        )
    elif args.command == "renew":
        host.renew(args.username, ask_pass=args.ask_pass)
    elif args.command == "default":
        host.default(args.username)
    elif args.command == "connect":
        host.connect(args.username)
