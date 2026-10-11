"""Operator-facing, non-privileged VDS Agent commands."""
from __future__ import annotations

import argparse
import json

from .config import validate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vds-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check-config", help="validate the non-secret VDS Agent configuration")
    args = parser.parse_args(argv)
    if args.command == "check-config":
        try:
            print(json.dumps(validate(), indent=2, sort_keys=True))
            return 0
        except ValueError as error:
            print(f"configuration invalid: {error}")
            return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
