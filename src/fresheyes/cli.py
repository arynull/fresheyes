"""Command line interface for fresheyes."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from . import __version__
from .config import Config, ConfigError, discover, load_file
from .engine import Scanner
from .findings import Severity
from .report import render_human, render_json, render_rules_human, render_rules_json

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_FORMATS = ("human", "json")

_DESCRIPTION = """\
fresheyes finds risky patterns in source code before they ship.

It runs entirely offline: no network calls, no telemetry, and it never executes
the code it reads.
"""

_EPILOG = """\
examples:
  fresheyes scan                       scan the current directory
  fresheyes scan src/ --format json    machine-readable output for CI
  fresheyes scan app.py                scan a single file
  fresheyes rules                      list every rule
"""


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the console script."""
    parser = argparse.ArgumentParser(
        prog="fresheyes",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"fresheyes {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = subparsers.add_parser(
        "scan",
        help="scan a file or directory for risky patterns",
        description="Scan PATH (default: current directory) and report findings.",
    )
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        metavar="PATH",
        help="file or directory to scan",
    )
    scan.add_argument(
        "--format",
        choices=_FORMATS,
        default="human",
        help="output format (default: human)",
    )
    scan.add_argument(
        "--config",
        metavar="FILE",
        help="configuration file (default: .fresheyes.toml or pyproject.toml)",
    )
    scan.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        help="override the failure threshold: critical, high, medium or low",
    )
    scan.add_argument(
        "--select",
        metavar="RULE",
        action="append",
        help="only run this rule (repeatable)",
    )
    scan.add_argument(
        "--ignore",
        metavar="RULE",
        action="append",
        help="skip this rule (repeatable)",
    )

    rules = subparsers.add_parser(
        "rules",
        help="list all available rules",
        description="Print every rule with its severity, languages and detector type.",
    )
    rules.add_argument(
        "--format",
        choices=_FORMATS,
        default="human",
        help="output format (default: human)",
    )
    return parser


def _load_config(explicit: str | None, path: Path) -> Config:
    """Resolve configuration from ``--config``, discovery, or defaults."""
    if explicit:
        config_path = Path(explicit)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        return load_file(config_path)
    found = discover(path)
    return found if found is not None else Config()


def _apply_overrides(config: Config, args: argparse.Namespace) -> Config:
    """Fold CLI overrides onto the file-based configuration."""
    select = tuple(args.select) if args.select else config.select
    ignore = tuple(args.ignore) if args.ignore else config.ignore
    threshold = config.fail_on_severity
    if args.fail_on:
        try:
            threshold = Severity.parse(args.fail_on)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    return Config(
        select=select,
        ignore=ignore,
        fail_on_severity=threshold,
        options=config.options,
        source=config.source,
    )


def _run_scan(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"fresheyes: no such path: {target}", file=stderr)
        return EXIT_ERROR

    config = _apply_overrides(_load_config(args.config, target), args)
    result = Scanner(config).scan_path(target)

    if args.format == "json":
        print(render_json(result, config), file=stdout)
    else:
        print(render_human(result, config), file=stdout)

    threshold = config.fail_on_severity
    blocking = [finding for finding in result.findings if finding.severity.rank >= threshold.rank]
    return EXIT_FINDINGS if blocking else EXIT_OK


def _run_rules(args: argparse.Namespace, stdout: TextIO) -> int:
    print(render_rules_json() if args.format == "json" else render_rules_human(), file=stdout)
    return EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Entry point for the ``fresheyes`` console script."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command is None:
        parser.print_help(out)
        return EXIT_ERROR

    try:
        if args.command == "scan":
            return _run_scan(args, out, err)
        if args.command == "rules":
            return _run_rules(args, out)
    except ConfigError as exc:
        print(f"fresheyes: {exc}", file=err)
        return EXIT_ERROR
    except OSError as exc:
        print(f"fresheyes: {exc}", file=err)
        return EXIT_ERROR

    parser.print_help(out)
    return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
