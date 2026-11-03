"""Command-line interface for strdeob."""

from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console

from . import __version__
from .core import ReadError, analyze, read_file
from .render import render

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

_DEFAULT_MAX_BYTES = 64 * 1024 * 1024


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="strdeob",
        description="Static string deobfuscator and IOC extractor for malware triage.",
        epilog=(
            "examples:\n"
            "  strdeob sample.bin\n"
            "  strdeob sample.bin --xor-max-keylen 2\n"
            "  strdeob sample.bin --json | jq .iocs\n"
            "  strdeob sample.bin --fail-on-ioc && echo clean\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", help="path to the file to analyse")
    parser.add_argument("--json", action="store_true", help="emit a JSON report instead of a table")
    parser.add_argument(
        "--min-str",
        type=int,
        default=4,
        metavar="N",
        help="minimum length for extracted/recovered strings (default: 4)",
    )
    parser.add_argument(
        "--xor-max-keylen",
        type=int,
        default=1,
        metavar="K",
        help="brute-force XOR keys up to K bytes; 0 disables the XOR pass (default: 1)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=_DEFAULT_MAX_BYTES,
        metavar="N",
        help=f"refuse files larger than N bytes (default: {_DEFAULT_MAX_BYTES})",
    )
    parser.add_argument(
        "--fail-on-ioc",
        action="store_true",
        help=f"exit {EXIT_ERROR} when any IOC is recovered",
    )
    parser.add_argument("--version", action="version", version=f"strdeob {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.min_str < 1:
        parser.error("--min-str must be >= 1")
    if args.xor_max_keylen < 0:
        parser.error("--xor-max-keylen must be >= 0")
    if args.max_bytes < 1:
        parser.error("--max-bytes must be >= 1")

    try:
        data = read_file(args.file, args.max_bytes)
    except ReadError as exc:
        print(f"strdeob: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report = analyze(data, path=args.file, min_length=args.min_str, max_keylen=args.xor_max_keylen)

    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        render(report, Console())

    if args.fail_on_ioc and report.iocs:
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
