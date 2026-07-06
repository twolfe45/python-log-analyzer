#!/usr/bin/env python3
"""Summarize failed/error/warning counts in a plain-text log file."""

import argparse
import os
import sys


def analyze_log(path: str) -> dict[str, int]:
    counts = {"failed": 0, "errors": 0, "warnings": 0}
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            text = line.lower()
            if "failed" in text:
                counts["failed"] += 1
            if "error" in text:
                counts["errors"] += 1
            if "warning" in text:
                counts["warnings"] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Count failed, error, and warning lines in a text log file."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to the log file (omit to be prompted interactively)",
    )
    args = parser.parse_args()

    log_file = args.log_file
    if not log_file:
        log_file = input("Enter the path to a text log file: ").strip()

    if not log_file:
        print("Error: no log file path provided.", file=sys.stderr)
        return 1

    if not os.path.isfile(log_file):
        print(f"Error: file not found: {log_file}", file=sys.stderr)
        return 1

    counts = analyze_log(log_file)

    print("\n========== Analysis Complete ==========")
    print(f"Failed Events : {counts['failed']}")
    print(f"Errors        : {counts['errors']}")
    print(f"Warnings      : {counts['warnings']}")
    print("=======================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())