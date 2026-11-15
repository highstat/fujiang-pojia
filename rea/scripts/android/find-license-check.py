#!/usr/bin/env python3
"""Find the licence check in a decoded APK tree.

Usage:
    python3 find-license-check.py <decoded-apk-dir>

Scans smali sources for the shapes that a licence check takes in smali:
a call to a validation method, a boolean test on the result, a date
comparison, and the strings that a licence error uses.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

METHOD_NAMES = re.compile(
    r"invoke-\w+\s+\{[^}]*\},?\s*L[^;]*?(?:Licen\w*|Serial\w*|Activat\w*|Trial\w*|"
    r"Expir\w*|Valid\w*|Register\w*|Premium\w*|Subscription\w*|Unlock\w*)[^;]*;",
    re.IGNORECASE,
)
BOOLEAN_TEST = re.compile(
    r"(if-eqz|if-nez)\s+(v\d+),\s*:?(cond_\w+|\w+)"
)
DATE_CALL = re.compile(
    r"Ljava/(?:time|util)/[^;]*?(currentTimeMillis|nanoTime|now)\(\)"
)
STRINGS = re.compile(
    r'const-string(?:/jumbo)?\s+[vp]\d+,\s+"(?P<text>[^"]*(?:licen|serial|trial|expire|'
    r'activat|registr|premium|unlock|purchas)[^"]*)"',
    re.IGNORECASE,
)
HARDCODE_BOOL = re.compile(
    r"(const/4\s+[vp]\d+,\s+0x0|const/4\s+[vp]\d+,\s+0x1)"
    r"[\s\S]{0,80}?return\s+[vp]\d+"
)


def scan(directory: Path) -> dict[str, list[tuple[str, int, str]]]:
    findings: dict[str, list[tuple[str, int, str]]] = {
        "method_calls": [],
        "boolean_tests": [],
        "date_uses": [],
        "strings": [],
        "hardcoded_returns": [],
    }

    for path in sorted(directory.rglob("*.smali")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            match = METHOD_NAMES.search(stripped)
            if match:
                findings["method_calls"].append((str(path), number, stripped))

            match = BOOLEAN_TEST.search(stripped)
            if match:
                findings["boolean_tests"].append((str(path), number, stripped))

            if DATE_CALL.search(stripped):
                findings["date_uses"].append((str(path), number, stripped))

            match = STRINGS.search(stripped)
            if match:
                findings["strings"].append((str(path), number, match.group("text")))

            if HARDCODE_BOOL.search(stripped):
                findings["hardcoded_returns"].append((str(path), number, stripped))

    return findings


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    directory = Path(sys.argv[1])
    if not directory.is_dir():
        print(f"not a directory: {directory}", file=sys.stderr)
        return 1

    findings = scan(directory)

    print(f"scanned {directory}\n")

    for label, entries in findings.items():
        print(f"== {label} ({len(entries)})")
        limit = 40 if label == "method_calls" else 25
        for path, number, text in entries[:limit]:
            print(f"  {path}:{number}: {text}")
        if len(entries) > limit:
            print(f"  ... {len(entries) - limit} more")
        print()

    if not any(findings.values()):
        print("no licence-shaped constructs found — the check may be native, "
              "obfuscated, or in a library module")
    return 0


if __name__ == "__main__":
    sys.exit(main())
