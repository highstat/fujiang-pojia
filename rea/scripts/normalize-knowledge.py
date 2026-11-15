#!/usr/bin/env python3
"""Normalise the metadata vocabulary of the REA knowledge corpus.

Usage:
    python3 normalize-knowledge.py [--check]

Rewrites the `platforms` and `arch` frontmatter fields to the canonical
vocabulary and separator style:

    platforms : "windows, macos, linux, android, ios"   (", " separator)
    arch      : "x86, x86-64, arm64"                    (", " separator)

Architecture synonyms are folded:

    x64, x86-64, amd64  -> x86-64
    aarch64, arm64 -> arm64; arm64e remains distinct
    i386, x86, ia32     -> x86
    arm, arm32, thumb32 -> arm

Platform names are lower-cased and sorted into a fixed order, so the same set
always renders identically.

With --check the script reports what would change and exits 1 when the corpus
is not normalised. Without the flag it rewrites the files in place.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PLATFORM_ORDER = ["windows", "macos", "linux", "android", "ios"]
PLATFORM_ALIASES = {
    "win": "windows", "win32": "windows", "windows": "windows",
    "darwin": "macos", "macos": "macos", "macosx": "macos", "osx": "macos",
    "linux": "linux", "gnu/linux": "linux",
    "android": "android",
    "ios": "ios",
}
ARCH_ALIASES = {
    "x86": "x86", "i386": "x86", "ia32": "x86", "x86-32": "x86", "x86_32": "x86",
    "x64": "x86-64", "x86-64": "x86-64", "x86_64": "x86-64", "amd64": "x86-64",
    "arm": "arm", "arm32": "arm", "thumb": "arm", "thumb32": "arm", "armv7": "arm",
    "arm64": "arm64", "arm64e": "arm64e", "aarch64": "arm64", "armv8": "arm64",
}
ARCH_ORDER = ["x86", "x86-64", "arm", "arm64", "arm64e"]

FRONTMATTER = re.compile(r"^---\n(.*?)\n---\n", re.S)


def normalise_platforms(value: str) -> str:
    value = json.loads(value) if value.strip().startswith('"') else value.strip()
    if value in ("-", ""):
        return "-"
    names = [PLATFORM_ALIASES.get(part.strip().lower(), part.strip().lower())
             for part in value.split(",")]
    names = [name for name in names if name]
    unique = [name for name in PLATFORM_ORDER if name in names]
    unknown = [name for name in names if name not in PLATFORM_ORDER]
    if unknown:
        raise ValueError(f"unknown platform(s): {unknown}")
    return ", ".join(unique) if unique else "-"


def normalise_arch(value: str) -> str:
    value = json.loads(value) if value.strip().startswith('"') else value.strip()
    if value in ("-", ""):
        return "-"
    names = [ARCH_ALIASES.get(part.strip().lower(), part.strip().lower())
             for part in value.split(",")]
    names = [name for name in names if name]
    unique = [name for name in ARCH_ORDER if name in names]
    unknown = [name for name in names if name not in ARCH_ORDER]
    if unknown:
        raise ValueError(f"unknown architecture(s): {unknown}")
    return ", ".join(unique) if unique else "-"


def process(path: Path, write: bool) -> bool:
    text = path.read_text(encoding="utf-8")
    match = FRONTMATTER.match(text)
    if match is None:
        return False

    frontmatter = match.group(1)
    changed = False
    updated_lines = []
    for line in frontmatter.split("\n"):
        for field, normaliser in (("platforms", normalise_platforms),
                                  ("arch", normalise_arch)):
            if line.startswith(field + ":"):
                _, _, value = line.partition(":")
                try:
                    new_value = normaliser(value)
                except ValueError as error:
                    print(f"{path}: {error}", file=sys.stderr)
                    raise
                current = value.strip().strip('"')
                if new_value != current:
                    changed = True
                    line = f'{field}: "{new_value}"'
                break
        updated_lines.append(line)

    if changed and write:
        new_frontmatter = "\n".join(updated_lines)
        path.write_text(
            text[:match.start()] + f"---\n{new_frontmatter}\n---\n" + text[match.end():],
            encoding="utf-8",
        )
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parent.parent / "knowledge")
    parser.add_argument("--check", action="store_true",
                        help="report differences without writing")
    args = parser.parse_args()

    entries = [
        path for path in sorted(args.root.rglob("*.md"))
        if path.name not in ("SCHEMA.md", "SKILL.md")
    ]
    if not entries:
        print(f"no entries found under {args.root}", file=sys.stderr)
        return 1

    try:
        changed_files = [path for path in entries if process(path, write=not args.check)]
    except ValueError:
        return 1

    if args.check:
        if changed_files:
            print(f"{len(changed_files)} entr{'y' if len(changed_files) == 1 else 'ies'} "
                  "need normalisation:", file=sys.stderr)
            for path in changed_files:
                print(f"  {path}", file=sys.stderr)
            return 1
        print(f"REA knowledge metadata normalised: {len(entries)} entries.")
        return 0

    print(f"normalised {len(changed_files)} of {len(entries)} entries")
    for path in changed_files:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
