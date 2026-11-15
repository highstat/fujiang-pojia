#!/usr/bin/env python3
"""Apply a patch manifest to a binary with verification and rollback.

Usage:
    python3 apply-patch.py manifest.json target output [--force]

The manifest format is documented in skills/rea-patching-automation/SKILL.md.
Every patch declares the bytes it expects to find. The applier refuses to
write when the expected bytes are not present, so a manifest written for a
different build cannot silently corrupt a target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import re
import stat
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_hex(value: str) -> bytes:
    cleaned = value.replace(" ", "").replace(",", "").replace("_", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as error:
        raise ValueError(f"not a hex byte string: {value!r}") from error


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("patches"), list) or not manifest["patches"]:
        raise ValueError("manifest must contain a non-empty patches array")
    if set(manifest) - {"target", "target_sha256", "patches", "format", "architecture", "notes"}:
        raise ValueError("unknown manifest fields")
    if not isinstance(manifest.get("target"), str) or not manifest["target"]:
        raise ValueError("manifest requires a target name")
    if not isinstance(manifest.get("target_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", manifest["target_sha256"]):
        raise ValueError("manifest requires a lowercase SHA-256")
    identifiers = set()
    ranges = []
    for patch in manifest["patches"]:
        if not isinstance(patch, dict) or any(not isinstance(patch.get(key), str) or not patch[key].strip() for key in ("id", "reason", "match", "replace")):
            raise ValueError("each patch requires non-empty id, reason, match and replace strings")
        if type(patch.get("offset")) is not int or patch["offset"] < 0:
            raise ValueError("patch offsets must be non-negative integers")
        if set(patch) - {"id", "reason", "match", "replace", "offset", "virtual_address", "section"}:
            raise ValueError("unknown patch fields")
        if patch["id"] in identifiers:
            raise ValueError("duplicate patch id")
        identifiers.add(patch["id"])
        match = parse_hex(patch["match"])
        replacement = parse_hex(patch["replace"])
        if not match or len(match) != len(replacement):
            raise ValueError("patch byte sequences must be non-empty and equal length")
        ranges.append((patch["offset"], patch["offset"] + len(match)))
    ranges.sort()
    if any(first[1] > second[0] for first, second in zip(ranges, ranges[1:])):
        raise ValueError("overlapping patches are not allowed")
    return manifest


def check_manifest(manifest: dict[str, Any], data: bytes) -> list[str]:
    """Return a list of human-readable problems. An empty list means the
    manifest matches the current bytes of the target."""
    problems: list[str] = []
    for patch in manifest["patches"]:
        offset = int(patch["offset"])
        match = parse_hex(patch["match"])
        found = data[offset:offset + len(match)]
        if found != match:
            problems.append(
                f"{patch.get('id', '<unnamed>')}: expected "
                f"{match.hex(' ')} at 0x{offset:x}, found {found.hex(' ')}"
            )
    return problems


def apply_patches(manifest: dict[str, Any], data: bytes) -> tuple[bytes, list[dict[str, Any]]]:
    buffer = bytearray(data)
    applied: list[dict[str, Any]] = []
    for patch in manifest["patches"]:
        offset = int(patch["offset"])
        match = parse_hex(patch["match"])
        replace = parse_hex(patch["replace"])
        if len(match) != len(replace):
            raise ValueError(
                f"{patch.get('id', '<unnamed>')}: length change "
                f"({len(match)} -> {len(replace)}) is not allowed; "
                "use a structural editor instead"
            )
        current = bytes(buffer[offset:offset + len(match)])
        if current != match:
            raise ValueError(
                f"{patch.get('id', '<unnamed>')}: at 0x{offset:x} found "
                f"{current.hex(' ')}, expected {match.hex(' ')}"
            )
        buffer[offset:offset + len(replace)] = replace
        applied.append(
            {
                "id": patch.get("id", "<unnamed>"),
                "offset": offset,
                "before": match.hex(" "),
                "after": replace.hex(" "),
            }
        )
    return bytes(buffer), applied


def atomic_write(target: Path, data: bytes, mode: int = 0o600) -> None:
    handle, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=target.name + ".")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode & 0o777)
        os.link(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--force",
        action="store_true",
        help="apply even when the target hash differs from the manifest",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="only report whether the manifest matches the target",
    )
    args = parser.parse_args()

    if args.target.is_symlink() or args.manifest.is_symlink():
        raise ValueError("input symbolic links are not supported")
    if not args.check and (args.output.resolve() == args.target.resolve() or os.path.lexists(args.output)):
        raise ValueError("output must be a new path, different from the original target")

    manifest = load_manifest(args.manifest)
    data = args.target.read_bytes()

    expected_hash = manifest.get("target_sha256")
    actual_hash = hashlib.sha256(data).hexdigest()
    if expected_hash and actual_hash != expected_hash and not args.force:
        print(
            f"refusing: sha256 {actual_hash} != manifest {expected_hash}\n"
            "         re-locate the patch offsets, or pass --force",
            file=sys.stderr,
        )
        return 2

    problems = check_manifest(manifest, data)
    if problems:
        print("manifest does not match the target:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 3

    if args.check:
        print(f"manifest matches {args.target} (sha256 {actual_hash})")
        return 0

    patched, applied = apply_patches(manifest, data)
    atomic_write(args.output, patched, stat.S_IMODE(args.target.stat().st_mode))

    for entry in applied:
        print(
            f"applied {entry['id']} at 0x{entry['offset']:x}: "
            f"{entry['before']} -> {entry['after']}"
        )
    print(f"wrote {args.output} ({len(applied)} patches, sha256 {sha256(args.output)})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"refusing: {error}", file=sys.stderr)
        sys.exit(1)
