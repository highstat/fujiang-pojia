#!/usr/bin/env python3
"""Validate the REA knowledge corpus against its schema.

Usage:
    python3 check-knowledge.py [--root knowledge] [--strict]

Checks every entry for:
    - frontmatter present, with exactly the required fields
    - id equal to the filename stem
    - domain matching the containing directory
    - updated equal to the expected date
    - verified is a boolean
    - the seven level-two sections present, in order
    - balanced code fences
    - no Han characters
    - relative Markdown links resolve

Exit status is 0 when the corpus conforms, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
from datetime import date
from urllib.parse import unquote, urlsplit
import re
import sys
from pathlib import Path

REQUIRED_FIELDS = [
    "id", "title", "domain", "kind", "platforms", "arch",
    "difficulty", "tools", "verified", "updated", "summary",
]
SECTIONS = [
    "Summary", "Recognition", "Method", "Variations",
    "Verification", "Pitfalls", "References",
]
KINDS = {"technique", "format", "pattern", "playbook-ref", "tooling"}
DIFFICULTIES = {"intro", "intermediate", "advanced"}
FRONTMATTER = re.compile(r"^---\n(.*?)\n---\n", re.S)
HAN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U0003134f]")
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
PLATFORMS = {"windows", "macos", "linux", "android", "ios"}
ARCHITECTURES = {"x86", "x86-64", "arm", "arm64", "arm64e"}
DOMAINS = {"native-core", "license-crypto", "windows-native", "windows-dotnet", "android", "ios", "macos", "linux-elf", "electron-js", "anti-analysis", "tooling"}


def parse_scalar(value: str):
    value = value.strip()
    if value.startswith('"'):
        return json.loads(value)
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value


def parse_frontmatter(raw: str) -> dict[str, object]:
    fields: dict[str, object] = {}
    for line in raw.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise ValueError("malformed frontmatter line")
        key, value = line.split(":", 1)
        if key.strip() in fields:
            raise ValueError("duplicate frontmatter key: " + key.strip())
        fields[key.strip()] = parse_scalar(value)
    return fields


def prose(text: str) -> tuple[str, bool]:
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r"^\s*([\x60]{3,}|~{3,})(.*)$", line)
        if match:
            marker, suffix = match.groups()
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence) and not suffix.strip():
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return "\n".join(lines), fence is None


def check_document(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    body, balanced = prose(text)
    problems = []
    if not balanced:
        problems.append(str(path) + ": unbalanced code fences")
    if HAN.search(text):
        problems.append(str(path) + ": contains Han characters")
    for reference in LINK.findall(body):
        parsed = urlsplit(reference)
        if not parsed.scheme and not parsed.netloc and parsed.path and not (path.parent / unquote(parsed.path)).exists():
            problems.append(str(path) + ": broken link " + reference)
    return problems


def check_file(path: Path, expected_date: str | None, strict: bool) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    relative = path.as_posix()

    if HAN.search(text):
        problems.append(f"{relative}: contains Han characters")

    match = FRONTMATTER.match(text)
    if match is None:
        return problems + [f"{relative}: missing frontmatter"]

    try:
        fields = parse_frontmatter(match.group(1))
    except ValueError as error:
        return [f"{relative}: {error}"]
    body, balanced = prose(text[match.end():])

    for field in REQUIRED_FIELDS:
        if field not in fields:
            problems.append(f"{relative}: missing frontmatter field '{field}'")
        elif field != "verified" and (not isinstance(fields[field], str) or not fields[field].strip()):
            problems.append(f"{relative}: {field} must be a non-empty string")
    if strict:
        extra = set(fields) - set(REQUIRED_FIELDS)
        if extra:
            problems.append(f"{relative}: unknown frontmatter fields {sorted(extra)}")

    if fields.get("id") != path.stem:
        problems.append(f"{relative}: id {fields.get('id')!r} != filename stem")
    if fields.get("domain") != path.parent.name or fields.get("domain") not in DOMAINS:
        problems.append(
            f"{relative}: domain {fields.get('domain')!r} != directory {path.parent.name!r}"
        )
    if fields.get("kind") not in KINDS:
        problems.append(f"{relative}: kind {fields.get('kind')!r} is not one of {sorted(KINDS)}")
    if fields.get("difficulty") not in DIFFICULTIES:
        problems.append(
            f"{relative}: difficulty {fields.get('difficulty')!r} is not one of {sorted(DIFFICULTIES)}"
        )
    if type(fields.get("verified")) is not bool:
        problems.append(f"{relative}: verified must be a boolean")
    try:
        updated = fields.get("updated", "")
        if date.fromisoformat(updated).isoformat() != updated:
            raise ValueError("non-canonical date")
    except (ValueError, TypeError):
        problems.append(f"{relative}: updated must be an ISO calendar date")
    if expected_date and fields.get("updated") != expected_date:
        problems.append(f"{relative}: updated {fields.get('updated')!r} != {expected_date!r}")
    if not isinstance(fields.get("summary"), str) or not fields.get("summary", "").strip():
        problems.append(f"{relative}: summary is empty")
    for field, allowed in [("platforms", PLATFORMS), ("arch", ARCHITECTURES)]:
        value = fields.get(field)
        if isinstance(value, str) and value != "-":
            names = value.split(", ")
            if len(set(names)) != len(names) or any(name not in allowed for name in names):
                problems.append(f"{relative}: non-canonical {field}")

    headings = re.findall(r"^## (.+?)\s*$", body, re.M)
    if headings != SECTIONS:
        problems.append(f"{relative}: level-two sections are {headings}")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent / "knowledge")
    parser.add_argument("--date", help="optional exact revision date; normally each entry keeps its own date")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    if not args.root.is_dir():
        print(f"knowledge root not found: {args.root}", file=sys.stderr)
        return 1

    entries = [
        path for path in sorted(args.root.rglob("*.md"))
        if path.name not in ("SCHEMA.md", "SKILL.md")
    ]
    if not entries:
        print(f"no entries found under {args.root}", file=sys.stderr)
        return 1

    problems: list[str] = []
    identities = set()
    for path in entries:
        problems.extend(check_file(path, args.date, args.strict))
        if path.stem in identities:
            problems.append(str(path) + ": duplicate entry id")
        identities.add(path.stem)
    corpus = args.root.parent
    for path in corpus.rglob("*.md"):
        problems.extend(check_document(path))
    skills = sorted((corpus / "skills").glob("*/SKILL.md"))
    for path in skills:
        try:
            match = FRONTMATTER.match(path.read_text(encoding="utf-8"))
            fields = parse_frontmatter(match.group(1)) if match else {}
            if fields.get("name") != path.parent.name or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", str(fields.get("name", ""))):
                raise ValueError("skill name must match its directory")
            if not isinstance(fields.get("description"), str) or not 1 <= len(fields["description"]) <= 1024:
                raise ValueError("missing or oversized skill description")
        except ValueError as error:
            problems.append(str(path) + ": " + str(error))

    if problems:
        print(f"{len(problems)} problem(s) in {len(entries)} entries:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1

    print(f"REA knowledge corpus valid: {len(entries)} entries across "
          f"{len({p.parent.name for p in entries})} domains; {len(skills)} skills and all Markdown links/fences checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
