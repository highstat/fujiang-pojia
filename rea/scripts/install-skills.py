#!/usr/bin/env python3
"""Install REA skills with local references, backups and rollback; never install engines."""

import argparse
import os
from pathlib import Path
import re
import shutil
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent


def refuse_links(path: Path) -> None:
    for current in [path, *path.parents]:
        if current.is_symlink():
            raise ValueError(f"symbolic-link destination is not supported: {current}")


def copy_tree(source: Path, destination: Path) -> None:
    if source.is_symlink():
        raise ValueError(f"source symbolic links are not supported: {source}")
    if source.is_dir():
        destination.mkdir()
        for child in sorted(source.iterdir()):
            if child.name != "__pycache__":
                copy_tree(child, destination / child.name)
    elif source.is_file():
        shutil.copy2(source, destination)
    else:
        raise ValueError(f"unsupported source: {source}")


def install(target: Path, dry_run: bool = False) -> list[str]:
    target = Path(os.path.abspath(target.expanduser()))
    if target == ROOT or ROOT in target.parents:
        raise ValueError("installation must not overwrite the source corpus")
    refuse_links(target)
    skills = sorted(path for path in (ROOT / "skills").iterdir() if path.is_dir())
    for skill in skills:
        if not re.fullmatch(r"rea-[a-z0-9-]+", skill.name) or not (skill / "SKILL.md").is_file():
            raise ValueError(f"invalid skill directory: {skill}")
        refuse_links(target / skill.name)
        if (target / skill.name).exists():
            if not (target / skill.name).is_dir():
                raise ValueError(f"expected an existing skill directory: {target / skill.name}")
            for child in (target / skill.name).rglob("*"):
                refuse_links(child)
    names = [skill.name for skill in skills]
    if "rea-knowledge-base" not in names:
        raise ValueError("shared resource skill is missing")
    if dry_run:
        print(f"Would install {len(skills)} skills and their resources into {target}; no changes made.")
        return names
    target.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".rea-stage-", dir=target))
    backup = target.parent / "fujiang-rea-backups" / uuid.uuid4().hex
    replaced = []
    try:
        for skill in skills:
            copy_tree(skill, stage / skill.name)
            entry = stage / skill.name / "SKILL.md"
            entry.write_text(entry.read_text(encoding="utf-8").replace("../../", "../rea-knowledge-base/references/"), encoding="utf-8")
        resources = stage / "rea-knowledge-base" / "references"
        resources.mkdir()
        for name in ["knowledge", "playbooks", "scripts", "templates", "references"]:
            copy_tree(ROOT / name, resources / name)
        (resources / "README.md").write_text("# Installed REA resources\n\n[Knowledge](knowledge/SKILL.md) · [Schema](knowledge/SCHEMA.md) · [Playbooks](playbooks/README.md) · [Tools](references/tool-matrix.md)\n\nThis is an offline snapshot, not an MCP server or engine installation.\n", encoding="utf-8")
        for name in names:
            destination = target / name
            saved = None
            if destination.exists():
                refuse_links(backup)
                backup.mkdir(parents=True, exist_ok=True, mode=0o700)
                saved = backup / name
                destination.rename(saved)
            replaced.append((destination, saved))
            (stage / name).rename(destination)
    except BaseException:
        for destination, saved in reversed(replaced):
            if destination.exists():
                shutil.rmtree(destination)
            if saved is not None:
                saved.rename(destination)
        raise
    finally:
        shutil.rmtree(stage)
    print(f"Installed {len(names)} skills with shared resources in {target}.")
    if backup.exists():
        print(f"Previous versions saved in {backup}.")
    print("Restart the host and verify discovery. MCP servers and analysis engines were not changed.")
    return names


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", type=Path, default=Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "opencode" / "skills")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    try:
        install(arguments.target, arguments.dry_run)
    except (ValueError, OSError) as error:
        parser.exit(1, f"REA installation failed: {error}\n")
