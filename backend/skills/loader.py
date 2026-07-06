"""Load project Skill definitions for agents."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any


SKILLS_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=16)
def load_skill(name: str) -> dict[str, Any]:
    skill_dir = SKILLS_DIR / name.replace("-", "_")
    skill_file = skill_dir / "SKILL.md"
    if not skill_file.exists():
        raise FileNotFoundError(f"Skill '{name}' not found at {skill_file}")
    text = skill_file.read_text(encoding="utf-8")
    metadata = _parse_metadata(text)
    metadata["body"] = text
    return metadata


def _parse_metadata(text: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {"tools": [], "workflow": []}
    in_tools = False
    in_workflow = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("name:"):
            metadata["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("version:"):
            metadata["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("context_radius:"):
            metadata["context_radius"] = int(line.split(":", 1)[1].strip())
        elif line == "tools:":
            in_tools = True
            in_workflow = False
        elif line == "workflow:":
            in_tools = False
            in_workflow = True
        elif in_tools and line.startswith("-"):
            metadata["tools"].append(line[1:].strip())
        elif in_workflow and re.match(r"^\d+\.", line):
            metadata["workflow"].append(re.sub(r"^\d+\.\s*", "", line))
        elif line and not line.startswith("-") and not re.match(r"^\d+\.", line):
            in_tools = False
            in_workflow = False
    if "name" not in metadata:
        raise ValueError("Skill metadata must include 'name:'")
    return metadata
