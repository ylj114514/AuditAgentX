"""基于文件扩展名的语言识别与代码规模统计。"""
from __future__ import annotations

from collections import Counter
import logging
from pathlib import Path
import os

logger = logging.getLogger(__name__)

EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".jsx": "JavaScript",
    ".tsx": "TypeScript", ".php": "PHP", ".java": "Java", ".go": "Go", ".rb": "Ruby",
    ".c": "C", ".cpp": "C++", ".cc": "C++", ".h": "C/C++", ".cs": "C#",
    ".rs": "Rust", ".vue": "Vue", ".sol": "Solidity", ".sh": "Shell",
    ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".sc": "Scala",
    ".swift": "Swift", ".dart": "Dart", ".m": "Objective-C", ".mm": "Objective-C++",
    ".r": "R", ".lua": "Lua", ".pl": "Perl", ".pm": "Perl",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hrl": "Erlang",
    ".hs": "Haskell", ".lhs": "Haskell", ".clj": "Clojure", ".cljs": "ClojureScript",
    ".groovy": "Groovy", ".fs": "F#", ".fsx": "F#", ".vb": "Visual Basic",
    ".ps1": "PowerShell", ".psm1": "PowerShell", ".zsh": "Shell", ".bash": "Shell",
    ".tf": "Terraform", ".hcl": "HCL", ".sql": "SQL", ".graphql": "GraphQL",
    ".html": "HTML", ".htm": "HTML", ".svelte": "Svelte",
}

NAME_LANG = {
    "dockerfile": "Dockerfile", "makefile": "Makefile", "cmakelists.txt": "CMake",
    "jenkinsfile": "Groovy", "vagrantfile": "Ruby", "rakefile": "Ruby",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", ".next", ".nuxt", "pods", "deriveddata",
}


def language_for(path: Path) -> str | None:
    name = path.name.lower()
    if name.startswith("dockerfile"):
        return "Dockerfile"
    return NAME_LANG.get(name) or EXT_LANG.get(path.suffix.lower())


def scan_files(root: Path, max_files: int = 20000) -> list[Path]:
    """遍历源码文件，跳过依赖/构建目录。"""
    root = root.resolve()
    if root.is_file():
        return [root] if language_for(root) else []
    files: list[Path] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs
            if d.lower() not in SKIP_DIRS and not (Path(current) / d).is_symlink()
        )
        for name in sorted(names):
            if len(files) >= max_files:
                break
            p = Path(current) / name
            try:
                if p.is_symlink():
                    continue
                p.resolve().relative_to(root)
            except (OSError, ValueError):
                continue
            if language_for(p):
                files.append(p)
        if len(files) >= max_files:
            break
    if len(files) >= max_files:
        logger.warning("源码文件枚举达到 max_files=%d；结果可能被截断", max_files)
    return files


def detect_languages(files: list[Path]) -> tuple[list[str], int]:
    """返回 (语言列表按占比排序, 总行数估算)。"""
    counter: Counter[str] = Counter()
    loc = 0
    for f in files:
        lang = language_for(f)
        if not lang:
            continue
        counter[lang] += 1
        try:
            with f.open("r", encoding="utf-8", errors="ignore") as fh:
                loc += sum(1 for _ in fh)
        except OSError:
            continue
    langs = [lang for lang, _ in counter.most_common()]
    return langs, loc
