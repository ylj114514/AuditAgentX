"""基于文件扩展名的语言识别与代码规模统计。"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".jsx": "JavaScript",
    ".tsx": "TypeScript", ".php": "PHP", ".java": "Java", ".go": "Go", ".rb": "Ruby",
    ".c": "C", ".cpp": "C++", ".cc": "C++", ".h": "C/C++", ".cs": "C#",
    ".rs": "Rust", ".vue": "Vue", ".sol": "Solidity", ".sh": "Shell",
}

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}


def scan_files(root: Path, max_files: int = 20000) -> list[Path]:
    """遍历源码文件，跳过依赖/构建目录。"""
    files: list[Path] = []
    for p in root.rglob("*"):
        if len(files) >= max_files:
            break
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in EXT_LANG:
            files.append(p)
    return files


def detect_languages(files: list[Path]) -> tuple[list[str], int]:
    """返回 (语言列表按占比排序, 总行数估算)。"""
    counter: Counter[str] = Counter()
    loc = 0
    for f in files:
        lang = EXT_LANG.get(f.suffix.lower())
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
