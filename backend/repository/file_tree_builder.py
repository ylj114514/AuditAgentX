"""构建项目目录树与入口点识别。"""
from __future__ import annotations

from pathlib import Path

from backend.repository.language_detector import EXT_LANG, SKIP_DIRS

ENTRYPOINT_NAMES = {
    "main.py", "app.py", "manage.py", "wsgi.py", "asgi.py",
    "index.php", "index.js", "server.js", "app.js",
    "main.go", "Application.java", "main.rb",
}


def build_tree(root: Path, files: list[Path]) -> list[dict]:
    """返回扁平目录树 [{path, type, language}]。"""
    tree: list[dict] = []
    for f in files:
        rel = f.relative_to(root).as_posix()
        tree.append({
            "path": rel,
            "type": "file",
            "language": EXT_LANG.get(f.suffix.lower(), "Other"),
        })
    return tree


def find_entrypoints(root: Path) -> list[str]:
    """识别常见入口文件（相对路径）。"""
    entries: list[str] = []
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in ENTRYPOINT_NAMES:
            entries.append(p.relative_to(root).as_posix())
    return entries
