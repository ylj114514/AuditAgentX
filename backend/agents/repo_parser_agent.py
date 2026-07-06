"""RepoParserAgent —— 仓库解析智能体。

不依赖 LLM，直接调用 repository 模块提取项目元信息。
"""
from __future__ import annotations

from pathlib import Path

from backend.repository.language_detector import scan_files, detect_languages
from backend.repository.dependency_parser import parse_dependencies
from backend.repository.file_tree_builder import build_tree, find_entrypoints


class RepoParserAgent:
    name = "repo_parser_agent"

    def run(self, code_root: Path) -> dict:
        files = scan_files(code_root)
        languages, loc = detect_languages(files)
        dep_files, frameworks = parse_dependencies(code_root)
        entrypoints = find_entrypoints(code_root)
        tree = build_tree(code_root, files)
        return {
            "languages": languages,
            "frameworks": frameworks,
            "dependencies": dep_files,
            "entrypoints": entrypoints,
            "file_count": len(files),
            "loc": loc,
            "tree": tree,
            "_files": [str(f) for f in files],  # 供后续扫描/审计使用
        }
